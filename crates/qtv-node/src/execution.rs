//! Transaction execution through the virtual machine.
//!
//! A transaction in this slice is a native transfer. Its call names the recipient
//! address and carries the transfer amount. The node runs a fixed program on the
//! qtv-vm interpreter that debits the sender by the amount and the protocol fee
//! and credits the recipient by the amount, so the balance change is a real
//! metered execution, not a bookkeeping step. The sender and recipient balances
//! enter the interpreter as its declared storage and the amount and fee enter as
//! its constant pool. On a clean halt the node reads the post execution balances
//! back; a checked subtraction that would underflow faults the run and no balance
//! moves, which is how an insufficient balance is rejected at execution.

use qtv_codec::{Decoder, Encoder};
use qtv_tx::Call;
use qtv_vm::asm::assemble;
use qtv_vm::interp::{Fault, Interpreter};

/// The storage slot the sender balance occupies during a run.
const SENDER_SLOT: u64 = 0;
/// The storage slot the recipient balance occupies during a run.
const RECIPIENT_SLOT: u64 = 1;

/// The fixed transfer program. It loads the amount and the fee from the constant
/// pool, debits the sender by their sum with a checked subtraction, and credits
/// the recipient by the amount, then halts. A checked subtraction faults on an
/// insufficient balance and a clean halt commits the two updated balances.
const TRANSFER_PROGRAM: &str = "\
LDC r0, 0
LDC r1, 1
ADD r2, r0, r1
LDI r3, 0
SLOAD r4, r3
SUB r4, r4, r2
SSTORE r3, r4
LDI r5, 1
SLOAD r6, r5
ADD r6, r6, r0
SSTORE r5, r6
HALT";

/// The meter a transfer program spends over the machine's weighted schedule, and so
/// the minimum meter limit a transfer needs to reach a clean halt.
pub const TRANSFER_METER: u64 = 1_210;

/// A native transfer call: the recipient address as the target and the amount as
/// eight little endian bytes of arguments.
pub fn transfer_call(recipient: &str, amount: u64) -> Call {
    let mut encoder = Encoder::new();
    encoder.put_u64(amount);
    Call::new(recipient.to_string(), encoder.into_bytes())
}

/// The amount a transfer call carries, or None when the arguments are not a
/// single eight byte amount.
pub fn transfer_amount(call: &Call) -> Option<u64> {
    let mut decoder = Decoder::new(call.args());
    let amount = decoder.get_u64().ok()?;
    decoder.finish().ok()?;
    Some(amount)
}

/// The reason a transfer failed to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    /// The sender could not cover the amount and the fee, so the debit faulted.
    InsufficientFunds,
    /// The meter limit did not cover the program's execution.
    MeterExhausted,
    /// Any other virtual machine fault, which a native transfer never reaches.
    Vm(Fault),
}

/// The outcome of a transfer: the post execution balances and the meter spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transferred {
    pub sender_balance: u64,
    pub recipient_balance: u64,
    pub meter_used: u64,
}

/// Execute a transfer through the virtual machine. The sender and recipient
/// balances seed the interpreter storage and the amount and fee seed the constant
/// pool. A clean halt yields the two post execution balances and the meter spent.
/// The meter limit is passed to the machine, which meters execution per operation
/// and faults when it would exceed the limit, and the machine's own metering is
/// mapped back onto our meter here at the one boundary where the two meet.
pub fn execute_transfer(
    sender_balance: u64,
    recipient_balance: u64,
    amount: u64,
    fee: u64,
    meter_limit: u64,
) -> Result<Transferred, ExecError> {
    let code = assemble(TRANSFER_PROGRAM).expect("the transfer program assembles");
    let consts = [amount, fee];
    let mut storage = std::collections::BTreeMap::new();
    storage.insert(SENDER_SLOT, sender_balance);
    storage.insert(RECIPIENT_SLOT, recipient_balance);

    let outcome = Interpreter::new(&code, &consts, meter_limit)
        .with_storage(storage)
        .run()
        .map_err(|fault| match fault {
            Fault::Overflow => ExecError::InsufficientFunds,
            Fault::OutOfGas => ExecError::MeterExhausted,
            other => ExecError::Vm(other),
        })?;

    Ok(Transferred {
        sender_balance: outcome.storage.get(&SENDER_SLOT).copied().unwrap_or(0),
        recipient_balance: outcome.storage.get(&RECIPIENT_SLOT).copied().unwrap_or(0),
        meter_used: outcome.gas_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_round_trips_its_amount() {
        let call = transfer_call("q1recipient", 4_200);
        assert_eq!(transfer_amount(&call), Some(4_200));
        assert_eq!(call.target(), "q1recipient");
    }

    #[test]
    fn a_malformed_call_has_no_amount() {
        let call = Call::new("q1recipient".to_string(), vec![1, 2, 3]);
        assert_eq!(transfer_amount(&call), None);
    }

    #[test]
    fn a_transfer_moves_the_amount_and_the_fee() {
        let out = execute_transfer(1_000, 50, 200, 10, TRANSFER_METER).expect("halt");
        assert_eq!(out.sender_balance, 1_000 - 200 - 10);
        assert_eq!(out.recipient_balance, 50 + 200);
        assert_eq!(out.meter_used, TRANSFER_METER);
    }

    #[test]
    fn a_transfer_that_cannot_pay_faults_and_moves_nothing() {
        let err = execute_transfer(150, 0, 200, 10, TRANSFER_METER).unwrap_err();
        assert_eq!(err, ExecError::InsufficientFunds);
    }

    #[test]
    fn a_transfer_below_its_meter_runs_out() {
        let err = execute_transfer(1_000, 0, 200, 10, TRANSFER_METER - 1).unwrap_err();
        assert_eq!(err, ExecError::MeterExhausted);
    }
}
