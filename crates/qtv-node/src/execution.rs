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
    /// The deployed container did not decode, or it names no entry for the call selector.
    BadContainer,
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

/// The outcome of a contract call: the contract's whole post execution storage, the native transfer
/// effects the call recorded through `send`, and the meter it spent.
#[derive(Debug)]
pub struct ContractOutcome {
    pub storage: std::collections::BTreeMap<u64, u64>,
    pub effects: Vec<qtv_vm::interp::Effect>,
    pub meter_used: u64,
}

fn read_be_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let word = bytes.get(*pos..end)?;
    *pos = end;
    Some(u32::from_be_bytes(word.try_into().ok()?))
}

fn read_be_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let word = bytes.get(*pos..end)?;
    *pos = end;
    Some(u64::from_be_bytes(word.try_into().ok()?))
}

fn read_slots(bytes: &[u8], pos: &mut usize) -> Option<Vec<u64>> {
    let count = read_be_u32(bytes, pos)?;
    // Start empty rather than reserving `count` up front. The count is attacker controlled in a
    // deployed container, so a huge value would reserve gigabytes and abort the node before a single
    // element is read. Growing as each bounded read succeeds caps the allocation at the bytes that
    // actually follow, so a count larger than the remaining bytes fails fast instead.
    let mut slots = Vec::new();
    for _ in 0..count {
        slots.push(read_be_u64(bytes, pos)?);
    }
    Some(slots)
}

/// Rebuild a container from its canonical bytes, the inverse of the machine's `canonical_bytes`. The
/// tagged qtv-vm serializes a container but does not read one back, and the chain must, so a deployed
/// container can run. The format is the `QVM1` tag, then the length prefixed code, the constant pool,
/// and the entries, each an entry selector, its code offset, and its declared reads and writes. It is
/// a pure function of the bytes, so every node rebuilds the identical container from the same deploy.
pub fn decode_container(bytes: &[u8]) -> Option<qtv_vm::container::Container> {
    use qtv_vm::container::{Container, Entry, StateAccess, SELECTOR_BYTES};
    if bytes.len() < 4 || &bytes[0..4] != b"QVM1" {
        return None;
    }
    let mut pos = 4usize;
    let code_len = read_be_u32(bytes, &mut pos)? as usize;
    let code_end = pos.checked_add(code_len)?;
    let code = bytes.get(pos..code_end)?.to_vec();
    pos = code_end;
    let consts_len = read_be_u32(bytes, &mut pos)?;
    // Start empty and grow as each bounded read succeeds, so an attacker supplied count cannot
    // reserve a huge allocation before any bytes are read. See read_slots for why.
    let mut consts = Vec::new();
    for _ in 0..consts_len {
        consts.push(read_be_u64(bytes, &mut pos)?);
    }
    let entries_len = read_be_u32(bytes, &mut pos)?;
    let mut entries = Vec::new();
    for _ in 0..entries_len {
        let sel_end = pos.checked_add(SELECTOR_BYTES)?;
        let mut selector = [0u8; SELECTOR_BYTES];
        selector.copy_from_slice(bytes.get(pos..sel_end)?);
        pos = sel_end;
        let offset = read_be_u32(bytes, &mut pos)?;
        let reads = read_slots(bytes, &mut pos)?;
        let writes = read_slots(bytes, &mut pos)?;
        entries.push(Entry {
            selector,
            offset,
            access: StateAccess { reads, writes },
        });
    }
    Some(Container::new(code, consts, entries))
}

/// Run one entry of a deployed contract through the virtual machine. The container's canonical bytes
/// rebuild the container, the entry is selected by its selector, the contract's whole storage seeds
/// the machine, and the argument memory carries the call arguments and the host context words the
/// caller placed. A clean halt yields the post execution storage, the recorded native transfer
/// effects, and the meter spent; a fault, an undecodable container, or an unknown selector is refused
/// and no state moves.
pub fn execute_contract_call(
    container_bytes: &[u8],
    selector: [u8; qtv_vm::container::SELECTOR_BYTES],
    storage: std::collections::BTreeMap<u64, u64>,
    memory: &[u8],
    meter_limit: u64,
) -> Result<ContractOutcome, ExecError> {
    let container = decode_container(container_bytes).ok_or(ExecError::BadContainer)?;
    let outcome = Interpreter::for_entry(&container, selector, meter_limit)
        .map_err(|_| ExecError::BadContainer)?
        .with_storage(storage)
        .with_memory(memory)
        .run()
        .map_err(|fault| match fault {
            Fault::Overflow => ExecError::InsufficientFunds,
            Fault::OutOfGas => ExecError::MeterExhausted,
            other => ExecError::Vm(other),
        })?;
    Ok(ContractOutcome {
        storage: outcome.storage,
        effects: outcome.effects,
        meter_used: outcome.gas_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_container_with_a_huge_count_is_refused_without_a_giant_allocation() {
        // The QVM1 tag, a zero length code section, then a constant count of four billion with no
        // constant bytes following. Before the fix this reserved billions of elements and aborted the
        // node. Now the decoder grows as it reads and fails the moment the bytes run out, returning
        // None without a large allocation.
        let mut bytes = b"QVM1".to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes()); // code length zero
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // a hostile constant count
        assert!(decode_container(&bytes).is_none());

        // The same for a hostile entry count.
        let mut bytes = b"QVM1".to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes()); // code length zero
        bytes.extend_from_slice(&0u32.to_be_bytes()); // no constants
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // a hostile entry count
        assert!(decode_container(&bytes).is_none());
    }

    #[test]
    fn a_contract_call_runs_a_decoded_container_and_persists_storage() {
        use qtv_vm::container::{Container, Entry, StateAccess};
        // Load constant zero, the value forty two, and store it into slot seven, then halt.
        let code = qtv_vm::asm::assemble("LDC r0, 0\nLDI r1, 7\nSSTORE r1, r0\nHALT")
            .expect("the program assembles");
        let selector = [1u8, 2, 3, 4];
        let container = Container::new(
            code,
            vec![42],
            vec![Entry {
                selector,
                offset: 0,
                access: StateAccess {
                    reads: vec![],
                    writes: vec![7],
                },
            }],
        );
        let bytes = container.canonical_bytes();

        // The chain rebuilds the container from its canonical bytes and runs the entry.
        let out = execute_contract_call(
            &bytes,
            selector,
            std::collections::BTreeMap::new(),
            &[],
            100_000,
        )
        .expect("the call halts");
        assert_eq!(out.storage.get(&7), Some(&42));

        // An unknown selector and an undecodable container are both refused.
        assert_eq!(
            execute_contract_call(&bytes, [9, 9, 9, 9], std::collections::BTreeMap::new(), &[], 100_000)
                .unwrap_err(),
            ExecError::BadContainer
        );
        assert_eq!(
            execute_contract_call(b"nope", selector, std::collections::BTreeMap::new(), &[], 100_000)
                .unwrap_err(),
            ExecError::BadContainer
        );
    }

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

    #[test]
    fn the_transfer_meter_is_constant_so_it_cannot_be_exceeded() {
        // The transfer program is straight line with no data dependent branch, so
        // the meter it spends does not depend on the amount, the fee, or the
        // balances. Across a spread of inputs that each reach a clean halt, the
        // meter spent is always exactly TRANSFER_METER, so a limit of TRANSFER_METER
        // is enough for every transfer and no transfer, whatever its values, spends
        // past it. The extreme case sits at the edge of the checked debit, amount
        // plus fee one below the sender balance.
        let cases = [
            (u64::MAX, 0u64, 0u64),
            (1_000, 1, 1),
            (1_000, 998, 1),
            (u64::MAX, u64::MAX / 2, u64::MAX / 2),
            (500, 200, 300),
        ];
        for (balance, amount, fee) in cases {
            let out = execute_transfer(balance, 0, amount, fee, TRANSFER_METER).expect("halt");
            assert_eq!(out.meter_used, TRANSFER_METER);
        }
    }

    #[test]
    fn no_transfer_commits_below_its_meter_limit() {
        // The dual of the constant cost: at every limit below that cost the run
        // faults rather than completing, so there is no path that runs past the
        // limit and still moves a balance. We sweep every limit from zero up to one
        // below the cost, and each one faults.
        for limit in 0..TRANSFER_METER {
            let err = execute_transfer(1_000, 0, 1, 1, limit).unwrap_err();
            assert_eq!(err, ExecError::MeterExhausted);
        }
    }
}
