// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_codec::{Decoder, Encoder};
use qtv_tx::Call;
use qtv_vm::asm::assemble;
use qtv_vm::interp::{Fault, Interpreter};

const SENDER_SLOT: u64 = 0;
const RECIPIENT_SLOT: u64 = 1;

fn sender_key() -> [u8; 32] {
    qtv_vm::abi::scalar_key(SENDER_SLOT)
}
fn recipient_key() -> [u8; 32] {
    qtv_vm::abi::scalar_key(RECIPIENT_SLOT)
}

const TRANSFER_PROGRAM: &str = "\
LDC r0, 0
LDC r1, 1
ADD r2, r0, r1
LDI r3, 0
SLOAD r4, r3
SUB r4, r4, r2
SSTORE r3, r4
LDI r5, 32
SLOAD r6, r5
ADD r6, r6, r0
SSTORE r5, r6
HALT";

pub const TRANSFER_METER: u64 = 1_210;

pub fn transfer_call(recipient: &str, amount: u64) -> Call {
    let mut encoder = Encoder::new();
    encoder.put_u64(amount);
    Call::new(recipient.to_string(), encoder.into_bytes())
}

pub fn transfer_amount(call: &Call) -> Option<u64> {
    let mut decoder = Decoder::new(call.args());
    let amount = decoder.get_u64().ok()?;
    decoder.finish().ok()?;
    Some(amount)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    InsufficientFunds,
    MeterExhausted,
    Vm(Fault),
    BadContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transferred {
    pub sender_balance: u64,
    pub recipient_balance: u64,
    pub meter_used: u64,
}

pub fn execute_transfer(
    sender_balance: u64,
    recipient_balance: u64,
    amount: u64,
    fee: u64,
    meter_limit: u64,
) -> Result<Transferred, ExecError> {
    let code = assemble(TRANSFER_PROGRAM).expect("the transfer program assembles");
    let consts = [amount, fee];
    let (sender_key, recipient_key) = (sender_key(), recipient_key());
    let mut storage = std::collections::BTreeMap::new();
    storage.insert(sender_key, sender_balance);
    storage.insert(recipient_key, recipient_balance);
    let mut memory = [0u8; 64];
    memory[..32].copy_from_slice(&sender_key);
    memory[32..].copy_from_slice(&recipient_key);

    let outcome = Interpreter::new(&code, &consts, meter_limit)
        .with_storage(storage)
        .with_memory(&memory)
        .run()
        .map_err(|fault| match fault {
            Fault::Overflow => ExecError::InsufficientFunds,
            Fault::OutOfGas => ExecError::MeterExhausted,
            other => ExecError::Vm(other),
        })?;

    Ok(Transferred {
        sender_balance: outcome.storage.get(&sender_key).copied().unwrap_or(0),
        recipient_balance: outcome.storage.get(&recipient_key).copied().unwrap_or(0),
        meter_used: outcome.gas_used,
    })
}

#[derive(Debug)]
pub struct ContractOutcome {
    pub storage: std::collections::BTreeMap<[u8; 32], u64>,
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
    let mut slots = Vec::new();
    for _ in 0..count {
        slots.push(read_be_u64(bytes, pos)?);
    }
    Some(slots)
}

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
        // The canonical container carries the keyed manifest, the map bases an entry may read and
        // write, right after the scalar reads and writes. Decoding them in the same order the VM
        // encodes them keeps this decoder in step with the format, so a deployed container carries its
        // keyed authorisation on chain and map writes are not rejected as undeclared.
        let keyed_reads = read_slots(bytes, &mut pos)?;
        let keyed_writes = read_slots(bytes, &mut pos)?;
        entries.push(Entry {
            selector,
            offset,
            access: StateAccess {
                reads,
                writes,
                keyed_reads,
                keyed_writes,
            },
        });
    }
    Some(Container::new(code, consts, entries))
}

pub fn execute_contract_call(
    container_bytes: &[u8],
    selector: [u8; qtv_vm::container::SELECTOR_BYTES],
    storage: std::collections::BTreeMap<[u8; 32], u64>,
    memory: &[u8],
    meter_limit: u64,
) -> Result<ContractOutcome, ExecError> {
    let container = decode_container(container_bytes).ok_or(ExecError::BadContainer)?;
    // Validate the selector exists, then dispatch every entry under its storage manifest, including the
    // first entry at code offset zero. Routing offset zero through Interpreter::new would leave the
    // manifest unset and silently drop the declared slot enforcement, the dispatch gas, and the
    // instruction boundary jump checks for the first entry of every contract.
    container
        .entry_offset(&selector)
        .ok_or(ExecError::BadContainer)?;
    let interpreter = Interpreter::for_entry(&container, selector, meter_limit)
        .map_err(|_| ExecError::BadContainer)?;
    let outcome = interpreter
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
        let mut bytes = b"QVM1".to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes()); // code length zero
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // a hostile constant count
        assert!(decode_container(&bytes).is_none());

        let mut bytes = b"QVM1".to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes()); // code length zero
        bytes.extend_from_slice(&0u32.to_be_bytes()); // no constants
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // a hostile entry count
        assert!(decode_container(&bytes).is_none());
    }

    #[test]
    fn a_contract_call_runs_a_decoded_container_and_persists_storage() {
        use qtv_vm::container::{Container, Entry, StateAccess};
        let key = qtv_vm::abi::scalar_key(7);
        let code = qtv_vm::asm::assemble("LDC r0, 0\nLDI r1, 0\nSSTORE r1, r0\nHALT")
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
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );
        let bytes = container.canonical_bytes();

        let out = execute_contract_call(
            &bytes,
            selector,
            std::collections::BTreeMap::new(),
            &key,
            100_000,
        )
        .expect("the call halts");
        assert_eq!(out.storage.get(&key), Some(&42));

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
        for limit in 0..TRANSFER_METER {
            let err = execute_transfer(1_000, 0, 1, 1, limit).unwrap_err();
            assert_eq!(err, ExecError::MeterExhausted);
        }
    }
}
