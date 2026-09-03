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

pub const CODE_ACCESS_BYTE_METER: u64 = 1;
pub const STORAGE_ACCESS_BYTE_METER: u64 = 1;
/// What one slot costs to touch. A slot is a trie read plus, if written, a trie write,
/// so it is charged well above a plain instruction. This replaces charging a call for
/// the size of the whole contract, which is what created the size ceiling, while still
/// pricing the real work so a call cannot walk a large keyspace for nothing.
pub const SLOT_ACCESS_METER: u64 = 200;

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
            Fault::OutOfMeter => ExecError::MeterExhausted,
            other => ExecError::Vm(other),
        })?;

    Ok(Transferred {
        sender_balance: outcome.storage.get(&sender_key).copied().unwrap_or(0),
        recipient_balance: outcome.storage.get(&recipient_key).copied().unwrap_or(0),
        meter_used: outcome.meter_used,
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

const MAX_SLOTS_PER_LIST: usize = 1 << 16;

fn read_slots(bytes: &[u8], pos: &mut usize) -> Option<Vec<u64>> {
    let count = read_be_u32(bytes, pos)? as usize;
    if count > MAX_SLOTS_PER_LIST {
        return None;
    }
    let available = bytes.len().saturating_sub(*pos) / 8;
    let mut slots = Vec::with_capacity(count.min(available));
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
    if consts_len as usize > qtv_vm::container::MAX_CONSTS {
        return None;
    }
    let mut consts =
        Vec::with_capacity((consts_len as usize).min(bytes.len().saturating_sub(pos) / 8));
    for _ in 0..consts_len {
        consts.push(read_be_u64(bytes, &mut pos)?);
    }
    let entries_len = read_be_u32(bytes, &mut pos)?;
    if entries_len as usize > qtv_vm::container::MAX_ENTRIES {
        return None;
    }
    let mut entries =
        Vec::with_capacity((entries_len as usize).min(bytes.len().saturating_sub(pos) / 24));
    for _ in 0..entries_len {
        let sel_end = pos.checked_add(SELECTOR_BYTES)?;
        let mut selector = [0u8; SELECTOR_BYTES];
        selector.copy_from_slice(bytes.get(pos..sel_end)?);
        pos = sel_end;
        let offset = read_be_u32(bytes, &mut pos)?;
        let reads = read_slots(bytes, &mut pos)?;
        let writes = read_slots(bytes, &mut pos)?;
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

/// Run an entry, reading storage slots on demand.
///
/// The whole of a contract's storage used to be handed in, and charged for, on every
/// call. That made a call cost what the contract HELD rather than what it TOUCHED, and
/// once a contract held more than the per transaction meter could pay for it could
/// never be called again. The loader is asked only for the slots the entry actually
/// reads, and only the slots it writes come back.
pub fn execute_contract_call_lazy(
    container_bytes: &[u8],
    selector: [u8; qtv_vm::container::SELECTOR_BYTES],
    loader: &dyn Fn(&[u8; 32]) -> u64,
    memory: &[u8],
    meter_limit: u64,
) -> Result<ContractOutcome, ExecError> {
    let access_cost = (container_bytes.len() as u64).saturating_mul(CODE_ACCESS_BYTE_METER);
    let vm_limit = meter_limit
        .checked_sub(access_cost)
        .ok_or(ExecError::MeterExhausted)?;
    let container = decode_container(container_bytes).ok_or(ExecError::BadContainer)?;
    container
        .entry_offset(&selector)
        .ok_or(ExecError::BadContainer)?;
    let interpreter = Interpreter::for_entry(&container, selector, vm_limit)
        .map_err(|_| ExecError::BadContainer)?;
    let outcome = interpreter
        .with_storage_loader(loader)
        .with_memory(memory)
        .run()
        .map_err(|fault| match fault {
            Fault::Overflow => ExecError::InsufficientFunds,
            Fault::OutOfMeter => ExecError::MeterExhausted,
            other => ExecError::Vm(other),
        })?;
    let touched = outcome.storage.len() as u64;
    Ok(ContractOutcome {
        storage: outcome
            .dirty
            .iter()
            .filter_map(|slot| outcome.storage.get(slot).map(|v| (*slot, *v)))
            .collect(),
        effects: outcome.effects,
        meter_used: outcome
            .meter_used
            .saturating_add(access_cost)
            .saturating_add(touched.saturating_mul(SLOT_ACCESS_METER)),
    })
}

pub fn execute_contract_call(
    container_bytes: &[u8],
    selector: [u8; qtv_vm::container::SELECTOR_BYTES],
    storage: std::collections::BTreeMap<[u8; 32], u64>,
    storage_bytes: usize,
    memory: &[u8],
    meter_limit: u64,
) -> Result<ContractOutcome, ExecError> {
    let access_cost = (container_bytes.len() as u64)
        .saturating_mul(CODE_ACCESS_BYTE_METER)
        .saturating_add((storage_bytes as u64).saturating_mul(STORAGE_ACCESS_BYTE_METER));
    let vm_limit = meter_limit
        .checked_sub(access_cost)
        .ok_or(ExecError::MeterExhausted)?;
    let container = decode_container(container_bytes).ok_or(ExecError::BadContainer)?;
    container
        .entry_offset(&selector)
        .ok_or(ExecError::BadContainer)?;
    let interpreter = Interpreter::for_entry(&container, selector, vm_limit)
        .map_err(|_| ExecError::BadContainer)?;
    let outcome = interpreter
        .with_storage(storage)
        .with_memory(memory)
        .run()
        .map_err(|fault| match fault {
            Fault::Overflow => ExecError::InsufficientFunds,
            Fault::OutOfMeter => ExecError::MeterExhausted,
            other => ExecError::Vm(other),
        })?;
    Ok(ContractOutcome {
        storage: outcome.storage,
        effects: outcome.effects,
        meter_used: outcome.meter_used.saturating_add(access_cost),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_container_with_a_huge_count_is_refused_without_a_giant_allocation() {
        let mut bytes = b"QVM1".to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert!(decode_container(&bytes).is_none());

        let mut bytes = b"QVM1".to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
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
            0,
            &key,
            100_000,
        )
        .expect("the call halts");
        assert_eq!(out.storage.get(&key), Some(&42));

        assert_eq!(
            execute_contract_call(
                &bytes,
                [9, 9, 9, 9],
                std::collections::BTreeMap::new(),
                0,
                &[],
                100_000
            )
            .unwrap_err(),
            ExecError::BadContainer
        );
        assert_eq!(
            execute_contract_call(
                b"nope",
                selector,
                std::collections::BTreeMap::new(),
                0,
                &[],
                100_000
            )
            .unwrap_err(),
            ExecError::BadContainer
        );
    }

    #[test]
    fn a_call_pays_for_the_container_it_loads() {
        use qtv_vm::container::{Container, Entry, StateAccess};
        let mut source = String::new();
        for _ in 0..2048 {
            source.push_str("NOP\n");
        }
        source.push_str("HALT");
        let code = qtv_vm::asm::assemble(&source).expect("the program assembles");
        let selector = [5u8, 6, 7, 8];
        let container = Container::new(
            code,
            vec![],
            vec![Entry {
                selector,
                offset: 0,
                access: StateAccess {
                    reads: vec![],
                    writes: vec![],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );
        let bytes = container.canonical_bytes();
        let access = bytes.len() as u64 * CODE_ACCESS_BYTE_METER;
        assert!(
            access > TRANSFER_METER,
            "the container must exceed the floor meter"
        );

        assert_eq!(
            execute_contract_call(
                &bytes,
                selector,
                std::collections::BTreeMap::new(),
                0,
                &[],
                access - 1,
            )
            .unwrap_err(),
            ExecError::MeterExhausted
        );

        let out = execute_contract_call(
            &bytes,
            selector,
            std::collections::BTreeMap::new(),
            0,
            &[],
            100_000,
        )
        .expect("the call halts");
        assert!(out.meter_used >= access);
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

    #[test]
    fn a_bloated_storage_costs_meter_before_it_is_ever_decoded() {
        use qtv_vm::container::{Container, Entry, StateAccess};
        let key = qtv_vm::abi::scalar_key(7);
        let code = qtv_vm::asm::assemble(
            "LDC r0, 0
LDI r1, 0
SSTORE r1, r0
HALT",
        )
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
        let code_only = bytes.len() as u64 * CODE_ACCESS_BYTE_METER;
        let bloat = 900_000usize;
        let with_bloat = code_only + bloat as u64 * STORAGE_ACCESS_BYTE_METER;

        let lean = execute_contract_call(
            &bytes,
            selector,
            std::collections::BTreeMap::new(),
            0,
            &key,
            100_000,
        )
        .expect("a lean contract runs");

        let fat = execute_contract_call(
            &bytes,
            selector,
            std::collections::BTreeMap::new(),
            bloat,
            &key,
            100_000,
        );
        assert_eq!(
            fat.unwrap_err(),
            ExecError::MeterExhausted,
            "storage bytes must be paid for, not carried free"
        );
        assert!(
            with_bloat > lean.meter_used,
            "a contract holding {bloat} bytes must cost more than the same code holding none"
        );
    }
}
