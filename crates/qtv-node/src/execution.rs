// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_codec::{Decoder, Encoder};
use qtv_tx::Call;
use qtv_vm::asm::assemble;
use qtv_vm::interp::{Fault, Interpreter};
use std::sync::OnceLock;

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
pub const SLOT_ACCESS_METER: u64 = 200;

pub const DEPLOY_BYTE_METER: u64 = 100;

pub fn deploy_meter_cost(container_bytes: usize) -> u64 {
    (container_bytes as u64).saturating_mul(DEPLOY_BYTE_METER)
}

#[cfg(test)]
mod deploy_price {
    use super::*;

    #[test]
    fn permanent_state_costs_more_than_the_flat_fee_can_buy() {
        const BLOCK_BUDGET: u64 = 50_000_000;
        let big = 130_984usize;
        let cost = deploy_meter_cost(big);
        assert!(
            cost > 1_210,
            "a {big} byte container must cost more than a plain transfer meter, cost {cost}"
        );
        assert!(
            cost > BLOCK_BUDGET / 100,
            "one such deploy must take a real share of the block budget, cost {cost}"
        );
    }

    #[test]
    fn the_block_budget_bounds_how_much_state_a_block_can_buy() {
        const BLOCK_BUDGET: u64 = 50_000_000;
        let max_bytes = BLOCK_BUDGET / DEPLOY_BYTE_METER;
        assert!(
            max_bytes <= 1_000_000,
            "a block must not admit {max_bytes} bytes of permanent contract code"
        );
        const MAX_TX: u64 = BLOCK_BUDGET / 4;
        assert!(
            deploy_meter_cost(60 * 1024) < MAX_TX / 2,
            "a 60 KiB contract must deploy comfortably, cost {}",
            deploy_meter_cost(60 * 1024)
        );
    }

    #[test]
    fn the_price_saturates_rather_than_wrapping() {
        assert_eq!(deploy_meter_cost(usize::MAX), u64::MAX);
    }
}

#[cfg(test)]
mod slot_charge {
    use super::*;

    fn run(src: &str, reads: Vec<u64>) -> ContractOutcome {
        let key = qtv_vm::abi::scalar_key(0);
        let code = qtv_vm::asm::assemble(src).expect("assembles");
        let selector = [3u8, 3, 3, 3];
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads,
                    writes: vec![],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );
        let mut memory = vec![0u8; 4096];
        memory[..32].copy_from_slice(&key);
        execute_contract_call_lazy(
            &container.canonical_bytes(),
            selector,
            &|_k| 41,
            &memory,
            4_000_000,
        )
        .expect("the call halts")
    }

    fn generous_limit_for(bytes: &[u8]) -> u64 {
        (bytes.len() as u64).saturating_mul(CODE_ACCESS_BYTE_METER) + 200_000
    }

    #[test]
    fn the_reading_stops_when_the_caller_runs_out_of_ways_to_pay_for_it() {
        use std::cell::Cell;

        let selector = [3u8, 3, 3, 3];
        let slots: Vec<u64> = (0..64).collect();
        let mut memory = vec![0u8; 32 * slots.len() + 64];
        for (i, slot) in slots.iter().enumerate() {
            let key = qtv_vm::abi::scalar_key(*slot);
            memory[i * 32..i * 32 + 32].copy_from_slice(&key);
        }
        let src = {
            let mut lines = String::new();
            for i in 0..slots.len() {
                lines.push_str(&format!("LDI r0, {}\nSLOAD r1, r0\n", i * 32));
            }
            lines.push_str("HALT");
            lines
        };
        let code = qtv_vm::asm::assemble(&src).expect("assembles");
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: slots.clone(),
                    writes: vec![],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );
        let bytes = container.canonical_bytes();

        let call = |limit: u64| {
            let asked = Cell::new(0u64);
            let outcome = {
                let counting = |_k: &[u8; 32]| {
                    asked.set(asked.get() + 1);
                    41u64
                };
                execute_contract_call_lazy(&bytes, selector, &counting, &memory, limit)
            };
            (asked.get(), outcome)
        };

        let (asked_generous, generous) = call(4_000_000);
        assert!(generous.is_ok(), "a funded call still runs every read");
        assert_eq!(
            asked_generous,
            slots.len() as u64,
            "a funded call reads every slot it declared"
        );

        let access_cost = (bytes.len() as u64).saturating_mul(CODE_ACCESS_BYTE_METER);
        let (asked_none, too_poor) = call(access_cost + 1);
        assert!(
            matches!(too_poor, Err(ExecError::MeterExhausted)),
            "a call that cannot pay to enter is refused for that reason, got {too_poor:?}"
        );
        assert_eq!(asked_none, 0, "and it reads nothing at all");

        let full_cost = generous
            .as_ref()
            .expect("the funded call halted")
            .meter_used;
        let lean = access_cost + (full_cost - access_cost) / 2;
        let (asked_lean, outcome) = call(lean);
        assert!(
            matches!(outcome, Err(ExecError::MeterExhausted)),
            "a call that cannot pay for its reads is refused, got {outcome:?} after {asked_lean} reads"
        );
        let affordable = lean.saturating_sub(access_cost) / SLOT_ACCESS_METER;
        assert!(
            asked_lean <= affordable,
            "the node must not read more slots than the caller could pay for: \
             asked {asked_lean}, affordable {affordable}"
        );
        assert!(
            asked_lean < slots.len() as u64,
            "the reading must stop short of the whole declared set"
        );
    }

    #[test]
    fn a_read_costs_the_same_slot_charge_as_a_write() {
        let with_read = run("LDI r0, 0\nSLOAD r1, r0\nHALT", vec![0]);
        let without = run("LDI r0, 0\nHALT", vec![]);
        assert!(
            with_read.meter_used >= without.meter_used + SLOT_ACCESS_METER,
            "a fetched slot must cost at least one slot access: with {} without {}",
            with_read.meter_used,
            without.meter_used
        );
        assert!(
            with_read.storage.is_empty(),
            "a read must still write nothing back"
        );
    }
}

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
    static TRANSFER_CODE: OnceLock<Vec<u8>> = OnceLock::new();
    let code = TRANSFER_CODE
        .get_or_init(|| assemble(TRANSFER_PROGRAM).expect("the transfer program assembles"));
    let consts = [amount, fee];
    let (sender_key, recipient_key) = (sender_key(), recipient_key());
    let mut storage = std::collections::BTreeMap::new();
    storage.insert(sender_key, sender_balance);
    storage.insert(recipient_key, recipient_balance);
    let mut memory = [0u8; 64];
    memory[..32].copy_from_slice(&sender_key);
    memory[32..].copy_from_slice(&recipient_key);

    let outcome = Interpreter::new(code, &consts, meter_limit)
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
    let interpreter =
        Interpreter::for_entry(&container, selector, vm_limit).map_err(|fault| match fault {
            Fault::OutOfMeter => ExecError::MeterExhausted,
            _ => ExecError::BadContainer,
        })?;
    let affordable_touches = vm_limit / SLOT_ACCESS_METER;
    let touches = std::cell::Cell::new(0u64);
    let beyond_budget = std::cell::Cell::new(false);
    let metered_loader = |key: &[u8; 32]| -> u64 {
        if touches.get() >= affordable_touches {
            beyond_budget.set(true);
            return 0;
        }
        touches.set(touches.get().saturating_add(1));
        loader(key)
    };
    let outcome = interpreter
        .with_storage_loader(&metered_loader)
        .with_memory(memory)
        .run()
        .map_err(|fault| match fault {
            Fault::Overflow => ExecError::InsufficientFunds,
            Fault::OutOfMeter => ExecError::MeterExhausted,
            other => ExecError::Vm(other),
        })?;
    if beyond_budget.get() {
        return Err(ExecError::MeterExhausted);
    }
    let touched = outcome.storage.len() as u64 + outcome.fetched as u64;
    let meter_used = outcome
        .meter_used
        .saturating_add(access_cost)
        .saturating_add(touched.saturating_mul(SLOT_ACCESS_METER));
    if meter_used > meter_limit {
        return Err(ExecError::MeterExhausted);
    }
    Ok(ContractOutcome {
        storage: outcome
            .dirty
            .iter()
            .filter_map(|slot| outcome.storage.get(slot).map(|v| (*slot, *v)))
            .collect(),
        effects: outcome.effects,
        meter_used,
    })
}

#[cfg(test)]
fn execute_contract_call(
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
    let interpreter =
        Interpreter::for_entry(&container, selector, vm_limit).map_err(|fault| match fault {
            Fault::OutOfMeter => ExecError::MeterExhausted,
            _ => ExecError::BadContainer,
        })?;
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
