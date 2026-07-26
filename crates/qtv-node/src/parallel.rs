// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use qtv_codec::{from_bytes, to_bytes};
use qtv_state::Key;
use qtv_tx::Wrapper;

use crate::execution::execute_transfer;
use crate::fee::FeeParams;
use crate::ledger::{state_key, Account, FeeSplit, Ledger};
use crate::mempool::plan_from_account;

fn access(wrapper: &Wrapper) -> (&str, &str) {
    (wrapper.body().sender(), wrapper.body().call().target())
}

pub fn plan_layers(candidates: &[Wrapper]) -> Vec<Vec<usize>> {
    let mut address_layer: HashMap<&str, usize> = HashMap::new();
    let mut layers: Vec<Vec<usize>> = Vec::new();

    for (index, wrapper) in candidates.iter().enumerate() {
        let (sender, recipient) = access(wrapper);
        let earlier = address_layer
            .get(sender)
            .copied()
            .max(address_layer.get(recipient).copied())
            .unwrap_or(0);
        let layer = earlier + 1;
        address_layer.insert(sender, layer);
        address_layer.insert(recipient, layer);
        if layers.len() < layer {
            layers.push(Vec::new());
        }
        layers[layer - 1].push(index);
    }

    layers
}

struct Task<'a> {
    index: usize,
    wrapper: &'a Wrapper,
    sender_address: String,
    recipient_address: String,
}

struct Write {
    index: usize,
    sender_key: Key,
    sender_bytes: Vec<u8>,
    recipient_key: Key,
    recipient_bytes: Vec<u8>,
    fee: u64,
    sender_address: String,
    recipient_address: String,
    amount: u64,
}

fn account_at(leaves: &BTreeMap<Key, Vec<u8>>, key: &Key) -> Account {
    match leaves.get(key) {
        Some(bytes) => from_bytes(bytes).unwrap_or_default(),
        None => Account::default(),
    }
}

fn run_task(
    task: &Task<'_>,
    leaves: &BTreeMap<Key, Vec<u8>>,
    fee_params: &FeeParams,
) -> Option<Write> {
    let sender_key = state_key(&task.sender_address);
    let sender = account_at(leaves, &sender_key);
    let plan = plan_from_account(task.wrapper, &sender, fee_params).ok()?;
    let recipient_key = state_key(&task.recipient_address);
    let recipient = account_at(leaves, &recipient_key);
    let transferred = execute_transfer(
        sender.balance,
        recipient.balance,
        plan.amount,
        plan.fee,
        task.wrapper.body().meter_limit(),
    )
    .ok()?;

    let mut new_sender = sender;
    new_sender.balance = transferred.sender_balance;
    new_sender.nonce += 1;
    let mut new_recipient = recipient;
    new_recipient.balance = transferred.recipient_balance;

    Some(Write {
        index: task.index,
        sender_key,
        sender_bytes: to_bytes(&new_sender),
        recipient_key,
        recipient_bytes: to_bytes(&new_recipient),
        fee: plan.fee,
        sender_address: task.sender_address.clone(),
        recipient_address: task.recipient_address.clone(),
        amount: plan.amount,
    })
}

fn run_layer(
    tasks: &[Task<'_>],
    leaves: &BTreeMap<Key, Vec<u8>>,
    fee_params: &FeeParams,
    threads: usize,
) -> Vec<Write> {
    let workers = threads.clamp(1, tasks.len().max(1));
    if workers <= 1 || tasks.len() <= 1 {
        return tasks
            .iter()
            .filter_map(|t| run_task(t, leaves, fee_params))
            .collect();
    }

    let next = AtomicUsize::new(0);
    let mut writes: Vec<Write> = Vec::with_capacity(tasks.len());
    thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut local = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= tasks.len() {
                            break;
                        }
                        if let Some(write) = run_task(&tasks[i], leaves, fee_params) {
                            local.push(write);
                        }
                    }
                    local
                })
            })
            .collect();
        for handle in handles {
            writes.extend(handle.join().expect("an execution worker panicked"));
        }
    });
    writes
}

pub fn execute_parallel(
    ledger: &mut Ledger,
    candidates: &[Wrapper],
    fee_params: &FeeParams,
    threads: usize,
    day: u64,
) -> Vec<Wrapper> {
    let stake_address = crate::ledger::stake_system_address();
    let claim_address = crate::ledger::stake_claim_address();
    let exit_address = crate::ledger::stake_exit_address();
    let withdraw_address = crate::ledger::stake_withdraw_address();
    let gov_address = crate::ledger::gov_system_address();
    let key_register_address = crate::ledger::key_register_address();
    let bridge_freeze_address = crate::ledger::bridge_freeze_address();
    let bridge_unfreeze_address = crate::ledger::bridge_unfreeze_address();
    let bridge_mint_address = crate::ledger::bridge_mint_address();
    let bridge_exit_address = crate::ledger::bridge_exit_address();
    ledger.bridge_expire(day.saturating_mul(86_400));
    if candidates.iter().any(|wrapper| {
        let (sender, target) = access(wrapper);
        target == stake_address.as_str()
            || target == claim_address.as_str()
            || target == exit_address.as_str()
            || target == withdraw_address.as_str()
            || target == gov_address.as_str()
            || target == key_register_address.as_str()
            || target == bridge_freeze_address.as_str()
            || target == bridge_unfreeze_address.as_str()
            || target == bridge_mint_address.as_str()
            || target == bridge_exit_address.as_str()
            || ledger.is_blacklisted(sender)
            || ledger.is_blacklisted(target)
            || ledger.is_frozen(sender)
            || crate::node::is_vm_op(ledger, wrapper)
    }) {
        return crate::node::execute_ordered(ledger, candidates, fee_params, day);
    }
    let layers = plan_layers(candidates);
    let mut included: Vec<usize> = Vec::new();
    let mut fees = FeeSplit::default();
    let mut transfer_events: Vec<(usize, String, String, u64, u64)> = Vec::new();

    for layer in &layers {
        let tasks: Vec<Task<'_>> = layer
            .iter()
            .map(|&index| {
                let wrapper = &candidates[index];
                let (sender_address, recipient_address) = access(wrapper);
                Task {
                    index,
                    wrapper,
                    sender_address: sender_address.to_string(),
                    recipient_address: recipient_address.to_string(),
                }
            })
            .collect();

        let mut writes = {
            let leaves = ledger.leaves();
            run_layer(&tasks, leaves, fee_params, threads)
        };
        writes.sort_by_key(|write| write.index);
        for write in writes {
            ledger.insert_raw(write.sender_key, write.sender_bytes);
            ledger.insert_raw(write.recipient_key, write.recipient_bytes);
            fees.add(FeeSplit::of(write.fee));
            transfer_events.push((
                write.index,
                write.sender_address,
                write.recipient_address,
                write.amount,
                write.fee,
            ));
            included.push(write.index);
        }
    }
    ledger.apply_fee_split(fees);

    // Record one transfer event per applied send in block position order, the same order the
    // ordered path records them, so both execution paths yield the identical event root.
    transfer_events.sort_by_key(|row| row.0);
    for (_, from, to, amount, fee) in transfer_events {
        ledger.record_transfer_event(&from, &to, amount, fee);
    }

    included.sort_unstable();
    included
        .into_iter()
        .map(|index| candidates[index].clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::transfer_call;
    use crate::ledger::Account;
    use crate::node::execute_ordered;
    use qtv_account::{derive, Account as KeyAccount};
    use qtv_tx::{sign, Body};

    const SEED: [u8; 32] = [23u8; 32];

    fn keypair(index: u64) -> KeyAccount {
        derive(&SEED, index)
    }

    fn fund(ledger: &mut Ledger, account: &KeyAccount, balance: u64) {
        ledger.set_account(
            &account.address(),
            &Account::funded(balance, account.scheme(), account.public_key().to_vec()),
        );
    }

    fn transfer(
        from: &KeyAccount,
        to: &str,
        amount: u64,
        nonce: u64,
        fee_params: &FeeParams,
    ) -> Wrapper {
        let call = transfer_call(to, amount);
        let body = Body::new(
            from.address(),
            nonce,
            crate::execution::TRANSFER_METER,
            u128::from(fee_params.transfer_fee()),
            call,
        );
        sign(from, &body)
    }

    fn population(count: u64, balance: u64) -> (Ledger, Vec<KeyAccount>) {
        let mut ledger = Ledger::new();
        let keys: Vec<KeyAccount> = (0..count).map(keypair).collect();
        for key in &keys {
            fund(&mut ledger, key, balance);
        }
        (ledger, keys)
    }

    fn included_ids(included: &[Wrapper]) -> Vec<String> {
        included.iter().map(Wrapper::id).collect()
    }

    fn assert_matches(base: &Ledger, block: &[Wrapper], fee_params: &FeeParams) {
        let mut sequential = base.clone();
        let sequential_included = execute_ordered(&mut sequential, block, fee_params, 0);

        for threads in [1usize, 2, 4, 8, 16] {
            let mut parallel = base.clone();
            let parallel_included = execute_parallel(&mut parallel, block, fee_params, threads, 0);
            assert_eq!(
                sequential.state_root(),
                parallel.state_root(),
                "state root differs at {threads} threads"
            );
            assert_eq!(
                included_ids(&sequential_included),
                included_ids(&parallel_included),
                "included set differs at {threads} threads"
            );
        }
    }

    #[test]
    fn an_independent_block_is_one_layer_and_matches() {
        let fee = FeeParams::devnet();
        let (ledger, keys) = population(64, 1_000_000);
        let block: Vec<Wrapper> = (0..32)
            .map(|i| transfer(&keys[i], &keys[32 + i].address(), 1_000, 0, &fee))
            .collect();

        let layers = plan_layers(&block);
        assert_eq!(layers.len(), 1, "an independent block is a single layer");
        assert_eq!(layers[0].len(), 32);
        assert_matches(&ledger, &block, &fee);
    }

    #[test]
    fn an_all_conflicting_block_degrades_to_sequential_and_matches() {
        let fee = FeeParams::devnet();
        let (ledger, keys) = population(40, 10_000_000);
        let block: Vec<Wrapper> = (0..32)
            .map(|i| transfer(&keys[0], &keys[1 + i].address(), 1_000, i as u64, &fee))
            .collect();

        let layers = plan_layers(&block);
        assert_eq!(layers.len(), 32, "an all conflicting block is fully serial");
        assert!(layers.iter().all(|layer| layer.len() == 1));
        assert_matches(&ledger, &block, &fee);
    }

    #[test]
    fn a_chain_of_dependencies_serialises_in_order_and_matches() {
        let fee = FeeParams::devnet();
        let (ledger, keys) = population(16, 5_000_000);
        let block: Vec<Wrapper> = (0..8)
            .map(|i| transfer(&keys[i], &keys[i + 1].address(), 2_000, 0, &fee))
            .collect();

        let layers = plan_layers(&block);
        assert_eq!(layers.len(), 8, "a dependency chain is fully serial");
        assert_matches(&ledger, &block, &fee);
    }

    #[test]
    fn a_random_mixed_block_matches_over_many_seeds() {
        let fee = FeeParams::devnet();
        let (ledger, keys) = population(24, 50_000_000);
        let accounts = keys.len() as u64;

        let mut state = 1311768467463790320u64;
        let mut next = || {
            state = state.wrapping_add(11400714819323198485);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(13787848793156543929);
            z = (z ^ (z >> 27)).wrapping_mul(10723151780598845931);
            z ^ (z >> 31)
        };

        for _ in 0..40 {
            let mut nonce = vec![0u64; keys.len()];
            let len = (next() % 40) as usize + 1;
            let mut block = Vec::with_capacity(len);
            for _ in 0..len {
                let s = (next() % accounts) as usize;
                let mut r = (next() % accounts) as usize;
                if r == s {
                    r = (r + 1) % keys.len();
                }
                let stale = next().is_multiple_of(7);
                let n = if stale && nonce[s] > 0 {
                    nonce[s] - 1
                } else {
                    let n = nonce[s];
                    nonce[s] += 1;
                    n
                };
                let amount = (next() % 5_000) + 1;
                block.push(transfer(&keys[s], &keys[r].address(), amount, n, &fee));
            }
            assert_matches(&ledger, &block, &fee);
        }
    }

    #[test]
    fn the_parallel_path_is_deterministic_across_runs() {
        let fee = FeeParams::devnet();
        let (ledger, keys) = population(24, 50_000_000);
        let block: Vec<Wrapper> = (0..20)
            .map(|i| {
                transfer(
                    &keys[i % 12],
                    &keys[12 + (i % 12)].address(),
                    500 + i as u64,
                    (i / 12) as u64,
                    &fee,
                )
            })
            .collect();

        let mut first = ledger.clone();
        let first_included = execute_parallel(&mut first, &block, &fee, 8, 0);
        for _ in 0..8 {
            let mut again = ledger.clone();
            let again_included = execute_parallel(&mut again, &block, &fee, 8, 0);
            assert_eq!(first.state_root(), again.state_root());
            assert_eq!(included_ids(&first_included), included_ids(&again_included));
        }
    }

    #[test]
    fn an_empty_block_has_no_layers_and_moves_nothing() {
        let fee = FeeParams::devnet();
        let (ledger, _) = population(4, 1_000);
        assert!(plan_layers(&[]).is_empty());
        let mut parallel = ledger.clone();
        let included = execute_parallel(&mut parallel, &[], &fee, 8, 0);
        assert!(included.is_empty());
        assert_eq!(parallel.state_root(), ledger.state_root());
    }

    #[test]
    fn the_parallel_and_ordered_paths_agree_on_the_event_root() {
        let fee = FeeParams::devnet();
        let (ledger, keys) = population(24, 50_000_000);
        // A mixed block that spans several dependency layers, so the parallel path applies it
        // out of block order across layers and must still record events in block position.
        let block: Vec<Wrapper> = (0..20)
            .map(|i| {
                transfer(
                    &keys[i % 12],
                    &keys[12 + (i % 12)].address(),
                    500 + i as u64,
                    (i / 12) as u64,
                    &fee,
                )
            })
            .collect();

        let mut ordered = ledger.clone();
        execute_ordered(&mut ordered, &block, &fee, 0);
        let ordered_root = {
            let leaves: Vec<Vec<u8>> = ordered
                .block_events()
                .iter()
                .map(crate::ledger::BlockEvent::encode)
                .collect();
            qtv_block::event_root(&leaves)
        };
        assert!(!ordered.block_events().is_empty(), "the block records events");

        for threads in [1usize, 2, 4, 8, 16] {
            let mut parallel = ledger.clone();
            execute_parallel(&mut parallel, &block, &fee, threads, 0);
            let leaves: Vec<Vec<u8>> = parallel
                .block_events()
                .iter()
                .map(crate::ledger::BlockEvent::encode)
                .collect();
            assert_eq!(
                qtv_block::event_root(&leaves),
                ordered_root,
                "event root differs at {threads} threads"
            );
        }
    }
}
