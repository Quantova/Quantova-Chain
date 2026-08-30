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
    let evidence_address = crate::ledger::evidence_address();
    let registration_address = crate::ledger::registration_address();
    let bridge_freeze_address = crate::ledger::bridge_freeze_address();
    let bridge_unfreeze_address = crate::ledger::bridge_unfreeze_address();
    let bridge_guardian_address = crate::ledger::bridge_guardian_address();
    let bridge_mint_address = crate::ledger::bridge_mint_address();
    let bridge_exit_address = crate::ledger::bridge_exit_address();
    let bridge_settle_address = crate::ledger::bridge_settle_address();
    let round_proposer = ledger.round_proposer().map(str::to_string);
    let grants_address = crate::ledger::grants_address();
    let now_seconds = day.saturating_mul(86_400);
    ledger.bridge_expire(now_seconds);
    ledger.guardian_expire(now_seconds);
    if candidates.iter().any(|wrapper| {
        let (sender, target) = access(wrapper);
        round_proposer.as_deref() == Some(sender)
            || round_proposer.as_deref() == Some(target)
            || sender == grants_address.as_str()
            || target == grants_address.as_str()
            || target == stake_address.as_str()
            || target == claim_address.as_str()
            || target == exit_address.as_str()
            || target == withdraw_address.as_str()
            || target == gov_address.as_str()
            || target == key_register_address.as_str()
            || target == evidence_address.as_str()
            || target == registration_address.as_str()
            || target == bridge_freeze_address.as_str()
            || target == bridge_unfreeze_address.as_str()
            || target == bridge_guardian_address.as_str()
            || target == bridge_mint_address.as_str()
            || target == bridge_exit_address.as_str()
            || target == bridge_settle_address.as_str()
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

    transfer_events.sort_by_key(|row| row.0);
    for (_, from, to, amount, fee) in transfer_events {
        ledger.record_transfer_event(&from, &to, amount, fee);
    }

    ledger.settle_session(day, included.len() as u64);

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
                sequential.q_root(),
                parallel.q_root(),
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
            assert_eq!(first.q_root(), again.q_root());
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
        assert_eq!(parallel.q_root(), ledger.q_root());
    }

    #[test]
    fn the_parallel_and_ordered_paths_agree_on_the_event_root() {
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
        assert!(
            !ordered.block_events().is_empty(),
            "the block records events"
        );

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

    #[test]
    fn a_case_aliased_self_transfer_cannot_mint_or_stall_the_nonce() {
        let fee = FeeParams::devnet();
        let attacker = keypair(0);
        let canonical = attacker.address();
        let alias = canonical.to_ascii_lowercase();
        assert_ne!(canonical, alias, "the alias is a distinct surface string");
        assert_eq!(
            qtv_idfmt::parse_address(&alias).unwrap(),
            qtv_idfmt::parse_address(&canonical).unwrap(),
            "the alias decodes to the same payload, so it shares the sender account leaf"
        );
        assert_eq!(
            state_key(&alias),
            state_key(&canonical),
            "the alias and the canonical form collide on one state key"
        );

        let start = 1_000_000u64;
        let amount = 250_000u64;

        let build = || {
            let call = transfer_call(&alias, amount);
            let body = qtv_tx::Body::new(
                canonical.clone(),
                0,
                crate::execution::TRANSFER_METER,
                u128::from(fee.transfer_fee()),
                call,
            );
            sign(&attacker, &body)
        };

        for parallel_path in [false, true] {
            let mut ledger = Ledger::new();
            fund(&mut ledger, &attacker, start);
            ledger.seed_supply(start);
            let before = ledger.balance(&canonical);
            assert_eq!(before, start);

            let tx = build();
            let included = if parallel_path {
                execute_parallel(&mut ledger, &[tx], &fee, 8, 0)
            } else {
                execute_ordered(&mut ledger, &[tx], &fee, 0)
            };

            let after = ledger.balance(&canonical);
            assert_eq!(
                after, before,
                "case aliased transfer minted funds (parallel={parallel_path}): {before} -> {after}"
            );
            assert!(
                after <= ledger.total_supply(),
                "conservation broke (parallel={parallel_path}): balance {after} exceeds supply {}",
                ledger.total_supply()
            );
            assert!(
                included.is_empty(),
                "the aliased transfer must be refused, not included (parallel={parallel_path})"
            );
        }
    }

    #[test]
    fn a_case_aliased_duplicate_cannot_fork_the_ordered_and_parallel_paths() {
        let fee = FeeParams::devnet();
        let attacker = keypair(0);
        let sink = keypair(1);
        let canonical = attacker.address();
        let alias = canonical.to_ascii_lowercase();

        let signed = |sender: &str| {
            let call = transfer_call(&sink.address(), 1_000);
            let body = qtv_tx::Body::new(
                sender.to_string(),
                0,
                crate::execution::TRANSFER_METER,
                u128::from(fee.transfer_fee()),
                call,
            );
            sign(&attacker, &body)
        };
        let block = vec![signed(&canonical), signed(&alias)];

        let mut base = Ledger::new();
        fund(&mut base, &attacker, 10_000_000);

        let mut ordered = base.clone();
        let ordered_included = execute_ordered(&mut ordered, &block, &fee, 0);
        assert_eq!(
            ordered_included.len(),
            1,
            "only the canonical transfer applies; the alias is refused"
        );

        for threads in [1usize, 2, 4, 8, 16] {
            let mut parallel = base.clone();
            let parallel_included = execute_parallel(&mut parallel, &block, &fee, threads, 0);
            assert_eq!(
                ordered.q_root(),
                parallel.q_root(),
                "state root forked at {threads} threads"
            );
            assert_eq!(
                ordered_included.len(),
                parallel_included.len(),
                "included set differs at {threads} threads"
            );
        }
    }

    #[test]
    fn a_case_aliased_pair_to_distinct_sinks_shares_no_layer_and_cannot_mint() {
        let fee = FeeParams::devnet();
        let attacker = keypair(0);
        let sink_a = keypair(1);
        let sink_b = keypair(2);
        let canonical = attacker.address();
        let alias = canonical.to_ascii_lowercase();
        assert_ne!(canonical, alias, "the alias is a distinct surface string");
        assert_eq!(
            state_key(&alias),
            state_key(&canonical),
            "the alias collides with the canonical account leaf"
        );

        let signed = |sender: &str, sink: &str| {
            let call = transfer_call(sink, 1_000);
            let body = qtv_tx::Body::new(
                sender.to_string(),
                0,
                crate::execution::TRANSFER_METER,
                u128::from(fee.transfer_fee()),
                call,
            );
            sign(&attacker, &body)
        };
        let block = vec![
            signed(&canonical, &sink_a.address()),
            signed(&alias, &sink_b.address()),
        ];

        let layers = plan_layers(&block);
        assert_eq!(
            layers.len(),
            1,
            "distinct surface senders and distinct sinks land in one parallel layer"
        );

        let start = 10_000_000u64;
        let mut base = Ledger::new();
        fund(&mut base, &attacker, start);
        base.seed_supply(start);

        let mut ordered = base.clone();
        let ordered_included = execute_ordered(&mut ordered, &block, &fee, 0);
        assert_eq!(
            ordered_included.len(),
            1,
            "only the canonical send applies; the aliased sender is refused"
        );
        assert_eq!(
            ordered.balance(&sink_b.address()),
            0,
            "the aliased sink is never credited"
        );

        for threads in [1usize, 2, 4, 8, 16] {
            let mut parallel = base.clone();
            let parallel_included = execute_parallel(&mut parallel, &block, &fee, threads, 0);
            assert_eq!(
                ordered.q_root(),
                parallel.q_root(),
                "state root forked at {threads} threads"
            );
            assert_eq!(
                included_ids(&ordered_included),
                included_ids(&parallel_included),
                "included set differs at {threads} threads"
            );
            assert_eq!(
                parallel.balance(&sink_b.address()),
                0,
                "the aliased sink is credited on the parallel path at {threads} threads"
            );
            assert!(
                parallel.balance(&canonical)
                    + parallel.balance(&sink_a.address())
                    + parallel.balance(&sink_b.address())
                    <= parallel.total_supply(),
                "conservation broke on the parallel path at {threads} threads"
            );
        }
    }

    #[test]
    fn a_transfer_into_then_out_of_the_fee_recipient_does_not_fork_parallel_from_serial() {
        let fee = FeeParams::devnet();
        let a = keypair(0);
        let b = keypair(1);
        let proposer = keypair(3);

        let f = fee.transfer_fee();
        let ps = FeeSplit::of(f).proposer;
        assert!(
            ps > 0,
            "the proposer fee share must be non zero for the collision to bite"
        );

        let amount0 = 1_000u64;
        let amount1 = amount0 + ps - f;

        let tx0 = transfer(&a, &proposer.address(), amount0, 0, &fee);
        let tx1 = transfer(&proposer, &b.address(), amount1, 0, &fee);
        let block = vec![tx0, tx1];

        let layers = plan_layers(&block);
        assert_eq!(
            layers.len(),
            2,
            "the fee recipient is party to both sends so the pair is serialised across two layers"
        );

        let start = 10_000_000u64;
        let mut base = Ledger::new();
        fund(&mut base, &a, start);
        fund(&mut base, &proposer, 0);
        base.seed_supply(start);
        base.set_round_proposer(&proposer.address());

        let mut ordered = base.clone();
        let ordered_included = execute_ordered(&mut ordered, &block, &fee, 0);
        assert_eq!(
            ordered_included.len(),
            2,
            "sequentially the proposer fee from the first send funds the second send"
        );

        for threads in [1usize, 2, 4, 8, 16] {
            let mut parallel = base.clone();
            let parallel_included = execute_parallel(&mut parallel, &block, &fee, threads, 0);
            assert_eq!(
                included_ids(&ordered_included),
                included_ids(&parallel_included),
                "included set differs at {threads} threads"
            );
            assert_eq!(
                ordered.q_root(),
                parallel.q_root(),
                "state root forked at {threads} threads"
            );
            assert_eq!(
                parallel.balance(&b.address()),
                ordered.balance(&b.address()),
                "the fee recipient outflow diverged at {threads} threads"
            );
        }
    }

    #[test]
    fn unparseable_addresses_do_not_share_one_account_leaf() {
        let a = state_key("not an address");
        let b = state_key("also not an address");
        let real = state_key(&keypair(0).address());
        assert_ne!(a, b, "distinct unparseable strings must not share a leaf");
        assert_ne!(
            a, real,
            "an unparseable string must not collide with a real account"
        );
        assert_ne!(
            b, real,
            "an unparseable string must not collide with a real account"
        );
    }

    #[test]
    fn the_parallel_and_ordered_paths_settle_the_armed_session_identically() {
        let fee = FeeParams::devnet();
        let (mut base, keys) = population(24, 50_000_000);

        let validator = qtv_idfmt::render_address(&[60u8; 32]).unwrap();
        base.seed_stake_pool(700_000 * 1_000_000);
        base.seed_validator_bond(&validator, 2_000 * 1_000_000);
        base.seed_validator_set(&[[60u8; 32]]);
        base.set_stake_mainnet_start(0);
        base.set_stake_price(70 * 1_000_000);

        let block: Vec<Wrapper> = (0..12)
            .map(|i| transfer(&keys[i], &keys[12 + i].address(), 1_000, 0, &fee))
            .collect();

        let day = 546;
        let mut ordered = base.clone();
        let ordered_included = execute_ordered(&mut ordered, &block, &fee, day);
        assert!(
            ordered.stake_pool() < 700_000 * 1_000_000,
            "the armed session must pay so the settle call is under test"
        );

        for threads in [2usize, 4, 8, 16] {
            let mut parallel = base.clone();
            let parallel_included = execute_parallel(&mut parallel, &block, &fee, threads, day);
            assert_eq!(
                ordered.q_root(),
                parallel.q_root(),
                "armed session state root differs at {threads} threads"
            );
            assert_eq!(
                included_ids(&ordered_included),
                included_ids(&parallel_included),
                "included set differs at {threads} threads"
            );
        }
    }

    #[test]
    fn a_lapsed_guardian_freeze_expires_identically_on_both_paths() {
        let fee = FeeParams::devnet();
        let (mut base, keys) = population(8, 1_000_000);

        let m1 = [201u8; 32];
        let m2 = [202u8; 32];
        base.set_guardian_set(&qtv_governance::GuardianSet::new(vec![m1, m2], 2));
        let target = [77u8; 32];
        assert!(
            base.guardian_freeze(0, &[target], &[m1, m2], 0),
            "the caucus arms a freeze on the target"
        );
        let frozen = qtv_idfmt::render_address(&target).unwrap();
        assert!(base.is_frozen(&frozen), "the target starts frozen");

        let block: Vec<Wrapper> = (0..4)
            .map(|i| transfer(&keys[i], &keys[4 + i].address(), 1_000, 0, &fee))
            .collect();
        assert_eq!(
            plan_layers(&block).len(),
            1,
            "the straddling block is all independent plain transfers so it stays on the parallel path"
        );

        let day = 8;
        let mut ordered = base.clone();
        execute_ordered(&mut ordered, &block, &fee, day);
        assert!(
            !ordered.is_frozen(&frozen),
            "the ordered path clears the freeze once its window has lapsed"
        );

        for threads in [2usize, 4, 8, 16] {
            let mut parallel = base.clone();
            execute_parallel(&mut parallel, &block, &fee, threads, day);
            assert!(
                !parallel.is_frozen(&frozen),
                "the parallel path leaves the lapsed freeze in place at {threads} threads"
            );
            assert_eq!(
                ordered.q_root(),
                parallel.q_root(),
                "a lapsed guardian freeze forks parallel from serial at {threads} threads"
            );
        }
    }
}
