//! Deterministic parallel execution of an ordered block.
//!
//! A block is an ordered list of transactions and the finalized state must be as
//! if every transaction ran in that order. Sequential execution reaches that
//! state one transaction at a time, which is the wall clock bottleneck: at about
//! ten microseconds of execution per transaction, a hundred thousand
//! transactions a second is a full second of execution per second of wall clock,
//! with no headroom. This module runs transactions with disjoint state across the
//! cores while holding the result bit identical to that sequential order.
//!
//! ## What a transaction reads and writes
//!
//! A transaction in this slice is a native transfer. The virtual machine debits
//! the sender by the amount and the fee and credits the recipient by the
//! amount, and validation reads the sender account for its key, its nonce, and
//! its balance. So the declared read set and the declared write set of a transfer
//! are both exactly the sender address and the recipient address, matching the
//! state access manifest the instruction set specification gives every entry.
//! Two transactions conflict, on a read write or a write write, when their
//! address sets intersect: they share the sender, share the recipient, or one
//! sends to the other.
//!
//! ## How the order is preserved
//!
//! The transactions are assigned to layers in block order. A transaction's layer
//! is one past the highest layer of any earlier transaction it conflicts with, so
//! for any two conflicting transactions the earlier one lands in a strictly lower
//! layer. The contrapositive is the property the parallel phase relies on: no two
//! transactions in the same layer conflict, so their address sets are pairwise
//! disjoint.
//!
//! Execution walks the layers in order. Within a layer every transaction is read
//! from the state as it stood at the start of the layer, executed on its own
//! cores, and its writes are collected; the writes are applied before the next
//! layer begins. Because the layer's address sets are disjoint, no transaction in
//! it can observe or overwrite another's account, so running the layer across the
//! cores lands on the exact state that running the same layer one transaction at a
//! time would.
//!
//! ## Why this equals the sequential order, on every input
//!
//! Take any transaction. Every earlier transaction that touches one of its two
//! accounts conflicts with it and therefore sits in a lower layer, already
//! applied; every transaction in its own layer touches neither of its accounts;
//! and no later transaction has run yet. So the accounts it reads hold exactly
//! the values the sequential order would have left there, its validation, its
//! virtual machine run, and its two writes are identical to sequential, and a
//! transaction the sequential order skips, on a failed validation or a fault, is
//! skipped here too and moves no state. By induction over the layers the whole
//! block lands on the sequential post state. The layering is a pure function of
//! the block and the declared addresses, with no wall clock and no thread order
//! in it, and the state root is fixed by the set of accounts and not by the order
//! they were written, so the post state and its root are bit identical to the
//! sequential path on every input.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use qtv_codec::{from_bytes, to_bytes};
use qtv_state::Key;
use qtv_tx::Wrapper;

use crate::execution::execute_transfer;
use crate::fee::FeeParams;
use crate::ledger::{state_key, Account, Ledger};
use crate::mempool::plan_from_account;

/// The two addresses a transfer declares it reads and writes: the sender and the
/// recipient, taken straight from the transaction.
fn access(wrapper: &Wrapper) -> (&str, &str) {
    (wrapper.body().sender(), wrapper.body().call().target())
}

/// Assign every transaction in a block to a conflict layer and return the layers
/// in order, each holding the block indices of its transactions. A transaction's
/// layer is one past the highest layer of any earlier transaction that shares one
/// of its two addresses, so conflicting transactions never share a layer and the
/// transactions within a layer have pairwise disjoint address sets. The layering
/// depends only on the ordered block and the declared addresses, so it is the
/// same on every run.
pub fn plan_layers(candidates: &[Wrapper]) -> Vec<Vec<usize>> {
    // The highest layer assigned so far to any transaction that touched an
    // address. An address unseen so far sits at layer zero.
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

/// The declared work of one transaction: its block index, the transaction, and the two addresses it
/// touches. The accounts themselves are read by the worker from the layer's leaf snapshot, so the read
/// and the decode run across the cores rather than serially before them.
struct Task<'a> {
    index: usize,
    wrapper: &'a Wrapper,
    sender_address: String,
    recipient_address: String,
}

/// The write a transaction commits: the two account records already encoded and already keyed, so the
/// serial apply is a pair of trie inserts with no encode or key derivation left in it. A transaction
/// the block order skips produces no write.
struct Write {
    index: usize,
    sender_key: Key,
    sender_bytes: Vec<u8>,
    recipient_key: Key,
    recipient_bytes: Vec<u8>,
    /// The fee this transfer charged. The shares are summed across the block and credited once, so the
    /// parallel path lands on the identical pool values as crediting each fee in turn.
    fee: u64,
}

/// Read and decode an account from a layer's leaf snapshot, an absent key reading as the default
/// account. This is the same read Ledger::account does against the trie, run here against the shared
/// leaf map so many workers read at once.
fn account_at(leaves: &BTreeMap<Key, Vec<u8>>, key: &Key) -> Account {
    match leaves.get(key) {
        Some(bytes) => from_bytes(bytes).expect("state holds a canonical account record"),
        None => Account::default(),
    }
}

/// Run one task exactly as the sequential path would, but reading its two accounts from the layer's
/// leaf snapshot and returning the updated records already encoded and keyed. Validate against the
/// sender account, execute the transfer through the virtual machine, and on a clean run return the two
/// writes to store back. A failed validation or a fault returns nothing, which moves no state, the
/// same skip the sequential path takes. The accounts in a layer are disjoint, so reading them from the
/// snapshot in parallel is exactly what each transaction would read in block order.
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
    })
}

/// Run a layer's tasks across the worker threads and return their writes. The
/// tasks have pairwise disjoint accounts, so a worker never touches another's
/// state and the writes carry no ordering between them. Workers pull the next
/// task from a shared counter, which balances an uneven layer without any unsafe
/// code or an external pool. A single task or a single worker runs inline.
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

/// Execute an ordered block against the ledger across up to `threads` cores,
/// producing the identical post state and root the sequential path produces, and
/// return the included transactions in block order. Transactions with disjoint
/// state run concurrently and conflicting transactions serialise in block order.
/// With one thread this is the sequential path with the same layering overhead.
pub fn execute_parallel(
    ledger: &mut Ledger,
    candidates: &[Wrapper],
    fee_params: &FeeParams,
    threads: usize,
    day: u64,
) -> Vec<Wrapper> {
    let stake_address = crate::ledger::stake_system_address();
    let claim_address = crate::ledger::stake_claim_address();
    let gov_address = crate::ledger::gov_system_address();
    if candidates.iter().any(|wrapper| {
        let (sender, target) = access(wrapper);
        target == stake_address.as_str()
            || target == claim_address.as_str()
            || target == gov_address.as_str()
            || ledger.is_blacklisted(sender)
            || ledger.is_blacklisted(target)
            || crate::node::is_vm_op(ledger, wrapper)
    }) {
        return crate::node::execute_ordered(ledger, candidates, fee_params, day);
    }
    let layers = plan_layers(candidates);
    let mut included: Vec<usize> = Vec::new();
    // The fee shares are summed across the whole block and credited to the pools once at the end. This
    // lands on the identical pool values as crediting each fee in turn, since addition is associative,
    // while it turns two pool writes per transaction into two for the whole block, which is a large
    // part of the serial writeback cost.
    let mut fee_validators: u64 = 0;
    let mut fee_grants: u64 = 0;

    for layer in &layers {
        // Name the two addresses each transaction touches. The accounts themselves are read inside the
        // workers from a snapshot of the leaves as they stand now, before any of the layer's writes
        // land, which is exactly what each transaction would read in block order since a layer's
        // accounts are disjoint.
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

        // Read, validate, execute, and encode across the cores against a leaf snapshot. The immutable
        // borrow of the leaves ends before the writes below take a mutable borrow to apply them.
        let mut writes = {
            let leaves = ledger.leaves();
            run_layer(&tasks, leaves, fee_params, threads)
        };
        // Apply the layer's writes in block order. The accounts are disjoint, so the order does not
        // change the state, but it keeps the apply a pure function of the block. Each write is already
        // encoded and keyed, so this serial section is a pair of trie inserts and nothing more.
        writes.sort_by_key(|write| write.index);
        for write in writes {
            ledger.insert_raw(write.sender_key, write.sender_bytes);
            ledger.insert_raw(write.recipient_key, write.recipient_bytes);
            let (validators, grants) = Ledger::fee_shares(write.fee);
            fee_validators = fee_validators.saturating_add(validators);
            fee_grants = fee_grants.saturating_add(grants);
            included.push(write.index);
        }
    }
    ledger.credit_pools(fee_validators, fee_grants);

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

    /// A ledger holding many funded accounts, and the keypairs behind them.
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

    /// The sequential path and the parallel path over the same block must reach
    /// the same post state and the same included set. Checked here across every
    /// thread count so the equivalence does not ride on one worker layout.
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
        // Each sender pays a fresh recipient nobody else touches, so no two
        // transactions share an address.
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
        // One sender pays many recipients in nonce order. Every transaction shares
        // the sender, so each lands in its own layer and the block is fully serial.
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
        // A pays B, B pays C, C pays D: each transaction's sender is the prior
        // recipient, so the whole run is a single dependency chain.
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

        // A small deterministic generator so the blocks are varied but the test is
        // reproducible without a dependency.
        let mut state = 1311768467463790320u64;
        let mut next = || {
            state = state.wrapping_add(11400714819323198485);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(13787848793156543929);
            z = (z ^ (z >> 27)).wrapping_mul(10723151780598845931);
            z ^ (z >> 31)
        };

        for _ in 0..40 {
            // Track a per sender nonce so most transactions are valid, with some
            // deliberately stale to exercise the skip path in both executors.
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
}
