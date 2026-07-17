//! The mempool, following SPEC-mempool.md.
//!
//! A transaction is admitted only when it is valid: its signature verifies under
//! the sender public key held in state, its nonce matches the next expected value
//! of the sender, and the sender can pay the transfer amount, the protocol fee,
//! and the meter. An invalid transaction is refused at the edge and never held, so
//! a bad signature or an insufficient balance can never reach a block. The pool
//! orders candidates by fee for a simple market and, within a sender, by nonce,
//! so block building over the same admitted set is reproducible.

use std::thread;

use qtv_tx::Wrapper;

use crate::execution::{transfer_amount, TRANSFER_METER};
use crate::fee::FeeParams;
use crate::ledger::{Account, Ledger};

/// The reason a transaction was refused admission. This enum is a public contract:
/// a client branches on these verdicts, so the set is closed and no catch all is
/// added, since a bin becomes the place everything unexplained goes and then it is a
/// contract that cannot change. Every branch of validation returns one of these, in a
/// fixed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The sender has no account with a public key to verify against.
    UnknownSender,
    /// The scheme identifier names a signature the node does not verify. It is
    /// distinct from a bad signature on purpose: the signature is not wrong, the
    /// scheme is one we do not check, so a client is told to change its scheme rather
    /// than told its key is wrong.
    UnsupportedScheme,
    /// The signature does not verify under the sender public key.
    BadSignature,
    /// The nonce does not match the next expected value of the sender. The check is
    /// strict equality, so a nonce too high is refused exactly like one too low and
    /// there is no future nonce queuing. A sender submits in strict nonce order, one
    /// at a time, and the expected and got values let a client resync.
    BadNonce { expected: u64, got: u64 },
    /// The call is not a well formed native transfer.
    BadCall,
    /// The transfer names the sender as its own recipient.
    SelfTransfer,
    /// The meter limit does not cover a transfer's execution. The sender's declared
    /// limit is below the minimum the execution needs, the same shape as a fee too low.
    MeterLimitTooLow,
    /// The offered fee is below the protocol fee. The fee is a floor and a bid: a
    /// higher offer orders a transaction earlier in the pool but the charge is always
    /// the fixed protocol fee, never the bid, so offering more never costs more.
    FeeTooLow,
    /// The sender cannot pay the amount and the fee.
    InsufficientFunds,
}

/// The outcome of admitting a transaction that passed validation. Accepted carries
/// two states so a client resubmitting can tell whether its earlier submission
/// already landed in the pool, and so a duplicate is never gossiped a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// Newly admitted to the pool this call.
    Fresh,
    /// Already held from an earlier submission, so this call was an idempotent no op.
    Known,
}

/// A validated native transfer ready to execute: the sender, the recipient, the
/// amount, and the protocol fee that will be charged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPlan {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
}

/// Validate a transaction against the current state and the fee parameters,
/// returning the transfer it will carry out or the reason it is refused. The
/// charged fee is the protocol fee taken from the parameters, not the raw figure
/// the sender declared, which must only reach that floor.
pub fn validate(
    wrapper: &Wrapper,
    ledger: &Ledger,
    fee_params: &FeeParams,
) -> Result<TransferPlan, Reject> {
    let sender = ledger.account(wrapper.body().sender());
    plan_from_account(wrapper, &sender, fee_params)
}

/// Validate a transaction against the current state and the fee parameters using a
/// signature verdict computed elsewhere rather than verifying the signature here.
/// It is `validate` for a caller that has already verified the signature, such as
/// the parallel pre pass the block executor runs over the whole block, so the
/// sequential loop applies the state dependent checks without recomputing the one
/// expensive check. A false verdict is refused as a bad signature and the state
/// rules are applied identically, so it admits the same transactions `validate`
/// admits against the same account.
pub fn validate_verified(
    wrapper: &Wrapper,
    ledger: &Ledger,
    fee_params: &FeeParams,
    signature_ok: bool,
) -> Result<TransferPlan, Reject> {
    let sender = ledger.account(wrapper.body().sender());
    plan_verified(wrapper, &sender, fee_params, signature_ok)
}

/// Validate a transaction against an already read sender account and the fee
/// parameters. This is the whole of `validate` past the state read, split out so
/// a caller that has already loaded the sender account, such as the parallel
/// executor working over a state snapshot, validates a transaction by the exact
/// same rules without a second trie lookup. The rules never touch the recipient
/// account, only the sender account and the transaction itself, so the outcome is
/// fixed by the sender account passed in.
pub fn plan_from_account(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
) -> Result<TransferPlan, Reject> {
    if !account.has_key() {
        return Err(Reject::UnknownSender);
    }
    if !qtv_tx::scheme_supported(wrapper.scheme()) {
        return Err(Reject::UnsupportedScheme);
    }
    if !qtv_tx::verify(wrapper, &account.public_key) {
        return Err(Reject::BadSignature);
    }
    plan_from_account_checks(wrapper, account, fee_params)
}

/// Validate a transaction against an already read sender account and the fee
/// parameters, taking the signature verdict as given rather than verifying it
/// here. This is `plan_from_account` for a caller that has already verified the
/// signature, such as the block executor's parallel pre pass, so the sequential
/// path applies the state dependent checks without recomputing the signature. A
/// false verdict is refused as a bad signature, the same skip `plan_from_account`
/// takes when the signature does not verify, and the state dependent checks are
/// the identical rules, so the transfer this returns and the transactions it
/// admits match `plan_from_account` on the same account. The verdict must be
/// qtv_tx::verify of this transaction under the public key this account carries,
/// and because verifying over an absent key is always false, a true verdict
/// already implies the account holds a key.
pub fn plan_verified(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
    signature_ok: bool,
) -> Result<TransferPlan, Reject> {
    if !qtv_tx::scheme_supported(wrapper.scheme()) {
        return Err(Reject::UnsupportedScheme);
    }
    if !signature_ok {
        return Err(Reject::BadSignature);
    }
    plan_from_account_checks(wrapper, account, fee_params)
}

/// The state dependent half of validation, applied once the sender key and the
/// signature are settled: the nonce, the call shape, the self transfer guard, the
/// meter floor, the fee floor, and the balance. Both the full validation and the
/// pre verified path share this, so the two apply byte identical state rules and
/// differ only in where the signature was checked.
fn plan_from_account_checks(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
) -> Result<TransferPlan, Reject> {
    let body = wrapper.body();
    let sender = body.sender().to_string();

    if body.nonce() != account.nonce {
        return Err(Reject::BadNonce {
            expected: account.nonce,
            got: body.nonce(),
        });
    }

    let amount = transfer_amount(body.call()).ok_or(Reject::BadCall)?;
    let recipient = body.call().target().to_string();
    if qtv_idfmt::parse_address(&recipient).is_err() {
        return Err(Reject::BadCall);
    }
    if recipient == sender {
        return Err(Reject::SelfTransfer);
    }
    if body.meter_limit() < TRANSFER_METER {
        return Err(Reject::MeterLimitTooLow);
    }

    let fee = fee_params.transfer_fee();
    if body.fee() < u128::from(fee) {
        return Err(Reject::FeeTooLow);
    }
    let debit = amount.checked_add(fee).ok_or(Reject::InsufficientFunds)?;
    if account.balance < debit {
        return Err(Reject::InsufficientFunds);
    }

    Ok(TransferPlan {
        sender,
        recipient,
        amount,
        fee,
    })
}

/// The smallest batch worth spreading across threads. Below this the signatures are
/// verified inline, since spawning and joining threads costs more than the handful of
/// verifications it would parallelise. This is the block executor's pre pass threshold,
/// held to the same value so admission and execution split a batch alike.
const PARALLEL_VERIFY_THRESHOLD: usize = 4;

/// Verify the signature of every transaction in the batch against the sender public key
/// held in state and return one verdict per transaction in batch order. The public keys
/// are read from the ledger up front in a single read only pass, then the verification,
/// a pure function of the signature and the key that touches no shared state, is split
/// into contiguous chunks across up to `verify_cores` scoped threads, each thread writing
/// the verdicts for its own chunk into its own slice of the result. A chunk boundary
/// decides only which core runs a given verification, never its outcome, so the returned
/// vector is identical for any core count and any scheduling. The core count is capped at
/// the transaction count so a thread always has work, and a batch below the threshold, or
/// a single core, is verified inline.
///
/// This is the block executor's signature pre pass applied at the mempool edge. An
/// account's key does not change between admissions, so the key the pre pass reads is the
/// key the per transaction path would verify against, and the verdict is the ground truth
/// the sequential admission loop reads instead of recomputing. Verifying over an absent
/// key is false, so a keyless sender yields a false verdict, refused down the verified
/// path exactly as `admit` refuses an unknown sender.
fn verify_signatures(ledger: &Ledger, batch: &[Wrapper], verify_cores: usize) -> Vec<bool> {
    // The sender public key each transaction is verified against, read from state once.
    // Verifying mutates no state, and an account's key does not change while a batch is
    // admitted, so this is the same key the per transaction path would verify against.
    let keys: Vec<Vec<u8>> = batch
        .iter()
        .map(|wrapper| ledger.account(wrapper.body().sender()).public_key)
        .collect();

    let mut verdicts = vec![false; batch.len()];
    let cores = verify_cores.min(batch.len());

    if cores <= 1 || batch.len() < PARALLEL_VERIFY_THRESHOLD {
        for (verdict, (wrapper, key)) in verdicts.iter_mut().zip(batch.iter().zip(&keys)) {
            *verdict = qtv_tx::verify(wrapper, key);
        }
        return verdicts;
    }

    // Contiguous chunks, at most one per core, covering the batch in order. Each thread
    // owns a disjoint slice of the verdict vector, so the verdicts land in batch order
    // with no coordination and no shared writes.
    let chunk = batch.len().div_ceil(cores);
    thread::scope(|scope| {
        for ((verdict_chunk, wrapper_chunk), key_chunk) in verdicts
            .chunks_mut(chunk)
            .zip(batch.chunks(chunk))
            .zip(keys.chunks(chunk))
        {
            scope.spawn(move || {
                for (verdict, (wrapper, key)) in verdict_chunk
                    .iter_mut()
                    .zip(wrapper_chunk.iter().zip(key_chunk))
                {
                    *verdict = qtv_tx::verify(wrapper, key);
                }
            });
        }
    });

    verdicts
}

/// The mempool of admitted transactions.
#[derive(Debug, Clone, Default)]
pub struct Mempool {
    pending: Vec<Wrapper>,
}

impl Mempool {
    /// An empty mempool.
    pub fn new() -> Self {
        Mempool {
            pending: Vec::new(),
        }
    }

    /// The number of admitted transactions waiting to enter a block.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether a transaction with this id is waiting in the pool. The node answers a
    /// pending status from this, the state between a submission being accepted and the
    /// block that finalises it.
    pub fn contains(&self, id: &str) -> bool {
        self.pending.iter().any(|w| w.id() == id)
    }

    /// Whether the pool holds no transactions.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Admit a transaction, validating it against the state and the fee parameters
    /// first. A refused transaction is never held and its reason is returned. A
    /// resubmission of a transaction already held is a no op and reports `Known`, so a
    /// resubmit is idempotent and the caller can tell it from a fresh admission.
    pub fn admit(
        &mut self,
        wrapper: Wrapper,
        ledger: &Ledger,
        fee_params: &FeeParams,
    ) -> Result<Admitted, Reject> {
        validate(&wrapper, ledger, fee_params)?;
        let id = wrapper.id();
        if self.pending.iter().any(|w| w.id() == id) {
            return Ok(Admitted::Known);
        }
        self.pending.push(wrapper);
        Ok(Admitted::Fresh)
    }

    /// Admit a batch of transactions in one parallel signature pre pass, then apply the
    /// state dependent checks in batch order. The signature, the one expensive check and
    /// the one check that does not depend on the pool or the running state, is lifted out
    /// of the per transaction path into a pre pass over the whole batch: every sender key
    /// is read from state, the verifications are split across the machine's cores, and one
    /// verdict per transaction lands in batch order. The batch is then walked in its
    /// original order, each transaction validated through the verified path with its
    /// verdict, a false verdict refused as a bad signature, and an admitted transaction
    /// inserted exactly as `admit` inserts it, duplicates dropped by id.
    ///
    /// Admission never mutates the ledger, so every transaction is validated against the
    /// same state whether it is admitted one at a time or in a batch, and a chunk boundary
    /// decides only which core verified a transaction, never its outcome. The resulting
    /// pool is therefore the pool `admit` would build from the same transactions in the
    /// same order, on any core count. The admitted transactions are returned in the order
    /// they were inserted, so a caller can mirror the per transaction bookkeeping, such as
    /// queueing the admitted transactions to gossip.
    pub fn admit_batch(
        &mut self,
        batch: Vec<Wrapper>,
        ledger: &Ledger,
        fee_params: &FeeParams,
    ) -> Vec<Wrapper> {
        let cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        self.admit_batch_across(batch, ledger, fee_params, cores)
    }

    /// `admit_batch` with the number of cores the signature pre pass may use made
    /// explicit, so the sequential path is `verify_cores` of one and the equivalence with
    /// per transaction `admit` across core counts can be exercised directly. The public
    /// entry passes the core count the machine reports.
    fn admit_batch_across(
        &mut self,
        batch: Vec<Wrapper>,
        ledger: &Ledger,
        fee_params: &FeeParams,
        verify_cores: usize,
    ) -> Vec<Wrapper> {
        let verified = verify_signatures(ledger, &batch, verify_cores);
        let mut admitted = Vec::new();
        for (index, wrapper) in batch.into_iter().enumerate() {
            if validate_verified(&wrapper, ledger, fee_params, verified[index]).is_err() {
                continue;
            }
            let id = wrapper.id();
            if self.pending.iter().any(|w| w.id() == id) {
                continue;
            }
            self.pending.push(wrapper.clone());
            admitted.push(wrapper);
        }
        admitted
    }

    /// The admitted transactions in build order: by declared fee for a simple
    /// market, then by sender and by nonce so a sender keeps its order. The order
    /// is a pure function of the pool, so block building is reproducible.
    pub fn candidates(&self) -> Vec<Wrapper> {
        let mut ordered = self.pending.clone();
        ordered.sort_by(|a, b| {
            b.body()
                .fee()
                .cmp(&a.body().fee())
                .then_with(|| a.body().sender().cmp(b.body().sender()))
                .then_with(|| a.body().nonce().cmp(&b.body().nonce()))
        });
        ordered
    }

    /// Drop the transactions that were included in a block, named by their ids.
    pub fn remove_included(&mut self, ids: &[String]) {
        self.pending.retain(|w| !ids.contains(&w.id()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::transfer_call;
    use crate::ledger::Account;
    use qtv_account::{derive, Account as KeyAccount};
    use qtv_tx::{sign, Body};

    fn keypair(index: u64) -> KeyAccount {
        derive(&[9u8; 32], index)
    }

    fn fund(ledger: &mut Ledger, account: &KeyAccount, balance: u64) {
        ledger.set_account(
            &account.address(),
            &Account::funded(balance, account.scheme(), account.public_key().to_vec()),
        );
    }

    fn signed_transfer(from: &KeyAccount, to: &str, amount: u64, nonce: u64, fee: u128) -> Wrapper {
        let call = transfer_call(to, amount);
        let body = Body::new(from.address(), nonce, TRANSFER_METER, fee, call);
        sign(from, &body)
    }

    #[test]
    fn a_valid_transfer_is_admitted() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert!(pool.admit(tx, &ledger, &params).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let mut tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut sig = tx.signature().to_vec();
        sig[0] ^= 1;
        tx = Wrapper::new(tx.body().clone(), tx.scheme(), sig);
        let mut pool = Mempool::new();
        assert_eq!(pool.admit(tx, &ledger, &params), Err(Reject::BadSignature));
        assert!(pool.is_empty());
    }

    #[test]
    fn an_unaffordable_transfer_is_refused() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 100);
        let tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(tx, &ledger, &params),
            Err(Reject::InsufficientFunds)
        );
    }

    #[test]
    fn a_wrong_nonce_is_refused() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            3,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(tx, &ledger, &params),
            Err(Reject::BadNonce {
                expected: 0,
                got: 3
            })
        );
    }

    #[test]
    fn an_unsupported_scheme_is_refused_as_such_not_as_a_bad_signature() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let good = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        // Re-wrap the signed body under a scheme identifier the node does not verify.
        // The signature is untouched, so this must read as unsupported rather than bad.
        let tx = Wrapper::new(good.body().clone(), 99, good.signature().to_vec());
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(tx, &ledger, &params),
            Err(Reject::UnsupportedScheme)
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn a_resubmission_is_known_and_idempotent() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert_eq!(pool.admit(tx.clone(), &ledger, &params), Ok(Admitted::Fresh));
        assert_eq!(pool.admit(tx, &ledger, &params), Ok(Admitted::Known));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn candidates_order_by_fee_then_sender_and_nonce() {
        let params = FeeParams::devnet();
        let base = u128::from(params.transfer_fee());
        let alice = keypair(0);
        let bob = keypair(1);
        let carol = keypair(2);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        fund(&mut ledger, &bob, 10_000);
        let low = signed_transfer(&alice, &carol.address(), 100, 0, base);
        let high = signed_transfer(&bob, &carol.address(), 100, 0, base + 5);
        let mut pool = Mempool::new();
        pool.admit(low.clone(), &ledger, &params).unwrap();
        pool.admit(high.clone(), &ledger, &params).unwrap();
        let ordered = pool.candidates();
        assert_eq!(ordered[0].id(), high.id());
        assert_eq!(ordered[1].id(), low.id());
    }

    fn ids(txs: &[Wrapper]) -> Vec<String> {
        txs.iter().map(Wrapper::id).collect()
    }

    /// A batch and the ledger it is admitted against, built to exercise every refusal
    /// path alongside the transactions that admit: a run of independent valid transfers
    /// from funded senders that the pre pass verifies in parallel, a corrupted signature
    /// and a keyless sender that both produce a false verdict, and a stale nonce, an
    /// unaffordable transfer, and a self transfer that pass the signature and fail a state
    /// check. It is large enough to split across many chunks.
    fn mixed_batch(params: &FeeParams) -> (Ledger, Vec<Wrapper>) {
        let count = 64u64;
        let keys: Vec<KeyAccount> = (0..count).map(keypair).collect();
        let mut ledger = Ledger::new();
        // Fund the first sixty accounts; index forty two is left almost empty so a
        // transfer from it cannot be paid. Indices sixty and above stay keyless.
        for (i, key) in keys.iter().enumerate().take(60) {
            let balance = if i == 42 { 1 } else { 5_000_000 };
            fund(&mut ledger, key, balance);
        }
        let fee = u128::from(params.transfer_fee());

        let mut batch = Vec::new();
        // A run of independent valid transfers, each from a fresh sender at nonce zero to
        // a recipient in the upper band, so most of the batch verifies and admits.
        for i in 0..40u64 {
            let sender = i as usize;
            let recipient = 40 + (i % 20) as usize;
            batch.push(signed_transfer(
                &keys[sender],
                &keys[recipient].address(),
                1_000,
                0,
                fee,
            ));
        }
        // A corrupted signature: a false verdict, refused as a bad signature.
        let good = signed_transfer(&keys[40], &keys[41].address(), 500, 0, fee);
        let mut sig = good.signature().to_vec();
        sig[0] ^= 1;
        batch.push(Wrapper::new(good.body().clone(), good.scheme(), sig));
        // A stale nonce from a sender whose next nonce is zero: a valid signature that
        // fails the nonce check.
        batch.push(signed_transfer(&keys[41], &keys[42].address(), 500, 5, fee));
        // An unaffordable transfer from the almost empty account: a valid signature that
        // fails the balance check.
        batch.push(signed_transfer(&keys[42], &keys[43].address(), 1_000_000, 0, fee));
        // A self transfer: a valid signature that fails the self transfer guard.
        batch.push(signed_transfer(&keys[43], &keys[43].address(), 100, 0, fee));
        // A keyless sender with no account in state: verifying over an absent key is
        // false, so it is refused exactly as an unknown sender is.
        batch.push(signed_transfer(&keys[60], &keys[44].address(), 100, 0, fee));

        (ledger, batch)
    }

    /// Admitting the batch through the parallel signature pre pass, on a forced serial
    /// path and across a range of core counts, builds the identical resulting pool as
    /// admitting each transaction one at a time through `admit`. A chunk boundary decides
    /// only which core verified a transaction, so the admitted set is byte identical no
    /// matter how the verification landed across cores.
    #[test]
    fn admit_batch_matches_per_transaction_admit_across_core_counts() {
        let params = FeeParams::devnet();
        let (ledger, batch) = mixed_batch(&params);

        // The reference pool: admit every transaction one at a time, the current path.
        let mut reference = Mempool::new();
        for tx in &batch {
            let _ = reference.admit(tx.clone(), &ledger, &params);
        }
        let reference_ids = ids(&reference.candidates());
        // The batch must both admit and refuse transactions, or the equivalence would be
        // vacuous.
        assert!(
            !reference.is_empty() && reference.len() < batch.len(),
            "the batch must both admit and refuse transactions"
        );

        for cores in [1usize, 2, 4, 8, 24] {
            let mut pool = Mempool::new();
            pool.admit_batch_across(batch.clone(), &ledger, &params, cores);
            assert_eq!(
                ids(&pool.candidates()),
                reference_ids,
                "the batch admitted set differs from per transaction admit at {cores} cores"
            );
            assert_eq!(
                pool.len(),
                reference.len(),
                "the batch admitted count differs at {cores} cores"
            );
        }

        // The public entry, driven by the core count the machine reports, matches the
        // same reference and returns exactly the admitted transactions in insertion order.
        let mut public = Mempool::new();
        let admitted = public.admit_batch(batch.clone(), &ledger, &params);
        assert_eq!(ids(&public.candidates()), reference_ids);
        assert_eq!(ids(&admitted), ids(&reference.pending));
    }
}
