//! The node state transition and finalization loop.
//!
//! A node holds chain state, a mempool, a committee driver, and the chain of
//! finalized blocks. For a height it selects the committee, produces a block from
//! the mempool, executes each transaction through the virtual machine so the
//! block carries a real post execution state root, drives the committee through
//! attestation and aggregation into a finality certificate over the real header,
//! and on finalization commits the block and advances to the next height. The
//! whole loop runs in one process over direct calls.

use std::collections::BTreeMap;
use std::thread;

use qtv_block::{Block as ChainBlock, Header};
use qtv_codec::{Decode, Decoder};
use qtv_governance::{Action, Conviction};
use qtv_tx::Wrapper;

use crate::consensus::{header_value, Beacon, Consensus, ConsensusValidator, Parent};
use crate::execution::execute_transfer;
use crate::fee::FeeParams;
use crate::ledger::{Account, Ledger};
use crate::mempool::{validate_verified, Admitted, Mempool, Reject};
use crate::parallel::execute_parallel;

use qtv_attest::Certificate;

/// A validator in the genesis committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorSpec {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
}

impl ValidatorSpec {
    /// An online validator with the given native stake.
    pub fn online(id: u64, stake: u64) -> Self {
        ValidatorSpec {
            id,
            stake,
            online: true,
        }
    }

    /// An offline validator with the given native stake. It is still selected and
    /// is simply skipped when it would attest, and is never slashed.
    pub fn offline(id: u64, stake: u64) -> Self {
        ValidatorSpec {
            id,
            stake,
            online: false,
        }
    }
}

/// A funded genesis account, its balance and the public key a signature is
/// verified against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisAccount {
    pub address: String,
    pub balance: u64,
    pub scheme: u8,
    pub public_key: Vec<u8>,
}

impl GenesisAccount {
    /// A genesis account for a derived key account funded with a balance.
    pub fn from_account(account: &qtv_account::Account, balance: u64) -> Self {
        GenesisAccount {
            address: account.address(),
            balance,
            scheme: account.scheme(),
            public_key: account.public_key().to_vec(),
        }
    }
}

/// The genesis configuration of a node: the fee parameters, the funded accounts,
/// the validator committee, and the genesis time.
#[derive(Clone, Debug)]
pub struct Genesis {
    pub fee_params: FeeParams,
    pub accounts: Vec<GenesisAccount>,
    pub validators: Vec<ValidatorSpec>,
    pub genesis_time: u64,
}

/// A finalized block: the chain block, its finality certificate, and the record
/// of the leader, the committee size, and the attesters that finalized it.
pub struct Finalized {
    pub block: ChainBlock,
    pub certificate: Certificate,
    pub leader: u64,
    pub committee_size: usize,
    pub attesters: Vec<u64>,
}

impl Finalized {
    /// The finalized header.
    pub fn header(&self) -> &Header {
        self.block.header()
    }

    /// The header hash the certificate is bound to.
    pub fn header_hash(&self) -> [u8; 32] {
        self.block.header_hash()
    }

    /// The block id under the block family.
    pub fn id(&self) -> String {
        self.block.id()
    }

    /// The transaction ids in the finalized body, in order.
    pub fn transaction_ids(&self) -> Vec<String> {
        self.block.body().iter().map(Wrapper::id).collect()
    }

    /// Whether the finality certificate reconciles with the real header: the
    /// header hash folded to a word equals the value the certificate carries.
    pub fn reconciles(&self) -> bool {
        header_value(&self.header_hash()) == self.certificate.envelope.block.val
    }
}

/// The reason a height failed to produce a finalized block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProduceError {
    /// The sortition admitted no committee for the height.
    NoCommittee,
    /// No entitled supermajority formed, so the block did not finalize.
    NotFinalized,
}

/// Fold a validator id into a deterministic key seed for its genesis account,
/// separated from any other key use by a domain tag.
fn validator_seed(id: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8..15].copy_from_slice(b"QTVNODE");
    seed
}

/// The proposer address a validator signs blocks under, derived deterministically
/// from its consensus id. Every node computes the same address for a leader, so a
/// header built by one node hashes the same on every other.
pub fn validator_address(id: u64) -> String {
    qtv_account::derive(&validator_seed(id), 0).address()
}

/// Execute an ordered list of candidate transactions against the ledger. Each
/// candidate that validates and executes through the virtual machine has its post
/// execution balances and bumped nonce written back, and a candidate that no
/// longer validates or that faults is skipped. The included transactions are
/// returned in the order they applied. The leader runs this over its mempool
/// candidates to build a block, and every other node runs it over the proposed
/// body to reach the same post execution state root.
///
/// Signature verification, the one expensive check and the one check that does not
/// depend on the running state, is lifted out of the sequential loop into a
/// parallel pre pass over the whole block: every candidate's signature is verified
/// across the cores up front, producing one verdict per candidate in candidate
/// order, and the loop then reads that verdict instead of recomputing it. The
/// public key an account signs under does not change while a block executes, so
/// the key the pre pass reads is the key the loop would verify against at any
/// point, and the verdict is a pure function of the signature and that key with no
/// thread order in it. Every state dependent check, the execution, and the ledger
/// mutation stay sequential and in order. The included set, the order, and the
/// post state are therefore byte identical to verifying each signature inline, on
/// every input and for any core count.
pub fn execute_ordered(
    ledger: &mut Ledger,
    candidates: &[Wrapper],
    fee_params: &FeeParams,
    day: u64,
) -> Vec<Wrapper> {
    let cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    execute_ordered_across(ledger, candidates, fee_params, cores, day)
}

pub fn day_of_height(height: u64) -> u64 {
    height.saturating_mul(qtv_bft::params::SLOT_MS) / 86_400_000
}

/// `execute_ordered` with the number of cores the signature pre pass may use made
/// explicit, so the sequential path is `verify_cores` of one and the equivalence
/// across core counts can be exercised directly. The public entry passes the core
/// count the machine reports.
/// A governance operation carried in the arguments of a transaction whose target is
/// the reserved governance system address. The leading argument byte selects the
/// operation and the rest is its payload.
pub(crate) enum GovOp {
    Propose(Action),
    Vote {
        referendum: u64,
        aye: bool,
        conviction: Conviction,
        stake: u64,
    },
    Enact(u64),
    Conclude(u64),
    Release,
}

fn decode_gov_op(op: u8, payload: &[u8]) -> Option<GovOp> {
    let mut decoder = Decoder::new(payload);
    let operation = match op {
        1 => GovOp::Propose(Action::decode(&mut decoder).ok()?),
        2 => GovOp::Vote {
            referendum: decoder.get_u64().ok()?,
            aye: decoder.get_u8().ok()? != 0,
            conviction: Conviction::decode(&mut decoder).ok()?,
            stake: decoder.get_u64().ok()?,
        },
        3 => GovOp::Enact(decoder.get_u64().ok()?),
        4 => GovOp::Conclude(decoder.get_u64().ok()?),
        5 => GovOp::Release,
        _ => return None,
    };
    decoder.finish().ok()?;
    Some(operation)
}

/// Whether a transaction is a well formed governance call: its target is the
/// governance system address, its sender holds a key, its scheme and signature and
/// nonce and meter and fee clear the same floors a transfer clears, and its
/// arguments decode to a governance operation. This is the shared gate the mempool
/// admits by and the executor dispatches by, so a governance call the mempool
/// accepts is one the executor runs.
pub(crate) fn governance_admissible(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
    signature_ok: bool,
) -> Option<GovOp> {
    let body = wrapper.body();
    if body.call().target() != crate::ledger::gov_system_address() {
        return None;
    }
    if !account.has_key() || !qtv_tx::scheme_supported(wrapper.scheme()) || !signature_ok {
        return None;
    }
    if body.nonce() != account.nonce || body.meter_limit() < crate::execution::TRANSFER_METER {
        return None;
    }
    if body.fee() < u128::from(fee_params.transfer_fee()) {
        return None;
    }
    let charged = u64::try_from(body.fee().min(u128::from(fee_params.ceiling_fee())))
        .unwrap_or_else(|_| fee_params.ceiling_fee());
    if account.balance < charged {
        return None;
    }
    let args = body.call().args();
    let op = *args.first()?;
    decode_gov_op(op, &args[1..])
}

/// Charge a governance call's fee, bump its nonce, and apply its operation. The
/// operation runs on the post fee account, and a submit or a vote that cannot cover
/// its own deposit or stake is a no op while the fee still applies, so a well formed
/// governance call that reaches here is always included. Returns false only when the
/// call is not an admissible governance call at all.
fn dispatch_governance(
    ledger: &mut Ledger,
    wrapper: &Wrapper,
    signature_ok: bool,
    fee_params: &FeeParams,
    now: u64,
) -> bool {
    let sender = wrapper.body().sender().to_string();
    let account = ledger.account(&sender);
    let operation = match governance_admissible(wrapper, &account, fee_params, signature_ok) {
        Some(operation) => operation,
        None => return false,
    };
    let charged = u64::try_from(wrapper.body().fee().min(u128::from(fee_params.ceiling_fee())))
        .unwrap_or_else(|_| fee_params.ceiling_fee());
    let mut charged_account = account;
    charged_account.balance -= charged;
    charged_account.nonce += 1;
    ledger.set_account(&sender, &charged_account);
    match operation {
        GovOp::Propose(action) => {
            ledger.gov_propose(&sender, action.track(), action, now);
        }
        GovOp::Vote {
            referendum,
            aye,
            conviction,
            stake,
        } => {
            ledger.gov_vote(&sender, referendum, aye, conviction, stake, now);
        }
        GovOp::Enact(referendum) => {
            let _ = ledger.gov_enact(referendum, now);
        }
        GovOp::Conclude(referendum) => {
            ledger.gov_conclude(referendum, now);
        }
        GovOp::Release => {
            ledger.gov_release(&sender, now);
        }
    }
    true
}

fn execute_ordered_across(
    ledger: &mut Ledger,
    candidates: &[Wrapper],
    fee_params: &FeeParams,
    verify_cores: usize,
    day: u64,
) -> Vec<Wrapper> {
    let verified = verify_signatures(ledger, candidates, verify_cores);
    let stake_address = crate::ledger::stake_system_address();
    let gov_address = crate::ledger::gov_system_address();
    let now_seconds = day.saturating_mul(86_400);
    let mut included = Vec::new();
    for (index, wrapper) in candidates.iter().enumerate() {
        if wrapper.body().call().target() == gov_address {
            if dispatch_governance(ledger, wrapper, verified[index], fee_params, now_seconds) {
                included.push(wrapper.clone());
            }
            continue;
        }
        let plan = match validate_verified(wrapper, ledger, fee_params, verified[index]) {
            Ok(plan) => plan,
            Err(_) => continue,
        };
        if plan.recipient == stake_address {
            if ledger.bond_with_fee(&plan.sender, plan.amount, plan.fee, day) {
                included.push(wrapper.clone());
            }
            continue;
        }
        let mut sender = ledger.account(&plan.sender);
        let mut recipient = ledger.account(&plan.recipient);
        let transferred = match execute_transfer(
            sender.balance,
            recipient.balance,
            plan.amount,
            plan.fee,
            wrapper.body().meter_limit(),
        ) {
            Ok(transferred) => transferred,
            Err(_) => continue,
        };
        sender.balance = transferred.sender_balance;
        sender.nonce += 1;
        recipient.balance = transferred.recipient_balance;
        ledger.set_account(&plan.sender, &sender);
        ledger.set_account(&plan.recipient, &recipient);
        included.push(wrapper.clone());
    }
    included
}

/// The smallest block worth spreading across threads. Below this the signatures
/// are verified inline, since spawning and joining threads costs more than the
/// handful of verifications it would parallelise.
const PARALLEL_VERIFY_THRESHOLD: usize = 4;

/// Verify the signature of every candidate against the sender public key held in
/// state and return one verdict per candidate in candidate order. The public keys
/// are read from the ledger up front in a single read only pass, then the
/// verification, a pure function of the signature and the key that touches no
/// shared state, is split into contiguous chunks across up to `verify_cores`
/// scoped threads, each thread writing the verdicts for its own chunk into its own
/// slice of the result. A chunk boundary decides only which core runs a given
/// verification, never its outcome, so the returned vector is identical for any
/// core count and any scheduling. The core count is capped at the candidate count
/// so a thread always has work, and a block below the threshold, or a single core,
/// is verified inline.
fn verify_signatures(ledger: &Ledger, candidates: &[Wrapper], verify_cores: usize) -> Vec<bool> {
    // The sender public key each candidate is verified against, read from state
    // once. Verifying mutates no state, and an account's key does not change while
    // a block executes, so this is the same key the sequential loop would verify
    // against at any point in the block.
    let keys: Vec<Vec<u8>> = candidates
        .iter()
        .map(|wrapper| ledger.account(wrapper.body().sender()).public_key)
        .collect();

    let mut verdicts = vec![false; candidates.len()];
    let cores = verify_cores.min(candidates.len());

    if cores <= 1 || candidates.len() < PARALLEL_VERIFY_THRESHOLD {
        for (verdict, (wrapper, key)) in verdicts.iter_mut().zip(candidates.iter().zip(&keys)) {
            *verdict = qtv_tx::verify(wrapper, key);
        }
        return verdicts;
    }

    // Contiguous chunks, at most one per core, covering the candidates in order.
    // Each thread owns a disjoint slice of the verdict vector, so the verdicts land
    // in candidate order with no coordination and no shared writes.
    let chunk = candidates.len().div_ceil(cores);
    thread::scope(|scope| {
        for ((verdict_chunk, wrapper_chunk), key_chunk) in verdicts
            .chunks_mut(chunk)
            .zip(candidates.chunks(chunk))
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

/// The node: the state transition and finalization loop over a fixed committee.
pub struct Node {
    ledger: Ledger,
    mempool: Mempool,
    consensus: Consensus,
    base_validators: Vec<ConsensusValidator>,
    fee_params: FeeParams,
    validator_addresses: BTreeMap<u64, String>,
    beacon: Beacon,
    height: u64,
    parent_header_hash: [u8; 32],
    parent_val: Parent,
    genesis_time: u64,
    chain: Vec<Finalized>,
    slashed: Vec<u64>,
    exec_threads: usize,
}

/// The committee weight set read from committed state. Each base validator keeps
/// its consensus id and liveness flag and takes its weight from its live bonded
/// stake on the ledger, so the sortition draws on the stake that is actually
/// locked rather than a genesis constant. It is a pure function of committed
/// state, so every node that has applied the same blocks builds the identical set
/// and draws the identical committee.
pub fn committee_weights(
    ledger: &Ledger,
    base: &[ConsensusValidator],
) -> Vec<ConsensusValidator> {
    let derived: Vec<ConsensusValidator> = base
        .iter()
        .map(|v| ConsensusValidator {
            id: v.id,
            stake: ledger.staked_weight(&validator_address(v.id)),
            online: v.online,
        })
        .collect();
    // Safety net against an empty committee. If committed state carries no bonded
    // stake for any base validator, there is no staking record to weigh, either
    // because the chain predates staking or because every validator has left. In
    // that case the base genesis weights stand, so the committee never empties and
    // the chain cannot halt for want of a drawable member. As soon as one validator
    // holds a bond, the live weights take over and the base weights are ignored.
    if derived.iter().all(|v| v.stake == 0) {
        return base.to_vec();
    }
    derived
}

impl Node {
    /// Build a node from its genesis configuration. Accounts are funded, the
    /// committee driver is built, and each validator is given a deterministic
    /// address for the proposer field.
    pub fn new(genesis: Genesis) -> Self {
        let mut ledger = Ledger::new();
        for account in &genesis.accounts {
            ledger.set_account(
                &account.address,
                &Account::funded(account.balance, account.scheme, account.public_key.clone()),
            );
        }

        let validators: Vec<ConsensusValidator> = genesis
            .validators
            .iter()
            .map(|v| ConsensusValidator {
                id: v.id,
                stake: v.stake,
                online: v.online,
            })
            .collect();
        let validator_addresses = genesis
            .validators
            .iter()
            .map(|v| (v.id, validator_address(v.id)))
            .collect();
        for v in &validators {
            ledger.seed_validator_bond(
                &validator_address(v.id),
                v.stake.saturating_mul(qtv_staking::NATIVE_UNIT as u64),
            );
        }

        Node {
            ledger,
            mempool: Mempool::new(),
            consensus: Consensus::new(&validators),
            base_validators: validators,
            fee_params: genesis.fee_params,
            validator_addresses,
            beacon: crate::consensus::genesis_beacon(),
            height: qtv_bft::params::MIN_HEIGHT,
            parent_header_hash: [0u8; 32],
            parent_val: Parent::Genesis,
            genesis_time: genesis.genesis_time,
            chain: Vec::new(),
            slashed: Vec::new(),
            exec_threads: 1,
        }
    }

    /// Set how many cores the node executes a block across. One core is the
    /// sequential path. More than one runs transactions with disjoint state
    /// concurrently and serialises conflicting ones in block order, for the
    /// identical post state and root. A server class validator sets this to its
    /// core count to lift execution off the wall clock.
    pub fn set_parallelism(&mut self, threads: usize) {
        self.exec_threads = threads.max(1);
    }

    /// The node with its block execution set to run across the given cores. The
    /// builder form of `set_parallelism`.
    pub fn with_parallelism(mut self, threads: usize) -> Self {
        self.set_parallelism(threads);
        self
    }

    /// Submit a signed transaction to the mempool. It is admitted only when valid,
    /// and the outcome distinguishes a fresh admission from an idempotent resubmit.
    pub fn submit(&mut self, transaction: Wrapper) -> Result<Admitted, Reject> {
        self.mempool
            .admit(transaction, &self.ledger, &self.fee_params)
    }

    /// Produce and finalize the block at the current height. Transactions are
    /// executed through the virtual machine, the resulting state root is committed
    /// in the header, the committee finalizes over that header, and the node
    /// advances to the next height.
    pub fn produce(&mut self) -> Result<&Finalized, ProduceError> {
        let height = self.height;
        let slot = height;

        self.consensus
            .reweight(&committee_weights(&self.ledger, &self.base_validators));
        let selection = self
            .consensus
            .select(&self.beacon, slot)
            .ok_or(ProduceError::NoCommittee)?;
        let proposer = self
            .validator_addresses
            .get(&selection.leader)
            .cloned()
            .unwrap_or_default();

        let included = self.execute_block();
        let included_ids: Vec<String> = included.iter().map(Wrapper::id).collect();

        let state_root = self.ledger.state_root();
        let transaction_root = qtv_block::transaction_root(&included);
        let event_root = qtv_block::empty_transaction_root();
        let time = self.genesis_time + height * qtv_bft::params::SLOT_MS;

        let header = Header::new(
            height,
            self.parent_header_hash,
            state_root,
            transaction_root,
            event_root,
            *self.beacon.seed(),
            proposer,
            time,
        );
        let header_hash = header.hash();

        let value = header_value(&header_hash);
        let block = crate::consensus::Block::new(height, value, self.parent_val);

        let certificate = self
            .consensus
            .finalize(&selection, height, slot, block, &self.beacon)
            .ok_or(ProduceError::NotFinalized)?;
        debug_assert!(self
            .consensus
            .verify(&certificate, &selection, &self.beacon));

        let cert_digest = certificate.digest();
        let attesters = certificate.attesters();
        let chain_block = ChainBlock::new(header, cert_digest.to_vec(), included);

        let finalized = Finalized {
            block: chain_block,
            certificate,
            leader: selection.leader,
            committee_size: selection.commitment.len(),
            attesters,
        };

        self.beacon = self.beacon.advance(&cert_digest, height);
        self.parent_header_hash = header_hash;
        self.parent_val = Parent::Value(value);
        self.height += 1;
        self.mempool.remove_included(&included_ids);
        self.chain.push(finalized);

        Ok(self.chain.last().expect("a block was just finalized"))
    }

    /// Execute the mempool candidates against state in build order. With one core
    /// this is the sequential path; with more it is the parallel executor, which
    /// produces the identical post state and root while running transactions with
    /// disjoint state concurrently.
    fn execute_block(&mut self) -> Vec<Wrapper> {
        let candidates = self.mempool.candidates();
        let day = day_of_height(self.height);
        if self.exec_threads > 1 {
            execute_parallel(
                &mut self.ledger,
                &candidates,
                &self.fee_params,
                self.exec_threads,
                day,
            )
        } else {
            execute_ordered(&mut self.ledger, &candidates, &self.fee_params, day)
        }
    }

    /// Produce a run of heights in order, stopping at the first that does not
    /// finalize.
    pub fn run(&mut self, heights: u64) -> Result<(), ProduceError> {
        for _ in 0..heights {
            self.produce()?;
        }
        Ok(())
    }

    /// The account state.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The next height the node will produce.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// The finalized chain in order.
    pub fn chain(&self) -> &[Finalized] {
        &self.chain
    }

    /// The number of transactions waiting in the mempool.
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// The validators slashed by the node. Only equivocation is slashable and none
    /// occurs in this in process slice, so this is always empty. An offline
    /// validator is never slashed.
    pub fn slashed(&self) -> &[u64] {
        &self.slashed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{transfer_call, TRANSFER_METER};
    use crate::ledger::Account;
    use qtv_account::{derive, Account as KeyAccount};
    use qtv_tx::{sign, Body};

    const SEED: [u8; 32] = [71u8; 32];

    fn keypair(index: u64) -> KeyAccount {
        derive(&SEED, index)
    }

    #[test]
    fn committee_weights_use_live_bonds_and_fall_back_when_state_is_bare() {
        let base = vec![
            ConsensusValidator::online(1, 2_000),
            ConsensusValidator::online(2, 2_000),
            ConsensusValidator::online(3, 2_000),
        ];

        // A bare ledger with no staking records falls back to the genesis weights,
        // so a node reloading a store that predates staking keeps its committee and
        // does not halt for want of a drawable member.
        let bare = Ledger::new();
        assert_eq!(committee_weights(&bare, &base), base);

        // Once a single validator holds a bond the live weights take over: the
        // bonded validator carries its whole unit weight and the rest weigh zero.
        let mut live = Ledger::new();
        live.seed_validator_bond(&validator_address(2), 5_000 * 1_000_000);
        let weights = committee_weights(&live, &base);
        assert_eq!(weights[0].stake, 0);
        assert_eq!(weights[1].stake, 5_000);
        assert_eq!(weights[2].stake, 0);
    }

    fn fund(ledger: &mut Ledger, account: &KeyAccount, balance: u64) {
        ledger.set_account(
            &account.address(),
            &Account::funded(balance, account.scheme(), account.public_key().to_vec()),
        );
    }

    fn transfer(from: &KeyAccount, to: &str, amount: u64, nonce: u64, fee: &FeeParams) -> Wrapper {
        let call = transfer_call(to, amount);
        let body = Body::new(
            from.address(),
            nonce,
            TRANSFER_METER,
            u128::from(fee.transfer_fee()),
            call,
        );
        sign(from, &body)
    }

    fn gov_call_tx(from: &KeyAccount, args: Vec<u8>, nonce: u64, fee: &FeeParams) -> Wrapper {
        let call = qtv_tx::Call::new(crate::ledger::gov_system_address(), args);
        let body = Body::new(
            from.address(),
            nonce,
            TRANSFER_METER,
            u128::from(fee.transfer_fee()),
            call,
        );
        sign(from, &body)
    }

    fn propose_price_args(rate: u128) -> Vec<u8> {
        let action = Action::Parameter {
            key: b"price".to_vec(),
            value: rate.to_le_bytes().to_vec(),
        };
        let mut args = vec![1u8];
        args.extend_from_slice(&qtv_codec::to_bytes(&action));
        args
    }

    fn vote_args(referendum: u64, aye: bool, conviction_code: u8, stake: u64) -> Vec<u8> {
        let mut encoder = qtv_codec::Encoder::new();
        encoder.put_u8(2);
        encoder.put_u64(referendum);
        encoder.put_u8(aye as u8);
        encoder.put_u8(conviction_code);
        encoder.put_u64(stake);
        encoder.into_bytes()
    }

    #[test]
    fn a_governance_transaction_drives_a_referendum_through_the_executor() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let proposer = keypair(100);
        let voter = keypair(101);
        fund(&mut ledger, &proposer, 30_000 * 1_000_000);
        fund(&mut ledger, &voter, 10_000 * 1_000_000);

        let propose = gov_call_tx(&proposer, propose_price_args(70_000_000), 0, &fee);
        let vote = gov_call_tx(&voter, vote_args(1, true, 0, 5_000 * 1_000_000), 0, &fee);
        let included = execute_ordered(&mut ledger, &[propose, vote], &fee, 0);
        assert_eq!(included.len(), 2);
        assert!(ledger.gov_referendum(1).is_some());
        assert_eq!(ledger.gov_total_locked(), 5_000 * 1_000_000);
        assert_eq!(ledger.stake_price(), 0);

        // Enact after the seven day QIP window: day 8 is 691,200s, past 604,800s.
        let mut enact = qtv_codec::Encoder::new();
        enact.put_u8(3);
        enact.put_u64(1);
        let enact_tx = gov_call_tx(&proposer, enact.into_bytes(), 1, &fee);
        let included = execute_ordered(&mut ledger, &[enact_tx], &fee, 8);
        assert_eq!(included.len(), 1);
        assert_eq!(ledger.stake_price(), 70_000_000);

        // A malformed governance operation is refused, not included.
        let bad = gov_call_tx(&proposer, vec![99u8], 2, &fee);
        assert!(execute_ordered(&mut ledger, &[bad], &fee, 8).is_empty());
    }

    #[test]
    fn the_parallel_path_routes_a_governance_block_to_the_same_result() {
        let fee = FeeParams::devnet();
        let proposer = keypair(102);
        let voter = keypair(103);
        let base = {
            let mut ledger = Ledger::new();
            fund(&mut ledger, &proposer, 30_000 * 1_000_000);
            fund(&mut ledger, &voter, 10_000 * 1_000_000);
            ledger
        };
        let block = vec![
            gov_call_tx(&proposer, propose_price_args(70_000_000), 0, &fee),
            gov_call_tx(&voter, vote_args(1, true, 0, 5_000 * 1_000_000), 0, &fee),
        ];
        let mut sequential = base.clone();
        execute_ordered(&mut sequential, &block, &fee, 0);
        let mut parallel = base.clone();
        crate::parallel::execute_parallel(&mut parallel, &block, &fee, 8, 0);
        assert_eq!(sequential.state_root(), parallel.state_root());
        assert!(parallel.gov_referendum(1).is_some());
    }

    fn corrupt_signature(tx: Wrapper) -> Wrapper {
        let mut sig = tx.signature().to_vec();
        sig[0] ^= 1;
        Wrapper::new(tx.body().clone(), tx.scheme(), sig)
    }

    fn ids(included: &[Wrapper]) -> Vec<String> {
        included.iter().map(Wrapper::id).collect()
    }

    /// A block and the ledger it runs against, built to exercise every skip path
    /// alongside the transactions that apply: valid independent transfers that the
    /// pre pass verifies in parallel, a corrupted signature and a keyless sender
    /// that both produce a false verdict, and a stale nonce, an unaffordable
    /// transfer, and a self transfer that pass the signature and fail a state
    /// check. It is large enough to split across many chunks.
    fn mixed_block(fee: &FeeParams) -> (Ledger, Vec<Wrapper>) {
        let count = 64u64;
        let keys: Vec<KeyAccount> = (0..count).map(keypair).collect();
        let mut ledger = Ledger::new();
        // Fund the first sixty accounts; index five is left almost empty so a
        // transfer from it cannot be paid. Indices sixty and above stay keyless.
        for (i, key) in keys.iter().enumerate().take(60) {
            let balance = if i == 5 { 1 } else { 5_000_000 };
            fund(&mut ledger, key, balance);
        }

        let mut block = Vec::new();
        // A run of independent valid transfers, a fresh sender to a recipient in
        // the upper band, so most of the block verifies and applies.
        for i in 0..40u64 {
            let sender = i as usize;
            let recipient = 40 + (i % 20) as usize;
            block.push(transfer(&keys[sender], &keys[recipient].address(), 1_000, 0, fee));
        }
        // A corrupted signature: a false verdict, skipped as a bad signature.
        block.push(corrupt_signature(transfer(
            &keys[1],
            &keys[41].address(),
            500,
            1,
            fee,
        )));
        // A stale nonce from a sender that already spent nonce zero above: a valid
        // signature that fails the nonce check.
        block.push(transfer(&keys[2], &keys[42].address(), 500, 0, fee));
        // An unaffordable transfer from the almost empty account: a valid signature
        // that fails the balance check.
        block.push(transfer(&keys[5], &keys[43].address(), 1_000_000, 0, fee));
        // A self transfer: a valid signature that fails the self transfer guard.
        block.push(transfer(&keys[3], &keys[3].address(), 100, 1, fee));
        // A keyless sender with no account in state: verifying over an absent key is
        // false, so it is skipped exactly as an unknown sender is.
        block.push(transfer(&keys[60], &keys[44].address(), 100, 0, fee));

        (ledger, block)
    }

    /// The signature pre pass produces the same verdicts on one core and on many,
    /// and those verdicts equal verifying each signature inline. The verdict is the
    /// ground truth the sequential loop reads, so pinning it across core counts
    /// pins the included set.
    #[test]
    fn the_signature_verdicts_are_identical_across_core_counts() {
        let fee = FeeParams::devnet();
        let (ledger, block) = mixed_block(&fee);

        let serial = verify_signatures(&ledger, &block, 1);
        for cores in [2usize, 3, 4, 8, 16, 24] {
            assert_eq!(
                serial,
                verify_signatures(&ledger, &block, cores),
                "the verdicts differ at {cores} cores"
            );
        }

        let inline: Vec<bool> = block
            .iter()
            .map(|w| qtv_tx::verify(w, &ledger.account(w.body().sender()).public_key))
            .collect();
        assert_eq!(
            serial, inline,
            "the pre pass verdict differs from the inline verify"
        );
        assert!(
            inline.iter().any(|&v| !v),
            "the block must exercise a false verdict"
        );
        assert!(
            inline.iter().any(|&v| v),
            "the block must exercise a true verdict"
        );
    }

    /// Executing the same candidates with the parallel signature pre pass, on a
    /// forced serial path and across a range of core counts, admits the identical
    /// transactions and reaches the identical state root as the sequential loop
    /// that verifies each signature inline. The finalized state is byte identical
    /// no matter how the verification landed across cores.
    #[test]
    fn execute_ordered_matches_the_inline_loop_across_core_counts() {
        let fee = FeeParams::devnet();
        let (base, block) = mixed_block(&fee);

        // The reference: the sequential loop as it stood before the pre pass,
        // verifying each signature in place through validate.
        let mut reference = base.clone();
        let reference_included = execute_ordered_inline(&mut reference, &block, &fee);
        let reference_root = reference.state_root();
        // The block must actually include some transactions and skip some, or the
        // equivalence would be vacuous.
        assert!(
            !reference_included.is_empty() && reference_included.len() < block.len(),
            "the block must both include and skip transactions"
        );

        for cores in [1usize, 2, 3, 4, 8, 16, 24] {
            let mut ledger = base.clone();
            let included = execute_ordered_across(&mut ledger, &block, &fee, cores, 0);
            assert_eq!(
                ids(&included),
                ids(&reference_included),
                "the included set differs at {cores} cores"
            );
            assert_eq!(
                ledger.state_root(),
                reference_root,
                "the state root differs at {cores} cores"
            );
        }

        // The public entry, driven by the core count the machine reports, matches
        // the same reference.
        let mut public = base.clone();
        let public_included = execute_ordered(&mut public, &block, &fee, 0);
        assert_eq!(ids(&public_included), ids(&reference_included));
        assert_eq!(public.state_root(), reference_root);
    }

    /// The sequential loop as it stood before the parallel signature pre pass,
    /// verifying each signature inline through validate. The pre pass must
    /// reproduce this byte for byte.
    fn execute_ordered_inline(
        ledger: &mut Ledger,
        candidates: &[Wrapper],
        fee_params: &FeeParams,
    ) -> Vec<Wrapper> {
        let mut included = Vec::new();
        for wrapper in candidates {
            let plan = match crate::mempool::validate(wrapper, ledger, fee_params) {
                Ok(plan) => plan,
                Err(_) => continue,
            };
            let mut sender = ledger.account(&plan.sender);
            let mut recipient = ledger.account(&plan.recipient);
            let transferred = match execute_transfer(
                sender.balance,
                recipient.balance,
                plan.amount,
                plan.fee,
                wrapper.body().meter_limit(),
            ) {
                Ok(transferred) => transferred,
                Err(_) => continue,
            };
            sender.balance = transferred.sender_balance;
            sender.nonce += 1;
            recipient.balance = transferred.recipient_balance;
            ledger.set_account(&plan.sender, &sender);
            ledger.set_account(&plan.recipient, &recipient);
            included.push(wrapper.clone());
        }
        included
    }
}
