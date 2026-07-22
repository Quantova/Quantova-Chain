
#[cfg(any(test, feature = "test-fixtures"))]
use std::collections::BTreeMap;
use std::thread;

#[cfg(any(test, feature = "test-fixtures"))]
use qtv_block::{Block as ChainBlock, Header};
use qtv_codec::{Decode, Decoder};
pub use qtv_crypto::ml_dsa::PublicKey;
use qtv_governance::{Action, Conviction};
pub use qtv_sampler::onetime::Root;
use qtv_tx::Wrapper;

#[cfg(any(test, feature = "test-fixtures"))]
use crate::consensus::{header_value, Beacon, Consensus, ConsensusValidator, Parent};
use crate::execution::execute_transfer;
use crate::fee::FeeParams;
use crate::ledger::{Account, Ledger};
#[cfg(any(test, feature = "test-fixtures"))]
use crate::mempool::{Admitted, Mempool, Reject};
use crate::mempool::validate_verified;
#[cfg(any(test, feature = "test-fixtures"))]
use crate::parallel::execute_parallel;

#[cfg(any(test, feature = "test-fixtures"))]
use qtv_attest::Certificate;

/// A validator's own published registration. Every field is a public commitment the
/// operator derived from the one secret it holds and never anything a second party can
/// reproduce from an id: the bond and reward address, the one time sortition root, the
/// attestation public key, and the peer to peer identity public key. Genesis carries
/// these and nothing else of a validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSpec {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    pub bond_address: String,
    pub root: Root,
    pub attest_pk: PublicKey,
    pub p2p_public: PublicKey,
}

impl ValidatorSpec {
    /// The registration a validator's own secret derives to. The operator runs this on
    /// its own machine over the secret in its keystore and contributes the public result
    /// to genesis; no one else holds the secret and no field is a function of the id.
    pub fn from_secret(id: u64, stake: u64, online: bool, secret: &[u8; 32], slots: u64) -> Self {
        let attester = qtv_attest::Attester::from_secret_with_slots(id, secret, stake, slots);
        ValidatorSpec {
            id,
            stake,
            online,
            bond_address: crate::keys::validator_address(secret),
            root: attester.root(),
            attest_pk: *attester.attest_public_key(),
            p2p_public: crate::keys::p2p_public(secret),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisAccount {
    pub address: String,
    pub balance: u64,
    pub scheme: u8,
    pub public_key: Vec<u8>,
}

impl GenesisAccount {
    pub fn from_account(account: &qtv_account::Account, balance: u64) -> Self {
        GenesisAccount {
            address: account.address(),
            balance,
            scheme: account.scheme(),
            public_key: account.public_key().to_vec(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Genesis {
    pub fee_params: FeeParams,
    pub accounts: Vec<GenesisAccount>,
    pub validators: Vec<ValidatorSpec>,
    pub genesis_time: u64,
}

#[cfg(any(test, feature = "test-fixtures"))]
pub struct Finalized {
    pub block: ChainBlock,
    pub certificate: Certificate,
    pub leader: u64,
    pub committee_size: usize,
    pub attesters: Vec<u64>,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Finalized {
    pub fn header(&self) -> &Header {
        self.block.header()
    }

    pub fn header_hash(&self) -> [u8; 32] {
        self.block.header_hash()
    }

    pub fn id(&self) -> String {
        self.block.id()
    }

    pub fn transaction_ids(&self) -> Vec<String> {
        self.block.body().iter().map(Wrapper::id).collect()
    }

    pub fn reconciles(&self) -> bool {
        header_value(&self.header_hash()) == self.certificate.envelope.block.val
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProduceError {
    NoCommittee,
    NotFinalized,
}

/// The bond and reward address of the validator behind a fixture secret index, for
/// tests and the single process simulation only. A production caller derives the
/// address from the operator secret it holds through `crate::keys::validator_address`,
/// never from the public id; this convenience is absent from a default node build.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn validator_address(id: u64) -> String {
    crate::keys::validator_address(&crate::keys::fixture_secret(id))
}

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

pub fn min_validator_cores() -> usize {
    let machine = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (machine / 2).max(1)
}

pub fn day_of_height(height: u64) -> u64 {
    height.saturating_mul(qtv_bft::params::SLOT_MS) / 86_400_000
}

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

pub(crate) fn is_key_register(wrapper: &Wrapper) -> bool {
    wrapper.body().call().target() == crate::ledger::key_register_address()
}

pub(crate) fn key_register_admissible(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
) -> Option<Vec<u8>> {
    let body = wrapper.body();
    if body.call().target() != crate::ledger::key_register_address() {
        return None;
    }
    if !qtv_tx::scheme_supported(wrapper.scheme()) {
        return None;
    }
    let public_key = body.call().args().to_vec();
    if qtv_account::address_for_key(wrapper.scheme(), &public_key).as_str() != body.sender() {
        return None;
    }
    if !qtv_tx::verify(wrapper, &public_key) {
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
    Some(public_key)
}

fn dispatch_governance(
    ledger: &mut Ledger,
    wrapper: &Wrapper,
    signature_ok: bool,
    fee_params: &FeeParams,
    now: u64,
) -> bool {
    let sender = wrapper.body().sender().to_string();
    if ledger.is_blacklisted(&sender) {
        return false;
    }
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
    ledger.collect_fee(charged);
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

fn dispatch_key_register(ledger: &mut Ledger, wrapper: &Wrapper, fee_params: &FeeParams) -> bool {
    let sender = wrapper.body().sender().to_string();
    if ledger.is_blacklisted(&sender) {
        return false;
    }
    let account = ledger.account(&sender);
    let public_key = match key_register_admissible(wrapper, &account, fee_params) {
        Some(key) => key,
        None => return false,
    };
    let charged = u64::try_from(wrapper.body().fee().min(u128::from(fee_params.ceiling_fee())))
        .unwrap_or_else(|_| fee_params.ceiling_fee());
    let mut updated = account;
    updated.balance -= charged;
    updated.nonce += 1;
    updated.scheme = wrapper.scheme();
    updated.public_key = public_key;
    ledger.set_account(&sender, &updated);
    ledger.collect_fee(charged);
    true
}

const VM_BLOCK_METER_BUDGET: u64 = 50_000_000;

pub(crate) fn is_vm_op(ledger: &Ledger, wrapper: &Wrapper) -> bool {
    let target = wrapper.body().call().target();
    target == crate::ledger::vm_deploy_address() || ledger.is_contract(target)
}

pub(crate) fn vm_admissible(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
    signature_ok: bool,
) -> bool {
    let body = wrapper.body();
    if !account.has_key() || !qtv_tx::scheme_supported(wrapper.scheme()) || !signature_ok {
        return false;
    }
    if body.nonce() != account.nonce
        || body.meter_limit() < crate::execution::TRANSFER_METER
        || body.meter_limit() > VM_BLOCK_METER_BUDGET
    {
        return false;
    }
    if body.fee() < u128::from(fee_params.transfer_fee()) {
        return false;
    }
    let charged = u64::try_from(body.fee().min(u128::from(fee_params.ceiling_fee())))
        .unwrap_or_else(|_| fee_params.ceiling_fee());
    account.balance >= charged
}

const DEPLOY_PARAMS_TAG: &[u8; 8] = b"QDEPLOY1";

fn split_deploy_args(args: &[u8]) -> (&[u8], &[u8]) {
    if args.len() >= 12 && &args[0..8] == DEPLOY_PARAMS_TAG {
        let len = u32::from_be_bytes([args[8], args[9], args[10], args[11]]) as usize;
        let start = 12usize;
        if let Some(end) = start.checked_add(len) {
            if end <= args.len() {
                return (&args[start..end], &args[end..]);
            }
        }
    }
    (args, &[])
}

fn dispatch_vm(
    ledger: &mut Ledger,
    wrapper: &Wrapper,
    signature_ok: bool,
    fee_params: &FeeParams,
    now_seconds: u64,
) -> bool {
    let sender = wrapper.body().sender().to_string();
    if ledger.is_blacklisted(&sender) {
        return false;
    }
    let account = ledger.account(&sender);
    if !vm_admissible(wrapper, &account, fee_params, signature_ok) {
        return false;
    }
    let charged = u64::try_from(wrapper.body().fee().min(u128::from(fee_params.ceiling_fee())))
        .unwrap_or_else(|_| fee_params.ceiling_fee());
    let target = wrapper.body().call().target().to_string();
    let args = wrapper.body().call().args().to_vec();
    let nonce = account.nonce;
    let meter = wrapper.body().meter_limit();
    let mut charged_account = account;
    charged_account.balance -= charged;
    charged_account.nonce += 1;
    ledger.set_account(&sender, &charged_account);
    ledger.collect_fee(charged);
    if target == crate::ledger::vm_deploy_address() {
        let (container, params) = split_deploy_args(&args);
        if let Some(contract) = ledger.deploy_contract(&sender, nonce, container) {
            let genesis = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
            let mut genesis_memory =
                vec![0u8; crate::ledger::CONTRACT_CONTEXT_BYTES + params.len()];
            genesis_memory[crate::ledger::CONTRACT_CONTEXT_BYTES..].copy_from_slice(params);
            ledger.call_contract(&sender, &contract, genesis, &genesis_memory, now_seconds, meter);
        }
    } else if args.len() >= 4 {
        let selector = [args[0], args[1], args[2], args[3]];
        ledger.call_contract(&sender, &target, selector, &args[4..], now_seconds, meter);
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
    let claim_address = crate::ledger::stake_claim_address();
    let gov_address = crate::ledger::gov_system_address();
    let now_seconds = day.saturating_mul(86_400);
    let mut included = Vec::new();
    let mut vm_meter: u64 = 0;
    for (index, wrapper) in candidates.iter().enumerate() {
        if ledger.is_blacklisted(wrapper.body().sender()) {
            continue;
        }
        if is_vm_op(ledger, wrapper) {
            let meter = wrapper.body().meter_limit();
            if vm_meter.saturating_add(meter) > VM_BLOCK_METER_BUDGET {
                continue;
            }
            if dispatch_vm(ledger, wrapper, verified[index], fee_params, now_seconds) {
                vm_meter = vm_meter.saturating_add(meter);
                included.push(wrapper.clone());
            }
            continue;
        }
        if wrapper.body().call().target() == gov_address {
            if dispatch_governance(ledger, wrapper, verified[index], fee_params, now_seconds) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if is_key_register(wrapper) {
            if dispatch_key_register(ledger, wrapper, fee_params) {
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
        if plan.recipient == claim_address {
            if ledger.claim_with_fee(&plan.sender, plan.fee, day) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if ledger.is_blacklisted(&plan.recipient) {
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
        ledger.collect_fee(plan.fee);
        included.push(wrapper.clone());
    }
    ledger.settle_session(day, included.len() as u64);
    included
}

const PARALLEL_VERIFY_THRESHOLD: usize = 4;

fn verify_signatures(ledger: &Ledger, candidates: &[Wrapper], verify_cores: usize) -> Vec<bool> {
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

/// A single process node that stands the whole committee up in one process, each
/// validator's attester computing its own reveal and the committee assembled from those
/// published reveals. A simulation, compiled only under cfg(test) or the test-fixtures
/// feature and absent from a default build.
#[cfg(any(test, feature = "test-fixtures"))]
pub struct Node {
    ledger: Ledger,
    mempool: Mempool,
    consensus: Consensus,
    base_validators: Vec<ConsensusValidator>,
    sim_attesters: BTreeMap<u64, qtv_attest::Attester>,
    sim_online: BTreeMap<u64, bool>,
    slots: u64,
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

/// Reweigh the public roster from the live ledger bonds, moving only stake weight and
/// keeping the fixed commitments. Falls back to the genesis weights when state is bare.
pub fn reweigh_roster(
    ledger: &Ledger,
    base: &[crate::consensus::ValidatorRegistration],
) -> Vec<crate::consensus::ValidatorRegistration> {
    let derived: Vec<crate::consensus::ValidatorRegistration> = base
        .iter()
        .map(|r| {
            let mut reweighed = r.clone();
            reweighed.stake = ledger.staked_weight(&r.bond_address);
            reweighed
        })
        .collect();
    if derived.iter().all(|r| r.stake == 0) {
        return base.to_vec();
    }
    derived
}

#[cfg(any(test, feature = "test-fixtures"))]
pub fn committee_weights(
    ledger: &Ledger,
    base: &[ConsensusValidator],
) -> Vec<ConsensusValidator> {
    let derived: Vec<ConsensusValidator> = base
        .iter()
        .map(|v| ConsensusValidator {
            id: v.id,
            stake: ledger.staked_weight(&v.bond_address),
            online: v.online,
            secret: v.secret,
            bond_address: v.bond_address.clone(),
        })
        .collect();
    if derived.iter().all(|v| v.stake == 0) {
        return base.to_vec();
    }
    derived
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Node {
    /// Build a single process node from genesis and the per validator secret roster.
    pub fn new(genesis: Genesis, secrets: &BTreeMap<u64, [u8; 32]>) -> Self {
        let slots = qtv_sampler::validator::DEFAULT_SLOTS;
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
                secret: *secrets
                    .get(&v.id)
                    .expect("a secret for every genesis validator"),
                bond_address: v.bond_address.clone(),
            })
            .collect();
        let validator_addresses = genesis
            .validators
            .iter()
            .map(|v| (v.id, v.bond_address.clone()))
            .collect();
        let mut validator_ids: Vec<[u8; 32]> = Vec::new();
        for v in &genesis.validators {
            ledger.seed_validator_bond(
                &v.bond_address,
                v.stake.saturating_mul(qtv_staking::NATIVE_UNIT as u64),
            );
            if let Ok(payload) = qtv_idfmt::parse_address(&v.bond_address) {
                if let Ok(id) = <[u8; 32]>::try_from(payload) {
                    validator_ids.push(id);
                }
            }
        }
        ledger.seed_validator_set(&validator_ids);

        let sim_attesters: BTreeMap<u64, qtv_attest::Attester> = validators
            .iter()
            .map(|v| {
                (
                    v.id,
                    qtv_attest::Attester::from_secret_with_slots(v.id, &v.secret, v.stake, slots),
                )
            })
            .collect();
        let sim_online = validators.iter().map(|v| (v.id, v.online)).collect();
        let consensus = Consensus::with_slots(
            validators[0].id,
            &validators[0].secret,
            crate::consensus::roster_of(&validators, slots),
            slots,
        );

        Node {
            ledger,
            mempool: Mempool::new(),
            consensus,
            base_validators: validators,
            sim_attesters,
            sim_online,
            slots,
            fee_params: genesis.fee_params,
            validator_addresses,
            beacon: crate::consensus::genesis_beacon(),
            height: qtv_bft::params::MIN_HEIGHT,
            parent_header_hash: [0u8; 32],
            parent_val: Parent::Genesis,
            genesis_time: genesis.genesis_time,
            chain: Vec::new(),
            slashed: Vec::new(),
            exec_threads: min_validator_cores(),
        }
    }

    /// The reveals every simulated validator publishes for the slot.
    fn published_reveals(&self, slot: u64) -> Vec<qtv_sampler::committee::PublishedReveal> {
        self.sim_attesters
            .iter()
            .filter_map(|(id, attester)| {
                let credential = attester.reveal(slot);
                if self
                    .consensus
                    .verify_published(
                        &self.beacon,
                        slot,
                        &qtv_sampler::committee::PublishedReveal::new(*id, credential.clone()),
                    )
                {
                    Some(qtv_sampler::committee::PublishedReveal::new(*id, credential))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn set_parallelism(&mut self, threads: usize) {
        self.exec_threads = threads.max(1);
    }

    pub fn with_parallelism(mut self, threads: usize) -> Self {
        self.set_parallelism(threads);
        self
    }

    pub fn exec_cores(&self) -> usize {
        self.exec_threads.max(min_validator_cores())
    }

    pub fn submit(&mut self, transaction: Wrapper) -> Result<Admitted, Reject> {
        self.mempool
            .admit(transaction, &self.ledger, &self.fee_params)
    }

    pub fn produce(&mut self) -> Result<&Finalized, ProduceError> {
        let height = self.height;
        let slot = height;

        let reweighed = committee_weights(&self.ledger, &self.base_validators);
        self.consensus
            .reweight(crate::consensus::roster_of(&reweighed, self.slots));
        let published = self.published_reveals(slot);
        let selection = self
            .consensus
            .select(&self.beacon, slot, &published)
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
        let event_leaves: Vec<Vec<u8>> = self
            .ledger
            .block_events()
            .iter()
            .map(crate::ledger::BlockEvent::encode)
            .collect();
        let event_root = qtv_block::event_root(&event_leaves);
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

        let attestations: Vec<qtv_attest::Attestation> = selection
            .members
            .iter()
            .filter(|id| self.sim_online.get(id).copied().unwrap_or(false))
            .filter_map(|id| self.sim_attesters.get(id))
            .map(|attester| attester.attest(height, slot, block, &self.beacon))
            .collect();
        let certificate = self
            .consensus
            .finalize(&selection, height, slot, block, &self.beacon, &attestations)
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

    fn execute_block(&mut self) -> Vec<Wrapper> {
        self.ledger.clear_block_events();
        let candidates = self.mempool.candidates();
        let day = day_of_height(self.height);
        let threads = self.exec_cores();
        if threads > 1 {
            execute_parallel(&mut self.ledger, &candidates, &self.fee_params, threads, day)
        } else {
            execute_ordered(&mut self.ledger, &candidates, &self.fee_params, day)
        }
    }

    pub fn run(&mut self, heights: u64) -> Result<(), ProduceError> {
        for _ in 0..heights {
            self.produce()?;
        }
        Ok(())
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn chain(&self) -> &[Finalized] {
        &self.chain
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

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

        let bare = Ledger::new();
        assert_eq!(committee_weights(&bare, &base), base);

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

    fn system_tx(
        from: &KeyAccount,
        target: &str,
        args: Vec<u8>,
        nonce: u64,
        meter: u64,
        fee: &FeeParams,
    ) -> Wrapper {
        let call = qtv_tx::Call::new(target.to_string(), args);
        let body = Body::new(
            from.address(),
            nonce,
            meter,
            u128::from(fee.transfer_fee()),
            call,
        );
        sign(from, &body)
    }

    fn address_bytes(address: &str) -> [u8; 32] {
        let payload = qtv_idfmt::parse_address(address).expect("a full address");
        let mut id = [0u8; 32];
        id.copy_from_slice(&payload);
        id
    }

    #[test]
    fn a_transfer_fee_burns_a_portion_and_funds_the_pools() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let alice = keypair(200);
        let bob = keypair(201);
        fund(&mut ledger, &alice, 10_000 * 1_000_000);

        let charged = fee.transfer_fee();
        let pool_before = ledger.stake_pool();
        let grants_before = ledger.grants_pool();
        let supply_before = ledger.account(&alice.address()).balance
            + ledger.account(&bob.address()).balance
            + pool_before
            + grants_before;

        let tx = transfer(&alice, &bob.address(), 1_000, 0, &fee);
        assert_eq!(
            execute_ordered(&mut ledger, &[tx], &fee, 0).len(),
            1,
            "the transfer is included"
        );

        let pool_gain = ledger.stake_pool() - pool_before;
        let grants_gain = ledger.grants_pool() - grants_before;
        let burned = Ledger::fee_burned(charged);
        assert!(pool_gain > 0 && grants_gain > 0, "both pools are funded");
        assert!(burned > 0, "a portion is burned");
        assert_eq!(
            pool_gain + grants_gain + burned,
            charged,
            "the whole fee splits into the pools and the burn, nothing created or lost"
        );

        let supply_after = ledger.account(&alice.address()).balance
            + ledger.account(&bob.address()).balance
            + ledger.stake_pool()
            + ledger.grants_pool();
        assert_eq!(
            supply_before - supply_after,
            burned,
            "the total supply falls by exactly the burned share"
        );
    }

    #[test]
    fn a_contract_deploys_and_a_call_runs_it_through_the_executor() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let deployer = keypair(130);
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);

        let code = qtv_vm::asm::assemble("LDI r1, 0\nMLOAD r0, r1\nLDI r2, 0\nSSTORE r2, r0\nHALT")
            .expect("the program assembles");
        let selector = [1u8, 2, 3, 4];
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: vec![],
                    writes: vec![0],
                },
            }],
        );

        let deploy = system_tx(
            &deployer,
            &crate::ledger::vm_deploy_address(),
            container.canonical_bytes(),
            0,
            100_000,
            &fee,
        );
        assert_eq!(execute_ordered(&mut ledger, &[deploy], &fee, 0).len(), 1);
        let contract = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        assert!(ledger.is_contract(&contract));

        let call = system_tx(&deployer, &contract, selector.to_vec(), 1, 100_000, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[call], &fee, 0).len(), 1);
        let stored = ledger.contract_storage(&address_bytes(&contract));
        let deployer_key = address_bytes(&deployer.address());
        let expected = crate::ledger::address_word(&deployer.address()).unwrap();
        assert_eq!(
            stored.get(&deployer_key),
            Some(&expected),
            "the injected caller was stored"
        );

        let mut parallel = {
            let mut l = Ledger::new();
            fund(&mut l, &deployer, 10_000 * 1_000_000);
            l
        };
        let deploy2 = system_tx(
            &deployer,
            &crate::ledger::vm_deploy_address(),
            container.canonical_bytes(),
            0,
            100_000,
            &fee,
        );
        crate::parallel::execute_parallel(&mut parallel, &[deploy2], &fee, 8, 0);
        assert!(parallel.is_contract(&contract));
    }

    #[test]
    fn a_deploy_runs_the_genesis_constructor_with_the_deployer_as_caller() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let deployer = keypair(140);
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);

        let code = qtv_vm::asm::assemble(
            "LDI r1, 0\nMLOAD r0, r1\nLDI r2, 1024\nSSTORE r2, r0\nHALT",
        )
        .expect("the program assembles");
        let genesis_selector = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector: genesis_selector,
                offset: 0,
                access: qtv_vm::container::StateAccess::default(),
            }],
        );

        let deploy = system_tx(
            &deployer,
            &crate::ledger::vm_deploy_address(),
            container.canonical_bytes(),
            0,
            100_000,
            &fee,
        );
        assert_eq!(execute_ordered(&mut ledger, &[deploy], &fee, 0).len(), 1);
        let contract = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        let contract_id = address_bytes(&contract);

        let deployer_word =
            u64::from_be_bytes(address_bytes(&deployer.address())[0..8].try_into().unwrap());
        assert_eq!(
            ledger
                .contract_storage(&contract_id)
                .get(&qtv_vm::abi::scalar_key(0)),
            Some(&deployer_word),
            "the genesis constructor stored the deployer at deploy"
        );
    }

    #[test]
    fn split_deploy_args_reads_the_frame_and_leaves_a_bare_container_whole() {
        let bare = b"QVM1 the whole container".to_vec();
        let (container, params) = super::split_deploy_args(&bare);
        assert_eq!(container, &bare[..]);
        assert!(params.is_empty());

        let mut framed = Vec::new();
        framed.extend_from_slice(super::DEPLOY_PARAMS_TAG);
        framed.extend_from_slice(&3u32.to_be_bytes());
        framed.extend_from_slice(b"ABC");
        framed.extend_from_slice(b"the params");
        let (container, params) = super::split_deploy_args(&framed);
        assert_eq!(container, b"ABC");
        assert_eq!(params, b"the params");

        let mut bad = Vec::new();
        bad.extend_from_slice(super::DEPLOY_PARAMS_TAG);
        bad.extend_from_slice(&999u32.to_be_bytes());
        bad.extend_from_slice(b"short");
        let (container, params) = super::split_deploy_args(&bad);
        assert_eq!(container, &bad[..]);
        assert!(params.is_empty());
    }

    #[test]
    fn a_framed_deploy_carries_its_parameters_into_the_genesis_run() {
        let fee = FeeParams::devnet();
        let deployer = keypair(141);
        let code = qtv_vm::asm::assemble(
            "LDI r1, 72\nMLOAD r0, r1\nLDI r2, 1024\nSSTORE r2, r0\nHALT",
        )
        .expect("the program assembles");
        let genesis_selector = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector: genesis_selector,
                offset: 0,
                access: qtv_vm::container::StateAccess::default(),
            }],
        );
        let cbytes = container.canonical_bytes();
        let param: u64 = 0xCAFE_F00D_1234_5678;

        let mut framed = Vec::new();
        framed.extend_from_slice(super::DEPLOY_PARAMS_TAG);
        framed.extend_from_slice(&(cbytes.len() as u32).to_be_bytes());
        framed.extend_from_slice(&cbytes);
        framed.extend_from_slice(&param.to_be_bytes());

        let mut ledger = Ledger::new();
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);
        let deploy = system_tx(&deployer, &crate::ledger::vm_deploy_address(), framed, 0, 100_000, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[deploy], &fee, 0).len(), 1);
        let contract = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        assert_eq!(
            ledger
                .contract_storage(&address_bytes(&contract))
                .get(&qtv_vm::abi::scalar_key(0)),
            Some(&param),
            "the framed deploy carried the parameter into the genesis run"
        );

        let mut bare_ledger = Ledger::new();
        fund(&mut bare_ledger, &deployer, 10_000 * 1_000_000);
        let bare = system_tx(&deployer, &crate::ledger::vm_deploy_address(), cbytes, 0, 100_000, &fee);
        assert_eq!(execute_ordered(&mut bare_ledger, &[bare], &fee, 0).len(), 1);
        assert_eq!(
            bare_ledger
                .contract_storage(&address_bytes(&contract))
                .get(&qtv_vm::abi::scalar_key(0)),
            Some(&0),
            "a bare deploy carries no parameter, so the genesis read and stored a zero"
        );
    }

    #[test]
    fn two_contract_calls_in_one_block_do_not_race_the_stored_counter() {
        let fee = FeeParams::devnet();
        let deployer = keypair(131);

        let code = qtv_vm::asm::assemble(
            "LDI r0, 0\nSLOAD r1, r0\nLDI r2, 1\nADD r1, r1, r2\nSSTORE r0, r1\nHALT",
        )
        .expect("the program assembles");
        let selector = [5u8, 6, 7, 8];
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: vec![0],
                    writes: vec![0],
                },
            }],
        );

        let contract = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        let contract_id = address_bytes(&contract);
        let caller_key = address_bytes(&deployer.address());

        let deploy = system_tx(
            &deployer,
            &crate::ledger::vm_deploy_address(),
            container.canonical_bytes(),
            0,
            100_000,
            &fee,
        );
        let call_one = system_tx(&deployer, &contract, selector.to_vec(), 1, 100_000, &fee);
        let call_two = system_tx(&deployer, &contract, selector.to_vec(), 2, 100_000, &fee);
        let block = vec![deploy, call_one, call_two];

        let mut ledger = Ledger::new();
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);
        let included = crate::parallel::execute_parallel(&mut ledger, &block, &fee, 8, 0);
        assert_eq!(included.len(), 3, "the deploy and both calls are included");
        assert_eq!(
            ledger.contract_storage(&contract_id).get(&caller_key),
            Some(&2),
            "the two calls increment in order, so the counter is two not one"
        );
    }

    #[test]
    fn a_contract_emit_records_a_block_event_and_a_nonempty_event_root() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let deployer = keypair(140);
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);

        let code = qtv_vm::asm::assemble(
            "LDI r0, 64\nLDI r3, 42\nMSTORE r0, r3\nLDI r1, 8\nLDI r2, 2882343476\nEMIT r0, r1, r2\nHALT",
        )
        .expect("the program assembles");
        let selector = [5u8, 6, 7, 8];
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: vec![],
                    writes: vec![],
                },
            }],
        );

        let deploy = system_tx(
            &deployer,
            &crate::ledger::vm_deploy_address(),
            container.canonical_bytes(),
            0,
            100_000,
            &fee,
        );
        assert_eq!(execute_ordered(&mut ledger, &[deploy], &fee, 0).len(), 1);
        let contract = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        assert!(ledger.block_events().is_empty());

        let call = system_tx(&deployer, &contract, selector.to_vec(), 1, 100_000, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[call], &fee, 0).len(), 1);

        let events = ledger.block_events();
        assert_eq!(events.len(), 1, "one event recorded");
        assert_eq!(events[0].contract, contract);
        assert_eq!(events[0].selector, [0xAB, 0xCD, 0x12, 0x34]);
        assert_eq!(events[0].data, 42u64.to_be_bytes().to_vec());

        let leaves: Vec<Vec<u8>> = events.iter().map(crate::ledger::BlockEvent::encode).collect();
        assert_ne!(
            qtv_block::event_root(&leaves),
            qtv_block::empty_transaction_root(),
            "a block that emitted an event has a nonempty event root"
        );
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

    fn register_tx(from: &KeyAccount, nonce: u64, fee: &FeeParams) -> Wrapper {
        let call = qtv_tx::Call::new(crate::ledger::key_register_address(), from.public_key().to_vec());
        let body = Body::new(
            from.address(),
            nonce,
            TRANSFER_METER,
            u128::from(fee.transfer_fee()),
            call,
        );
        sign(from, &body)
    }

    #[test]
    fn a_keyless_account_registers_its_key_and_can_then_send() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let user = keypair(140);
        let friend = keypair(141);
        ledger.set_account(
            &user.address(),
            &Account { nonce: 0, balance: 100_000, scheme: 0, public_key: Vec::new() },
        );
        assert!(!ledger.account(&user.address()).has_key(), "a funded receiver starts keyless");

        let early = transfer(&user, &friend.address(), 1000, 0, &fee);
        assert!(
            execute_ordered(&mut ledger, &[early], &fee, 0).is_empty(),
            "a keyless account cannot send"
        );

        let reg = register_tx(&user, 0, &fee);
        assert_eq!(
            execute_ordered(&mut ledger, &[reg], &fee, 0).len(),
            1,
            "the registration is included"
        );
        assert!(ledger.account(&user.address()).has_key(), "the key is now installed");
        assert_eq!(ledger.account(&user.address()).nonce, 1);

        let send = transfer(&user, &friend.address(), 1000, 1, &fee);
        assert_eq!(
            execute_ordered(&mut ledger, &[send], &fee, 0).len(),
            1,
            "a registered account can send"
        );
        assert_eq!(ledger.account(&friend.address()).balance, 1000);
    }

    #[test]
    fn a_registration_cannot_install_a_key_for_an_address_that_is_not_the_signers() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let attacker = keypair(150);
        let victim = keypair(151);
        ledger.set_account(
            &victim.address(),
            &Account { nonce: 0, balance: 100_000, scheme: 0, public_key: Vec::new() },
        );

        let call = qtv_tx::Call::new(
            crate::ledger::key_register_address(),
            attacker.public_key().to_vec(),
        );
        let body = Body::new(victim.address(), 0, TRANSFER_METER, u128::from(fee.transfer_fee()), call);
        let forged_wrong_key = sign(&attacker, &body);
        assert!(
            execute_ordered(&mut ledger, &[forged_wrong_key], &fee, 0).is_empty(),
            "a key that does not hash to the sender is refused"
        );
        assert!(!ledger.account(&victim.address()).has_key(), "the victim stays keyless");

        let call = qtv_tx::Call::new(
            crate::ledger::key_register_address(),
            victim.public_key().to_vec(),
        );
        let body = Body::new(victim.address(), 0, TRANSFER_METER, u128::from(fee.transfer_fee()), call);
        let forged_wrong_signer = sign(&attacker, &body);
        let before = ledger.state_root();
        assert!(
            execute_ordered(&mut ledger, &[forged_wrong_signer.clone()], &fee, 0).is_empty(),
            "a registration not signed by the key owner is refused"
        );
        assert!(!ledger.account(&victim.address()).has_key(), "the victim still stays keyless");
        assert_eq!(ledger.state_root(), before, "a refused registration moves nothing");

        let mut parallel = ledger.clone();
        assert!(
            crate::parallel::execute_parallel(&mut parallel, &[forged_wrong_signer], &fee, 8, 0)
                .is_empty()
        );
        assert_eq!(parallel.state_root(), ledger.state_root());
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

        let mut enact = qtv_codec::Encoder::new();
        enact.put_u8(3);
        enact.put_u64(1);
        let enact_tx = gov_call_tx(&proposer, enact.into_bytes(), 1, &fee);
        let included = execute_ordered(&mut ledger, &[enact_tx], &fee, 8);
        assert_eq!(included.len(), 1);
        assert_eq!(ledger.stake_price(), 70_000_000);

        let bad = gov_call_tx(&proposer, vec![99u8], 2, &fee);
        assert!(execute_ordered(&mut ledger, &[bad], &fee, 8).is_empty());
    }

    #[test]
    fn a_governance_blacklist_stops_the_address_from_transacting() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let proposer = keypair(112);
        let voter = keypair(113);
        let hostile = keypair(114);
        let peer = keypair(115);
        fund(&mut ledger, &proposer, 300_000 * 1_000_000);
        fund(&mut ledger, &voter, 10_000 * 1_000_000);
        fund(&mut ledger, &hostile, 10_000 * 1_000_000);
        fund(&mut ledger, &peer, 10_000 * 1_000_000);

        let target = qtv_idfmt::parse_address(&hostile.address()).unwrap();
        let action = Action::Blacklist { target };
        let mut propose_args = vec![1u8];
        propose_args.extend_from_slice(&qtv_codec::to_bytes(&action));
        let propose = gov_call_tx(&proposer, propose_args, 0, &fee);
        let vote = gov_call_tx(&voter, vote_args(1, true, 0, 5_000 * 1_000_000), 0, &fee);
        execute_ordered(&mut ledger, &[propose, vote], &fee, 0);

        let mut enact = qtv_codec::Encoder::new();
        enact.put_u8(3);
        enact.put_u64(1);
        execute_ordered(
            &mut ledger,
            &[gov_call_tx(&proposer, enact.into_bytes(), 1, &fee)],
            &fee,
            3,
        );
        assert!(ledger.is_blacklisted(&hostile.address()));

        let out = transfer(&hostile, &peer.address(), 100 * 1_000_000, 0, &fee);
        assert!(execute_ordered(&mut ledger, &[out.clone()], &fee, 3).is_empty());
        let into = transfer(&peer, &hostile.address(), 100 * 1_000_000, 0, &fee);
        assert!(execute_ordered(&mut ledger, &[into], &fee, 3).is_empty());
        let clean = transfer(&peer, &voter.address(), 100 * 1_000_000, 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[clean], &fee, 3).len(), 1);

        let mut parallel = ledger.clone();
        assert!(crate::parallel::execute_parallel(&mut parallel, &[out], &fee, 8, 3).is_empty());
        assert_eq!(parallel.state_root(), ledger.state_root());
    }

    #[test]
    fn a_blacklisted_sender_is_refused_for_every_operation_not_only_a_transfer() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let proposer = keypair(130);
        let voter = keypair(131);
        let hostile = keypair(132);
        fund(&mut ledger, &proposer, 300_000 * 1_000_000);
        fund(&mut ledger, &voter, 10_000 * 1_000_000);
        fund(&mut ledger, &hostile, 10_000 * 1_000_000);

        let target = qtv_idfmt::parse_address(&hostile.address()).unwrap();
        let action = Action::Blacklist { target };
        let mut propose_args = vec![1u8];
        propose_args.extend_from_slice(&qtv_codec::to_bytes(&action));
        execute_ordered(
            &mut ledger,
            &[
                gov_call_tx(&proposer, propose_args, 0, &fee),
                gov_call_tx(&voter, vote_args(1, true, 0, 5_000 * 1_000_000), 0, &fee),
            ],
            &fee,
            0,
        );
        let mut enact = qtv_codec::Encoder::new();
        enact.put_u8(3);
        enact.put_u64(1);
        execute_ordered(
            &mut ledger,
            &[gov_call_tx(&proposer, enact.into_bytes(), 1, &fee)],
            &fee,
            3,
        );
        assert!(ledger.is_blacklisted(&hostile.address()));

        let hostile_nonce = ledger.account(&hostile.address()).nonce;

        let gov = gov_call_tx(&hostile, propose_price_args(70_000_000), hostile_nonce, &fee);
        assert!(
            execute_ordered(&mut ledger, &[gov.clone()], &fee, 3).is_empty(),
            "a blacklisted sender must not drive governance"
        );

        let bond = transfer(
            &hostile,
            &crate::ledger::stake_system_address(),
            100 * 1_000_000,
            hostile_nonce,
            &fee,
        );
        assert!(
            execute_ordered(&mut ledger, &[bond], &fee, 3).is_empty(),
            "a blacklisted sender must not bond"
        );

        assert_eq!(ledger.account(&hostile.address()).nonce, hostile_nonce);

        let mut parallel = ledger.clone();
        assert!(crate::parallel::execute_parallel(&mut parallel, &[gov], &fee, 8, 3).is_empty());
        assert_eq!(parallel.state_root(), ledger.state_root());
    }

    #[test]
    fn a_claim_transaction_withdraws_vested_rewards_through_the_executor() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let validator = keypair(120);
        fund(&mut ledger, &validator, 1_000 * 1_000_000);
        ledger.seed_stake_pool(700_000 * 1_000_000);
        ledger.seed_validator_bond(&validator.address(), 2_000 * 1_000_000);
        ledger.set_stake_mainnet_start(0);
        ledger.set_stake_price(70 * 1_000_000);
        ledger.accrue_reward(&validator.address(), qtv_staking::Session::Low, 400);

        let claim_day = 400 + 365;
        assert!(ledger.claimable_reward(&validator.address(), claim_day) > 0);
        let before = ledger.balance(&validator.address());

        let claim = transfer(&validator, &crate::ledger::stake_claim_address(), 0, 0, &fee);
        let included = execute_ordered(&mut ledger, &[claim], &fee, claim_day);
        assert_eq!(included.len(), 1);
        assert!(ledger.balance(&validator.address()) > before);
        assert_eq!(ledger.claimable_reward(&validator.address(), claim_day), 0);
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

    fn mixed_block(fee: &FeeParams) -> (Ledger, Vec<Wrapper>) {
        let count = 64u64;
        let keys: Vec<KeyAccount> = (0..count).map(keypair).collect();
        let mut ledger = Ledger::new();
        for (i, key) in keys.iter().enumerate().take(60) {
            let balance = if i == 5 { 1 } else { 5_000_000 };
            fund(&mut ledger, key, balance);
        }

        let mut block = Vec::new();
        for i in 0..40u64 {
            let sender = i as usize;
            let recipient = 40 + (i % 20) as usize;
            block.push(transfer(&keys[sender], &keys[recipient].address(), 1_000, 0, fee));
        }
        block.push(corrupt_signature(transfer(
            &keys[1],
            &keys[41].address(),
            500,
            1,
            fee,
        )));
        block.push(transfer(&keys[2], &keys[42].address(), 500, 0, fee));
        block.push(transfer(&keys[5], &keys[43].address(), 1_000_000, 0, fee));
        block.push(transfer(&keys[3], &keys[3].address(), 100, 1, fee));
        block.push(transfer(&keys[60], &keys[44].address(), 100, 0, fee));

        (ledger, block)
    }

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

    #[test]
    fn execute_ordered_matches_the_inline_loop_across_core_counts() {
        let fee = FeeParams::devnet();
        let (base, block) = mixed_block(&fee);

        let mut reference = base.clone();
        let reference_included = execute_ordered_inline(&mut reference, &block, &fee);
        let reference_root = reference.state_root();
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

        let mut public = base.clone();
        let public_included = execute_ordered(&mut public, &block, &fee, 0);
        assert_eq!(ids(&public_included), ids(&reference_included));
        assert_eq!(public.state_root(), reference_root);
    }

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
            ledger.collect_fee(plan.fee);
            included.push(wrapper.clone());
        }
        included
    }
}
