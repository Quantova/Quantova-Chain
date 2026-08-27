// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
pub struct GenesisBridgedAsset {
    pub asset_id: [u8; 16],
    pub cap: u128,
    pub epoch_cap: u128,
    pub requires_stark: bool,
}

pub struct Genesis {
    pub fee_params: FeeParams,
    pub accounts: Vec<GenesisAccount>,
    pub validators: Vec<ValidatorSpec>,
    pub genesis_time: u64,
    pub guardians: qtv_governance::GuardianSet,
    pub bridge_dest_chain: Option<u32>,
    pub bridge_operators: Option<crate::bridge::OperatorSet>,
    pub bridged_assets: Vec<GenesisBridgedAsset>,
    pub bridge_era: Option<[u8; 32]>,
}

#[cfg(any(test, feature = "test-fixtures"))]
pub struct Finalized {
    pub block: ChainBlock,
    pub certificate: Certificate,
    pub leader: u64,
    pub committee_size: usize,
    pub members: Vec<u64>,
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
    DoubleSignRefused,
    FinalityViolation,
}

#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityHalt {
    pub height: u64,
    pub finalized: [u8; 32],
    pub conflicting: [u8; 32],
}

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
            let _ = ledger.gov_enact(referendum, now, fee_params.chain_id);
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

pub(crate) fn is_evidence(wrapper: &Wrapper) -> bool {
    wrapper.body().call().target() == crate::ledger::evidence_address()
}

pub(crate) fn is_registration(wrapper: &Wrapper) -> bool {
    wrapper.body().call().target() == crate::ledger::registration_address()
}

pub(crate) fn evidence_admissible(chain_id: u64, wrapper: &Wrapper, ledger: &Ledger) -> bool {
    let evidence = match crate::evidence::Equivocation::decode(wrapper.body().call().args()) {
        Some(evidence) => evidence,
        None => return false,
    };
    if ledger.is_validator_banned(&evidence.offender) {
        return false;
    }
    match ledger.validator_attest_key(&evidence.offender) {
        Some(attest_pk) => evidence.attributes(chain_id, &attest_pk),
        None => false,
    }
}

fn dispatch_evidence(chain_id: u64, ledger: &mut Ledger, wrapper: &Wrapper) -> bool {
    let evidence = match crate::evidence::Equivocation::decode(wrapper.body().call().args()) {
        Some(evidence) => evidence,
        None => return false,
    };
    let attest_pk = match ledger.validator_attest_key(&evidence.offender) {
        Some(attest_pk) => attest_pk,
        None => return false,
    };
    if !evidence.attributes(chain_id, &attest_pk) {
        return false;
    }
    ledger.slash_validator(&evidence.offender)
}

const GUARDIAN_DOMAIN: &[u8] = b"QUANTOVA/Q/BRIDGE-GUARDIAN/v1";
const GUARDIAN_UNFREEZE: u8 = 0;
const GUARDIAN_FREEZE: u8 = 1;
const GUARDIAN_ENACT: u8 = 2;
const MAX_GUARDIAN_PAYLOAD: usize = 1 << 16;
const MAX_GUARDIAN_TARGETS: usize = 64;
const MAX_GUARDIAN_APPROVALS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
struct GuardianApproval {
    scheme: u8,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GuardianAct {
    op: u8,
    bound: u64,
    targets: Vec<[u8; 32]>,
    approvals: Vec<GuardianApproval>,
    payload: Vec<u8>,
}

impl GuardianAct {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = qtv_codec::Encoder::new();
        encoder.put_u8(self.op);
        encoder.put_u64(self.bound);
        encoder.put_u32(self.targets.len() as u32);
        for target in &self.targets {
            encoder.put_bytes(target);
        }
        encoder.put_u32(self.approvals.len() as u32);
        for approval in &self.approvals {
            encoder.put_u8(approval.scheme);
            encoder.put_bytes(&approval.public_key);
            encoder.put_bytes(&approval.signature);
        }
        encoder.put_bytes(&self.payload);
        encoder.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Option<GuardianAct> {
        let mut decoder = Decoder::new(bytes);
        let op = decoder.get_u8().ok()?;
        let bound = decoder.get_u64().ok()?;
        let target_count = decoder.get_u32().ok()? as usize;
        if target_count > MAX_GUARDIAN_TARGETS {
            return None;
        }
        let mut targets = Vec::with_capacity(target_count);
        for _ in 0..target_count {
            targets.push(<[u8; 32]>::try_from(decoder.get_bytes().ok()?).ok()?);
        }
        let approval_count = decoder.get_u32().ok()? as usize;
        if approval_count > MAX_GUARDIAN_APPROVALS {
            return None;
        }
        let mut approvals = Vec::with_capacity(approval_count);
        for _ in 0..approval_count {
            let scheme = decoder.get_u8().ok()?;
            let public_key = decoder.get_bytes().ok()?.to_vec();
            let signature = decoder.get_bytes().ok()?.to_vec();
            approvals.push(GuardianApproval {
                scheme,
                public_key,
                signature,
            });
        }
        let payload = decoder.get_bytes().ok()?.to_vec();
        if payload.len() > MAX_GUARDIAN_PAYLOAD {
            return None;
        }
        (decoder.remaining() == 0).then_some(GuardianAct {
            op,
            bound,
            targets,
            approvals,
            payload,
        })
    }
}

fn guardian_challenge(chain_id: u64, era: &[u8; 32], act: &GuardianAct) -> Vec<u8> {
    let mut message = Vec::with_capacity(8 + 32 + 1 + 8 + 4 + act.targets.len() * 32);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(era);
    message.push(act.op);
    message.extend_from_slice(&act.bound.to_le_bytes());
    message.extend_from_slice(&(act.targets.len() as u32).to_le_bytes());
    for target in &act.targets {
        message.extend_from_slice(target);
    }
    message.extend_from_slice(&(act.payload.len() as u32).to_le_bytes());
    message.extend_from_slice(&act.payload);
    message
}

fn guardian_enact_action(act: &GuardianAct) -> Option<Action> {
    if act.op != GUARDIAN_ENACT || !act.targets.is_empty() {
        return None;
    }
    let mut decoder = Decoder::new(&act.payload);
    let action = Action::decode(&mut decoder).ok()?;
    if decoder.remaining() != 0 {
        return None;
    }
    match action {
        Action::CommitteeRotate { .. } | Action::AssetRegister { .. } => Some(action),
        _ => None,
    }
}

pub fn guardian_enact_challenge(
    chain_id: u64,
    era: &[u8; 32],
    enact_nonce: u64,
    action: &Action,
) -> Vec<u8> {
    let act = GuardianAct {
        op: GUARDIAN_ENACT,
        bound: enact_nonce,
        targets: Vec::new(),
        approvals: Vec::new(),
        payload: qtv_codec::to_bytes(action),
    };
    guardian_challenge(chain_id, era, &act)
}

#[allow(clippy::too_many_arguments)]
pub fn build_guardian_enact_tx(
    action: &Action,
    chain_id: u64,
    enact_nonce: u64,
    approvals: Vec<(u8, Vec<u8>, Vec<u8>)>,
    relayer: &qtv_account::Account,
    nonce: u64,
    meter: u64,
    fee: u128,
) -> Wrapper {
    let act = GuardianAct {
        op: GUARDIAN_ENACT,
        bound: enact_nonce,
        targets: Vec::new(),
        approvals: approvals
            .into_iter()
            .map(|(scheme, public_key, signature)| GuardianApproval {
                scheme,
                public_key,
                signature,
            })
            .collect(),
        payload: qtv_codec::to_bytes(action),
    };
    let call = qtv_tx::Call::new(crate::ledger::bridge_guardian_address(), act.encode());
    let body = qtv_tx::Body::with_context(relayer.address(), nonce, meter, fee, call, 0, chain_id);
    qtv_tx::sign(relayer, &body)
}

fn guardian_member_id(scheme: u8, public_key: &[u8]) -> Option<[u8; 32]> {
    let address = qtv_account::address_for_key(scheme, public_key);
    let payload = qtv_idfmt::parse_address(&address).ok()?;
    <[u8; 32]>::try_from(payload.as_slice()).ok()
}

#[cfg(test)]
thread_local! {
    pub(crate) static GUARDIAN_VERIFY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn guardian_signature_ok(scheme: u8, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    #[cfg(test)]
    GUARDIAN_VERIFY_CALLS.with(|c| c.set(c.get() + 1));
    match scheme {
        qtv_account::SCHEME_LATTICE => {
            let pk: &[u8; qtv_crypto::ml_dsa::PUBLIC_KEY_BYTES] = match public_key.try_into() {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sig: &[u8; qtv_crypto::ml_dsa::SIGNATURE_BYTES] = match signature.try_into() {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            qtv_crypto::ml_dsa::verify(pk, message, sig, GUARDIAN_DOMAIN)
        }
        qtv_account::SCHEME_HASH => {
            let pk: &[u8; qtv_crypto::slh_dsa::PUBLIC_KEY_BYTES] = match public_key.try_into() {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            qtv_crypto::slh_dsa::verify(pk, message, signature, GUARDIAN_DOMAIN)
        }
        _ => false,
    }
}

fn guardian_approvers(
    set: &qtv_governance::GuardianSet,
    act: &GuardianAct,
    chain_id: u64,
    era: &[u8; 32],
) -> Vec<[u8; 32]> {
    let message = guardian_challenge(chain_id, era, act);
    let mut attempted: Vec<[u8; 32]> = Vec::new();
    let mut verified: Vec<[u8; 32]> = Vec::new();
    for approval in &act.approvals {
        let id = match guardian_member_id(approval.scheme, &approval.public_key) {
            Some(id) => id,
            None => continue,
        };
        if attempted.contains(&id) {
            continue;
        }
        attempted.push(id);
        if !set.is_member(&id) {
            continue;
        }
        if guardian_signature_ok(approval.scheme, &approval.public_key, &message, &approval.signature) {
            verified.push(id);
        }
    }
    verified
}

pub(crate) fn is_bridge_guardian(wrapper: &Wrapper) -> bool {
    wrapper.body().call().target() == crate::ledger::bridge_guardian_address()
}

pub(crate) fn guardian_admissible(ledger: &Ledger, wrapper: &Wrapper, chain_id: u64) -> bool {
    let set = ledger.guardian_set();
    if !set.well_formed() {
        return false;
    }
    let act = match GuardianAct::decode(wrapper.body().call().args()) {
        Some(act) => act,
        None => return false,
    };
    match act.op {
        GUARDIAN_FREEZE => {
            if act.targets.is_empty() {
                return false;
            }
            if act.bound != ledger.guardian_freeze_epoch() {
                return false;
            }
            if act.targets.iter().any(|target| ledger.is_protected_account(target)) {
                return false;
            }
        }
        GUARDIAN_UNFREEZE => match ledger.bridge_freeze() {
            Some(freeze) if freeze.until == act.bound => {}
            _ => return false,
        },
        GUARDIAN_ENACT => {
            if guardian_enact_action(&act).is_none() {
                return false;
            }
            if act.bound != ledger.guardian_enact_nonce() {
                return false;
            }
        }
        _ => return false,
    }
    set.authorizes(&guardian_approvers(&set, &act, chain_id, &ledger.bridge_era()))
}

fn dispatch_bridge_guardian(
    ledger: &mut Ledger,
    wrapper: &Wrapper,
    chain_id: u64,
    now: u64,
) -> bool {
    let set = ledger.guardian_set();
    if !set.well_formed() {
        return false;
    }
    let act = match GuardianAct::decode(wrapper.body().call().args()) {
        Some(act) => act,
        None => return false,
    };
    let approvers = guardian_approvers(&set, &act, chain_id, &ledger.bridge_era());
    match act.op {
        GUARDIAN_FREEZE => ledger.guardian_freeze(act.bound, &act.targets, &approvers, now),
        GUARDIAN_UNFREEZE => match ledger.bridge_freeze() {
            Some(freeze) if freeze.until == act.bound => {
                ledger.guardian_bridge_unfreeze(&approvers, now)
            }
            _ => false,
        },
        GUARDIAN_ENACT => match guardian_enact_action(&act) {
            Some(action) => {
                set.authorizes(&approvers)
                    && ledger.guardian_enact_bridge_action(&action, act.bound, now, chain_id)
            }
            None => false,
        },
        _ => false,
    }
}

pub(crate) fn is_bridge_mint(wrapper: &Wrapper) -> bool {
    wrapper.body().call().target() == crate::ledger::bridge_mint_address()
}

pub(crate) fn is_bridge_exit(wrapper: &Wrapper) -> bool {
    wrapper.body().call().target() == crate::ledger::bridge_exit_address()
}

fn bridge_mint_fact(ledger: &Ledger, wrapper: &Wrapper, chain_id: u64) -> Option<crate::bridge::Fact> {
    let artifact = crate::bridge::MintArtifact::decode(wrapper.body().call().args())?;
    let dest_chain = ledger.bridge_dest_chain()?;
    let operators = ledger.bridge_operator_set()?;
    if !crate::bridge::quorum_attests(&operators, &artifact.attestation, dest_chain, chain_id, &ledger.bridge_era()) {
        return None;
    }
    let fact = artifact.attestation.fact;
    if let Some(asset) = ledger.bridged_asset(&fact.asset_id) {
        if asset.requires_stark {
            let prover = operators.operators.first().map(|(id, _)| *id)?;
            if crate::bridge::check_stark(&fact, artifact.stark.as_ref(), prover)
                != crate::bridge::StarkCheck::BoundUnverified
            {
                return None;
            }
        }
    }
    Some(fact)
}

const MAX_BRIDGE_STARK_BYTES: usize = 1 << 20;

fn max_mint_artifact_bytes(ledger: &Ledger) -> usize {
    let operators = ledger.bridge_operator_set().map(|s| s.operators.len()).unwrap_or(0);
    let sig_frame = 4 + 2 + qtv_crypto::ml_dsa::SIGNATURE_BYTES;
    let attestation = 2 + crate::bridge::FACT_ENCODED_LEN + 4 + operators.saturating_mul(sig_frame);
    let stark = 1 + 32 + 4 + MAX_BRIDGE_STARK_BYTES;
    4 + attestation + 4 + stark
}

pub(crate) fn bridge_mint_source_key(wrapper: &Wrapper) -> Option<(u32, [u8; 32])> {
    crate::bridge::MintArtifact::decode(wrapper.body().call().args())
        .map(|artifact| (artifact.attestation.fact.source_chain, artifact.attestation.fact.source_ref))
}

pub(crate) fn bridge_mint_admissible(ledger: &Ledger, wrapper: &Wrapper, chain_id: u64) -> bool {
    if ledger.bridge_is_frozen() {
        return false;
    }
    if wrapper.body().call().args().len() > max_mint_artifact_bytes(ledger) {
        return false;
    }
    let (source_chain, source_ref) = match bridge_mint_source_key(wrapper) {
        Some(key) => key,
        None => return false,
    };
    if ledger.bridge_reference_seen(source_chain, &source_ref) {
        return false;
    }
    let fact = match bridge_mint_fact(ledger, wrapper, chain_id) {
        Some(fact) => fact,
        None => return false,
    };
    ledger.execution_height() <= fact.expiry_height
}

fn dispatch_bridge_mint(ledger: &mut Ledger, wrapper: &Wrapper, chain_id: u64) -> bool {
    if ledger.bridge_is_frozen() {
        return false;
    }
    let fact = match bridge_mint_fact(ledger, wrapper, chain_id) {
        Some(fact) => fact,
        None => return false,
    };
    ledger.bridge_mint(&fact)
}

pub(crate) fn is_bridge_settle(wrapper: &Wrapper) -> bool {
    wrapper.body().call().target() == crate::ledger::bridge_settle_address()
}

fn bridge_settle_fact(ledger: &Ledger, wrapper: &Wrapper, chain_id: u64) -> Option<crate::bridge::ExitFact> {
    let attestation = crate::bridge::ExitAttestation::decode(wrapper.body().call().args())?;
    let dest_chain = ledger.bridge_dest_chain()?;
    let operators = ledger.bridge_operator_set()?;
    if !crate::bridge::exit_quorum_attests(&operators, &attestation, dest_chain, chain_id, &ledger.bridge_era()) {
        return None;
    }
    Some(attestation.fact)
}

pub(crate) fn bridge_settle_burn_ref(wrapper: &Wrapper) -> Option<[u8; 32]> {
    crate::bridge::ExitAttestation::decode(wrapper.body().call().args())
        .map(|attestation| attestation.fact.burn_ref)
}

fn max_settle_artifact_bytes(ledger: &Ledger) -> usize {
    let operators = ledger.bridge_operator_set().map(|s| s.operators.len()).unwrap_or(0);
    let sig_frame = 4 + 2 + qtv_crypto::ml_dsa::SIGNATURE_BYTES;
    2 + crate::bridge::EXIT_FACT_ENCODED_LEN + 4 + operators.saturating_mul(sig_frame)
}

pub(crate) fn bridge_settle_admissible(ledger: &Ledger, wrapper: &Wrapper, chain_id: u64) -> bool {
    if !ledger.bridge_exits_enabled() {
        return false;
    }
    if ledger.bridge_is_frozen() {
        return false;
    }
    if wrapper.body().call().args().len() > max_settle_artifact_bytes(ledger) {
        return false;
    }
    let fact = match bridge_settle_fact(ledger, wrapper, chain_id) {
        Some(fact) => fact,
        None => return false,
    };
    !ledger.bridge_exit_settled(&fact.burn_ref)
}

fn dispatch_bridge_settle(ledger: &mut Ledger, wrapper: &Wrapper, chain_id: u64) -> bool {
    if !ledger.bridge_exits_enabled() {
        return false;
    }
    if ledger.bridge_is_frozen() {
        return false;
    }
    let fact = match bridge_settle_fact(ledger, wrapper, chain_id) {
        Some(fact) => fact,
        None => return false,
    };
    match fact.outcome {
        crate::bridge::ExitOutcome::Settle => ledger.bridge_settle(&fact),
        crate::bridge::ExitOutcome::Slash => ledger.bridge_slash(&fact),
    }
}

pub(crate) fn bridge_exit_admissible(
    ledger: &Ledger,
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
    signature_ok: bool,
) -> Option<crate::bridge::ExitRequest> {
    let body = wrapper.body();
    if body.call().target() != crate::ledger::bridge_exit_address() {
        return None;
    }
    if !ledger.bridge_exits_enabled() {
        return None;
    }
    if ledger.bridge_is_frozen() {
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
    crate::bridge::ExitRequest::decode(body.call().args())
}

fn dispatch_bridge_exit(
    ledger: &mut Ledger,
    wrapper: &Wrapper,
    signature_ok: bool,
    fee_params: &FeeParams,
) -> bool {
    let sender = wrapper.body().sender().to_string();
    if ledger.is_blacklisted(&sender) {
        return false;
    }
    if !ledger.bridge_exits_enabled() {
        return false;
    }
    if ledger.bridge_is_frozen() {
        return false;
    }
    let account = ledger.account(&sender);
    let request = match bridge_exit_admissible(ledger, wrapper, &account, fee_params, signature_ok) {
        Some(request) => request,
        None => return false,
    };
    let holder = match qtv_idfmt::parse_address(&sender)
        .ok()
        .and_then(|payload| <[u8; 32]>::try_from(payload.as_slice()).ok())
    {
        Some(id) => id,
        None => return false,
    };
    let charged = u64::try_from(wrapper.body().fee().min(u128::from(fee_params.ceiling_fee())))
        .unwrap_or_else(|_| fee_params.ceiling_fee());
    let mut charged_account = account;
    charged_account.balance -= charged;
    charged_account.nonce += 1;
    ledger.set_account(&sender, &charged_account);
    ledger.collect_fee(charged);
    ledger.bridge_burn(
        &request.asset_id,
        &holder,
        request.amount,
        &request.destination,
        fee_params.chain_id,
        wrapper.body().nonce(),
    )
}

const VM_BLOCK_METER_BUDGET: u64 = 50_000_000;
const MAX_TX_METER: u64 = VM_BLOCK_METER_BUDGET / 4;
const MAX_VM_ARGS: usize = 128 * 1024;

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
    if body.call().args().len() > MAX_VM_ARGS {
        return false;
    }
    if body.nonce() != account.nonce
        || body.meter_limit() < crate::execution::TRANSFER_METER
        || body.meter_limit() > MAX_TX_METER
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
    if ledger.bridge_is_frozen() && ledger.is_bridge_gateway(wrapper.body().call().target()) {
        return false;
    }
    let account = ledger.account(&sender);
    if !vm_admissible(wrapper, &account, fee_params, signature_ok) {
        return false;
    }
    let charged = u64::try_from(wrapper.body().fee().min(u128::from(fee_params.ceiling_fee())))
        .unwrap_or_else(|_| fee_params.ceiling_fee());
    let value = wrapper.body().value();
    let in_asset = wrapper.body().in_asset();
    let native_debit = if in_asset.is_none() { value } else { 0 };
    if account.balance < charged.saturating_add(native_debit) {
        return false;
    }
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
            let genesis_ok = ledger.call_contract(
                &sender,
                &contract,
                genesis,
                &genesis_memory,
                now_seconds,
                meter,
                value,
                in_asset,
                fee_params.chain_id,
            );
            let declares_genesis = crate::execution::decode_container(container)
                .map(|c| c.entries.iter().any(|e| e.selector == genesis))
                .unwrap_or(false);
            if declares_genesis && !genesis_ok {
                ledger.clear_contract_code(&contract);
            }
        }
    } else if args.len() >= 4 {
        let selector = [args[0], args[1], args[2], args[3]];
        if selector != qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE) {
            ledger.call_contract(
                &sender,
                &target,
                selector,
                &args[4..],
                now_seconds,
                meter,
                value,
                in_asset,
                fee_params.chain_id,
            );
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
    let claim_address = crate::ledger::stake_claim_address();
    let exit_address = crate::ledger::stake_exit_address();
    let withdraw_address = crate::ledger::stake_withdraw_address();
    let gov_address = crate::ledger::gov_system_address();
    let bridge_freeze_address = crate::ledger::bridge_freeze_address();
    let bridge_unfreeze_address = crate::ledger::bridge_unfreeze_address();
    let now_seconds = day.saturating_mul(86_400);
    ledger.bridge_expire(now_seconds);
    ledger.guardian_expire(now_seconds);
    let mut included = Vec::new();
    let mut vm_meter: u64 = 0;
    for (index, wrapper) in candidates.iter().enumerate() {
        if wrapper.body().chain_id() != fee_params.chain_id {
            continue;
        }
        if ledger.is_blacklisted(wrapper.body().sender()) {
            continue;
        }
        if ledger.is_frozen(wrapper.body().sender())
            && wrapper.body().call().target() != gov_address
        {
            continue;
        }
        if is_vm_op(ledger, wrapper) {
            let meter = wrapper.body().meter_limit();
            if vm_meter.saturating_add(meter) > VM_BLOCK_METER_BUDGET {
                continue;
            }
            if ledger
                .apply_atomic(|l| dispatch_vm(l, wrapper, verified[index], fee_params, now_seconds))
            {
                vm_meter = vm_meter.saturating_add(meter);
                included.push(wrapper.clone());
            }
            continue;
        }
        if wrapper.body().call().target() == gov_address {
            if ledger.apply_atomic(|l| {
                dispatch_governance(l, wrapper, verified[index], fee_params, now_seconds)
            }) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if is_key_register(wrapper) {
            if ledger.apply_atomic(|l| dispatch_key_register(l, wrapper, fee_params)) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if is_evidence(wrapper) {
            if ledger.apply_atomic(|l| dispatch_evidence(fee_params.chain_id, l, wrapper)) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if is_bridge_guardian(wrapper) {
            if ledger.apply_atomic(|l| {
                dispatch_bridge_guardian(l, wrapper, fee_params.chain_id, now_seconds)
            }) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if is_bridge_mint(wrapper) {
            if ledger.apply_atomic(|l| dispatch_bridge_mint(l, wrapper, fee_params.chain_id)) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if is_bridge_settle(wrapper) {
            if ledger.apply_atomic(|l| dispatch_bridge_settle(l, wrapper, fee_params.chain_id)) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if is_bridge_exit(wrapper) {
            if ledger
                .apply_atomic(|l| dispatch_bridge_exit(l, wrapper, verified[index], fee_params))
            {
                included.push(wrapper.clone());
            }
            continue;
        }
        if is_registration(wrapper) {
            included.push(wrapper.clone());
            continue;
        }
        let plan = match validate_verified(wrapper, ledger, fee_params, verified[index]) {
            Ok(plan) => plan,
            Err(_) => continue,
        };
        #[cfg(test)]
        if plan.recipient == crate::ledger::fault_probe_address() {
            let _ = ledger.apply_atomic(|l| {
                let mut victim = l.account(&plan.sender);
                victim.balance = victim.balance.wrapping_sub(plan.amount);
                victim.nonce += 1;
                l.set_account(&plan.sender, &victim);
                l.record_transfer_event(&plan.sender, &plan.recipient, plan.amount, plan.fee);
                panic!("injected native fault probe");
            });
            continue;
        }
        if plan.recipient == stake_address {
            if ledger.apply_atomic(|l| l.bond_with_fee(&plan.sender, plan.amount, plan.fee, day)) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if plan.recipient == claim_address {
            if ledger.apply_atomic(|l| l.claim_with_fee(&plan.sender, plan.fee, day)) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if plan.recipient == exit_address {
            if ledger.apply_atomic(|l| l.request_exit_with_fee(&plan.sender, plan.fee, day)) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if plan.recipient == withdraw_address {
            if ledger.apply_atomic(|l| l.withdraw_with_fee(&plan.sender, plan.fee, day)) {
                included.push(wrapper.clone());
            }
            continue;
        }
        if plan.recipient == bridge_freeze_address {
            if ledger.apply_atomic(|l| l.bridge_freeze_with_fee(&plan.sender, plan.fee, now_seconds))
            {
                included.push(wrapper.clone());
            }
            continue;
        }
        if plan.recipient == bridge_unfreeze_address {
            if ledger
                .apply_atomic(|l| l.bridge_unfreeze_with_fee(&plan.sender, plan.fee, now_seconds))
            {
                included.push(wrapper.clone());
            }
            continue;
        }
        if ledger.is_blacklisted(&plan.recipient) {
            continue;
        }
        let applied = ledger.apply_atomic(|l| {
            let mut sender = l.account(&plan.sender);
            let mut recipient = l.account(&plan.recipient);
            let transferred = match execute_transfer(
                sender.balance,
                recipient.balance,
                plan.amount,
                plan.fee,
                wrapper.body().meter_limit(),
            ) {
                Ok(transferred) => transferred,
                Err(_) => return false,
            };
            sender.balance = transferred.sender_balance;
            sender.nonce += 1;
            recipient.balance = transferred.recipient_balance;
            l.set_account(&plan.sender, &sender);
            l.set_account(&plan.recipient, &recipient);
            l.collect_fee(plan.fee);
            l.record_transfer_event(&plan.sender, &plan.recipient, plan.amount, plan.fee);
            true
        });
        if applied {
            included.push(wrapper.clone());
        }
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
    equivocator: Option<u64>,
    foreign_evidence: Vec<qtv_attest::Attestation>,
    sign_guard: Option<crate::watermark::SignGuard>,
    finality: crate::consensus::FinalityLedger,
}

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
    pub fn new(genesis: Genesis, secrets: &BTreeMap<u64, [u8; 32]>) -> Self {
        Self::new_with_slots(genesis, secrets, qtv_sampler::validator::DEFAULT_SLOTS)
    }

    pub fn new_with_slots(
        genesis: Genesis,
        secrets: &BTreeMap<u64, [u8; 32]>,
        slots: u64,
    ) -> Self {
        let mut ledger = Ledger::new();
        for account in &genesis.accounts {
            ledger.set_account(
                &account.address,
                &Account::funded(account.balance, account.scheme, account.public_key.clone()),
            );
        }
        ledger.seed_grants_account();
        if !genesis.guardians.members.is_empty() {
            ledger.seed_guardian_set(&genesis.guardians);
        }
        if let Some(dest_chain) = genesis.bridge_dest_chain {
            ledger.seed_bridge_dest_chain(dest_chain);
        }
        if let Some(ref operators) = genesis.bridge_operators {
            ledger.seed_bridge_operator_set(operators);
        }
        for asset in &genesis.bridged_assets {
            ledger.register_bridged_asset(&asset.asset_id, asset.cap, asset.epoch_cap, asset.requires_stark);
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
            ledger.set_validator_attest_key(&v.bond_address, &v.attest_pk);
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
            genesis.fee_params.chain_id,
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
            equivocator: None,
            foreign_evidence: Vec::new(),
            sign_guard: None,
            finality: crate::consensus::FinalityLedger::new(),
        }
    }

    pub fn force_equivocation(&mut self, id: u64) {
        self.equivocator = Some(id);
    }

    pub fn observe_finalization_evidence(&mut self, attestations: Vec<qtv_attest::Attestation>) {
        self.foreign_evidence.extend(attestations);
    }

    pub fn forge_finalization_quorum(
        &self,
        ids: &[u64],
        view: u64,
        value: [u8; 32],
    ) -> Vec<qtv_attest::Attestation> {
        let height = self.height;
        let slot = qtv_sampler::epoch::slot_in_epoch(height, self.slots);
        let chain_id = self.consensus.chain_id();
        let block = crate::consensus::Block::new(height, value, self.parent_val);
        let committee = self
            .consensus
            .select(&self.beacon, slot, &self.published_reveals(slot))
            .map(|s| s.commitment.digest())
            .unwrap_or([0u8; 32]);
        ids.iter()
            .filter_map(|id| self.sim_attesters.get(id))
            .map(|attester| attester.attest(chain_id, height, slot, view, committee, block, &self.beacon))
            .collect()
    }

    pub fn with_sign_guard(mut self, path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        self.sign_guard = Some(crate::watermark::SignGuard::open(path)?);
        Ok(self)
    }

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
        let epoch = qtv_sampler::epoch::epoch_of(height, self.slots);
        let slot = qtv_sampler::epoch::slot_in_epoch(height, self.slots);

        if epoch != self.consensus.epoch() {
            for attester in self.sim_attesters.values_mut() {
                *attester = attester.at_epoch(epoch);
            }
        }
        let reweighed = committee_weights(&self.ledger, &self.base_validators);
        let roster: Vec<crate::consensus::ValidatorRegistration> = reweighed
            .iter()
            .map(|v| {
                let att = self
                    .sim_attesters
                    .get(&v.id)
                    .expect("an attester for every validator");
                crate::consensus::ValidatorRegistration {
                    id: v.id,
                    stake: v.stake,
                    online: v.online,
                    bond_address: v.bond_address.clone(),
                    root: att.root(),
                    attest_pk: *att.attest_public_key(),
                }
            })
            .collect();
        self.consensus.rotate_to_epoch(epoch, roster.clone());
        let published = self.published_reveals(slot);
        let selection = self
            .consensus
            .select(&self.beacon, slot, &published)
            .ok_or(ProduceError::NoCommittee)?;
        if let Some(guard) = self.sign_guard.as_mut() {
            if !guard.try_sign(height, 0).unwrap_or(false) {
                return Err(ProduceError::DoubleSignRefused);
            }
        }
        let proposer = self
            .validator_addresses
            .get(&selection.leader)
            .cloned()
            .unwrap_or_default();

        self.ledger.set_round_proposer(&proposer);
        let included = self.execute_block();
        let included_ids: Vec<String> = included.iter().map(Wrapper::id).collect();

        let q_root = self.ledger.q_root();
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
            q_root,
            transaction_root,
            event_root,
            *self.beacon.seed(),
            proposer,
            time,
        );
        let header_hash = header.hash();

        let value = header_value(&header_hash);
        let block = crate::consensus::Block::new(height, value, self.parent_val);

        let chain_id = self.consensus.chain_id();
        let attestations: Vec<qtv_attest::Attestation> = selection
            .members
            .iter()
            .filter(|id| self.sim_online.get(id).copied().unwrap_or(false))
            .filter_map(|id| self.sim_attesters.get(id))
            .map(|attester| {
                attester.attest(chain_id, height, slot, 0, selection.commitment.digest(), block, &self.beacon)
            })
            .collect();

        let mut evidence = attestations.clone();
        if let Some(bad) = self.equivocator {
            if selection.members.contains(&bad) {
                if let Some(attester) = self.sim_attesters.get(&bad) {
                    let conflicting = crate::consensus::Block::new(
                        height,
                        header_value(&[0xEE; 32]),
                        self.parent_val,
                    );
                    evidence.push(attester.attest(
                        chain_id,
                        height,
                        slot,
                        0,
                        selection.commitment.digest(),
                        conflicting,
                        &self.beacon,
                    ));
                }
            }
        }
        evidence.append(&mut self.foreign_evidence);
        let mut offenders = crate::consensus::equivocation_offenders(chain_id, &evidence, &roster);
        for id in crate::consensus::double_finalize_offenders(chain_id, &evidence, &roster, selection.tau) {
            if !offenders.contains(&id) {
                offenders.push(id);
            }
        }

        let certificate = self
            .consensus
            .finalize(&selection, height, slot, block, &self.beacon, &attestations)
            .ok_or(ProduceError::NotFinalized)?;
        debug_assert!(self
            .consensus
            .verify(&certificate, &selection, &self.beacon));

        if let crate::consensus::FinalityStatus::Violation { .. } =
            self.finality.observe(height, value)
        {
            return Err(ProduceError::FinalityViolation);
        }

        let cert_digest = certificate.digest();
        let attesters = certificate.attesters();
        let chain_block = ChainBlock::new(header, cert_digest.to_vec(), included);

        let finalized = Finalized {
            block: chain_block,
            certificate,
            leader: selection.leader,
            committee_size: selection.commitment.len(),
            members: selection.members.clone(),
            attesters,
        };

        self.beacon = self.beacon.advance_from_reveals(slot, &selection.reveals);
        self.parent_header_hash = header_hash;
        self.parent_val = Parent::Value(value);
        self.height += 1;
        self.mempool.remove_included(&included_ids);
        self.chain.push(finalized);

        for id in &offenders {
            if let Some(address) = self.validator_addresses.get(id).cloned() {
                if self.ledger.slash_validator(&address) && !self.slashed.contains(id) {
                    self.slashed.push(*id);
                }
            }
        }

        Ok(self.chain.last().expect("a block was just finalized"))
    }

    fn execute_block(&mut self) -> Vec<Wrapper> {
        self.ledger.clear_block_events();
        self.ledger.set_execution_height(self.height);
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

    pub fn epoch(&self) -> u64 {
        self.consensus.epoch()
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

    pub fn finalized_value(&self, height: u64) -> Option<[u8; 32]> {
        self.finality.finalized_value(height)
    }

    pub fn observe_certificate(
        &mut self,
        height: u64,
        value: [u8; 32],
    ) -> Result<crate::consensus::FinalityStatus, FinalityHalt> {
        match self.finality.observe(height, value) {
            crate::consensus::FinalityStatus::Violation {
                height,
                finalized,
                conflicting,
            } => Err(FinalityHalt {
                height,
                finalized,
                conflicting,
            }),
            status => Ok(status),
        }
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

    fn payable_tx(
        from: &KeyAccount,
        target: &str,
        args: Vec<u8>,
        nonce: u64,
        meter: u64,
        fee: &FeeParams,
        value: u64,
    ) -> Wrapper {
        let call = qtv_tx::Call::new(target.to_string(), args);
        let body = Body::with_context(
            from.address(),
            nonce,
            meter,
            u128::from(fee.transfer_fee()),
            call,
            value,
            qtv_tx::LOCAL_CHAIN_ID,
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
    fn a_transfer_to_a_system_record_address_does_not_halt_the_executor() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let alice = keypair(300);
        fund(&mut ledger, &alice, 10_000 * 1_000_000);
        ledger.set_stake_pool(9_000);
        let pool_key = qtv_crypto::sha3::sha3_256(b"qtv/stake/pool");
        let hostile = qtv_idfmt::render_address(&pool_key).expect("a full hash reaches the floor");
        let pool_before = ledger.stake_pool();
        let tx = transfer(&alice, &hostile, 1, 0, &fee);
        let included = execute_ordered(&mut ledger, &[tx], &fee, 0);
        assert_eq!(included.len(), 1, "the crafted transfer is handled as an ordinary send");
        assert_eq!(
            ledger.account(&hostile).balance,
            1,
            "the unit lands in a domain-separated account leaf, not the system record"
        );
        assert!(
            ledger.stake_pool() >= pool_before,
            "the stake pool record stays a coherent balance and is never clobbered"
        );
    }

    #[test]
    fn a_transfer_fee_splits_seventy_ten_twenty_and_burns_the_supply() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let alice = keypair(200);
        let bob = keypair(201);
        fund(&mut ledger, &alice, 10_000 * 1_000_000);
        ledger.seed_supply(10_000 * 1_000_000);

        let proposer = qtv_idfmt::render_address(&[0x5Au8; 32]).unwrap();
        ledger.set_round_proposer(&proposer);
        let grants = crate::ledger::grants_address();
        let marketing =
            qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(b"qtv/ecosystem/marketing")).unwrap();
        let market_maker =
            qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(b"qtv/ecosystem/market-maker")).unwrap();

        let charged = fee.transfer_fee();
        assert_eq!(charged, 500, "the devnet transfer fee");
        let supply_before = ledger.total_supply();

        let tx = transfer(&alice, &bob.address(), 1_000, 0, &fee);
        assert_eq!(
            execute_ordered(&mut ledger, &[tx], &fee, 0).len(),
            1,
            "the transfer is included"
        );

        assert_eq!(ledger.balance(&proposer), 50, "the proposer takes a tenth");
        assert_eq!(ledger.balance(&grants), 100, "grants takes a fifth");
        assert_eq!(ledger.balance(&marketing), 0, "marketing takes no fee cut");
        assert_eq!(ledger.balance(&market_maker), 0, "the market maker takes no fee cut");

        assert_eq!(
            supply_before - ledger.total_supply(),
            350,
            "the supply falls by the seven tenths that burns"
        );

        let balances = ledger.balance(&alice.address())
            + ledger.balance(&bob.address())
            + ledger.balance(&proposer)
            + ledger.balance(&grants);
        assert_eq!(
            ledger.total_supply(),
            balances,
            "the supply still equals the sum of every balance after the burn"
        );

        let dust = crate::ledger::FeeSplit::of(7);
        assert_eq!(
            (dust.burn, dust.proposer, dust.grants),
            (4, 0, 3),
            "the rounding dust lands in the grants share"
        );
        assert_eq!(dust.total(), 7, "the split conserves the fee to the unit");
    }

    #[test]
    fn a_contract_deploys_and_a_call_runs_it_through_the_executor() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let deployer = keypair(130);
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);

        let code = qtv_vm::asm::assemble("LDI r1, 0\nMLOAD r0, r1\nLDI r2, 1024\nSSTORE r2, r0\nHALT")
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
                    keyed_reads: vec![],
                    keyed_writes: vec![],
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
        let expected = crate::ledger::address_word(&deployer.address()).unwrap();
        assert_eq!(
            stored.get(&qtv_vm::abi::scalar_key(0)),
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
                access: qtv_vm::container::StateAccess {
                    reads: vec![],
                    writes: vec![0],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
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
    fn a_deployed_contract_rejects_a_genesis_selector_call_and_keeps_its_owner() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let owner = keypair(160);
        let stranger = keypair(161);
        fund(&mut ledger, &owner, 10_000 * 1_000_000);
        fund(&mut ledger, &stranger, 10_000 * 1_000_000);

        let code = qtv_vm::asm::assemble("LDI r1, 0\nMLOAD r0, r1\nLDI r2, 1024\nSSTORE r2, r0\nHALT")
            .expect("the program assembles");
        let genesis = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector: genesis,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: vec![],
                    writes: vec![0],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );

        let deploy = system_tx(
            &owner,
            &crate::ledger::vm_deploy_address(),
            container.canonical_bytes(),
            0,
            100_000,
            &fee,
        );
        assert_eq!(execute_ordered(&mut ledger, &[deploy], &fee, 0).len(), 1);
        let contract = crate::ledger::contract_address(&owner.address(), 0).unwrap();
        let contract_id = address_bytes(&contract);
        let owner_word =
            u64::from_be_bytes(address_bytes(&owner.address())[0..8].try_into().unwrap());
        assert_eq!(
            ledger.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(0)),
            Some(&owner_word),
            "the deploy runs genesis once and records the deployer as owner"
        );

        let reinvoke = system_tx(&stranger, &contract, genesis.to_vec(), 0, 100_000, &fee);
        execute_ordered(&mut ledger, &[reinvoke], &fee, 0);

        let stranger_word =
            u64::from_be_bytes(address_bytes(&stranger.address())[0..8].try_into().unwrap());
        assert_ne!(owner_word, stranger_word, "the two accounts are distinct");
        assert_eq!(
            ledger.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(0)),
            Some(&owner_word),
            "a genesis selector call on a deployed contract does not overwrite the owner"
        );
    }

    fn payer_contract(amount: u64) -> qtv_vm::container::Container {
        let pull =
            qtv_vm::asm::assemble("LDI r0, 0\nLDI r1, 32\nLDC r2, 0\nSEND r0, r1, r2\nHALT")
                .expect("assembles");
        let deposit_offset = pull.len() as u32;
        let mut code = pull;
        code.extend_from_slice(&qtv_vm::asm::assemble("HALT").expect("assembles"));
        qtv_vm::container::Container::new(
            code,
            vec![amount],
            vec![
                qtv_vm::container::Entry {
                    selector: qtv_vm::container::selector("pull()"),
                    offset: 0,
                    access: qtv_vm::container::StateAccess::default(),
                },
                qtv_vm::container::Entry {
                    selector: qtv_vm::container::selector("deposit()"),
                    offset: deposit_offset,
                    access: qtv_vm::container::StateAccess::default(),
                },
            ],
        )
    }

    #[test]
    fn a_contract_sends_and_receives_real_native_funds_with_value_conserved() {
        let fee = FeeParams::devnet();
        let charged = fee.transfer_fee();
        let mut ledger = Ledger::new();
        let deployer = keypair(180);
        let payee = keypair(181);
        let deployer_start = 10_000 * 1_000_000u64;
        let payee_start = 1_000_000u64;
        fund(&mut ledger, &deployer, deployer_start);
        fund(&mut ledger, &payee, payee_start);

        let payout = 2_000u64;
        let deposit_value = 5_000u64;
        let container = payer_contract(payout);
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
        assert_eq!(ledger.balance(&contract), 0, "a fresh contract holds nothing");

        let deposit_sel = qtv_vm::container::selector("deposit()");
        let deposit = payable_tx(
            &deployer,
            &contract,
            deposit_sel.to_vec(),
            1,
            100_000,
            &fee,
            deposit_value,
        );
        assert_eq!(execute_ordered(&mut ledger, &[deposit], &fee, 0).len(), 1);
        assert_eq!(
            ledger.balance(&contract),
            deposit_value,
            "the contract took custody of the native value it was sent"
        );
        assert_eq!(
            ledger.balance(&deployer.address()),
            deployer_start - 2 * charged - deposit_value,
            "the depositor paid two fees and parted with the value it sent"
        );

        let supply_before = ledger.balance(&contract) + ledger.balance(&payee.address());
        let pull_sel = qtv_vm::container::selector("pull()");
        let pull = system_tx(&payee, &contract, pull_sel.to_vec(), 0, 100_000, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[pull], &fee, 0).len(), 1);

        assert_eq!(
            ledger.balance(&contract),
            deposit_value - payout,
            "the contract paid the amount out of its own balance"
        );
        assert_eq!(
            ledger.balance(&payee.address()),
            payee_start - charged + payout,
            "the caller received the native funds the contract sent"
        );
        let supply_after = ledger.balance(&contract) + ledger.balance(&payee.address());
        assert_eq!(
            supply_after + charged,
            supply_before,
            "the only change beyond the paid fee is a conserved move from the contract to the caller"
        );
    }

    #[test]
    fn a_contract_send_over_its_balance_reverts_and_creates_nothing() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let deployer = keypair(182);
        let payee = keypair(183);
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);
        fund(&mut ledger, &payee, 1_000_000);

        let container = payer_contract(9_999u64);
        let deploy = system_tx(
            &deployer,
            &crate::ledger::vm_deploy_address(),
            container.canonical_bytes(),
            0,
            100_000,
            &fee,
        );
        execute_ordered(&mut ledger, &[deploy], &fee, 0);
        let contract = crate::ledger::contract_address(&deployer.address(), 0).unwrap();

        let deposit = payable_tx(
            &deployer,
            &contract,
            qtv_vm::container::selector("deposit()").to_vec(),
            1,
            100_000,
            &fee,
            1_000u64,
        );
        execute_ordered(&mut ledger, &[deposit], &fee, 0);
        assert_eq!(ledger.balance(&contract), 1_000);

        let payee_before = ledger.balance(&payee.address());
        let pull = system_tx(
            &payee,
            &contract,
            qtv_vm::container::selector("pull()").to_vec(),
            0,
            100_000,
            &fee,
        );
        execute_ordered(&mut ledger, &[pull], &fee, 0);

        assert_eq!(
            ledger.balance(&contract),
            1_000,
            "an overdrawn send moves nothing out of the contract"
        );
        assert_eq!(
            ledger.balance(&payee.address()),
            payee_before - fee.transfer_fee(),
            "the caller minted no funds and only paid the fee"
        );
    }

    #[test]
    fn a_malformed_container_is_rejected_at_deploy() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let deployer = keypair(170);
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);

        let genesis = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
        let bad_code = qtv_vm::asm::assemble("LDI r0, 1\nJMP 3\nHALT").expect("assembles");
        let malformed = qtv_vm::container::Container::new(
            bad_code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector: genesis,
                offset: 0,
                access: qtv_vm::container::StateAccess::default(),
            }],
        );
        assert!(malformed.verify().is_err(), "the container is malformed");

        let deploy = system_tx(
            &deployer,
            &crate::ledger::vm_deploy_address(),
            malformed.canonical_bytes(),
            0,
            100_000,
            &fee,
        );
        execute_ordered(&mut ledger, &[deploy], &fee, 0);
        let rejected = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        assert!(
            !ledger.is_contract(&rejected),
            "a malformed container deploys no contract"
        );

        let good_code = qtv_vm::asm::assemble("LDI r0, 1\nHALT").expect("assembles");
        let good = qtv_vm::container::Container::new(
            good_code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector: genesis,
                offset: 0,
                access: qtv_vm::container::StateAccess::default(),
            }],
        );
        let deploy_good = system_tx(
            &deployer,
            &crate::ledger::vm_deploy_address(),
            good.canonical_bytes(),
            1,
            100_000,
            &fee,
        );
        execute_ordered(&mut ledger, &[deploy_good], &fee, 0);
        let accepted = crate::ledger::contract_address(&deployer.address(), 1).unwrap();
        assert!(
            ledger.is_contract(&accepted),
            "a well formed container deploys"
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
            "LDI r1, 88\nMLOAD r0, r1\nLDI r2, 1024\nSSTORE r2, r0\nHALT",
        )
        .expect("the program assembles");
        let genesis_selector = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector: genesis_selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: vec![],
                    writes: vec![0],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
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
    fn a_framed_deploy_whose_genesis_faults_leaves_no_orphan_contract() {
        let fee = FeeParams::devnet();
        let deployer = keypair(151);
        let code = qtv_vm::asm::assemble("LDI r1, 88\nLDI r2, 64\nLDI r3, 40\nSEND r1, r2, r3\nHALT")
            .expect("the program assembles");
        let genesis_selector = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector: genesis_selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: vec![],
                    writes: vec![],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );
        let cbytes = container.canonical_bytes();
        let mut framed = Vec::new();
        framed.extend_from_slice(super::DEPLOY_PARAMS_TAG);
        framed.extend_from_slice(&(cbytes.len() as u32).to_be_bytes());
        framed.extend_from_slice(&cbytes);
        framed.extend_from_slice(&[0xB2u8; 32]);
        framed.extend_from_slice(&[9u8; 32]);

        let mut ledger = Ledger::new();
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);
        let deploy =
            system_tx(&deployer, &crate::ledger::vm_deploy_address(), framed, 0, 100_000, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[deploy], &fee, 0).len(), 1);
        let contract = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        assert!(
            !ledger.is_contract(&contract),
            "a framed deploy whose declared genesis faults must not leave an orphan container"
        );
    }

    #[test]
    fn two_contract_calls_in_one_block_do_not_race_the_stored_counter() {
        let fee = FeeParams::devnet();
        let deployer = keypair(131);

        let code = qtv_vm::asm::assemble(
            "LDI r0, 1024\nSLOAD r1, r0\nLDI r2, 1\nADD r1, r1, r2\nSSTORE r0, r1\nHALT",
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
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );

        let contract = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        let contract_id = address_bytes(&contract);

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
            ledger.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(0)),
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
                    keyed_reads: vec![],
                    keyed_writes: vec![],
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

    #[test]
    fn a_native_transfer_records_a_block_event_and_a_nonempty_event_root() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let alice = keypair(400);
        let bob = keypair(401);
        fund(&mut ledger, &alice, 10_000 * 1_000_000);

        let tx = transfer(&alice, &bob.address(), 1_000, 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[tx], &fee, 0).len(), 1);

        let events = ledger.block_events();
        assert_eq!(events.len(), 1, "one native transfer event recorded");
        assert_eq!(events[0].contract, crate::ledger::NATIVE_EVENT_SOURCE);
        assert_eq!(events[0].selector, crate::ledger::EVENT_TRANSFER);
        let mut decoder = qtv_codec::Decoder::new(&events[0].data);
        assert_eq!(decoder.get_bytes().unwrap(), alice.address().as_bytes());
        assert_eq!(decoder.get_bytes().unwrap(), bob.address().as_bytes());
        assert_eq!(decoder.get_u64().unwrap(), 1_000);
        assert_eq!(decoder.get_u64().unwrap(), u64::from(fee.transfer_fee()));

        let leaves: Vec<Vec<u8>> = events.iter().map(crate::ledger::BlockEvent::encode).collect();
        assert_ne!(
            qtv_block::event_root(&leaves),
            qtv_block::empty_transaction_root(),
            "a block with a native transfer has a nonempty event root"
        );
    }

    #[test]
    fn a_faulted_transaction_rolls_back_and_leaves_the_rest_of_the_block_intact() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let alice = keypair(500);
        let bob = keypair(501);
        let carol = keypair(502);
        let dave = keypair(503);
        let erin = keypair(504);
        fund(&mut ledger, &alice, 10_000 * 1_000_000);
        fund(&mut ledger, &carol, 10_000 * 1_000_000);
        fund(&mut ledger, &dave, 10_000 * 1_000_000);

        let carol_before = ledger.account(&carol.address());
        let root_before = ledger.q_root();

        let good_first = transfer(&alice, &bob.address(), 1_000, 0, &fee);
        let faulting = transfer(&carol, &crate::ledger::fault_probe_address(), 2_000, 0, &fee);
        let good_second = transfer(&dave, &erin.address(), 3_000, 0, &fee);

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let included = execute_ordered(&mut ledger, &[good_first, faulting, good_second], &fee, 0);
        std::panic::set_hook(previous);

        assert_eq!(included.len(), 2, "the faulted transaction is not included");
        assert_eq!(ledger.balance(&bob.address()), 1_000, "the earlier transfer stands");
        assert_eq!(ledger.balance(&erin.address()), 3_000, "the later transfer stands");
        assert_eq!(
            ledger.account(&carol.address()),
            carol_before,
            "no partial write from the faulted transaction survives"
        );
        assert_ne!(
            ledger.q_root(),
            root_before,
            "the two good transfers still moved the state root"
        );
        assert_eq!(
            ledger.block_events().len(),
            2,
            "only the two good transfers left events, the faulted one recorded none"
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
        let before = ledger.q_root();
        assert!(
            execute_ordered(&mut ledger, &[forged_wrong_signer.clone()], &fee, 0).is_empty(),
            "a registration not signed by the key owner is refused"
        );
        assert!(!ledger.account(&victim.address()).has_key(), "the victim still stays keyless");
        assert_eq!(ledger.q_root(), before, "a refused registration moves nothing");

        let mut parallel = ledger.clone();
        assert!(
            crate::parallel::execute_parallel(&mut parallel, &[forged_wrong_signer], &fee, 8, 0)
                .is_empty()
        );
        assert_eq!(parallel.q_root(), ledger.q_root());
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
        fund(&mut ledger, &proposer, 2_260_000 * 1_000_000);
        fund(&mut ledger, &voter, 10_000 * 1_000_000);
        ledger.seed_validator_bond(&voter.address(), 10_000 * 1_000_000);

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
        let included = execute_ordered(&mut ledger, &[enact_tx], &fee, 15);
        assert_eq!(included.len(), 1);
        assert_eq!(ledger.stake_price(), 70_000_000);

        let bad = gov_call_tx(&proposer, vec![99u8], 2, &fee);
        assert!(execute_ordered(&mut ledger, &[bad], &fee, 15).is_empty());
    }

    #[test]
    fn a_frozen_voter_still_votes_but_still_cannot_move_value() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let proposer = keypair(150);
        let voter = keypair(151);
        let payee = keypair(152);
        let g1 = keypair(153);
        let g2 = keypair(154);
        let g3 = keypair(155);
        fund(&mut ledger, &proposer, 2_260_000 * 1_000_000);
        fund(&mut ledger, &voter, 10_000 * 1_000_000);
        ledger.seed_validator_bond(&voter.address(), 10_000 * 1_000_000);

        let propose = gov_call_tx(&proposer, propose_price_args(70_000_000), 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[propose], &fee, 0).len(), 1);
        assert!(ledger.gov_referendum(1).is_some());

        ledger.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![
                address_bytes(&g1.address()),
                address_bytes(&g2.address()),
                address_bytes(&g3.address()),
            ],
            2,
        ));
        assert!(ledger.guardian_freeze(
            0,
            &[address_bytes(&voter.address())],
            &[address_bytes(&g1.address()), address_bytes(&g2.address())],
            0,
        ));
        assert!(ledger.is_frozen(&voter.address()), "the quorum froze the voter");

        let vote = gov_call_tx(&voter, vote_args(1, true, 0, 5_000 * 1_000_000), 0, &fee);
        let escape = transfer(&voter, &payee.address(), 1_000 * 1_000_000, 1, &fee);
        let included = execute_ordered(&mut ledger, &[vote, escape], &fee, 0);
        assert_eq!(included.len(), 1, "the frozen voter's ballot lands while its transfer is dropped");
        assert_eq!(
            ledger.gov_total_locked(),
            5_000 * 1_000_000,
            "a frozen electorate can never be silenced against a guardian caucus"
        );
        assert_eq!(
            ledger.account(&payee.address()).balance,
            0,
            "the freeze still blocks the frozen account from moving value out"
        );
    }

    #[test]
    fn a_governance_blacklist_stops_the_address_from_transacting() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let proposer = keypair(112);
        let voter = keypair(113);
        let hostile = keypair(114);
        let peer = keypair(115);
        fund(&mut ledger, &proposer, 400_000 * 1_000_000);
        fund(&mut ledger, &voter, 10_000 * 1_000_000);
        fund(&mut ledger, &hostile, 10_000 * 1_000_000);
        fund(&mut ledger, &peer, 10_000 * 1_000_000);
        ledger.seed_validator_bond(&voter.address(), 10_000 * 1_000_000);

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
        assert_eq!(parallel.q_root(), ledger.q_root());
    }

    #[test]
    fn a_governance_freeze_stops_a_sender_but_still_lets_it_receive() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let proposer = keypair(140);
        let voter = keypair(141);
        let hostile = keypair(142);
        let peer = keypair(143);
        fund(&mut ledger, &proposer, 400_000 * 1_000_000);
        fund(&mut ledger, &voter, 10_000 * 1_000_000);
        fund(&mut ledger, &hostile, 10_000 * 1_000_000);
        fund(&mut ledger, &peer, 10_000 * 1_000_000);
        ledger.seed_validator_bond(&voter.address(), 10_000 * 1_000_000);

        let target = qtv_idfmt::parse_address(&hostile.address()).unwrap();
        let action = Action::Freeze { targets: vec![target] };
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
            2,
        );
        assert!(ledger.is_frozen(&hostile.address()));

        let out = transfer(&hostile, &peer.address(), 100 * 1_000_000, 0, &fee);
        assert!(
            execute_ordered(&mut ledger, &[out], &fee, 2).is_empty(),
            "a frozen account cannot send"
        );
        let into = transfer(&peer, &hostile.address(), 100 * 1_000_000, 0, &fee);
        assert_eq!(
            execute_ordered(&mut ledger, &[into], &fee, 2).len(),
            1,
            "a frozen account still receives"
        );
    }

    #[test]
    fn a_transaction_bonds_then_exits_then_withdraws_the_stake() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let staker = keypair(150);
        fund(&mut ledger, &staker, 5_000 * 1_000_000);
        let sid = address_bytes(&staker.address());

        let bond = transfer(&staker, &crate::ledger::stake_system_address(), 2_000 * 1_000_000, 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[bond], &fee, 0).len(), 1);
        assert_eq!(ledger.stake_bond(&sid).unwrap().amount, 2_000 * 1_000_000);

        let nonce = ledger.account(&staker.address()).nonce;
        let exit = transfer(&staker, &crate::ledger::stake_exit_address(), 0, nonce, &fee);
        assert!(
            execute_ordered(&mut ledger, &[exit.clone()], &fee, 89).is_empty(),
            "an exit before the lock clears is not included"
        );
        assert_eq!(execute_ordered(&mut ledger, &[exit], &fee, 90).len(), 1);
        assert!(ledger.stake_bond(&sid).unwrap().exit_requested_at.is_some());

        let nonce = ledger.account(&staker.address()).nonce;
        let withdraw = transfer(&staker, &crate::ledger::stake_withdraw_address(), 0, nonce, &fee);
        assert!(
            execute_ordered(&mut ledger, &[withdraw.clone()], &fee, 90 + 20).is_empty(),
            "a withdraw before the unbonding elapses is not included"
        );
        assert_eq!(execute_ordered(&mut ledger, &[withdraw], &fee, 90 + 21).len(), 1);
        assert!(ledger.stake_bond(&sid).is_none());
    }

    #[test]
    fn a_blacklisted_sender_is_refused_for_every_operation_not_only_a_transfer() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let proposer = keypair(130);
        let voter = keypair(131);
        let hostile = keypair(132);
        fund(&mut ledger, &proposer, 400_000 * 1_000_000);
        fund(&mut ledger, &voter, 10_000 * 1_000_000);
        fund(&mut ledger, &hostile, 10_000 * 1_000_000);
        ledger.seed_validator_bond(&voter.address(), 10_000 * 1_000_000);

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
        assert_eq!(parallel.q_root(), ledger.q_root());
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
        ledger.accrue_reward(&validator.address(), 400);

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
            fund(&mut ledger, &proposer, 2_260_000 * 1_000_000);
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
        assert_eq!(sequential.q_root(), parallel.q_root());
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
        let reference_root = reference.q_root();
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
                ledger.q_root(),
                reference_root,
                "the state root differs at {cores} cores"
            );
        }

        let mut public = base.clone();
        let public_included = execute_ordered(&mut public, &block, &fee, 0);
        assert_eq!(ids(&public_included), ids(&reference_included));
        assert_eq!(public.q_root(), reference_root);
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

    #[test]
    fn a_no_fee_unsigned_evidence_transaction_from_any_sender_slashes_the_offender() {
        use qtv_attest::{Attester, Beacon, Block, Parent};

        let fee = FeeParams::devnet();
        let offender_secret = [9u8; 32];
        let offender = crate::keys::validator_address(&offender_secret);
        let attester = Attester::from_secret(1, &offender_secret, 2_000);
        let offender_pk = attester.attest_public_key().to_vec();

        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(fee.chain_id, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let b = attester.attest(fee.chain_id, 1, 1, 0, [0u8; 32], block_b, &beacon);
        let evidence = crate::evidence::Equivocation {
            offender: offender.clone(),
            height: 1,
            view_a: 0,
            view_b: 0,
            slot_a: 1,
            slot_b: 1,
            committee_a: [0u8; 32],
            committee_b: [0u8; 32],
            block_a: block_a.to_bytes(),
            sig_a: a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: b.sig.to_vec(),
        };

        let mut ledger = Ledger::new();
        ledger.seed_supply(1_000_000_000);
        ledger.seed_validator_bond(&offender, 2_000 * 1_000_000);
        ledger.set_validator_attest_key(&offender, &offender_pk);

        let call = qtv_tx::Call::new(crate::ledger::evidence_address(), evidence.encode());
        let body = Body::with_context(
            crate::ledger::evidence_address(),
            0,
            0,
            0,
            call,
            0,
            fee.chain_id,
        );
        let tx = Wrapper::new(body, qtv_tx::SCHEME_LATTICE, Vec::new());

        assert!(!ledger.is_validator_banned(&offender));
        let included = execute_ordered(&mut ledger, &[tx.clone()], &fee, 0);
        assert_eq!(included.len(), 1, "the zero fee unsigned evidence is included");
        assert!(
            ledger.is_validator_banned(&offender),
            "the offender is slashed though no fee was paid and no sender signed"
        );
        assert_eq!(ledger.staked_weight(&offender), 0, "the offender's stake is slashed");

        let replay = execute_ordered(&mut ledger, &[tx], &fee, 0);
        assert!(
            replay.is_empty(),
            "evidence against an already banned offender is not included again"
        );
    }

    #[test]
    fn a_registration_record_is_included_and_moves_no_account_state() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        ledger.seed_supply(1_000_000_000);
        let holder = derive(&[4u8; 32], 0);
        fund(&mut ledger, &holder, 1_000_000);

        let call = qtv_tx::Call::new(crate::ledger::registration_address(), vec![1, 2, 3, 4]);
        let body = Body::with_context(
            crate::ledger::registration_address(),
            0,
            0,
            0,
            call,
            0,
            fee.chain_id,
        );
        let tx = Wrapper::new(body, qtv_tx::SCHEME_LATTICE, Vec::new());

        let included = execute_ordered(&mut ledger, &[tx], &fee, 0);
        assert_eq!(included.len(), 1, "the registration record rides in the block");
        assert_eq!(ledger.balance(&holder.address()), 1_000_000, "no balance moved");
        assert_eq!(ledger.total_supply(), 1_000_000_000, "no supply moved");
        assert_eq!(
            ledger.account(&crate::ledger::registration_address()),
            Account::default(),
            "the registration record creates no account of its own"
        );
    }

    #[test]
    fn a_bridge_freeze_and_unfreeze_ride_their_system_addresses_and_return_the_bond() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let freezer = keypair(220);
        let start = 2_000_000 * 1_000_000;
        fund(&mut ledger, &freezer, start);
        let charged = fee.transfer_fee();

        let freeze = transfer(&freezer, &crate::ledger::bridge_freeze_address(), 0, 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[freeze], &fee, 0).len(), 1);
        assert!(ledger.bridge_is_frozen(), "the freeze halts the bridge the block it lands");
        assert_eq!(
            ledger.balance(&freezer.address()),
            start - qtv_governance::BRIDGE_FREEZE_BOND - charged,
            "the bond and the fee leave the caller"
        );

        let unfreeze = transfer(&freezer, &crate::ledger::bridge_unfreeze_address(), 0, 1, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[unfreeze], &fee, 0).len(), 1);
        assert!(!ledger.bridge_is_frozen());
        assert_eq!(
            ledger.balance(&freezer.address()),
            start - 2 * charged,
            "the full bond returns and only the two fees are spent"
        );
    }

    fn guardian_act_bytes(
        op: u8,
        bound: u64,
        targets: Vec<[u8; 32]>,
        signers: &[&KeyAccount],
        chain_id: u64,
    ) -> Vec<u8> {
        let template = GuardianAct {
            op,
            bound,
            targets: targets.clone(),
            approvals: Vec::new(),
            payload: Vec::new(),
        };
        let message = guardian_challenge(chain_id, &[0u8; 32], &template);
        let approvals = signers
            .iter()
            .map(|signer| {
                let (_pk, sk) = qtv_crypto::ml_dsa::keygen(signer.seed());
                let signature = qtv_crypto::ml_dsa::sign(&sk, &message, GUARDIAN_DOMAIN, &[0u8; 32])
                    .expect("the guardian challenge stays within the length bound")
                    .to_vec();
                GuardianApproval {
                    scheme: signer.scheme(),
                    public_key: signer.public_key().to_vec(),
                    signature,
                }
            })
            .collect();
        GuardianAct {
            op,
            bound,
            targets,
            approvals,
            payload: Vec::new(),
        }
        .encode()
    }

    #[test]
    fn an_unseeded_guardian_caucus_authorizes_nothing_and_a_seeded_quorum_freezes_and_lifts() {
        let fee = FeeParams::devnet();
        let chain = fee.chain_id;
        let mut ledger = Ledger::new();

        let g1 = keypair(240);
        let g2 = keypair(241);
        let g3 = keypair(242);
        let relayer = keypair(243);
        let target_id = [0x5Au8; 32];
        let target = qtv_idfmt::render_address(&target_id).unwrap();

        let unseeded = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_FREEZE, 0, vec![target_id], &[&g1, &g2], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert_eq!(
            execute_ordered(&mut ledger, &[unseeded], &fee, 0).len(),
            0,
            "with no caucus seeded a fully signed act authorizes nothing"
        );
        assert!(!ledger.is_frozen(&target));

        ledger.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![
                address_bytes(&g1.address()),
                address_bytes(&g2.address()),
                address_bytes(&g3.address()),
            ],
            2,
        ));

        let lone = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_FREEZE, 0, vec![target_id], &[&g1], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert_eq!(
            execute_ordered(&mut ledger, &[lone], &fee, 0).len(),
            0,
            "one guardian falls short of the two threshold"
        );
        assert!(!ledger.is_frozen(&target));

        let freeze = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_FREEZE, 0, vec![target_id], &[&g1, &g2], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert_eq!(execute_ordered(&mut ledger, &[freeze], &fee, 0).len(), 1);
        assert!(ledger.is_frozen(&target), "a quorum freezes the target account");

        let freezer = keypair(244);
        let start = 2_000_000 * 1_000_000;
        fund(&mut ledger, &freezer, start);
        let bond_tx = transfer(&freezer, &crate::ledger::bridge_freeze_address(), 0, 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[bond_tx], &fee, 0).len(), 1);
        assert!(ledger.bridge_is_frozen());
        let until = ledger.bridge_freeze().unwrap().until;
        let treasury_before = ledger.stake_treasury();

        let stale = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_UNFREEZE, until + 1, Vec::new(), &[&g1, &g3], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert_eq!(
            execute_ordered(&mut ledger, &[stale], &fee, 0).len(),
            0,
            "an approval bound to a different freeze horizon is refused"
        );
        assert!(ledger.bridge_is_frozen());

        let lift = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_UNFREEZE, until, Vec::new(), &[&g1, &g3], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert_eq!(execute_ordered(&mut ledger, &[lift], &fee, 0).len(), 1);
        assert!(!ledger.bridge_is_frozen(), "a quorum lifts the bridge freeze early");
        assert_eq!(
            ledger.stake_treasury(),
            treasury_before + qtv_governance::BRIDGE_FREEZE_BOND,
            "a guardian lift slashes the freezer bond to the treasury"
        );
    }

    #[test]
    fn the_mempool_gate_admits_a_signed_quorum_and_rejects_an_unsigned_act() {
        let fee = FeeParams::devnet();
        let chain = fee.chain_id;
        let mut ledger = Ledger::new();
        let g1 = keypair(250);
        let g2 = keypair(251);
        let relayer = keypair(252);
        let target_id = [0x6Bu8; 32];

        let signed = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_FREEZE, 0, vec![target_id], &[&g1, &g2], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert!(
            !guardian_admissible(&ledger, &signed, chain),
            "an unseeded caucus admits nothing"
        );

        ledger.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![address_bytes(&g1.address()), address_bytes(&g2.address()), [9u8; 32]],
            2,
        ));
        assert!(guardian_admissible(&ledger, &signed, chain));

        let unsigned = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_FREEZE, 0, vec![target_id], &[], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert!(
            !guardian_admissible(&ledger, &unsigned, chain),
            "an act carrying no approvals never reaches the threshold"
        );
    }

    #[test]
    fn a_flood_of_approvals_for_one_member_runs_at_most_one_verify() {
        let fee = FeeParams::devnet();
        let chain = fee.chain_id;
        let g1 = keypair(260);
        let set = qtv_governance::GuardianSet::new(
            vec![address_bytes(&g1.address()), [9u8; 32], [8u8; 32]],
            2,
        );

        let approvals = (0..MAX_GUARDIAN_APPROVALS)
            .map(|_| GuardianApproval {
                scheme: g1.scheme(),
                public_key: g1.public_key().to_vec(),
                signature: vec![0u8; qtv_crypto::ml_dsa::SIGNATURE_BYTES],
            })
            .collect();
        let act = GuardianAct {
            op: GUARDIAN_FREEZE,
            bound: 0,
            targets: vec![[0x4Cu8; 32]],
            approvals,
            payload: Vec::new(),
        };

        GUARDIAN_VERIFY_CALLS.with(|c| c.set(0));
        let approvers = guardian_approvers(&set, &act, chain, &[0u8; 32]);
        let calls = GUARDIAN_VERIFY_CALLS.with(|c| c.get());
        assert!(approvers.is_empty(), "garbage signatures authorize no member");
        assert!(calls <= 1, "ran {calls} verifies for a single repeated member id");
    }

    #[test]
    fn the_mempool_gate_refuses_a_guardian_freeze_aimed_at_a_reserved_pot() {
        let fee = FeeParams::devnet();
        let chain = fee.chain_id;
        let mut ledger = Ledger::new();
        let g1 = keypair(270);
        let g2 = keypair(271);
        let relayer = keypair(272);
        ledger.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![address_bytes(&g1.address()), address_bytes(&g2.address()), [9u8; 32]],
            2,
        ));

        let pot_id = address_bytes(&crate::ledger::stake_treasury_address());
        let barred = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_FREEZE, 0, vec![pot_id], &[&g1, &g2], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert!(
            !guardian_admissible(&ledger, &barred, chain),
            "a freeze aimed at a reserved pot is refused at admission"
        );

        let bonded = keypair(273);
        ledger.seed_validator_bond(&bonded.address(), 5_000 * 1_000_000);
        let bonded_id = address_bytes(&bonded.address());
        let onto_bonded = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_FREEZE, 0, vec![bonded_id], &[&g1, &g2], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert!(
            guardian_admissible(&ledger, &onto_bonded, chain),
            "a bonded validator carries no shield and is freezable"
        );

        let plain = system_tx(
            &relayer,
            &crate::ledger::bridge_guardian_address(),
            guardian_act_bytes(GUARDIAN_FREEZE, 0, vec![[0x4Du8; 32]], &[&g1, &g2], chain),
            0,
            TRANSFER_METER,
            &fee,
        );
        assert!(
            guardian_admissible(&ledger, &plain, chain),
            "a freeze aimed at an ordinary account is still admitted"
        );
    }

    #[test]
    fn a_bridge_freeze_auto_expires_across_blocks_and_refunds_the_bond() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let freezer = keypair(221);
        let start = 2_000_000 * 1_000_000;
        fund(&mut ledger, &freezer, start);
        let charged = fee.transfer_fee();

        let freeze = transfer(&freezer, &crate::ledger::bridge_freeze_address(), 0, 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[freeze], &fee, 0).len(), 1);
        assert!(ledger.bridge_is_frozen());

        let horizon_day = qtv_governance::BRIDGE_FREEZE_DURATION / 86_400;
        execute_ordered(&mut ledger, &[], &fee, horizon_day - 1);
        assert!(ledger.bridge_is_frozen(), "the freeze stands before its horizon");

        execute_ordered(&mut ledger, &[], &fee, horizon_day);
        assert!(!ledger.bridge_is_frozen(), "a block at the horizon sweeps the freeze");
        assert_eq!(
            ledger.balance(&freezer.address()),
            start - charged,
            "auto expiry refunds the whole bond"
        );
    }

    #[test]
    fn a_frozen_bridge_rejects_a_call_to_the_registered_gateway_contract() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let deployer = keypair(222);
        let freezer = keypair(223);
        let user = keypair(224);
        fund(&mut ledger, &deployer, 10_000 * 1_000_000);
        fund(&mut ledger, &freezer, 2_000_000 * 1_000_000);
        fund(&mut ledger, &user, 10_000 * 1_000_000);

        let code = qtv_vm::asm::assemble("LDI r1, 0\nMLOAD r0, r1\nLDI r2, 1024\nSSTORE r2, r0\nHALT")
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
                    keyed_reads: vec![],
                    keyed_writes: vec![],
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
        let gateway = crate::ledger::contract_address(&deployer.address(), 0).unwrap();
        ledger.seed_bridge_gateway(&address_bytes(&gateway));

        let open_call = system_tx(&user, &gateway, selector.to_vec(), 0, 100_000, &fee);
        assert_eq!(
            execute_ordered(&mut ledger, &[open_call], &fee, 0).len(),
            1,
            "an open bridge serves gateway calls"
        );

        let freeze = transfer(&freezer, &crate::ledger::bridge_freeze_address(), 0, 0, &fee);
        let frozen_call = system_tx(&user, &gateway, selector.to_vec(), 1, 100_000, &fee);
        let included = execute_ordered(&mut ledger, &[freeze, frozen_call], &fee, 0);
        assert_eq!(
            included.len(),
            1,
            "the freeze rides but the gateway call is halted in the same block"
        );
        assert!(ledger.bridge_is_frozen());
        assert_eq!(ledger.account(&user.address()).nonce, 1, "the halted call never advanced the caller");
    }

    const BRIDGE_DEST: u32 = 9000;
    type OperatorSecret = [u8; qtv_crypto::ml_dsa::SECRET_KEY_BYTES];

    fn bridge_operator(index: u64) -> ([u8; qtv_crypto::ml_dsa::PUBLIC_KEY_BYTES], OperatorSecret) {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&index.to_le_bytes());
        qtv_crypto::ml_dsa::keygen(&seed)
    }

    const BRIDGE_CHAIN_ID: u64 = qtv_tx::LOCAL_CHAIN_ID;

    fn attest_for(sk: &OperatorSecret, fact: &crate::bridge::Fact, chain_id: u64) -> Vec<u8> {
        qtv_crypto::ml_dsa::sign(sk, &fact.attest_preimage(chain_id), &crate::bridge::attest_context(&[0u8; 32]), &[0u8; 32])
            .expect("the fact preimage stays within the length bound")
            .to_vec()
    }

    fn attest(sk: &OperatorSecret, fact: &crate::bridge::Fact) -> Vec<u8> {
        attest_for(sk, fact, BRIDGE_CHAIN_ID)
    }

    const BRIDGE_VAULT: [u8; 32] = [0x5b; 32];

    fn seed_committee(ledger: &mut Ledger) -> (OperatorSecret, OperatorSecret) {
        let (pk0, sk0) = bridge_operator(1);
        let (pk1, sk1) = bridge_operator(2);
        let (pk2, _sk2) = bridge_operator(3);
        ledger.seed_bridge_dest_chain(BRIDGE_DEST);
        ledger.seed_bridge_pool_vault(&BRIDGE_VAULT);
        ledger.seed_bridge_operator_set(&crate::bridge::OperatorSet::new(
            vec![(0, pk0.to_vec()), (1, pk1.to_vec()), (2, pk2.to_vec())],
            2,
        ));
        (sk0, sk1)
    }

    fn deposit_fact(recipient: [u8; 32], asset_id: [u8; 16], amount: u128, source_ref: [u8; 32]) -> crate::bridge::Fact {
        crate::bridge::Fact {
            version: crate::bridge::FACT_VERSION,
            source_chain: 1,
            dest_chain: BRIDGE_DEST,
            route_id: 7,
            direction: crate::bridge::Direction::Deposit,
            nonce: 1,
            source_ref,
            asset_id,
            amount,
            recipient,
            finality_depth: 6,
            observed_height: 10,
            expiry_height: 100,
        }
    }

    fn signed_artifact(fact: &crate::bridge::Fact, sk0: &OperatorSecret, sk1: &OperatorSecret) -> crate::bridge::MintArtifact {
        crate::bridge::MintArtifact {
            attestation: crate::bridge::Attestation {
                fact: fact.clone(),
                signatures: vec![
                    crate::bridge::SignerSig { operator_id: 0, signature: attest(sk0, fact) },
                    crate::bridge::SignerSig { operator_id: 1, signature: attest(sk1, fact) },
                ],
            },
            stark: None,
        }
    }

    fn mint_tx(relayer: &KeyAccount, artifact: &crate::bridge::MintArtifact, fee: &FeeParams) -> Wrapper {
        system_tx(relayer, &crate::ledger::bridge_mint_address(), artifact.encode(), 0, TRANSFER_METER, fee)
    }

    #[test]
    fn a_single_signer_committee_is_refused_at_seed_and_cannot_mint() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let asset = [7u8; 16];
        ledger.seed_bridge_dest_chain(BRIDGE_DEST);
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);

        let (pk0, sk0) = bridge_operator(1);
        let seeded = ledger
            .seed_bridge_operator_set(&crate::bridge::OperatorSet::new(vec![(0, pk0.to_vec())], 1));
        assert!(seeded.is_none(), "a threshold one operator set is refused at the seed");
        assert!(
            ledger.bridge_operator_set().is_none(),
            "the refused threshold one set left the bridge without a committee"
        );

        let relayer = keypair(450);
        let recipient_id = address_bytes(&keypair(451).address());
        let lone_fact = deposit_fact(recipient_id, asset, 100_000, [0x71; 32]);
        let lone_signature = crate::bridge::MintArtifact {
            attestation: crate::bridge::Attestation {
                fact: lone_fact.clone(),
                signatures: vec![crate::bridge::SignerSig {
                    operator_id: 0,
                    signature: attest(&sk0, &lone_fact),
                }],
            },
            stark: None,
        };
        assert!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &lone_signature, &fee)], &fee, 0)
                .is_empty(),
            "with no committee seated, a single signature mints nothing"
        );
        assert_eq!(ledger.bridged_supply(&asset), 0, "the refused mint moved no supply");

        let (sk0, sk1) = seed_committee(&mut ledger);
        assert_eq!(
            ledger.bridge_operator_set().map(|set| set.threshold),
            Some(2),
            "a two of n committee seats normally"
        );
        let fresh = deposit_fact(recipient_id, asset, 100_000, [0x72; 32]);
        assert_eq!(
            execute_ordered(
                &mut ledger,
                &[mint_tx(&relayer, &signed_artifact(&fresh, &sk0, &sk1), &fee)],
                &fee,
                0,
            )
            .len(),
            1,
            "a two of n committee still mints"
        );
        assert_eq!(ledger.bridged_supply(&asset), 100_000);
    }

    #[test]
    fn a_mint_past_its_signed_expiry_height_is_refused() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(700);
        let recipient_id = address_bytes(&keypair(701).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 10_000_000, 10_000_000, false);

        let stale = deposit_fact(recipient_id, asset, 100_000, [0x81; 32]);
        assert_eq!(stale.expiry_height, 100, "the fixture stamps a signed expiry height");

        ledger.set_execution_height(101);
        assert!(
            execute_ordered(
                &mut ledger,
                &[mint_tx(&relayer, &signed_artifact(&stale, &sk0, &sk1), &fee)],
                &fee,
                0,
            )
            .is_empty(),
            "a fact past its signed expiry height mints nothing"
        );
        assert_eq!(ledger.bridged_supply(&asset), 0, "the stale mint moved no supply");
        assert!(
            !ledger.bridge_reference_seen(1, &[0x81; 32]),
            "the refused stale mint left its source reference unseen for a timely retry"
        );

        ledger.set_execution_height(100);
        let fresh = deposit_fact(recipient_id, asset, 100_000, [0x82; 32]);
        assert_eq!(
            execute_ordered(
                &mut ledger,
                &[mint_tx(&relayer, &signed_artifact(&fresh, &sk0, &sk1), &fee)],
                &fee,
                0,
            )
            .len(),
            1,
            "a fact at or before its signed expiry height still mints"
        );
        assert_eq!(ledger.bridged_supply(&asset), 100_000, "the timely mint credited the amount");
    }

    #[test]
    fn a_verified_attestation_mints_the_exact_amount_to_the_recipient() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(400);
        let recipient = keypair(401);
        let recipient_id = address_bytes(&recipient.address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);

        let fact = deposit_fact(recipient_id, asset, 500_000, [0x11; 32]);
        let artifact = signed_artifact(&fact, &sk0, &sk1);
        let included = execute_ordered(&mut ledger, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0);

        assert_eq!(included.len(), 1, "the verified mint rides in the block");
        assert_eq!(ledger.bridged_balance(&asset, &recipient_id), 500_000, "the recipient holds the attested amount");
        assert_eq!(ledger.bridged_supply(&asset), 500_000, "the bridged supply rose by the attested amount");
        assert!(ledger.bridge_reference_seen(1, &[0x11; 32]), "the deposit reference is marked against replay");
    }

    #[test]
    fn a_quorum_signed_for_a_sibling_chain_id_does_not_mint() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(410);
        let recipient_id = address_bytes(&keypair(411).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);

        let sibling = BRIDGE_CHAIN_ID ^ (1u64 << 40);
        assert_eq!(sibling as u32, BRIDGE_CHAIN_ID as u32, "the sibling shares the low 32 bits");
        let fact = deposit_fact(recipient_id, asset, 500_000, [0x12; 32]);
        let artifact = crate::bridge::MintArtifact {
            attestation: crate::bridge::Attestation {
                fact: fact.clone(),
                signatures: vec![
                    crate::bridge::SignerSig { operator_id: 0, signature: attest_for(&sk0, &fact, sibling) },
                    crate::bridge::SignerSig { operator_id: 1, signature: attest_for(&sk1, &fact, sibling) },
                ],
            },
            stark: None,
        };
        let included = execute_ordered(&mut ledger, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0);
        assert!(included.is_empty(), "a quorum signed for a sibling chain id never mints here");
        assert_eq!(ledger.bridged_supply(&asset), 0);
        assert!(!ledger.bridge_reference_seen(1, &[0x12; 32]), "the refused mint leaves the reference unseen");
    }

    #[test]
    fn a_replayed_deposit_reference_is_refused() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(402);
        let recipient_id = address_bytes(&keypair(403).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);

        let fact = deposit_fact(recipient_id, asset, 400_000, [0x22; 32]);
        let artifact = signed_artifact(&fact, &sk0, &sk1);
        assert_eq!(execute_ordered(&mut ledger, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0).len(), 1);
        assert_eq!(ledger.bridged_supply(&asset), 400_000);

        let replay = execute_ordered(&mut ledger, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0);
        assert!(replay.is_empty(), "the same deposit reference never mints twice");
        assert_eq!(ledger.bridged_supply(&asset), 400_000, "the replay moved no supply");
        assert_eq!(ledger.bridged_balance(&asset, &recipient_id), 400_000);
    }

    #[test]
    fn a_flood_of_replayed_or_duplicate_mints_runs_no_quorum_verify() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let recipient_id = address_bytes(&keypair(431).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);

        let resident_fact = deposit_fact(recipient_id, asset, 100_000, [0x61; 32]);
        let resident = signed_artifact(&resident_fact, &sk0, &sk1);
        let mut pool = crate::mempool::Mempool::new();
        assert_eq!(
            pool.admit(mint_tx(&keypair(430), &resident, &fee), &ledger, &fee),
            Ok(crate::mempool::Admitted::Fresh)
        );

        crate::bridge::VERIFY_CALLS.with(|c| c.set(0));
        for i in 0..128u64 {
            let dup = mint_tx(&keypair(600 + i), &resident, &fee);
            assert_eq!(
                pool.admit(dup, &ledger, &fee),
                Ok(crate::mempool::Admitted::Known)
            );
        }
        assert_eq!(
            crate::bridge::VERIFY_CALLS.with(|c| c.get()),
            0,
            "a duplicate mint runs no quorum verify"
        );

        let seen_fact = deposit_fact(recipient_id, asset, 100_000, [0x62; 32]);
        assert!(ledger.bridge_mint(&seen_fact));
        let replayed = signed_artifact(&seen_fact, &sk0, &sk1);
        crate::bridge::VERIFY_CALLS.with(|c| c.set(0));
        for i in 0..128u64 {
            let tx = mint_tx(&keypair(800 + i), &replayed, &fee);
            assert_eq!(
                pool.admit(tx, &ledger, &fee),
                Err(crate::mempool::Reject::BadCall)
            );
        }
        assert_eq!(
            crate::bridge::VERIFY_CALLS.with(|c| c.get()),
            0,
            "a replayed mint runs no quorum verify"
        );
    }

    #[test]
    fn a_single_sender_mint_flood_is_rate_limited_before_the_quorum() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let recipient_id = address_bytes(&keypair(441).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, u128::MAX, u128::MAX, false);

        let relayer = keypair(440);
        let mut pool = crate::mempool::Mempool::new();
        crate::bridge::VERIFY_CALLS.with(|c| c.set(0));
        let mut rate_limited = 0usize;
        for i in 0..256u64 {
            let mut source_ref = [0u8; 32];
            source_ref[..8].copy_from_slice(&i.to_le_bytes());
            let fact = deposit_fact(recipient_id, asset, 1, source_ref);
            let artifact = signed_artifact(&fact, &sk0, &sk1);
            if pool.admit(mint_tx(&relayer, &artifact, &fee), &ledger, &fee)
                == Err(crate::mempool::Reject::RateLimited)
            {
                rate_limited += 1;
            }
        }
        assert!(rate_limited > 0, "a single sender flood is eventually rate limited");
        let verifies = crate::bridge::VERIFY_CALLS.with(|c| c.get());
        assert!(
            verifies <= crate::mempool::DEFAULT_FEELESS_ADMITS_PER_WINDOW * 2,
            "a single sender drives at most the capped number of quorum verifies, ran {verifies}"
        );
    }

    fn corrupt_artifact(fact: &crate::bridge::Fact, sk0: &OperatorSecret, sk1: &OperatorSecret) -> crate::bridge::MintArtifact {
        let mut artifact = signed_artifact(fact, sk0, sk1);
        artifact.attestation.signatures[0].signature[0] ^= 0xFF;
        artifact.attestation.signatures[1].signature[0] ^= 0xFF;
        artifact
    }

    #[test]
    fn a_spoofed_feeless_flood_cannot_starve_a_relayers_own_mints() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(460);
        let recipient_id = address_bytes(&keypair(461).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, u128::MAX, u128::MAX, false);

        let seen_fact = deposit_fact(recipient_id, asset, 1, [0xA1; 32]);
        assert!(ledger.bridge_mint(&seen_fact));
        let replayed = signed_artifact(&seen_fact, &sk0, &sk1);

        let mut seen_pool = crate::mempool::Mempool::new();
        crate::bridge::VERIFY_CALLS.with(|c| c.set(0));
        for _ in 0..(crate::mempool::DEFAULT_FEELESS_ADMITS_PER_WINDOW + 8) {
            assert_eq!(
                seen_pool.admit(mint_tx(&relayer, &replayed, &fee), &ledger, &fee),
                Err(crate::mempool::Reject::BadCall)
            );
        }
        assert_eq!(
            crate::bridge::VERIFY_CALLS.with(|c| c.get()),
            0,
            "a flood of already-seen replays runs no quorum verify and spends no feeless budget"
        );

        let genuine = signed_artifact(&deposit_fact(recipient_id, asset, 1, [0xA2; 32]), &sk0, &sk1);
        assert_eq!(
            seen_pool.admit(mint_tx(&relayer, &genuine, &fee), &ledger, &fee),
            Ok(crate::mempool::Admitted::Fresh),
            "a genuine mint still admits after a seen replay flood that spent no budget"
        );

        let mut spoof_pool = crate::mempool::Mempool::new();
        for i in 0..(crate::mempool::DEFAULT_FEELESS_ADMITS_PER_WINDOW / 2) as u64 {
            let mut source_ref = [0u8; 32];
            source_ref[..8].copy_from_slice(&i.to_le_bytes());
            let junk = corrupt_artifact(&deposit_fact(recipient_id, asset, 1, source_ref), &sk0, &sk1);
            assert_eq!(
                spoof_pool.admit(mint_tx(&relayer, &junk, &fee), &ledger, &fee),
                Err(crate::mempool::Reject::BadCall)
            );
        }
        let own = signed_artifact(&deposit_fact(recipient_id, asset, 1, [0xB9; 32]), &sk0, &sk1);
        assert_eq!(
            spoof_pool.admit(mint_tx(&relayer, &own, &fee), &ledger, &fee),
            Ok(crate::mempool::Admitted::Fresh),
            "junk spoofing the relayer's address cannot starve the relayer within the global window"
        );
    }

    #[test]
    fn an_over_asset_cap_mint_is_refused() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(404);
        let recipient_id = address_bytes(&keypair(405).address());
        let asset = [8u8; 16];
        ledger.register_bridged_asset(&asset, 400_000, 1_000_000, false);

        let fact = deposit_fact(recipient_id, asset, 500_000, [0x33; 32]);
        let artifact = signed_artifact(&fact, &sk0, &sk1);
        let included = execute_ordered(&mut ledger, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0);

        assert!(included.is_empty(), "a mint over the total cap is refused");
        assert_eq!(ledger.bridged_supply(&asset), 0, "no supply was minted over the cap");
        assert_eq!(ledger.bridged_balance(&asset, &recipient_id), 0);
        assert!(!ledger.bridge_reference_seen(1, &[0x33; 32]), "a refused mint leaves the reference unseen");
    }

    #[test]
    fn an_unset_bridge_dest_chain_refuses_a_mint_until_it_is_bound() {
        let fee = FeeParams::devnet();
        let relayer = keypair(450);
        let recipient_id = address_bytes(&keypair(451).address());
        let asset = [7u8; 16];

        let (pk0, sk0) = bridge_operator(1);
        let (pk1, sk1) = bridge_operator(2);
        let mut unset = Ledger::new();
        unset.seed_bridge_operator_set(&crate::bridge::OperatorSet::new(
            vec![(0, pk0.to_vec()), (1, pk1.to_vec())],
            2,
        ));
        unset.seed_bridge_pool_vault(&BRIDGE_VAULT);
        unset.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);
        let fact = deposit_fact(recipient_id, asset, 100_000, [0x71; 32]);
        let artifact = crate::bridge::MintArtifact {
            attestation: crate::bridge::Attestation {
                fact: fact.clone(),
                signatures: vec![
                    crate::bridge::SignerSig { operator_id: 0, signature: attest(&sk0, &fact) },
                    crate::bridge::SignerSig { operator_id: 1, signature: attest(&sk1, &fact) },
                ],
            },
            stark: None,
        };

        assert!(unset.bridge_dest_chain().is_none());
        assert!(!bridge_mint_admissible(&unset, &mint_tx(&relayer, &artifact, &fee), BRIDGE_CHAIN_ID));
        assert!(execute_ordered(&mut unset, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0).is_empty());
        assert_eq!(unset.bridged_supply(&asset), 0, "an unbound destination chain mints nothing");

        let mut bound = unset.clone();
        bound.seed_bridge_dest_chain(BRIDGE_DEST);
        assert_eq!(bound.bridge_dest_chain(), Some(BRIDGE_DEST));
        assert!(bridge_mint_admissible(&bound, &mint_tx(&relayer, &artifact, &fee), BRIDGE_CHAIN_ID));
        assert_eq!(execute_ordered(&mut bound, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0).len(), 1);
        assert_eq!(bound.bridged_balance(&asset, &recipient_id), 100_000, "the bound destination chain binds the mint");
    }

    #[test]
    fn an_over_epoch_cap_mint_is_refused_across_two_deposits() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(406);
        let recipient_id = address_bytes(&keypair(407).address());
        let asset = [9u8; 16];
        ledger.register_bridged_asset(&asset, 10_000_000, 500_000, false);

        let first = deposit_fact(recipient_id, asset, 300_000, [0x44; 32]);
        assert_eq!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&first, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );

        let second = deposit_fact(recipient_id, asset, 300_000, [0x45; 32]);
        let included = execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&second, &sk0, &sk1), &fee)], &fee, 0);
        assert!(included.is_empty(), "the second deposit crosses the epoch cap and is refused");
        assert_eq!(ledger.bridged_supply(&asset), 300_000, "only the first deposit minted this epoch");

        ledger.set_bridge_epoch(1);
        let third = execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&second, &sk0, &sk1), &fee)], &fee, 0);
        assert_eq!(third.len(), 1, "the next epoch admits the deposit again");
        assert_eq!(ledger.bridged_supply(&asset), 600_000);
    }

    #[test]
    fn a_tampered_attestation_does_not_mint() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(408);
        let recipient_id = address_bytes(&keypair(409).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);

        let fact = deposit_fact(recipient_id, asset, 500_000, [0x55; 32]);
        let mut artifact = signed_artifact(&fact, &sk0, &sk1);
        artifact.attestation.fact.amount = 900_000;
        let included = execute_ordered(&mut ledger, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0);

        assert!(included.is_empty(), "a fact changed after signing does not attest and does not mint");
        assert_eq!(ledger.bridged_supply(&asset), 0);
    }

    #[test]
    fn a_wrong_key_quorum_does_not_mint() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (_sk0, _sk1) = seed_committee(&mut ledger);
        let relayer = keypair(410);
        let recipient_id = address_bytes(&keypair(411).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);

        let (_pkx, skx) = bridge_operator(90);
        let (_pky, sky) = bridge_operator(91);
        let fact = deposit_fact(recipient_id, asset, 500_000, [0x56; 32]);
        let artifact = crate::bridge::MintArtifact {
            attestation: crate::bridge::Attestation {
                fact: fact.clone(),
                signatures: vec![
                    crate::bridge::SignerSig { operator_id: 0, signature: attest(&skx, &fact) },
                    crate::bridge::SignerSig { operator_id: 1, signature: attest(&sky, &fact) },
                ],
            },
            stark: None,
        };
        let included = execute_ordered(&mut ledger, &[mint_tx(&relayer, &artifact, &fee)], &fee, 0);

        assert!(included.is_empty(), "signatures from keys off the committee never mint");
        assert_eq!(ledger.bridged_supply(&asset), 0);
    }

    #[test]
    fn a_holder_exit_burns_the_bridged_amount() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(412);
        let holder = keypair(413);
        let holder_id = address_bytes(&holder.address());
        let start = 10_000 * 1_000_000;
        fund(&mut ledger, &holder, start);
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);
        ledger.seed_bridge_exits_enabled(true);

        let fact = deposit_fact(holder_id, asset, 500_000, [0x66; 32]);
        assert_eq!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&fact, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );
        assert_eq!(ledger.bridged_balance(&asset, &holder_id), 500_000);

        let request = crate::bridge::ExitRequest { asset_id: asset, amount: 200_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);
        let included = execute_ordered(&mut ledger, &[exit], &fee, 0);

        assert_eq!(included.len(), 1, "the holder's exit rides in the block");
        assert_eq!(ledger.bridged_balance(&asset, &holder_id), 300_000, "the burn debited the exit amount");
        assert_eq!(ledger.bridged_supply(&asset), 300_000, "the exit lowered the bridged supply");
        assert_eq!(ledger.balance(&holder.address()), start - fee.transfer_fee(), "the holder paid one fee");
    }

    #[test]
    fn an_exit_is_refused_until_exits_are_enabled() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(460);
        let holder = keypair(461);
        let holder_id = address_bytes(&holder.address());
        let start = 10_000 * 1_000_000;
        fund(&mut ledger, &holder, start);
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);

        let fact = deposit_fact(holder_id, asset, 500_000, [0x99; 32]);
        assert_eq!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&fact, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );
        assert!(!ledger.bridge_exits_enabled(), "exits are closed by default");

        let request = crate::bridge::ExitRequest { asset_id: asset, amount: 200_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);

        let mut pool = crate::mempool::Mempool::new();
        assert!(pool.admit(exit.clone(), &ledger, &fee).is_err(), "a disabled exit is refused at admission");

        let refused = execute_ordered(&mut ledger, &[exit.clone()], &fee, 0);
        assert!(refused.is_empty(), "a disabled exit is not included");
        assert_eq!(ledger.bridged_balance(&asset, &holder_id), 500_000, "the disabled exit burned nothing");
        assert_eq!(ledger.bridged_supply(&asset), 500_000, "the disabled exit moved no supply");
        assert_eq!(ledger.balance(&holder.address()), start, "the disabled exit charged no fee");
        assert_eq!(ledger.account(&holder.address()).nonce, 0, "the disabled exit bumped no nonce");

        ledger.seed_bridge_exits_enabled(true);
        let included = execute_ordered(&mut ledger, &[exit], &fee, 0);
        assert_eq!(included.len(), 1, "the exit rides once exits are enabled");
        assert_eq!(ledger.bridged_balance(&asset, &holder_id), 300_000, "the enabled exit debited the amount");
        assert_eq!(ledger.balance(&holder.address()), start - fee.transfer_fee(), "the enabled exit charged one fee");
        assert_eq!(ledger.account(&holder.address()).nonce, 1, "the enabled exit bumped the nonce");
    }

    #[test]
    fn a_frozen_bridge_refuses_mint_and_exit() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(414);
        let holder = keypair(415);
        let holder_id = address_bytes(&holder.address());
        let start = 10_000 * 1_000_000;
        fund(&mut ledger, &holder, start);
        let freezer = keypair(416);
        fund(&mut ledger, &freezer, 2_000_000 * 1_000_000);
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);
        ledger.seed_bridge_exits_enabled(true);

        let seeded = deposit_fact(holder_id, asset, 500_000, [0x77; 32]);
        assert_eq!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&seeded, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );

        let freeze = transfer(&freezer, &crate::ledger::bridge_freeze_address(), 0, 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[freeze], &fee, 0).len(), 1);
        assert!(ledger.bridge_is_frozen());

        let fresh = deposit_fact(holder_id, asset, 100_000, [0x78; 32]);
        let frozen_mint = execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&fresh, &sk0, &sk1), &fee)], &fee, 0);
        assert!(frozen_mint.is_empty(), "a frozen bridge refuses a mint");
        assert_eq!(ledger.bridged_supply(&asset), 500_000, "the frozen mint moved no supply");

        let request = crate::bridge::ExitRequest { asset_id: asset, amount: 100_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);
        let frozen_exit = execute_ordered(&mut ledger, &[exit], &fee, 0);
        assert!(frozen_exit.is_empty(), "a frozen bridge refuses an exit");
        assert_eq!(ledger.bridged_balance(&asset, &holder_id), 500_000, "the frozen exit burned nothing");
        assert_eq!(ledger.balance(&holder.address()), start, "the frozen exit charged no fee");
    }

    #[test]
    fn a_frozen_bridge_refuses_an_exit_at_admission() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(470);
        let holder = keypair(471);
        let holder_id = address_bytes(&holder.address());
        let freezer = keypair(472);
        let start = 10_000 * 1_000_000;
        fund(&mut ledger, &holder, start);
        fund(&mut ledger, &freezer, 2_000_000 * 1_000_000);
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);
        ledger.seed_bridge_exits_enabled(true);

        let fact = deposit_fact(holder_id, asset, 500_000, [0xAB; 32]);
        assert_eq!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&fact, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );

        let request = crate::bridge::ExitRequest { asset_id: asset, amount: 200_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);

        let mut open_pool = crate::mempool::Mempool::new();
        assert!(open_pool.admit(exit.clone(), &ledger, &fee).is_ok(), "an unfrozen exit is admitted");

        let freeze = transfer(&freezer, &crate::ledger::bridge_freeze_address(), 0, 0, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[freeze], &fee, 0).len(), 1);
        assert!(ledger.bridge_is_frozen());

        let mut frozen_pool = crate::mempool::Mempool::new();
        assert!(frozen_pool.admit(exit, &ledger, &fee).is_err(), "a frozen exit is refused at admission");
    }

    #[test]
    fn a_stark_bound_mint_admits_only_a_bound_envelope() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(450);
        let recipient_id = address_bytes(&keypair(451).address());
        let asset = [0x5A; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, true);

        let absent = deposit_fact(recipient_id, asset, 100_000, [0xD1; 32]);
        let mut a = signed_artifact(&absent, &sk0, &sk1);
        a.stark = None;
        assert!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &a, &fee)], &fee, 0).is_empty(),
            "a stark-bound asset refuses a mint with no STARK envelope"
        );

        let unbound = deposit_fact(recipient_id, asset, 100_000, [0xD2; 32]);
        let mut u = signed_artifact(&unbound, &sk0, &sk1);
        u.stark = Some(crate::bridge::StarkEnvelope { statement_digest: [0u8; 32], proof: vec![] });
        assert!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &u, &fee)], &fee, 0).is_empty(),
            "a stark-bound asset refuses an unbound STARK envelope"
        );
        assert_eq!(ledger.bridged_supply(&asset), 0, "no unbound mint moved supply");

        let bound = deposit_fact(recipient_id, asset, 100_000, [0xD3; 32]);
        let mut b = signed_artifact(&bound, &sk0, &sk1);
        b.stark = Some(crate::bridge::StarkEnvelope {
            statement_digest: bound.statement_digest(0),
            proof: vec![1u8; 32],
        });
        assert_eq!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &b, &fee)], &fee, 0).len(),
            1,
            "a stark-bound asset mints on a correctly bound STARK envelope"
        );
        assert_eq!(ledger.bridged_balance(&asset, &recipient_id), 100_000);
    }

    #[test]
    fn two_mints_of_one_deposit_from_different_senders_take_one_slot() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer_a = keypair(440);
        let relayer_b = keypair(441);
        let recipient_id = address_bytes(&keypair(442).address());
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);
        let fact = deposit_fact(recipient_id, asset, 500_000, [0xC1; 32]);
        let artifact = signed_artifact(&fact, &sk0, &sk1);

        let mut pool = crate::mempool::Mempool::new();
        assert!(pool.admit(mint_tx(&relayer_a, &artifact, &fee), &ledger, &fee).is_ok());
        assert!(pool.admit(mint_tx(&relayer_b, &artifact, &fee), &ledger, &fee).is_ok());
        assert_eq!(pool.len(), 1, "one deposit reference occupies at most one mempool slot");
    }

    #[test]
    fn an_oversized_mint_artifact_is_refused_at_admission() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);
        let relayer = keypair(443);
        let recipient_id = address_bytes(&keypair(444).address());

        let small = deposit_fact(recipient_id, asset, 500_000, [0xC2; 32]);
        let mut small_artifact = signed_artifact(&small, &sk0, &sk1);
        small_artifact.stark = Some(crate::bridge::StarkEnvelope {
            statement_digest: small.statement_digest(0),
            proof: vec![0u8; 1024],
        });
        let mut pool = crate::mempool::Mempool::new();
        assert!(
            pool.admit(mint_tx(&relayer, &small_artifact, &fee), &ledger, &fee).is_ok(),
            "a normally sized artifact is admitted"
        );

        let big = deposit_fact(recipient_id, asset, 500_000, [0xC3; 32]);
        let mut big_artifact = signed_artifact(&big, &sk0, &sk1);
        big_artifact.stark = Some(crate::bridge::StarkEnvelope {
            statement_digest: big.statement_digest(0),
            proof: vec![0u8; 2 * 1024 * 1024],
        });
        assert!(
            pool.admit(mint_tx(&relayer, &big_artifact, &fee), &ledger, &fee).is_err(),
            "an oversized mint artifact is refused"
        );
        assert_eq!(pool.len(), 1, "only the normally sized artifact took a slot");
    }

    #[test]
    fn an_over_balance_exit_charges_no_fee_and_bumps_no_nonce() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        let relayer = keypair(430);
        let holder = keypair(431);
        let holder_id = address_bytes(&holder.address());
        let start = 10_000 * 1_000_000;
        fund(&mut ledger, &holder, start);
        let asset = [7u8; 16];
        ledger.register_bridged_asset(&asset, 1_000_000, 1_000_000, false);
        ledger.seed_bridge_exits_enabled(true);

        let fact = deposit_fact(holder_id, asset, 500_000, [0xB1; 32]);
        assert_eq!(
            execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&fact, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );
        assert_eq!(ledger.bridged_balance(&asset, &holder_id), 500_000);

        let request = crate::bridge::ExitRequest { asset_id: asset, amount: 600_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);
        let included = execute_ordered(&mut ledger, &[exit], &fee, 0);

        assert!(included.is_empty(), "an exit over the holder's bridged balance is not included");
        assert_eq!(ledger.balance(&holder.address()), start, "the failed exit charged no fee");
        assert_eq!(ledger.account(&holder.address()).nonce, 0, "the failed exit bumped no nonce");
        assert_eq!(ledger.bridged_balance(&asset, &holder_id), 500_000, "the failed exit burned nothing");
    }

    #[test]
    fn parallel_and_ordered_agree_on_a_bridge_block_across_a_freeze_horizon() {
        let fee = FeeParams::devnet();
        let mut base = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut base);
        let relayer = keypair(420);
        let holder = keypair(421);
        let holder_id = address_bytes(&holder.address());
        let freezer = keypair(422);
        let other = keypair(423);
        let start = 10_000 * 1_000_000;
        fund(&mut base, &holder, start);
        fund(&mut base, &freezer, 2_000_000 * 1_000_000);
        fund(&mut base, &other, start);
        let asset = [7u8; 16];
        base.register_bridged_asset(&asset, 10_000_000, 10_000_000, false);
        base.seed_bridge_exits_enabled(true);

        let seed = deposit_fact(holder_id, asset, 1_000_000, [0xA1; 32]);
        assert_eq!(
            execute_ordered(&mut base, &[mint_tx(&relayer, &signed_artifact(&seed, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );
        let freeze = transfer(&freezer, &crate::ledger::bridge_freeze_address(), 0, 0, &fee);
        assert_eq!(execute_ordered(&mut base, &[freeze], &fee, 0).len(), 1);
        assert!(base.bridge_is_frozen());

        let horizon_day = qtv_governance::BRIDGE_FREEZE_DURATION / 86_400;
        let fresh = deposit_fact(holder_id, asset, 500_000, [0xA2; 32]);
        let mint = mint_tx(&relayer, &signed_artifact(&fresh, &sk0, &sk1), &fee);
        let request = crate::bridge::ExitRequest { asset_id: asset, amount: 400_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);
        let payment = transfer(&other, &keypair(424).address(), 1_000, 0, &fee);
        let block = vec![mint, exit, payment];

        let mut ordered = base.clone();
        execute_ordered(&mut ordered, &block, &fee, horizon_day);

        let mut parallel = base.clone();
        crate::parallel::execute_parallel(&mut parallel, &block, &fee, 4, horizon_day);

        assert_eq!(
            ordered.q_root(),
            parallel.q_root(),
            "the parallel and ordered paths diverge on a bridge mint/exit block crossing a freeze horizon"
        );
        assert!(!parallel.bridge_is_frozen(), "the freeze auto expired on the parallel path");
        assert_eq!(
            parallel.bridged_supply(&asset),
            1_100_000,
            "the mint and exit both applied on the parallel path"
        );
    }

    const EXIT_VAULT: [u8; 32] = [0x5b; 32];
    const EXIT_ASSET: [u8; 16] = [0x7c; 16];

    fn exit_fact(
        outcome: crate::bridge::ExitOutcome,
        amount: u128,
        beneficiary: [u8; 32],
        burn_ref: [u8; 32],
    ) -> crate::bridge::ExitFact {
        crate::bridge::ExitFact {
            version: crate::bridge::EXIT_FACT_VERSION,
            corridor: 1,
            dest_chain: BRIDGE_DEST,
            asset_id: EXIT_ASSET,
            amount,
            beneficiary,
            burn_ref,
            outcome,
        }
    }

    fn attest_exit(sk: &OperatorSecret, fact: &crate::bridge::ExitFact, chain_id: u64) -> Vec<u8> {
        qtv_crypto::ml_dsa::sign(sk, &fact.ack_preimage(chain_id), &crate::bridge::exit_ack_context(&[0u8; 32]), &[0u8; 32])
            .expect("the exit preimage stays within the length bound")
            .to_vec()
    }

    fn signed_exit(
        fact: &crate::bridge::ExitFact,
        sk0: &OperatorSecret,
        sk1: &OperatorSecret,
    ) -> crate::bridge::ExitAttestation {
        crate::bridge::ExitAttestation {
            fact: fact.clone(),
            signatures: vec![
                crate::bridge::SignerSig { operator_id: 0, signature: attest_exit(sk0, fact, BRIDGE_CHAIN_ID) },
                crate::bridge::SignerSig { operator_id: 1, signature: attest_exit(sk1, fact, BRIDGE_CHAIN_ID) },
            ],
        }
    }

    fn settle_tx(relayer: &KeyAccount, attestation: &crate::bridge::ExitAttestation, fee: &FeeParams) -> Wrapper {
        system_tx(relayer, &crate::ledger::bridge_settle_address(), attestation.encode(), 0, TRANSFER_METER, fee)
    }

    #[allow(clippy::too_many_arguments)]
    fn seed_exit_bridge(
        ledger: &mut Ledger,
        custody: u128,
        cap: u128,
        epoch_cap: u128,
        payout_cap: u128,
    ) -> (OperatorSecret, OperatorSecret) {
        let (sk0, sk1) = seed_committee(ledger);
        ledger.register_bridged_asset(&EXIT_ASSET, cap, epoch_cap, false);
        ledger.seed_bridge_exits_enabled(true);
        ledger.seed_bridge_pool_vault(&EXIT_VAULT);
        ledger.seed_bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET, custody);
        ledger.seed_bridge_payout_cap(payout_cap);
        (sk0, sk1)
    }

    fn last_burn_ref(ledger: &Ledger) -> [u8; 32] {
        ledger
            .block_events()
            .iter()
            .rev()
            .find(|event| event.selector == crate::ledger::EVENT_BRIDGE_BURN)
            .and_then(|event| crate::ledger::bridge_burn_leaf_ref(&event.data))
            .expect("a burn event is present")
    }

    #[test]
    fn a_verified_slash_pays_the_beneficiary_from_the_pool_custody() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut ledger, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(500);
        let beneficiary = [0x55u8; 32];
        let burn_ref = [0x11u8; 32];
        ledger.seed_outstanding_burn(&burn_ref, &EXIT_ASSET, 550_000, &beneficiary);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, beneficiary, burn_ref);
        let attestation = signed_exit(&fact, &sk0, &sk1);

        let included = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(included.len(), 1, "the verified slash rides in the block");
        assert_eq!(ledger.bridged_balance(&EXIT_ASSET, &beneficiary), 550_000, "the beneficiary is paid the attested amount");
        assert_eq!(ledger.bridged_supply(&EXIT_ASSET), 550_000, "the payout re-materializes the refund under the cap");
        assert_eq!(ledger.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET), 1_000_000, "the on chain refund is backed by custody but does not draw it down");
        assert_eq!(ledger.bridge_epoch_paid_global(0), 550_000, "the global epoch payout total advances");
        assert!(ledger.bridge_exit_settled(&burn_ref), "the burn_ref is consumed against replay");
    }

    #[test]
    fn a_verified_settle_closes_the_exit_without_moving_funds() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut ledger, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(500);
        let beneficiary = [0x55u8; 32];
        let burn_ref = [0x22u8; 32];
        ledger.seed_outstanding_burn(&burn_ref, &EXIT_ASSET, 550_000, &beneficiary);
        let fact = exit_fact(crate::bridge::ExitOutcome::Settle, 550_000, beneficiary, burn_ref);
        let attestation = signed_exit(&fact, &sk0, &sk1);

        let included = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(included.len(), 1, "the verified settle rides in the block");
        assert_eq!(ledger.bridged_balance(&EXIT_ASSET, &beneficiary), 0, "a settle moves no funds on chain");
        assert_eq!(ledger.bridged_supply(&EXIT_ASSET), 0, "a settle changes no supply");
        assert_eq!(ledger.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET), 450_000, "a proven settle draws the paid amount out of custody once");
        assert!(ledger.bridge_exit_settled(&burn_ref), "the settled burn_ref is consumed against replay");
    }

    #[test]
    fn a_mint_then_burn_then_settle_conserves_custody_against_supply() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut ledger, 0, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(600);
        let holder = keypair(601);
        let holder_id = address_bytes(&holder.address());
        fund(&mut ledger, &holder, 10_000 * 1_000_000);

        let deposit = deposit_fact(holder_id, EXIT_ASSET, 500_000, [0x31; 32]);
        assert_eq!(execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&deposit, &sk0, &sk1), &fee)], &fee, 0).len(), 1);
        assert_eq!(ledger.bridged_supply(&EXIT_ASSET), 500_000);
        assert_eq!(ledger.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET), 500_000, "the mint backs the wrapped one for one");

        let request = crate::bridge::ExitRequest { asset_id: EXIT_ASSET, amount: 200_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[exit], &fee, 0).len(), 1);
        assert_eq!(ledger.bridged_supply(&EXIT_ASSET), 300_000, "the burn retired the exit amount");
        assert_eq!(ledger.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET), 500_000, "the burn alone does not move custody");

        let burn_ref = last_burn_ref(&ledger);
        let fact = exit_fact(crate::bridge::ExitOutcome::Settle, 200_000, holder_id, burn_ref);
        assert_eq!(execute_ordered(&mut ledger, &[settle_tx(&relayer, &signed_exit(&fact, &sk0, &sk1), &fee)], &fee, 0).len(), 1);
        assert_eq!(ledger.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET), 300_000, "the proven settle drew the paid amount from custody exactly once");
        assert_eq!(ledger.bridged_supply(&EXIT_ASSET), 300_000, "custody and supply conserve after burn then settle");
        assert!(ledger.bridge_exit_settled(&burn_ref));
    }

    #[test]
    fn a_mint_then_burn_then_slash_conserves_custody_against_supply() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut ledger, 0, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(602);
        let holder = keypair(603);
        let holder_id = address_bytes(&holder.address());
        fund(&mut ledger, &holder, 10_000 * 1_000_000);

        let deposit = deposit_fact(holder_id, EXIT_ASSET, 500_000, [0x41; 32]);
        assert_eq!(execute_ordered(&mut ledger, &[mint_tx(&relayer, &signed_artifact(&deposit, &sk0, &sk1), &fee)], &fee, 0).len(), 1);

        let request = crate::bridge::ExitRequest { asset_id: EXIT_ASSET, amount: 200_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);
        assert_eq!(execute_ordered(&mut ledger, &[exit], &fee, 0).len(), 1);
        assert_eq!(ledger.bridged_supply(&EXIT_ASSET), 300_000);
        assert_eq!(ledger.bridged_balance(&EXIT_ASSET, &holder_id), 300_000);

        let burn_ref = last_burn_ref(&ledger);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 200_000, holder_id, burn_ref);
        assert_eq!(execute_ordered(&mut ledger, &[settle_tx(&relayer, &signed_exit(&fact, &sk0, &sk1), &fee)], &fee, 0).len(), 1);
        assert_eq!(ledger.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET), 500_000, "the on chain refund never draws custody down");
        assert_eq!(ledger.bridged_supply(&EXIT_ASSET), 500_000, "the refund re-materialised the burned wrapped");
        assert_eq!(ledger.bridged_balance(&EXIT_ASSET, &holder_id), 500_000, "the holder is made whole after a failed payout");
        assert!(ledger.bridge_exit_settled(&burn_ref));
    }

    #[test]
    fn a_settle_or_slash_with_no_matching_burn_is_refused_and_a_real_burn_conserves() {
        let fee = FeeParams::devnet();

        let mut forged = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut forged, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(800);
        let beneficiary = [0x55u8; 32];
        let ghost = [0xDEu8; 32];
        assert!(
            forged.bridge_outstanding_burn(&ghost).is_none(),
            "no burn stands behind the fabricated ref"
        );
        let settle = exit_fact(crate::bridge::ExitOutcome::Settle, 500_000, beneficiary, ghost);
        assert_eq!(
            execute_ordered(&mut forged, &[settle_tx(&relayer, &signed_exit(&settle, &sk0, &sk1), &fee)], &fee, 0).len(),
            0,
            "a settle on a fabricated burn_ref draws nothing"
        );
        let slash = exit_fact(crate::bridge::ExitOutcome::Slash, 500_000, beneficiary, ghost);
        assert_eq!(
            execute_ordered(&mut forged, &[settle_tx(&relayer, &signed_exit(&slash, &sk0, &sk1), &fee)], &fee, 0).len(),
            0,
            "a slash on a fabricated burn_ref re-mints nothing"
        );
        assert_eq!(
            forged.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET),
            1_000_000,
            "the fabricated exit left custody untouched"
        );
        assert_eq!(forged.bridged_supply(&EXIT_ASSET), 0, "the fabricated exit moved no supply");
        assert!(!forged.bridge_exit_settled(&ghost), "the fabricated burn_ref was never consumed");

        let mut settled = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut settled, 0, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(801);
        let holder = keypair(802);
        let holder_id = address_bytes(&holder.address());
        fund(&mut settled, &holder, 10_000 * 1_000_000);
        let deposit = deposit_fact(holder_id, EXIT_ASSET, 500_000, [0x51; 32]);
        assert_eq!(
            execute_ordered(&mut settled, &[mint_tx(&relayer, &signed_artifact(&deposit, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );
        let request = crate::bridge::ExitRequest { asset_id: EXIT_ASSET, amount: 200_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);
        assert_eq!(execute_ordered(&mut settled, &[exit], &fee, 0).len(), 1);
        let burn_ref = last_burn_ref(&settled);
        let fact = exit_fact(crate::bridge::ExitOutcome::Settle, 200_000, holder_id, burn_ref);
        assert_eq!(
            execute_ordered(&mut settled, &[settle_tx(&relayer, &signed_exit(&fact, &sk0, &sk1), &fee)], &fee, 0).len(),
            1,
            "a real burn settles"
        );
        assert!(
            settled.bridge_outstanding_burn(&burn_ref).is_none(),
            "the settle consumed the outstanding burn"
        );
        assert!(
            settled.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET) >= settled.bridged_supply(&EXIT_ASSET),
            "custody stays at or above supply after a settle"
        );
        assert_eq!(
            execute_ordered(&mut settled, &[settle_tx(&relayer, &signed_exit(&fact, &sk0, &sk1), &fee)], &fee, 0).len(),
            0,
            "the consumed burn settles nothing a second time"
        );

        let mut slashed = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut slashed, 0, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(803);
        let holder = keypair(804);
        let holder_id = address_bytes(&holder.address());
        fund(&mut slashed, &holder, 10_000 * 1_000_000);
        let deposit = deposit_fact(holder_id, EXIT_ASSET, 500_000, [0x52; 32]);
        assert_eq!(
            execute_ordered(&mut slashed, &[mint_tx(&relayer, &signed_artifact(&deposit, &sk0, &sk1), &fee)], &fee, 0).len(),
            1
        );
        let request = crate::bridge::ExitRequest { asset_id: EXIT_ASSET, amount: 200_000, destination: [0xEE; 32] };
        let exit = system_tx(&holder, &crate::ledger::bridge_exit_address(), request.encode(), 0, TRANSFER_METER, &fee);
        assert_eq!(execute_ordered(&mut slashed, &[exit], &fee, 0).len(), 1);
        let burn_ref = last_burn_ref(&slashed);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 200_000, holder_id, burn_ref);
        assert_eq!(
            execute_ordered(&mut slashed, &[settle_tx(&relayer, &signed_exit(&fact, &sk0, &sk1), &fee)], &fee, 0).len(),
            1,
            "a real burn slashes"
        );
        assert!(
            slashed.bridge_outstanding_burn(&burn_ref).is_none(),
            "the slash consumed the outstanding burn"
        );
        assert_eq!(
            slashed.bridged_balance(&EXIT_ASSET, &holder_id),
            500_000,
            "the holder is made whole after a failed payout"
        );
        assert!(
            slashed.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET) >= slashed.bridged_supply(&EXIT_ASSET),
            "custody stays at or above supply after a slash"
        );
    }

    #[test]
    fn a_prove_nothing_settle_attestation_is_refused() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let _ = seed_exit_bridge(&mut ledger, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(500);
        let empty = crate::bridge::ExitFact {
            version: crate::bridge::EXIT_FACT_VERSION,
            corridor: 0,
            dest_chain: 0,
            asset_id: [0u8; 16],
            amount: 0,
            beneficiary: [0u8; 32],
            burn_ref: [0u8; 32],
            outcome: crate::bridge::ExitOutcome::Slash,
        };
        let attestation = crate::bridge::ExitAttestation { fact: empty, signatures: vec![] };
        let included = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(included.len(), 0, "an empty prove nothing attestation never settles");
        assert_eq!(ledger.bridged_supply(&EXIT_ASSET), 0);
    }

    #[test]
    fn a_duplicate_signer_slash_is_refused() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, _sk1) = seed_exit_bridge(&mut ledger, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(500);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, [0x55u8; 32], [0x33u8; 32]);
        let attestation = crate::bridge::ExitAttestation {
            fact: fact.clone(),
            signatures: vec![
                crate::bridge::SignerSig { operator_id: 0, signature: attest_exit(&sk0, &fact, BRIDGE_CHAIN_ID) },
                crate::bridge::SignerSig { operator_id: 0, signature: attest_exit(&sk0, &fact, BRIDGE_CHAIN_ID) },
            ],
        };
        let included = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(included.len(), 0, "one signer named twice never reaches a two quorum");
        assert_eq!(ledger.bridged_balance(&EXIT_ASSET, &[0x55u8; 32]), 0);
    }

    #[test]
    fn an_under_quorum_slash_is_refused() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, _sk1) = seed_exit_bridge(&mut ledger, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(500);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, [0x55u8; 32], [0x44u8; 32]);
        let attestation = crate::bridge::ExitAttestation {
            fact: fact.clone(),
            signatures: vec![crate::bridge::SignerSig { operator_id: 0, signature: attest_exit(&sk0, &fact, BRIDGE_CHAIN_ID) }],
        };
        let included = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(included.len(), 0, "one signer falls short of the two quorum");
    }

    #[test]
    fn a_settle_without_a_seeded_committee_is_refused() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        ledger.register_bridged_asset(&EXIT_ASSET, 10_000_000, 1_000_000, false);
        ledger.seed_bridge_exits_enabled(true);
        ledger.seed_bridge_pool_vault(&EXIT_VAULT);
        ledger.seed_bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET, 1_000_000);
        ledger.seed_bridge_payout_cap(5_000_000);
        ledger.seed_bridge_dest_chain(BRIDGE_DEST);
        let (_pk0, sk0) = bridge_operator(1);
        let (_pk1, sk1) = bridge_operator(2);
        let relayer = keypair(500);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, [0x55u8; 32], [0x66u8; 32]);
        let attestation = signed_exit(&fact, &sk0, &sk1);
        let included = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(included.len(), 0, "a settle with no on chain operator set is refused");
    }

    #[test]
    fn a_slash_signed_for_a_sibling_chain_id_is_refused() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut ledger, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(500);
        let sibling = BRIDGE_CHAIN_ID ^ (1u64 << 40);
        assert_eq!(sibling as u32, BRIDGE_CHAIN_ID as u32, "the sibling shares the low 32 bits");
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, [0x55u8; 32], [0x77u8; 32]);
        let attestation = crate::bridge::ExitAttestation {
            fact: fact.clone(),
            signatures: vec![
                crate::bridge::SignerSig { operator_id: 0, signature: attest_exit(&sk0, &fact, sibling) },
                crate::bridge::SignerSig { operator_id: 1, signature: attest_exit(&sk1, &fact, sibling) },
            ],
        };
        let included = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(included.len(), 0, "a quorum signed for a sibling chain id does not settle here");
    }

    #[test]
    fn a_replayed_slash_burn_ref_pays_at_most_once() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut ledger, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(500);
        let beneficiary = [0x55u8; 32];
        let burn_ref = [0x88u8; 32];
        ledger.seed_outstanding_burn(&burn_ref, &EXIT_ASSET, 550_000, &beneficiary);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, beneficiary, burn_ref);
        let attestation = signed_exit(&fact, &sk0, &sk1);

        let first = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(first.len(), 1, "the first slash pays");
        let second = execute_ordered(&mut ledger, &[settle_tx(&relayer, &attestation, &fee)], &fee, 0);
        assert_eq!(second.len(), 0, "the replayed burn_ref pays nothing the second time");
        assert_eq!(ledger.bridged_balance(&EXIT_ASSET, &beneficiary), 550_000, "the beneficiary is paid exactly once");
        assert_eq!(ledger.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET), 1_000_000, "the refund pays once and leaves custody in place");
    }

    #[test]
    fn an_over_cap_slash_is_refused() {
        let fee = FeeParams::devnet();
        let relayer = keypair(500);
        let beneficiary = [0x55u8; 32];

        let mut over_global = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut over_global, 1_000_000, 10_000_000, 1_000_000, 500_000);
        over_global.seed_outstanding_burn(&[0x91u8; 32], &EXIT_ASSET, 550_000, &beneficiary);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, beneficiary, [0x91u8; 32]);
        let att = signed_exit(&fact, &sk0, &sk1);
        assert_eq!(execute_ordered(&mut over_global, &[settle_tx(&relayer, &att, &fee)], &fee, 0).len(), 0, "a payout over the global cap is refused");
        assert_eq!(over_global.bridged_balance(&EXIT_ASSET, &beneficiary), 0, "the refused payout moves no funds");

        let mut over_asset = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut over_asset, 1_000_000, 10_000_000, 500_000, 5_000_000);
        over_asset.seed_outstanding_burn(&[0x92u8; 32], &EXIT_ASSET, 550_000, &beneficiary);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, beneficiary, [0x92u8; 32]);
        let att = signed_exit(&fact, &sk0, &sk1);
        assert_eq!(execute_ordered(&mut over_asset, &[settle_tx(&relayer, &att, &fee)], &fee, 0).len(), 0, "a payout over the per asset epoch cap is refused");

        let mut thin_pool = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut thin_pool, 100_000, 10_000_000, 1_000_000, 5_000_000);
        thin_pool.seed_outstanding_burn(&[0x93u8; 32], &EXIT_ASSET, 550_000, &beneficiary);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, beneficiary, [0x93u8; 32]);
        let att = signed_exit(&fact, &sk0, &sk1);
        assert_eq!(execute_ordered(&mut thin_pool, &[settle_tx(&relayer, &att, &fee)], &fee, 0).len(), 0, "a payout above the pool custody fails closed");
        assert_eq!(thin_pool.bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET), 100_000, "the thin pool is untouched");
    }

    #[test]
    fn a_frozen_bridge_blocks_settle_and_slash() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_exit_bridge(&mut ledger, 1_000_000, 10_000_000, 1_000_000, 5_000_000);
        let relayer = keypair(500);
        let freezer = keypair(501);
        fund(&mut ledger, &freezer, 2_000_000 * 1_000_000);
        let freeze = transfer(&freezer, &crate::ledger::bridge_freeze_address(), 0, 0, &fee);
        execute_ordered(&mut ledger, &[freeze], &fee, 0);
        assert!(ledger.bridge_is_frozen(), "the bridge is frozen");

        let slash = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, [0x55u8; 32], [0xa1u8; 32]);
        let settle = exit_fact(crate::bridge::ExitOutcome::Settle, 550_000, [0x55u8; 32], [0xa2u8; 32]);
        let slash_att = signed_exit(&slash, &sk0, &sk1);
        let settle_att = signed_exit(&settle, &sk0, &sk1);
        assert_eq!(execute_ordered(&mut ledger, &[settle_tx(&relayer, &slash_att, &fee)], &fee, 0).len(), 0, "a frozen bridge blocks slash");
        assert_eq!(execute_ordered(&mut ledger, &[settle_tx(&relayer, &settle_att, &fee)], &fee, 0).len(), 0, "a frozen bridge blocks settle");
        assert!(!ledger.bridge_exit_settled(&[0xa1u8; 32]));
        assert!(!ledger.bridge_exit_settled(&[0xa2u8; 32]));
    }

    #[test]
    fn a_slash_is_refused_while_exits_are_disabled() {
        let fee = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let (sk0, sk1) = seed_committee(&mut ledger);
        ledger.register_bridged_asset(&EXIT_ASSET, 10_000_000, 1_000_000, false);
        ledger.seed_bridge_pool_vault(&EXIT_VAULT);
        ledger.seed_bridge_vault_custody(&EXIT_VAULT, &EXIT_ASSET, 1_000_000);
        ledger.seed_bridge_payout_cap(5_000_000);
        assert!(!ledger.bridge_exits_enabled(), "the exits switch defaults off");
        let relayer = keypair(500);
        let fact = exit_fact(crate::bridge::ExitOutcome::Slash, 550_000, [0x55u8; 32], [0xb1u8; 32]);
        let att = signed_exit(&fact, &sk0, &sk1);
        assert_eq!(execute_ordered(&mut ledger, &[settle_tx(&relayer, &att, &fee)], &fee, 0).len(), 0, "the default gate off build settles nothing");
    }
}
