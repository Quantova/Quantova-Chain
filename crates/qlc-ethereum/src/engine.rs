// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::beacon::{
    compute_domain, compute_signing_root, current_sync_committee_layout, finalized_root_layout,
    next_sync_committee_layout, participating_pubkeys, BeaconBlockHeader, SyncAggregate,
    SyncCommittee, DOMAIN_SYNC_COMMITTEE, EXECUTION_RECEIPTS_DEPTH, EXECUTION_RECEIPTS_INDEX,
};
use crate::bls::BlsAggregateVerifier;
use crate::config::EvmChainConfig;
use crate::keccak::keccak256;
use crate::mpt;
use crate::receipt::{self, RawDeposit};
use crate::rlp;
use crate::ssz;
use qlc_stark::shake256_256;
use qlc_core::VerifiedEvent;
use qlc_stark::corridors::{evm_light_client, EventClaim, ProofStatement};
use qlc_stark::StarkStatement;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthError {
    NotBeaconChain,
    InvalidParticipationLength { got: usize, expected: usize },
    InsufficientParticipation { got: usize, needed: usize },
    WrongPeriod,
    InconsistentSlots { signature_slot: u64, attested_slot: u64 },
    BadFinalityProof,
    BadExecutionProof,
    BadSyncCommitteeProof,
    BadSignature,
    MissingReceipt,
    CapExceeded { amount: u128, cap: u128 },
    UnconfiguredDepositContract,
    Receipt(receipt::ReceiptError),
    Mpt(mpt::MptError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionCommit {
    pub receipts_root: [u8; 32],
    pub block_number: u64,
    pub execution_branch: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientUpdate {
    pub attested_header: BeaconBlockHeader,
    pub finalized_header: BeaconBlockHeader,
    pub finality_branch: Vec<[u8; 32]>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
    pub execution: ExecutionCommit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommitteeUpdate {
    pub attested_header: BeaconBlockHeader,
    pub next_sync_committee: SyncCommittee,
    pub next_sync_committee_branch: Vec<[u8; 32]>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositProof {
    pub receipt_index: u64,
    pub receipt_proof: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustlessDeposit {
    source_ref: [u8; 32],
    amount: u128,
    recipient: [u8; 32],
    asset_id: [u8; 16],
    block_number: u64,
    finality_depth: u32,
}

impl TrustlessDeposit {
    pub fn source_ref(&self) -> [u8; 32] {
        self.source_ref
    }

    pub fn amount(&self) -> u128 {
        self.amount
    }

    pub fn recipient(&self) -> [u8; 32] {
        self.recipient
    }

    pub fn asset_id(&self) -> [u8; 16] {
        self.asset_id
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn finality_depth(&self) -> u32 {
        self.finality_depth
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn new_for_test(
        source_ref: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
        asset_id: [u8; 16],
        block_number: u64,
        finality_depth: u32,
    ) -> TrustlessDeposit {
        TrustlessDeposit {
            source_ref,
            amount,
            recipient,
            asset_id,
            block_number,
            finality_depth,
        }
    }
}

struct CoreDeposit {
    anchor: [u8; 32],
    source_ref: [u8; 32],
    raw: RawDeposit,
    block_number: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientStore {
    pub config: EvmChainConfig,
    pub period: u64,
    current_sync_committee: SyncCommittee,
    next_sync_committee: Option<SyncCommittee>,
    pub finalized_header: BeaconBlockHeader,
}

impl LightClientStore {
    pub fn current_sync_committee(&self) -> &SyncCommittee {
        &self.current_sync_committee
    }

    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.next_sync_committee.as_ref()
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn from_trusted_committee(
        config: EvmChainConfig,
        period: u64,
        current_sync_committee: SyncCommittee,
        finalized_header: BeaconBlockHeader,
    ) -> LightClientStore {
        LightClientStore {
            config,
            period,
            current_sync_committee,
            next_sync_committee: None,
            finalized_header,
        }
    }
}

pub fn bootstrap(
    config: EvmChainConfig,
    period: u64,
    checkpoint_header: BeaconBlockHeader,
    current_sync_committee: SyncCommittee,
    current_sync_committee_branch: Vec<[u8; 32]>,
) -> Result<LightClientStore, EthError> {
    if !config.verifies_beacon_sync_committee() {
        return Err(EthError::NotBeaconChain);
    }
    let electra = config.is_electra_at_slot(checkpoint_header.slot);
    let (index, depth) = current_sync_committee_layout(electra);
    let leaf = current_sync_committee.hash_tree_root();
    if !ssz::is_valid_merkle_branch(
        &leaf,
        &current_sync_committee_branch,
        depth,
        index,
        &checkpoint_header.state_root,
    ) {
        return Err(EthError::BadSyncCommitteeProof);
    }
    Ok(LightClientStore {
        config,
        period,
        current_sync_committee,
        next_sync_committee: None,
        finalized_header: checkpoint_header,
    })
}

fn select_committee(
    store: &LightClientStore,
    signature_slot: u64,
) -> Result<&SyncCommittee, EthError> {
    let signature_period = store.config.sync_committee_period(signature_slot);
    if signature_period == store.period {
        Ok(&store.current_sync_committee)
    } else if signature_period == store.period + 1 {
        store
            .next_sync_committee
            .as_ref()
            .ok_or(EthError::WrongPeriod)
    } else {
        Err(EthError::WrongPeriod)
    }
}

fn verify_sync_aggregate(
    store: &LightClientStore,
    attested_header: &BeaconBlockHeader,
    sync_aggregate: &SyncAggregate,
    signature_slot: u64,
    verifier: &dyn BlsAggregateVerifier,
) -> Result<(), EthError> {
    let committee = select_committee(store, signature_slot)?;
    let expected = store.config.sync_committee_size;
    if committee.pubkeys.len() != expected || sync_aggregate.participation.len() != expected {
        return Err(EthError::InvalidParticipationLength {
            got: sync_aggregate.participation.len(),
            expected,
        });
    }
    let participants = sync_aggregate.participants();
    let needed = store.config.supermajority_threshold();
    if participants < needed {
        return Err(EthError::InsufficientParticipation {
            got: participants,
            needed,
        });
    }
    let fork_version = store.config.fork_version_at_slot(signature_slot.saturating_sub(1));
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        fork_version.0,
        &store.config.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&attested_header.hash_tree_root(), &domain);
    let pubkeys = participating_pubkeys(committee, sync_aggregate);
    if !verifier.fast_aggregate_verify(&pubkeys, &signing_root, &sync_aggregate.signature) {
        return Err(EthError::BadSignature);
    }
    Ok(())
}

fn verify_finality(update: &LightClientUpdate, electra: bool) -> Result<(), EthError> {
    let (index, depth) = finalized_root_layout(electra);
    let leaf = update.finalized_header.hash_tree_root();
    if !ssz::is_valid_merkle_branch(
        &leaf,
        &update.finality_branch,
        depth,
        index,
        &update.attested_header.state_root,
    ) {
        return Err(EthError::BadFinalityProof);
    }
    Ok(())
}

fn verify_execution(update: &LightClientUpdate) -> Result<(), EthError> {
    if !ssz::is_valid_merkle_branch(
        &update.execution.receipts_root,
        &update.execution.execution_branch,
        EXECUTION_RECEIPTS_DEPTH,
        EXECUTION_RECEIPTS_INDEX,
        &update.finalized_header.body_root,
    ) {
        return Err(EthError::BadExecutionProof);
    }
    Ok(())
}

fn deposit_source_ref(anchor: &[u8; 32], key: &[u8], log_index: u32) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(anchor);
    buf.extend_from_slice(key);
    buf.extend_from_slice(&log_index.to_le_bytes());
    keccak256(&buf)
}

fn verify_deposit_core(
    store: &LightClientStore,
    update: &LightClientUpdate,
    deposit: &DepositProof,
    verifier: &dyn BlsAggregateVerifier,
) -> Result<CoreDeposit, EthError> {
    if !store.config.verifies_beacon_sync_committee() {
        return Err(EthError::NotBeaconChain);
    }
    if update.signature_slot < update.attested_header.slot
        || store.config.sync_committee_period(update.signature_slot)
            != store.config.sync_committee_period(update.attested_header.slot)
    {
        return Err(EthError::InconsistentSlots {
            signature_slot: update.signature_slot,
            attested_slot: update.attested_header.slot,
        });
    }
    verify_sync_aggregate(
        store,
        &update.attested_header,
        &update.sync_aggregate,
        update.signature_slot,
        verifier,
    )?;
    let electra = store.config.is_electra_at_slot(update.signature_slot);
    verify_finality(update, electra)?;
    verify_execution(update)?;

    let key = rlp::encode_uint(deposit.receipt_index);
    let value = mpt::verify_proof(
        &update.execution.receipts_root,
        &key,
        &deposit.receipt_proof,
    )
    .map_err(EthError::Mpt)?
    .ok_or(EthError::MissingReceipt)?;
    let deposit_contract = &store.config.deposit_contract;
    if deposit_contract.iter().all(|&b| b == deposit_contract[0]) {
        return Err(EthError::UnconfiguredDepositContract);
    }
    let raw = receipt::extract_deposit(&value, deposit_contract).map_err(EthError::Receipt)?;
    if raw.amount > store.config.max_deposit_base_units {
        return Err(EthError::CapExceeded {
            amount: raw.amount,
            cap: store.config.max_deposit_base_units,
        });
    }

    let anchor = update.finalized_header.hash_tree_root();
    let source_ref = deposit_source_ref(&anchor, &key, raw.log_index);
    Ok(CoreDeposit {
        anchor,
        source_ref,
        raw,
        block_number: update.finalized_header.slot,
    })
}

pub fn verify_deposit_update(
    store: &LightClientStore,
    update: &LightClientUpdate,
    deposit: &DepositProof,
    verifier: &dyn BlsAggregateVerifier,
) -> Result<ProofStatement, EthError> {
    let core = verify_deposit_core(store, update, deposit, verifier)?;
    let event = EventClaim {
        source_ref: core.source_ref,
        asset_id: core.raw.asset_id,
        amount: core.raw.amount,
        recipient: core.raw.recipient,
    };
    Ok(evm_light_client(
        store.config.corridor_id,
        qlc_stark::QUANTOVA_DEST_CHAIN_ID,
        core.block_number,
        core.anchor,
        event,
        store.config.finality_depth,
    ))
}

pub fn verify_trustless_deposit(
    store: &LightClientStore,
    update: &LightClientUpdate,
    deposit: &DepositProof,
    verifier: &dyn BlsAggregateVerifier,
) -> Result<TrustlessDeposit, EthError> {
    let core = verify_deposit_core(store, update, deposit, verifier)?;
    Ok(TrustlessDeposit {
        source_ref: core.source_ref,
        amount: core.raw.amount,
        recipient: core.raw.recipient,
        asset_id: core.raw.asset_id,
        block_number: core.block_number,
        finality_depth: store.config.finality_depth,
    })
}

pub fn public_input_digest(statement: &ProofStatement) -> [u8; 32] {
    shake256_256(&statement.encode())
}

pub fn lower_to_stark(statement: &ProofStatement) -> StarkStatement {
    statement.to_stark_statement(public_input_digest(statement))
}

pub fn to_verified_event(
    config: &EvmChainConfig,
    block_number: u64,
    source_ref: [u8; 32],
    raw: &RawDeposit,
) -> VerifiedEvent {
    VerifiedEvent {
        source_chain: config.corridor_id,
        source_ref,
        asset_id: raw.asset_id,
        amount: raw.amount,
        recipient: raw.recipient,
        height: block_number,
        confirmations: config.finality_depth,
    }
}

pub fn apply_sync_committee_update(
    store: &mut LightClientStore,
    update: &SyncCommitteeUpdate,
    verifier: &dyn BlsAggregateVerifier,
) -> Result<(), EthError> {
    if !store.config.verifies_beacon_sync_committee() {
        return Err(EthError::NotBeaconChain);
    }
    if store.config.sync_committee_period(update.attested_header.slot) != store.period {
        return Err(EthError::WrongPeriod);
    }
    verify_sync_aggregate(
        store,
        &update.attested_header,
        &update.sync_aggregate,
        update.signature_slot,
        verifier,
    )?;
    let electra = store.config.is_electra_at_slot(update.attested_header.slot);
    let (index, depth) = next_sync_committee_layout(electra);
    let leaf = update.next_sync_committee.hash_tree_root();
    if !ssz::is_valid_merkle_branch(
        &leaf,
        &update.next_sync_committee_branch,
        depth,
        index,
        &update.attested_header.state_root,
    ) {
        return Err(EthError::BadSyncCommitteeProof);
    }
    store.next_sync_committee = Some(update.next_sync_committee.clone());
    Ok(())
}

pub fn advance_period(store: &mut LightClientStore) -> Result<(), EthError> {
    match store.next_sync_committee.take() {
        Some(next) => {
            store.current_sync_committee = next;
            store.period += 1;
            Ok(())
        }
        None => Err(EthError::WrongPeriod),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::{
        FINALIZED_ROOT_DEPTH, FINALIZED_ROOT_DEPTH_ELECTRA, FINALIZED_ROOT_GINDEX_ELECTRA,
        FINALIZED_ROOT_INDEX, NEXT_SYNC_COMMITTEE_DEPTH, NEXT_SYNC_COMMITTEE_INDEX,
    };
    use crate::bls::testkit::{model_pubkey, model_sign, HashCommitmentBls};
    use crate::bls::{BlsPubkey, BlsSignature};
    use crate::config;
    use crate::mpt::builder;
    use crate::receipt::fixtures::deposit_receipt;

    const PERIOD: u64 = 870;
    const PERIOD_SLOTS: u64 = 32 * 256;
    const SIG_SLOT: u64 = PERIOD * PERIOD_SLOTS + 100;

    fn secret(prefix: u8, i: usize) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = prefix;
        s[1] = (i % 256) as u8;
        s[2] = (i / 256) as u8;
        s
    }

    fn committee(prefix: u8) -> (SyncCommittee, Vec<[u8; 32]>) {
        let secrets: Vec<[u8; 32]> = (0..512).map(|i| secret(prefix, i)).collect();
        let pubkeys: Vec<BlsPubkey> = secrets.iter().map(model_pubkey).collect();
        let committee = SyncCommittee {
            pubkeys,
            aggregate_pubkey: BlsPubkey([prefix; 48]),
        };
        (committee, secrets)
    }

    fn sign_header(
        committee: &SyncCommittee,
        participation: &[bool],
        attested: &BeaconBlockHeader,
        config: &EvmChainConfig,
    ) -> BlsSignature {
        let fork_version = config.fork_version_at_slot(SIG_SLOT);
        let domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE,
            fork_version.0,
            &config.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&attested.hash_tree_root(), &domain);
        let agg = SyncAggregate {
            participation: participation.to_vec(),
            signature: BlsSignature([0u8; 96]),
        };
        let pubkeys = participating_pubkeys(committee, &agg);
        model_sign(&pubkeys, &signing_root)
    }

    fn full_participation() -> Vec<bool> {
        let mut p = vec![false; 512];
        p[..400].fill(true);
        p
    }

    struct Fixture {
        store: LightClientStore,
        update: LightClientUpdate,
        deposit: DepositProof,
        recipient: [u8; 32],
        amount: u128,
        asset_id: [u8; 16],
        finalized_root: [u8; 32],
    }

    fn build_fixture(amount: u128, participation: Vec<bool>) -> Fixture {
        build_fixture_for(config::ethereum(), amount, participation)
    }

    const TEST_DEPOSIT_CONTRACT: [u8; 20] = [
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x71, 0x82, 0x93, 0xa4,
        0xb5, 0xc6, 0xd7, 0xe8, 0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e,
    ];

    fn build_fixture_for(mut cfg: EvmChainConfig, amount: u128, participation: Vec<bool>) -> Fixture {
        cfg.deposit_contract = TEST_DEPOSIT_CONTRACT;
        let recipient = [0x5c; 32];
        let asset_id = [0x77; 16];
        let receipt = deposit_receipt(&cfg.deposit_contract, &recipient, amount, &asset_id);
        fixture_from_receipt(
            cfg,
            receipt,
            participation,
            recipient,
            amount,
            asset_id,
            FINALIZED_ROOT_INDEX,
            FINALIZED_ROOT_DEPTH,
        )
    }

    fn build_electra_fixture(amount: u128, participation: Vec<bool>) -> Fixture {
        let mut cfg = config::ethereum();
        cfg.electra_epoch = Some(0);
        cfg.deposit_contract = TEST_DEPOSIT_CONTRACT;
        let recipient = [0x5c; 32];
        let asset_id = [0x77; 16];
        let receipt = deposit_receipt(&cfg.deposit_contract, &recipient, amount, &asset_id);
        fixture_from_receipt(
            cfg,
            receipt,
            participation,
            recipient,
            amount,
            asset_id,
            FINALIZED_ROOT_GINDEX_ELECTRA,
            FINALIZED_ROOT_DEPTH_ELECTRA,
        )
    }

    fn fixture_from_receipt(
        cfg: EvmChainConfig,
        receipt: Vec<u8>,
        participation: Vec<bool>,
        recipient: [u8; 32],
        amount: u128,
        asset_id: [u8; 16],
        fin_index: u64,
        fin_depth: usize,
    ) -> Fixture {
        let mut entries = Vec::new();
        for i in 0..6u64 {
            let key = rlp::encode_uint(i);
            let value = if i == 3 {
                receipt.clone()
            } else {
                let mut v = Vec::new();
                v.extend_from_slice(b"other-receipt-payload-over-thirty-two-bytes-");
                v.push(i as u8);
                v
            };
            entries.push((key, value));
        }
        let nibble_entries: Vec<(Vec<u8>, Vec<u8>)> = entries
            .iter()
            .map(|(k, v)| {
                let mut nibbles = Vec::new();
                for b in k {
                    nibbles.push(b >> 4);
                    nibbles.push(b & 0x0f);
                }
                (nibbles, v.clone())
            })
            .collect();
        let trie = builder::build(nibble_entries);
        let receipts_root = builder::root_hash(&trie);
        let receipt_proof = builder::prove(&trie, &entries[3].0);

        let execution_branch: Vec<[u8; 32]> = (0..EXECUTION_RECEIPTS_DEPTH)
            .map(|i| [0xe0 + i as u8; 32])
            .collect();
        let body_root = ssz::merkle_root_from_branch(
            &receipts_root,
            &execution_branch,
            EXECUTION_RECEIPTS_INDEX,
        );

        let finalized_header = BeaconBlockHeader {
            slot: PERIOD * PERIOD_SLOTS + 40,
            proposer_index: 99,
            parent_root: [0x01; 32],
            state_root: [0x02; 32],
            body_root,
        };
        let finalized_root = finalized_header.hash_tree_root();

        let finality_branch: Vec<[u8; 32]> = (0..fin_depth)
            .map(|i| [0xf0 + i as u8; 32])
            .collect();
        let attested_state_root =
            ssz::merkle_root_from_branch(&finalized_root, &finality_branch, fin_index);

        let attested_header = BeaconBlockHeader {
            slot: PERIOD * PERIOD_SLOTS + 60,
            proposer_index: 100,
            parent_root: [0x03; 32],
            state_root: attested_state_root,
            body_root: [0x04; 32],
        };

        let (committee, _secrets) = committee(0xaa);
        let signature = sign_header(&committee, &participation, &attested_header, &cfg);
        let sync_aggregate = SyncAggregate {
            participation,
            signature,
        };

        let store = LightClientStore {
            config: cfg,
            period: PERIOD,
            current_sync_committee: committee,
            next_sync_committee: None,
            finalized_header,
        };

        let update = LightClientUpdate {
            attested_header,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot: SIG_SLOT,
            execution: ExecutionCommit {
                receipts_root,
                block_number: 20_000_000,
                execution_branch,
            },
        };

        let deposit = DepositProof {
            receipt_index: 3,
            receipt_proof,
        };

        Fixture {
            store,
            update,
            deposit,
            recipient,
            amount,
            asset_id,
            finalized_root,
        }
    }

    #[test]
    fn a_valid_aggregate_over_a_finalized_header_yields_the_statement() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let statement =
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(statement.kind, qlc_stark::StatementKind::EvmLightClient);
        assert_eq!(statement.corridor_id, 2);
        assert_eq!(statement.anchor, f.finalized_root);
        assert_eq!(statement.event.amount, f.amount);
        assert_eq!(statement.event.recipient, f.recipient);
        assert_eq!(statement.event.asset_id, f.asset_id);
        assert_eq!(statement.finality_depth, 64);
    }

    #[test]
    fn a_wrong_aggregate_fails() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        f.update.sync_aggregate.signature.0[0] ^= 0xff;
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::BadSignature)
        );
    }

    #[test]
    fn a_forged_participation_bit_breaks_the_aggregate() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        f.update.sync_aggregate.participation[401] = true;
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::BadSignature)
        );
    }

    #[test]
    fn below_a_supermajority_is_refused() {
        let mut participation = vec![false; 512];
        participation[..300].fill(true);
        let f = build_fixture(7_000_000_000_000_000_000u128, participation);
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::InsufficientParticipation {
                got: 300,
                needed: 342
            })
        );
    }

    #[test]
    fn a_participation_vector_padded_past_the_committee_is_refused() {
        let mut participation = vec![false; 512];
        participation[0] = true;
        participation.extend(std::iter::repeat(true).take(341));
        let f = build_fixture(7_000_000_000_000_000_000u128, participation);
        assert!(f.update.sync_aggregate.participants() >= 342);
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::InvalidParticipationLength {
                got: 853,
                expected: 512
            })
        );
    }

    #[test]
    fn a_signature_slot_before_the_attested_header_is_refused() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let attested = f.update.attested_header.slot;
        f.update.signature_slot = attested - 5;
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::InconsistentSlots {
                signature_slot: attested - 5,
                attested_slot: attested,
            })
        );
    }

    #[test]
    fn a_signature_slot_in_another_period_is_refused() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let attested = f.update.attested_header.slot;
        let crossed = (PERIOD + 1) * PERIOD_SLOTS + 10;
        f.update.signature_slot = crossed;
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::InconsistentSlots {
                signature_slot: crossed,
                attested_slot: attested,
            })
        );
    }

    #[test]
    fn a_broken_finality_branch_is_refused() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        f.update.finality_branch[0][0] ^= 0xff;
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::BadFinalityProof)
        );
    }

    #[test]
    fn a_broken_execution_branch_is_refused() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        f.update.execution.execution_branch[0][0] ^= 0xff;
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::BadExecutionProof)
        );
    }

    #[test]
    fn a_tampered_receipt_proof_fails() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let last = f.deposit.receipt_proof.len() - 1;
        f.deposit.receipt_proof[last][6] ^= 0xff;
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::Mpt(mpt::MptError::HashMismatch))
        );
    }

    #[test]
    fn a_deposit_above_the_base_unit_cap_is_refused() {
        let cap = config::ethereum().max_deposit_base_units;
        let f = build_fixture(cap + 1, full_participation());
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::CapExceeded {
                amount: cap + 1,
                cap
            })
        );
    }

    #[test]
    fn every_rollup_config_is_served_by_the_one_engine() {
        for cfg in [
            config::arbitrum(),
            config::optimism(),
            config::base(),
            config::robinhood_chain(),
        ] {
            let corridor = cfg.corridor_id;
            let f = build_fixture_for(cfg, 5_000_000_000_000_000_000u128, full_participation());
            let statement =
                verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
            assert_eq!(statement.kind, qlc_stark::StatementKind::EvmLightClient);
            assert_eq!(statement.corridor_id, corridor);
            assert_eq!(statement.finality_depth, 64);
        }
    }

    #[test]
    fn a_non_beacon_chain_does_not_run_the_sync_committee_path() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        f.store.config = config::bnb_chain();
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::NotBeaconChain)
        );
    }

    #[test]
    fn a_sync_committee_period_rotation_verifies() {
        let cfg = config::ethereum();
        let (current, _) = committee(0xaa);
        let (next, _) = committee(0xbb);

        let next_branch: Vec<[u8; 32]> = (0..NEXT_SYNC_COMMITTEE_DEPTH)
            .map(|i| [0xc0 + i as u8; 32])
            .collect();
        let next_leaf = next.hash_tree_root();
        let attested_state_root =
            ssz::merkle_root_from_branch(&next_leaf, &next_branch, NEXT_SYNC_COMMITTEE_INDEX);

        let attested_header = BeaconBlockHeader {
            slot: PERIOD * PERIOD_SLOTS + 60,
            proposer_index: 100,
            parent_root: [0x03; 32],
            state_root: attested_state_root,
            body_root: [0x04; 32],
        };

        let participation = full_participation();
        let signature = sign_header(&current, &participation, &attested_header, &cfg);

        let mut store = LightClientStore {
            config: cfg,
            period: PERIOD,
            current_sync_committee: current,
            next_sync_committee: None,
            finalized_header: BeaconBlockHeader {
                slot: PERIOD * PERIOD_SLOTS + 40,
                proposer_index: 99,
                parent_root: [0x01; 32],
                state_root: [0x02; 32],
                body_root: [0x05; 32],
            },
        };

        let update = SyncCommitteeUpdate {
            attested_header,
            next_sync_committee: next.clone(),
            next_sync_committee_branch: next_branch,
            sync_aggregate: SyncAggregate {
                participation,
                signature,
            },
            signature_slot: SIG_SLOT,
        };

        assert!(apply_sync_committee_update(&mut store, &update, &HashCommitmentBls).is_ok());
        assert_eq!(store.next_sync_committee, Some(next.clone()));
        assert!(advance_period(&mut store).is_ok());
        assert_eq!(store.period, PERIOD + 1);
        assert_eq!(store.current_sync_committee, next);
    }

    #[test]
    fn a_committee_proven_against_the_checkpoint_state_root_bootstraps_the_store() {
        use crate::beacon::{current_sync_committee_layout, CURRENT_SYNC_COMMITTEE_DEPTH};
        let cfg = config::ethereum();
        let (committee, _) = committee(0xaa);
        let (index, _depth) = current_sync_committee_layout(false);
        let branch: Vec<[u8; 32]> = (0..CURRENT_SYNC_COMMITTEE_DEPTH)
            .map(|i| [0xd0 + i as u8; 32])
            .collect();
        let leaf = committee.hash_tree_root();
        let state_root = ssz::merkle_root_from_branch(&leaf, &branch, index);
        let checkpoint = BeaconBlockHeader {
            slot: PERIOD * PERIOD_SLOTS + 8,
            proposer_index: 7,
            parent_root: [0x01; 32],
            state_root,
            body_root: [0x02; 32],
        };
        let store =
            bootstrap(cfg, PERIOD, checkpoint, committee.clone(), branch.clone()).unwrap();
        assert_eq!(store.current_sync_committee(), &committee);
        assert_eq!(store.next_sync_committee(), None);

        let mut wrong = branch;
        wrong[0][0] ^= 0xff;
        assert_eq!(
            bootstrap(config::ethereum(), PERIOD, checkpoint, committee, wrong),
            Err(EthError::BadSyncCommitteeProof)
        );
    }

    #[test]
    fn a_wrong_next_committee_branch_is_refused() {
        let cfg = config::ethereum();
        let (current, _) = committee(0xaa);
        let (next, _) = committee(0xbb);

        let next_branch: Vec<[u8; 32]> = (0..NEXT_SYNC_COMMITTEE_DEPTH)
            .map(|i| [0xc0 + i as u8; 32])
            .collect();
        let next_leaf = next.hash_tree_root();
        let attested_state_root =
            ssz::merkle_root_from_branch(&next_leaf, &next_branch, NEXT_SYNC_COMMITTEE_INDEX);

        let attested_header = BeaconBlockHeader {
            slot: PERIOD * PERIOD_SLOTS + 60,
            proposer_index: 100,
            parent_root: [0x03; 32],
            state_root: attested_state_root,
            body_root: [0x04; 32],
        };
        let participation = full_participation();
        let signature = sign_header(&current, &participation, &attested_header, &cfg);

        let mut store = LightClientStore {
            config: cfg,
            period: PERIOD,
            current_sync_committee: current,
            next_sync_committee: None,
            finalized_header: attested_header,
        };

        let mut bad_branch = update_branch();
        bad_branch[0][0] ^= 0xff;
        let update = SyncCommitteeUpdate {
            attested_header,
            next_sync_committee: next,
            next_sync_committee_branch: bad_branch,
            sync_aggregate: SyncAggregate {
                participation,
                signature,
            },
            signature_slot: SIG_SLOT,
        };
        assert_eq!(
            apply_sync_committee_update(&mut store, &update, &HashCommitmentBls),
            Err(EthError::BadSyncCommitteeProof)
        );
    }

    fn update_branch() -> Vec<[u8; 32]> {
        (0..NEXT_SYNC_COMMITTEE_DEPTH)
            .map(|i| [0xc0 + i as u8; 32])
            .collect()
    }

    #[test]
    fn the_statement_lowers_to_a_hash_only_stark_statement() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let statement =
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        let lowered = lower_to_stark(&statement);
        assert_eq!(lowered.kind, qlc_stark::StatementKind::EvmLightClient);
        assert_eq!(lowered.corridor_id, 2);
        assert_eq!(lowered.public_input_digest, shake256_256(&statement.encode()));
    }

    #[test]
    fn only_the_attestation_and_the_hash_stark_cross_the_airlock() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let statement =
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(statement.encode().len(), ProofStatement::ENCODED_LEN);

        let lowered = lower_to_stark(&statement);
        let attestation = vec![0x01u8; qlc_airlock::ML_DSA_65_SIG_LEN];
        let stark_proof = vec![0x02u8; 128];
        let crossing = qlc_airlock::encode_ingress(&attestation, &lowered, &stark_proof);
        let ingress = qlc_airlock::parse_ingress(&crossing).unwrap();
        assert_eq!(
            ingress.proof.statement.kind,
            qlc_stark::StatementKind::EvmLightClient
        );
        assert_eq!(
            ingress.attestation.signature.len(),
            qlc_airlock::ML_DSA_65_SIG_LEN
        );
    }

    #[test]
    fn the_verified_event_carries_the_origin_tagged_asset() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let raw = RawDeposit {
            recipient: f.recipient,
            amount: f.amount,
            asset_id: f.asset_id,
            log_index: 0,
        };
        let ev = to_verified_event(&f.store.config, 20_000_000, [0x09; 32], &raw);
        assert_eq!(ev.source_chain, 2);
        assert_eq!(ev.asset_id, f.asset_id);
        assert_eq!(ev.amount, f.amount);
        assert_eq!(ev.height, 20_000_000);
    }

    #[test]
    fn a_finalized_deposit_proves_trustless_end_to_end() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let proven =
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(proven.amount, f.amount);
        assert_eq!(proven.recipient, f.recipient);
        assert_eq!(proven.asset_id, f.asset_id);
        assert_eq!(proven.block_number, PERIOD * PERIOD_SLOTS + 40);
        assert_eq!(proven.finality_depth, 64);
        assert_ne!(proven.source_ref, [0u8; 32]);
    }

    #[test]
    fn a_trustless_deposit_is_only_readable_through_the_verifier_output() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let proven =
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(proven.amount(), f.amount);
        assert_eq!(proven.recipient(), f.recipient);
        assert_eq!(proven.asset_id(), f.asset_id);
        assert_eq!(proven.finality_depth(), 64);
        assert_ne!(proven.source_ref(), [0u8; 32]);
    }

    #[test]
    fn the_trustless_deposit_carries_the_same_values_as_the_statement() {
        let f = build_fixture(3_000_000_000_000_000_000u128, full_participation());
        let statement =
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        let proven =
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(proven.source_ref, statement.event.source_ref);
        assert_eq!(proven.amount, statement.event.amount);
        assert_eq!(proven.recipient, statement.event.recipient);
        assert_eq!(proven.asset_id, statement.event.asset_id);
    }

    #[test]
    fn a_receipt_from_another_bridge_contract_carries_no_trustless_deposit() {
        let mut f = build_fixture(1_000u128, full_participation());
        f.store.config.deposit_contract = [
            0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        ];
        assert_eq!(
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::Receipt(receipt::ReceiptError::NoDeposit))
        );
    }

    #[test]
    fn a_placeholder_deposit_contract_fails_closed() {
        let mut f = build_fixture(1_000u128, full_participation());
        f.store.config.deposit_contract = [0x11; 20];
        assert_eq!(
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::UnconfiguredDepositContract)
        );
    }

    #[test]
    fn a_log_under_a_foreign_topic_is_not_a_trustless_deposit() {
        let mut cfg = config::ethereum();
        cfg.deposit_contract = TEST_DEPOSIT_CONTRACT;
        let recipient = [0x5c; 32];
        let asset_id = [0x77; 16];
        let foreign_topic = keccak256(b"SomeOtherEvent(bytes32,uint256,bytes16)");
        let log = receipt::fixtures::encode_log(
            &cfg.deposit_contract,
            &[foreign_topic, recipient],
            &receipt::fixtures::deposit_data(1_000u128, &asset_id),
        );
        let receipt_bytes = rlp::encode_list(&[
            rlp::encode_bytes(&[1u8]),
            rlp::encode_uint(21000),
            rlp::encode_bytes(&[0u8; 256]),
            rlp::encode_list(&[log]),
        ]);
        let f = fixture_from_receipt(
            cfg,
            receipt_bytes,
            full_participation(),
            recipient,
            1_000,
            asset_id,
            FINALIZED_ROOT_INDEX,
            FINALIZED_ROOT_DEPTH,
        );
        assert_eq!(
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::Receipt(receipt::ReceiptError::NoDeposit))
        );
    }

    #[test]
    fn a_deneb_finality_proof_verifies_under_deneb_and_is_refused_under_electra() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        assert!(verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls).is_ok());
        f.store.config.electra_epoch = Some(0);
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::BadFinalityProof)
        );
    }

    #[test]
    fn an_electra_finality_proof_verifies_under_electra_and_is_refused_under_deneb() {
        let mut f = build_electra_fixture(7_000_000_000_000_000_000u128, full_participation());
        assert!(verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls).is_ok());
        f.store.config.electra_epoch = None;
        assert_eq!(
            verify_deposit_update(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::BadFinalityProof)
        );
    }

    #[test]
    fn a_tampered_receipt_proof_carries_no_trustless_deposit() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let last = f.deposit.receipt_proof.len() - 1;
        f.deposit.receipt_proof[last][6] ^= 0xff;
        assert_eq!(
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::Mpt(mpt::MptError::HashMismatch))
        );
    }

    #[test]
    fn a_trustless_deposit_above_the_base_unit_cap_is_refused() {
        let cap = config::ethereum().max_deposit_base_units;
        let f = build_fixture(cap + 1, full_participation());
        assert_eq!(
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::CapExceeded { amount: cap + 1, cap })
        );
    }

    #[test]
    fn a_trustless_deposit_below_a_supermajority_is_refused() {
        let mut participation = vec![false; 512];
        participation[..300].fill(true);
        let f = build_fixture(1_000u128, participation);
        assert_eq!(
            verify_trustless_deposit(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::InsufficientParticipation { got: 300, needed: 342 })
        );
    }
}
