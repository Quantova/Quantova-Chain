// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::chain::ChainConfig;
use crate::commit::{verify_commit, Commit, CommitError, Header};
use crate::light::{check_anchor, check_trusting_commit, LightError, TrustedState};
use crate::proof::{extract_deposit, Deposit, ExistenceProof, ProofError};
use crate::proto::Timestamp;
use crate::validator::ValidatorSet;
use qlc_core::VerifiedEvent;
use qlc_stark::corridors::{cosmos_tendermint, EventClaim, ProofStatement};
use qlc_stark::shake256_256;
use qlc_stark::StarkStatement;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorridorError {
    ChainMismatch,
    MalformedAppHash,
    Unanchored(LightError),
    Commit(CommitError),
    Proof(ProofError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorridorOutput {
    pub statement: ProofStatement,
    pub event: VerifiedEvent,
    pub signed_power: u128,
}

fn event_claim(deposit: &Deposit) -> EventClaim {
    EventClaim {
        source_ref: deposit.source_ref,
        asset_id: deposit.asset_id,
        amount: deposit.amount,
        recipient: deposit.recipient,
    }
}

fn verified_event(cfg: &ChainConfig, header: &Header, deposit: &Deposit) -> VerifiedEvent {
    VerifiedEvent {
        source_chain: cfg.corridor_id,
        source_ref: deposit.source_ref,
        asset_id: deposit.asset_id,
        amount: deposit.amount,
        recipient: deposit.recipient,
        height: header.height as u64,
        confirmations: cfg.confirmation_depth,
    }
}

pub fn public_input_digest(statement: &ProofStatement) -> [u8; 32] {
    shake256_256(&statement.encode())
}

pub fn lower(statement: &ProofStatement) -> StarkStatement {
    statement.to_stark_statement(public_input_digest(statement))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustlessDeposit {
    source_ref: [u8; 32],
    amount: u128,
    recipient: [u8; 32],
    asset_id: [u8; 16],
    height: u64,
    confirmations: u32,
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

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn confirmations(&self) -> u32 {
        self.confirmations
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn new_for_test(
        source_ref: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
        asset_id: [u8; 16],
        height: u64,
        confirmations: u32,
    ) -> TrustlessDeposit {
        TrustlessDeposit {
            source_ref,
            amount,
            recipient,
            asset_id,
            height,
            confirmations,
        }
    }
}

fn verify_deposit_core(
    cfg: &ChainConfig,
    trusted: &TrustedState,
    header: &Header,
    commit: &Commit,
    set: &ValidatorSet,
    proof: &ExistenceProof,
    now: Timestamp,
) -> Result<(Deposit, u128), CorridorError> {
    if header.chain_id != cfg.chain_id {
        return Err(CorridorError::ChainMismatch);
    }
    check_anchor(cfg, trusted, header, set, now).map_err(CorridorError::Unanchored)?;
    let signed_power =
        verify_commit(cfg.chain_id, header, commit, set).map_err(CorridorError::Commit)?;
    check_trusting_commit(cfg, trusted, header, commit).map_err(CorridorError::Unanchored)?;

    if header.app_hash.len() != 32 {
        return Err(CorridorError::MalformedAppHash);
    }
    let mut app_hash = [0u8; 32];
    app_hash.copy_from_slice(&header.app_hash);

    let deposit = extract_deposit(
        &app_hash,
        cfg.bridge_store_name,
        cfg.bridge_store_prefix,
        proof,
    )
    .map_err(CorridorError::Proof)?;
    Ok((deposit, signed_power))
}

pub fn verify_deposit(
    cfg: &ChainConfig,
    trusted: &TrustedState,
    header: &Header,
    commit: &Commit,
    set: &ValidatorSet,
    proof: &ExistenceProof,
    now: Timestamp,
) -> Result<CorridorOutput, CorridorError> {
    let (deposit, signed_power) =
        verify_deposit_core(cfg, trusted, header, commit, set, proof, now)?;

    let statement = cosmos_tendermint(
        cfg.corridor_id,
        qlc_stark::QUANTOVA_DEST_CHAIN_ID,
        header.height as u64,
        header.hash(),
        event_claim(&deposit),
        cfg.confirmation_depth,
    );
    let event = verified_event(cfg, header, &deposit);

    Ok(CorridorOutput {
        statement,
        event,
        signed_power,
    })
}

pub fn verify_trustless_deposit(
    cfg: &ChainConfig,
    trusted: &TrustedState,
    header: &Header,
    commit: &Commit,
    set: &ValidatorSet,
    proof: &ExistenceProof,
    now: Timestamp,
) -> Result<TrustlessDeposit, CorridorError> {
    let (deposit, _signed_power) =
        verify_deposit_core(cfg, trusted, header, commit, set, proof, now)?;
    Ok(TrustlessDeposit {
        source_ref: deposit.source_ref,
        amount: deposit.amount,
        recipient: deposit.recipient,
        asset_id: deposit.asset_id,
        height: header.height as u64,
        confirmations: cfg.confirmation_depth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::COSMOS_HUB;
    use crate::commit::{BlockIdFlag, CommitSig};
    use crate::ed25519::{public_key_from_seed, sign};
    use crate::proof::{encode_deposit_value, ExistenceProof, InnerOp, LeafOp};
    use crate::proto::{vote_sign_bytes, BlockId, CanonicalVote, Timestamp, PRECOMMIT_TYPE};
    use crate::validator::{ValidatorInfo, ValidatorSet};
    use qlc_stark::StatementKind;

    struct Keyed {
        seed: [u8; 32],
        info: ValidatorInfo,
    }

    fn keyed(byte: u8, power: u64) -> Keyed {
        let seed = [byte; 32];
        Keyed {
            seed,
            info: ValidatorInfo {
                pubkey: public_key_from_seed(&seed),
                voting_power: power,
            },
        }
    }

    fn anchor(set: &ValidatorSet) -> TrustedState {
        TrustedState {
            height: 0,
            time: Timestamp {
                seconds: 1_700_000_000 - 3600,
                nanos: 0,
            },
            header_hash: [0u8; 32],
            validators: set.clone(),
            next_validators_hash: set.hash().to_vec(),
        }
    }

    fn wnow() -> Timestamp {
        Timestamp {
            seconds: 1_700_000_000,
            nanos: 9,
        }
    }

    fn deposit_proof() -> ExistenceProof {
        let recipient = [0x51u8; 32];
        let asset_id = *b"qATOM.atom\0\0\0\0\0\0";
        let amount: u128 = 7_500_000u128;
        ExistenceProof {
            key: b"bridge/deposits/0x1a2b".to_vec(),
            value: encode_deposit_value(&recipient, &asset_id, amount),
            leaf: LeafOp {
                prefix: vec![0x00, 0x02, 0x00],
            },
            path: vec![
                InnerOp {
                    prefix: vec![0x01, 0x0a],
                    suffix: vec![0x1b, 0x2c],
                },
                InnerOp {
                    prefix: vec![0x01],
                    suffix: vec![0x33, 0x44, 0x55],
                },
            ],
            store: None,
        }
    }

    fn scene(signers: &[usize]) -> (Header, Commit, ValidatorSet, ExistenceProof) {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let set = ValidatorSet::new(vs.iter().map(|k| k.info).collect());
        let (app_hash, proof) =
            crate::proof::wrap_store_layer(deposit_proof(), COSMOS_HUB.bridge_store_name);

        let header = Header {
            version_block: 11,
            version_app: 0,
            chain_id: COSMOS_HUB.chain_id.to_string(),
            height: 18_500_000,
            time: Timestamp {
                seconds: 1_700_000_000,
                nanos: 9,
            },
            last_block_id: BlockId {
                hash: vec![0xaa; 32],
                part_total: 1,
                part_hash: vec![0xbb; 32],
            },
            last_commit_hash: vec![0x01; 32],
            data_hash: vec![0x02; 32],
            validators_hash: set.hash().to_vec(),
            next_validators_hash: set.hash().to_vec(),
            consensus_hash: vec![0x03; 32],
            app_hash: app_hash.to_vec(),
            last_results_hash: vec![0x05; 32],
            evidence_hash: vec![0x06; 32],
            proposer_address: set.validators[0].address().to_vec(),
        };

        let block_id = BlockId {
            hash: header.hash().to_vec(),
            part_total: 1,
            part_hash: vec![0xcc; 32],
        };
        let mut signatures = Vec::new();
        for &i in signers {
            let k = &vs[i];
            let timestamp = Timestamp {
                seconds: 1_700_000_001,
                nanos: k.seed[0] as i32,
            };
            let vote = CanonicalVote {
                vote_type: PRECOMMIT_TYPE,
                height: header.height,
                round: 0,
                block_id: block_id.clone(),
                timestamp,
                chain_id: COSMOS_HUB.chain_id.to_string(),
            };
            signatures.push(CommitSig {
                flag: BlockIdFlag::Commit,
                validator_address: k.info.address(),
                timestamp,
                signature: sign(&k.seed, &vote_sign_bytes(&vote)).to_vec(),
            });
        }
        let commit = Commit {
            height: header.height,
            round: 0,
            block_id,
            signatures,
        };
        (header, commit, set, proof)
    }

    #[test]
    fn a_signed_header_and_a_deposit_proof_yield_the_cosmos_statement() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();

        assert_eq!(out.statement.kind, StatementKind::CosmosTendermint);
        assert_eq!(out.statement.corridor_id, 16);
        assert_eq!(out.statement.anchor, header.hash());
        assert_eq!(out.statement.finality_depth, COSMOS_HUB.confirmation_depth);
        assert_eq!(out.statement.event.amount, 7_500_000u128);
        assert_eq!(out.statement.event.recipient, [0x51u8; 32]);
        assert_eq!(out.event.source_chain, 16);
        assert_eq!(out.event.height, 18_500_000);
        assert_eq!(out.signed_power, 100);
    }

    #[test]
    fn the_lowered_stark_statement_is_hash_only_and_fixed_width() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        let lowered = lower(&out.statement);

        assert_eq!(lowered.kind, StatementKind::CosmosTendermint);
        assert_eq!(lowered.corridor_id, 16);
        assert_eq!(lowered.dest_chain_id, qlc_stark::QUANTOVA_DEST_CHAIN_ID);
        assert_eq!(lowered.nonce, header.height as u64);
        assert_eq!(
            lowered.public_input_digest,
            shake256_256(&out.statement.encode())
        );
        assert_eq!(lowered.encode().len(), StarkStatement::ENCODED_LEN);
    }

    #[test]
    fn the_slot_nonce_and_destination_are_bound_into_the_public_input() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        assert_eq!(out.statement.nonce, header.height as u64);
        assert_eq!(
            out.statement.dest_chain_id,
            qlc_stark::QUANTOVA_DEST_CHAIN_ID
        );

        let mut replayed_slot = out.statement;
        replayed_slot.nonce += 1;
        assert_ne!(
            public_input_digest(&replayed_slot),
            public_input_digest(&out.statement)
        );

        let mut other_chain = out.statement;
        other_chain.dest_chain_id += 1;
        assert_ne!(
            public_input_digest(&other_chain),
            public_input_digest(&out.statement)
        );
    }

    #[test]
    fn the_statement_is_fixed_width_with_no_room_for_foreign_material() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        let encoded = out.statement.encode();
        assert_eq!(encoded.len(), ProofStatement::ENCODED_LEN);
        assert_eq!(ProofStatement::decode(&encoded), Some(out.statement));
    }

    #[test]
    fn the_public_input_binds_the_amount() {
        let (header, commit, set, mut proof) = scene(&[0, 1, 2, 3]);
        let base = verify_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        let base_digest = public_input_digest(&base.statement);

        let recipient = [0x51u8; 32];
        let asset_id = *b"qATOM.atom\0\0\0\0\0\0";
        proof.value = encode_deposit_value(&recipient, &asset_id, 7_500_001u128);
        proof.store = None;
        let (app_hash2, proof) =
            crate::proof::wrap_store_layer(proof, COSMOS_HUB.bridge_store_name);
        let mut header2 = header.clone();
        header2.app_hash = app_hash2.to_vec();
        let commit2 = resign(&header2, &set);
        let bumped = verify_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header2,
            &commit2,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();

        assert_ne!(public_input_digest(&bumped.statement), base_digest);
    }

    fn resign(header: &Header, set: &ValidatorSet) -> Commit {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let _ = set;
        let block_id = BlockId {
            hash: header.hash().to_vec(),
            part_total: 1,
            part_hash: vec![0xcc; 32],
        };
        let mut signatures = Vec::new();
        for k in &vs {
            let timestamp = Timestamp {
                seconds: 1_700_000_001,
                nanos: k.seed[0] as i32,
            };
            let vote = CanonicalVote {
                vote_type: PRECOMMIT_TYPE,
                height: header.height,
                round: 0,
                block_id: block_id.clone(),
                timestamp,
                chain_id: header.chain_id.clone(),
            };
            signatures.push(CommitSig {
                flag: BlockIdFlag::Commit,
                validator_address: k.info.address(),
                timestamp,
                signature: sign(&k.seed, &vote_sign_bytes(&vote)).to_vec(),
            });
        }
        Commit {
            height: header.height,
            round: 0,
            block_id,
            signatures,
        }
    }

    #[test]
    fn a_short_commit_produces_no_statement() {
        let (header, commit, set, proof) = scene(&[0, 1]);
        assert!(matches!(
            verify_deposit(
                &COSMOS_HUB,
                &anchor(&set),
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            ),
            Err(CorridorError::Commit(
                CommitError::NotEnoughVotingPower { .. }
            ))
        ));
    }

    #[test]
    fn a_tampered_proof_produces_no_statement() {
        let (header, commit, set, mut proof) = scene(&[0, 1, 2, 3]);
        proof.value[48] ^= 0x01;
        assert_eq!(
            verify_deposit(
                &COSMOS_HUB,
                &anchor(&set),
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            ),
            Err(CorridorError::Proof(ProofError::StoreRootMismatch))
        );
    }

    #[test]
    fn a_deposit_outside_the_bridge_store_produces_no_statement() {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let set = ValidatorSet::new(vs.iter().map(|k| k.info).collect());

        let recipient = [0x51u8; 32];
        let asset_id = *b"qATOM.atom\0\0\0\0\0\0";
        let proof = ExistenceProof {
            key: b"staking/deposits/0x1a2b".to_vec(),
            value: encode_deposit_value(&recipient, &asset_id, 7_500_000u128),
            leaf: LeafOp {
                prefix: vec![0x00, 0x02, 0x00],
            },
            path: vec![
                InnerOp {
                    prefix: vec![0x01, 0x0a],
                    suffix: vec![0x1b, 0x2c],
                },
                InnerOp {
                    prefix: vec![0x01],
                    suffix: vec![0x33, 0x44, 0x55],
                },
            ],
            store: None,
        };
        let app_hash = proof.calculate_root();

        let header = Header {
            version_block: 11,
            version_app: 0,
            chain_id: COSMOS_HUB.chain_id.to_string(),
            height: 18_500_000,
            time: Timestamp {
                seconds: 1_700_000_000,
                nanos: 9,
            },
            last_block_id: BlockId {
                hash: vec![0xaa; 32],
                part_total: 1,
                part_hash: vec![0xbb; 32],
            },
            last_commit_hash: vec![0x01; 32],
            data_hash: vec![0x02; 32],
            validators_hash: set.hash().to_vec(),
            next_validators_hash: set.hash().to_vec(),
            consensus_hash: vec![0x03; 32],
            app_hash: app_hash.to_vec(),
            last_results_hash: vec![0x05; 32],
            evidence_hash: vec![0x06; 32],
            proposer_address: set.validators[0].address().to_vec(),
        };
        let commit = resign(&header, &set);

        assert_eq!(
            verify_deposit(
                &COSMOS_HUB,
                &anchor(&set),
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            ),
            Err(CorridorError::Proof(ProofError::ForeignStoreKey))
        );
    }

    #[test]
    fn the_same_engine_serves_another_cosmos_chain() {
        let (mut header, _c, set, proof) = scene(&[0, 1, 2, 3]);
        header.chain_id = crate::chain::OSMOSIS.chain_id.to_string();
        let commit = resign(&header, &set);
        let out = verify_deposit(
            &crate::chain::OSMOSIS,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        assert_eq!(out.statement.corridor_id, 17);
        assert_eq!(out.statement.kind, StatementKind::CosmosTendermint);
    }

    #[test]
    fn a_signed_header_and_a_deposit_proof_prove_trustless_end_to_end() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let proven = verify_trustless_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        assert_eq!(proven.amount, 7_500_000u128);
        assert_eq!(proven.recipient, [0x51u8; 32]);
        assert_eq!(proven.asset_id, *b"qATOM.atom\0\0\0\0\0\0");
        assert_eq!(proven.height, 18_500_000);
        assert_eq!(proven.confirmations, COSMOS_HUB.confirmation_depth);
        assert_ne!(proven.source_ref, [0u8; 32]);
    }

    #[test]
    fn a_trustless_deposit_is_only_readable_through_the_verifier_output() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let proven = verify_trustless_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        assert_eq!(proven.amount(), 7_500_000u128);
        assert_eq!(proven.recipient(), [0x51u8; 32]);
        assert_eq!(proven.asset_id(), *b"qATOM.atom\0\0\0\0\0\0");
        assert_eq!(proven.confirmations(), COSMOS_HUB.confirmation_depth);
        assert_ne!(proven.source_ref(), [0u8; 32]);
    }

    #[test]
    fn the_trustless_deposit_carries_the_same_values_as_the_statement() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        let proven = verify_trustless_deposit(
            &COSMOS_HUB,
            &anchor(&set),
            &header,
            &commit,
            &set,
            &proof,
            wnow(),
        )
        .unwrap();
        assert_eq!(proven.source_ref, out.statement.event.source_ref);
        assert_eq!(proven.amount, out.statement.event.amount);
        assert_eq!(proven.recipient, out.statement.event.recipient);
        assert_eq!(proven.asset_id, out.statement.event.asset_id);
    }

    #[test]
    fn a_short_commit_proves_no_trustless_deposit() {
        let (header, commit, set, proof) = scene(&[0, 1]);
        assert!(matches!(
            verify_trustless_deposit(
                &COSMOS_HUB,
                &anchor(&set),
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            ),
            Err(CorridorError::Commit(
                CommitError::NotEnoughVotingPower { .. }
            ))
        ));
    }

    #[test]
    fn a_tampered_proof_proves_no_trustless_deposit() {
        let (header, commit, set, mut proof) = scene(&[0, 1, 2, 3]);
        proof.value[48] ^= 0x01;
        assert_eq!(
            verify_trustless_deposit(
                &COSMOS_HUB,
                &anchor(&set),
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            ),
            Err(CorridorError::Proof(ProofError::StoreRootMismatch))
        );
    }

    #[test]
    fn a_header_from_another_chain_proves_no_trustless_deposit() {
        let (mut header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        header.chain_id = "osmosis-1".to_string();
        assert_eq!(
            verify_trustless_deposit(
                &COSMOS_HUB,
                &anchor(&set),
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            ),
            Err(CorridorError::ChainMismatch)
        );
    }

    #[test]
    fn a_malformed_app_hash_proves_no_trustless_deposit() {
        let (mut header, _c, set, proof) = scene(&[0, 1, 2, 3]);
        header.app_hash = vec![0x04; 31];
        let commit = resign(&header, &set);
        assert_eq!(
            verify_trustless_deposit(
                &COSMOS_HUB,
                &anchor(&set),
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            ),
            Err(CorridorError::MalformedAppHash)
        );
    }

    #[test]
    fn a_superset_that_only_borrows_trusted_addresses_mints_no_deposit() {
        let t1 = keyed(1, 25);
        let t2 = keyed(2, 25);
        let t3 = keyed(3, 25);
        let t4 = keyed(4, 25);
        let trusted_set = ValidatorSet::new(vec![t1.info, t2.info, t3.info, t4.info]);

        let a1 = keyed(200, 1000);
        let a2 = keyed(201, 1000);
        let forged = ValidatorSet::new(vec![t1.info, t2.info, t3.info, t4.info, a1.info, a2.info]);

        let proof = deposit_proof();
        let app_hash = proof.calculate_root();
        let header = Header {
            version_block: 11,
            version_app: 0,
            chain_id: COSMOS_HUB.chain_id.to_string(),
            height: 18_500_000,
            time: Timestamp {
                seconds: 1_700_000_000,
                nanos: 9,
            },
            last_block_id: BlockId {
                hash: vec![0xaa; 32],
                part_total: 1,
                part_hash: vec![0xbb; 32],
            },
            last_commit_hash: vec![0x01; 32],
            data_hash: vec![0x02; 32],
            validators_hash: forged.hash().to_vec(),
            next_validators_hash: forged.hash().to_vec(),
            consensus_hash: vec![0x03; 32],
            app_hash: app_hash.to_vec(),
            last_results_hash: vec![0x05; 32],
            evidence_hash: vec![0x06; 32],
            proposer_address: forged.validators[0].address().to_vec(),
        };

        let block_id = BlockId {
            hash: header.hash().to_vec(),
            part_total: 1,
            part_hash: vec![0xcc; 32],
        };
        let mut signatures = Vec::new();
        for k in [&a1, &a2] {
            let timestamp = Timestamp {
                seconds: 1_700_000_001,
                nanos: k.seed[0] as i32,
            };
            let vote = CanonicalVote {
                vote_type: PRECOMMIT_TYPE,
                height: header.height,
                round: 0,
                block_id: block_id.clone(),
                timestamp,
                chain_id: COSMOS_HUB.chain_id.to_string(),
            };
            signatures.push(CommitSig {
                flag: BlockIdFlag::Commit,
                validator_address: k.info.address(),
                timestamp,
                signature: sign(&k.seed, &vote_sign_bytes(&vote)).to_vec(),
            });
        }
        let commit = Commit {
            height: header.height,
            round: 0,
            block_id,
            signatures,
        };

        assert_eq!(
            verify_trustless_deposit(
                &COSMOS_HUB,
                &anchor(&trusted_set),
                &header,
                &commit,
                &forged,
                &proof,
                wnow()
            ),
            Err(CorridorError::Unanchored(
                LightError::InsufficientTrustedSignatures {
                    signed: 0,
                    trusted_total: 100,
                }
            ))
        );

        let (lheader, lcommit, lset, lproof) = scene(&[0, 1, 2, 3]);
        assert!(verify_trustless_deposit(
            &COSMOS_HUB,
            &anchor(&lset),
            &lheader,
            &lcommit,
            &lset,
            &lproof,
            wnow()
        )
        .is_ok());
    }

    #[test]
    fn a_self_generated_validator_set_is_rejected_against_the_pinned_anchor() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);

        let matching = anchor(&set);
        assert!(
            verify_trustless_deposit(
                &COSMOS_HUB,
                &matching,
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            )
            .is_ok(),
            "the pinned validator set verifies its own signed header"
        );

        let others = ValidatorSet::new(
            [keyed(50, 25), keyed(51, 25), keyed(52, 25), keyed(53, 25)]
                .iter()
                .map(|k| k.info)
                .collect(),
        );
        assert!(matches!(
            verify_trustless_deposit(
                &COSMOS_HUB,
                &anchor(&others),
                &header,
                &commit,
                &set,
                &proof,
                wnow()
            ),
            Err(CorridorError::Unanchored(
                LightError::InsufficientOverlap { .. }
            ))
        ));
    }
}
