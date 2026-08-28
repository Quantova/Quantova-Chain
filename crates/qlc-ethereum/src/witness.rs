// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::bls::BlsAggregateVerifier;
use crate::engine::{verify_deposit_update, DepositProof, EthError, LightClientStore, LightClientUpdate};
use qlc_stark::corridors::ProofStatement;
use qlc_stark::shake256_256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthereumCheckedFacts {
    pub attested_header_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub participants: u32,
}

impl EthereumCheckedFacts {
    pub const ENCODED_LEN: usize = 32 + 32 + 4;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.attested_header_root);
        out.extend_from_slice(&self.receipts_root);
        out.extend_from_slice(&self.participants.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProveReadyWitness {
    pub statement: ProofStatement,
    pub public_input_digest: [u8; 32],
    pub facts: EthereumCheckedFacts,
}

impl ProveReadyWitness {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.statement.encode();
        out.extend_from_slice(&self.facts.encode());
        out
    }
}

fn digest_of(statement: &ProofStatement, facts: &EthereumCheckedFacts) -> [u8; 32] {
    let mut buf = statement.encode();
    buf.extend_from_slice(&facts.encode());
    shake256_256(&buf)
}

pub fn prove_ready_witness(
    store: &LightClientStore,
    update: &LightClientUpdate,
    deposit: &DepositProof,
    verifier: &dyn BlsAggregateVerifier,
) -> Result<ProveReadyWitness, EthError> {
    let statement = verify_deposit_update(store, update, deposit, verifier)?;
    let facts = EthereumCheckedFacts {
        attested_header_root: update.attested_header.hash_tree_root(),
        receipts_root: update.execution.receipts_root,
        participants: update.sync_aggregate.participants() as u32,
    };
    let public_input_digest = digest_of(&statement, &facts);
    Ok(ProveReadyWitness {
        statement,
        public_input_digest,
        facts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::{
        compute_domain, compute_signing_root, participating_pubkeys, BeaconBlockHeader,
        SyncAggregate, SyncCommittee, DOMAIN_SYNC_COMMITTEE, EXECUTION_RECEIPTS_DEPTH,
        EXECUTION_RECEIPTS_INDEX, FINALIZED_ROOT_DEPTH, FINALIZED_ROOT_INDEX,
    };
    use crate::bls::testkit::{model_pubkey, model_sign, HashCommitmentBls};
    use crate::bls::{BlsPubkey, BlsSignature};
    use crate::config::{self, EvmChainConfig};
    use crate::engine::ExecutionCommit;
    use crate::mpt::builder;
    use crate::receipt::fixtures::deposit_receipt;
    use crate::rlp;
    use crate::ssz;

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
    }

    fn build_fixture(amount: u128, participation: Vec<bool>) -> Fixture {
        let mut cfg = config::ethereum();
        cfg.deposit_contract = [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x71, 0x82, 0x93, 0xa4,
            0xb5, 0xc6, 0xd7, 0xe8, 0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e,
        ];
        let recipient = [0x5c; 32];
        let asset_id = [0x77; 16];

        let receipt = deposit_receipt(&cfg.deposit_contract, &recipient, amount, &asset_id);
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

        let finality_branch: Vec<[u8; 32]> = (0..FINALIZED_ROOT_DEPTH)
            .map(|i| [0xf0 + i as u8; 32])
            .collect();
        let attested_state_root =
            ssz::merkle_root_from_branch(&finalized_root, &finality_branch, FINALIZED_ROOT_INDEX);

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

        let store = LightClientStore::from_trusted_committee(cfg, PERIOD, committee, finalized_header);

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
        }
    }

    #[test]
    fn a_successful_verification_yields_a_stable_canonical_witness() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let a = prove_ready_witness(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        let b = prove_ready_witness(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn the_digest_matches_a_fresh_hash_of_the_statement_and_facts() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let witness =
            prove_ready_witness(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(witness.public_input_digest, shake256_256(&witness.encode()));
    }

    #[test]
    fn the_witness_carries_the_attested_root_and_the_participant_count() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let witness =
            prove_ready_witness(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(witness.facts.attested_header_root, f.update.attested_header.hash_tree_root());
        assert_eq!(witness.facts.receipts_root, f.update.execution.receipts_root);
        assert_eq!(witness.facts.participants, 400);
        assert_eq!(witness.statement.corridor_id, 2);
    }

    #[test]
    fn fewer_participants_changes_the_witness_digest() {
        let full = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let mut fewer_participation = vec![false; 512];
        fewer_participation[..350].fill(true);
        let fewer = build_fixture(7_000_000_000_000_000_000u128, fewer_participation);
        let a = prove_ready_witness(&full.store, &full.update, &full.deposit, &HashCommitmentBls).unwrap();
        let b = prove_ready_witness(&fewer.store, &fewer.update, &fewer.deposit, &HashCommitmentBls).unwrap();
        assert_ne!(a.public_input_digest, b.public_input_digest);
    }

    #[test]
    fn a_wrong_aggregate_yields_no_witness() {
        let mut f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        f.update.sync_aggregate.signature.0[0] ^= 0xff;
        assert_eq!(
            prove_ready_witness(&f.store, &f.update, &f.deposit, &HashCommitmentBls),
            Err(EthError::BadSignature)
        );
    }

    #[test]
    fn the_encoded_witness_is_a_fixed_width_of_hash_and_count_fields_only() {
        let f = build_fixture(7_000_000_000_000_000_000u128, full_participation());
        let witness =
            prove_ready_witness(&f.store, &f.update, &f.deposit, &HashCommitmentBls).unwrap();
        assert_eq!(
            witness.encode().len(),
            ProofStatement::ENCODED_LEN + EthereumCheckedFacts::ENCODED_LEN
        );
    }
}
