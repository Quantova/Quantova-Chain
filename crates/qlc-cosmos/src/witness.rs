// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::statement::CorridorOutput;
use qlc_stark::corridors::ProofStatement;
use qlc_stark::shake256_256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CosmosCheckedFacts {
    pub header_height: u64,
    pub signed_power: u64,
}

impl CosmosCheckedFacts {
    pub const ENCODED_LEN: usize = 8 + 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.header_height.to_le_bytes());
        out.extend_from_slice(&self.signed_power.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProveReadyWitness {
    pub statement: ProofStatement,
    pub public_input_digest: [u8; 32],
    pub facts: CosmosCheckedFacts,
}

impl ProveReadyWitness {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.statement.encode();
        out.extend_from_slice(&self.facts.encode());
        out
    }
}

fn digest_of(statement: &ProofStatement, facts: &CosmosCheckedFacts) -> [u8; 32] {
    let mut buf = statement.encode();
    buf.extend_from_slice(&facts.encode());
    shake256_256(&buf)
}

pub fn prove_ready_witness(out: &CorridorOutput) -> ProveReadyWitness {
    let facts = CosmosCheckedFacts {
        header_height: out.event.height,
        signed_power: out.signed_power.min(u64::MAX as u128) as u64,
    };
    let public_input_digest = digest_of(&out.statement, &facts);
    ProveReadyWitness {
        statement: out.statement,
        public_input_digest,
        facts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::COSMOS_HUB;
    use crate::commit::{BlockIdFlag, Commit, CommitSig, Header};
    use crate::ed25519::{public_key_from_seed, sign};
    use crate::proof::{encode_deposit_value, ExistenceProof, InnerOp, LeafOp};
    use crate::proto::{vote_sign_bytes, BlockId, CanonicalVote, Timestamp, PRECOMMIT_TYPE};
    use crate::light::TrustedState;
    use crate::statement::verify_deposit;
    use crate::validator::{ValidatorInfo, ValidatorSet};

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
            time: Timestamp { seconds: 1_700_000_000 - 3600, nanos: 0 },
            header_hash: [0u8; 32],
            validators: set.clone(),
            next_validators_hash: set.hash().to_vec(),
        }
    }

    fn wnow() -> Timestamp {
        Timestamp { seconds: 1_700_000_000, nanos: 9 }
    }

    fn deposit_proof() -> ExistenceProof {
        let recipient = [0x51u8; 32];
        let asset_id = *b"qATOM.atom\0\0\0\0\0\0";
        let amount: u128 = 7_500_000u128;
        ExistenceProof {
            key: b"bridge/deposits/0x1a2b".to_vec(),
            value: encode_deposit_value(&recipient, &asset_id, amount),
            leaf: LeafOp { prefix: vec![0x00, 0x02, 0x00] },
            path: vec![
                InnerOp { prefix: vec![0x01, 0x0a], suffix: vec![0x1b, 0x2c] },
                InnerOp { prefix: vec![0x01], suffix: vec![0x33, 0x44, 0x55] },
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
            time: Timestamp { seconds: 1_700_000_000, nanos: 9 },
            last_block_id: BlockId { hash: vec![0xaa; 32], part_total: 1, part_hash: vec![0xbb; 32] },
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

        let block_id = BlockId { hash: header.hash().to_vec(), part_total: 1, part_hash: vec![0xcc; 32] };
        let mut signatures = Vec::new();
        for &i in signers {
            let k = &vs[i];
            let timestamp = Timestamp { seconds: 1_700_000_001, nanos: k.seed[0] as i32 };
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
        let commit = Commit { height: header.height, round: 0, block_id, signatures };
        (header, commit, set, proof)
    }

    #[test]
    fn a_successful_verification_yields_a_stable_canonical_witness() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(&COSMOS_HUB, &anchor(&set), &header, &commit, &set, &proof, wnow()).unwrap();
        let a = prove_ready_witness(&out);
        let b = prove_ready_witness(&out);
        assert_eq!(a, b);
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn the_digest_matches_a_fresh_hash_of_the_statement_and_facts() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(&COSMOS_HUB, &anchor(&set), &header, &commit, &set, &proof, wnow()).unwrap();
        let witness = prove_ready_witness(&out);
        assert_eq!(witness.public_input_digest, shake256_256(&witness.encode()));
    }

    #[test]
    fn the_witness_carries_the_height_and_the_signed_power() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(&COSMOS_HUB, &anchor(&set), &header, &commit, &set, &proof, wnow()).unwrap();
        let witness = prove_ready_witness(&out);
        assert_eq!(witness.facts.header_height, 18_500_000);
        assert_eq!(witness.facts.signed_power, 100);
        assert_eq!(witness.statement.corridor_id, 16);
    }

    #[test]
    fn a_different_signed_power_changes_the_witness_digest() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let full = verify_deposit(&COSMOS_HUB, &anchor(&set), &header, &commit, &set, &proof, wnow()).unwrap();
        let (header2, commit2, set2, proof2) = scene(&[0, 1, 2]);
        let partial = verify_deposit(&COSMOS_HUB, &anchor(&set2), &header2, &commit2, &set2, &proof2, wnow()).unwrap();
        let a = prove_ready_witness(&full);
        let b = prove_ready_witness(&partial);
        assert_ne!(a.public_input_digest, b.public_input_digest);
    }

    #[test]
    fn the_encoded_witness_is_a_fixed_width_of_hash_and_count_fields_only() {
        let (header, commit, set, proof) = scene(&[0, 1, 2, 3]);
        let out = verify_deposit(&COSMOS_HUB, &anchor(&set), &header, &commit, &set, &proof, wnow()).unwrap();
        let witness = prove_ready_witness(&out);
        assert_eq!(
            witness.encode().len(),
            ProofStatement::ENCODED_LEN + CosmosCheckedFacts::ENCODED_LEN
        );
    }
}
