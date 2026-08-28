// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{HashMap, HashSet};

use crate::ed25519::verify;
use crate::merkle::merkle_root;
use crate::proto::{
    encode_block_id, encode_timestamp, put_varint, vote_sign_bytes, BlockId, CanonicalVote,
    Timestamp, PRECOMMIT_TYPE,
};
use crate::validator::{has_two_thirds, ValidatorSet};

fn cdc_bytes(b: &[u8]) -> Vec<u8> {
    if b.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(2 + b.len());
    out.push(0x0a);
    put_varint(&mut out, b.len() as u64);
    out.extend_from_slice(b);
    out
}

fn cdc_string(s: &str) -> Vec<u8> {
    cdc_bytes(s.as_bytes())
}

fn cdc_i64(v: i64) -> Vec<u8> {
    if v == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.push(0x08);
    put_varint(&mut out, v as u64);
    out
}

fn cdc_version(block: u64, app: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if block != 0 {
        out.push(0x08);
        put_varint(&mut out, block);
    }
    if app != 0 {
        out.push(0x10);
        put_varint(&mut out, app);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version_block: u64,
    pub version_app: u64,
    pub chain_id: String,
    pub height: i64,
    pub time: Timestamp,
    pub last_block_id: BlockId,
    pub last_commit_hash: Vec<u8>,
    pub data_hash: Vec<u8>,
    pub validators_hash: Vec<u8>,
    pub next_validators_hash: Vec<u8>,
    pub consensus_hash: Vec<u8>,
    pub app_hash: Vec<u8>,
    pub last_results_hash: Vec<u8>,
    pub evidence_hash: Vec<u8>,
    pub proposer_address: Vec<u8>,
}

impl Header {
    pub fn hash(&self) -> [u8; 32] {
        let leaves: Vec<Vec<u8>> = vec![
            cdc_version(self.version_block, self.version_app),
            cdc_string(&self.chain_id),
            cdc_i64(self.height),
            encode_timestamp(&self.time),
            encode_block_id(&self.last_block_id),
            cdc_bytes(&self.last_commit_hash),
            cdc_bytes(&self.data_hash),
            cdc_bytes(&self.validators_hash),
            cdc_bytes(&self.next_validators_hash),
            cdc_bytes(&self.consensus_hash),
            cdc_bytes(&self.app_hash),
            cdc_bytes(&self.last_results_hash),
            cdc_bytes(&self.evidence_hash),
            cdc_bytes(&self.proposer_address),
        ];
        merkle_root(&leaves)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockIdFlag {
    Absent,
    Commit,
    Nil,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSig {
    pub flag: BlockIdFlag,
    pub validator_address: [u8; 20],
    pub timestamp: Timestamp,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub height: i64,
    pub round: i64,
    pub block_id: BlockId,
    pub signatures: Vec<CommitSig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError {
    HeaderMismatch,
    NotEnoughVotingPower { signed: u128, total: u128 },
    SetTooLarge,
}

pub fn tally_signed_power(
    chain_id: &str,
    header: &Header,
    commit: &Commit,
    set: &ValidatorSet,
) -> Result<u128, CommitError> {
    if set.validators.len() > crate::validator::MAX_VALIDATORS
        || commit.signatures.len() > crate::validator::MAX_VALIDATORS
    {
        return Err(CommitError::SetTooLarge);
    }
    if commit.block_id.hash != header.hash() {
        return Err(CommitError::HeaderMismatch);
    }
    let mut by_address: HashMap<[u8; 20], &crate::validator::ValidatorInfo> =
        HashMap::with_capacity(set.validators.len());
    for v in &set.validators {
        by_address.entry(v.address()).or_insert(v);
    }
    let mut signed: u128 = 0;
    let mut counted: HashSet<[u8; 20]> = HashSet::new();

    for sig in &commit.signatures {
        if sig.flag != BlockIdFlag::Commit {
            continue;
        }
        if counted.contains(&sig.validator_address) {
            continue;
        }
        let validator = match by_address.get(&sig.validator_address) {
            Some(v) => *v,
            None => continue,
        };
        if sig.signature.len() != 64 {
            continue;
        }
        counted.insert(sig.validator_address);
        let vote = CanonicalVote {
            vote_type: PRECOMMIT_TYPE,
            height: commit.height,
            round: commit.round,
            block_id: commit.block_id.clone(),
            timestamp: sig.timestamp,
            chain_id: chain_id.to_string(),
        };
        let message = vote_sign_bytes(&vote);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig.signature);
        if verify(&validator.pubkey, &message, &signature) {
            signed += validator.voting_power as u128;
        }
    }

    Ok(signed)
}

pub fn verify_commit(
    chain_id: &str,
    header: &Header,
    commit: &Commit,
    set: &ValidatorSet,
) -> Result<u128, CommitError> {
    let signed = tally_signed_power(chain_id, header, commit, set)?;
    let total = set.total_power();
    if has_two_thirds(signed, total) {
        Ok(signed)
    } else {
        Err(CommitError::NotEnoughVotingPower { signed, total })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::{public_key_from_seed, sign};
    use crate::validator::ValidatorInfo;

    const CHAIN_ID: &str = "cosmoshub-4";

    struct Keyed {
        seed: [u8; 32],
        info: ValidatorInfo,
    }

    fn keyed(seed_byte: u8, power: u64) -> Keyed {
        let seed = [seed_byte; 32];
        let info = ValidatorInfo {
            pubkey: public_key_from_seed(&seed),
            voting_power: power,
        };
        Keyed { seed, info }
    }

    fn sample_header(set: &ValidatorSet) -> Header {
        Header {
            version_block: 11,
            version_app: 0,
            chain_id: CHAIN_ID.to_string(),
            height: 18_010_657,
            time: Timestamp {
                seconds: 1_700_000_000,
                nanos: 500,
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
            app_hash: vec![0x04; 32],
            last_results_hash: vec![0x05; 32],
            evidence_hash: vec![0x06; 32],
            proposer_address: set.validators[0].address().to_vec(),
        }
    }

    fn precommit(keyed: &Keyed, commit: &Commit) -> CommitSig {
        let timestamp = Timestamp {
            seconds: 1_700_000_001,
            nanos: keyed.seed[0] as i32,
        };
        let vote = CanonicalVote {
            vote_type: PRECOMMIT_TYPE,
            height: commit.height,
            round: commit.round,
            block_id: commit.block_id.clone(),
            timestamp,
            chain_id: CHAIN_ID.to_string(),
        };
        let signature = sign(&keyed.seed, &vote_sign_bytes(&vote));
        CommitSig {
            flag: BlockIdFlag::Commit,
            validator_address: keyed.info.address(),
            timestamp,
            signature: signature.to_vec(),
        }
    }

    fn build(validators: &[Keyed], signers: &[usize]) -> (Header, Commit, ValidatorSet) {
        let set = ValidatorSet::new(validators.iter().map(|k| k.info).collect());
        let header = sample_header(&set);
        let mut commit = Commit {
            height: header.height,
            round: 0,
            block_id: BlockId {
                hash: header.hash().to_vec(),
                part_total: 1,
                part_hash: vec![0xcc; 32],
            },
            signatures: Vec::new(),
        };
        commit.signatures = signers.iter().map(|&i| precommit(&validators[i], &commit)).collect();
        (header, commit, set)
    }

    #[test]
    fn a_full_commit_reaches_the_total_power() {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let (header, commit, set) = build(&vs, &[0, 1, 2, 3]);
        assert_eq!(verify_commit(CHAIN_ID, &header, &commit, &set), Ok(100));
    }

    #[test]
    fn more_than_two_thirds_verifies() {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let (header, commit, set) = build(&vs, &[0, 1, 2]);
        assert_eq!(verify_commit(CHAIN_ID, &header, &commit, &set), Ok(75));
    }

    #[test]
    fn exactly_two_thirds_fails() {
        let vs = vec![keyed(1, 30), keyed(2, 30), keyed(3, 30)];
        let (header, commit, set) = build(&vs, &[0, 1]);
        assert_eq!(
            verify_commit(CHAIN_ID, &header, &commit, &set),
            Err(CommitError::NotEnoughVotingPower { signed: 60, total: 90 })
        );
    }

    #[test]
    fn less_than_two_thirds_fails() {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let (header, commit, set) = build(&vs, &[0, 1]);
        assert_eq!(
            verify_commit(CHAIN_ID, &header, &commit, &set),
            Err(CommitError::NotEnoughVotingPower { signed: 50, total: 100 })
        );
    }

    #[test]
    fn a_tampered_header_no_longer_matches_the_commit() {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let (mut header, commit, set) = build(&vs, &[0, 1, 2, 3]);
        header.app_hash = vec![0x99; 32];
        assert_eq!(
            verify_commit(CHAIN_ID, &header, &commit, &set),
            Err(CommitError::HeaderMismatch)
        );
    }

    #[test]
    fn a_forged_signature_earns_no_power() {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let (header, mut commit, set) = build(&vs, &[0, 1, 2]);
        commit.signatures[2].signature = vec![0x00; 64];
        assert_eq!(
            verify_commit(CHAIN_ID, &header, &commit, &set),
            Err(CommitError::NotEnoughVotingPower { signed: 50, total: 100 })
        );
    }

    #[test]
    fn a_signature_over_a_different_chain_id_is_rejected() {
        let vs = vec![keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
        let (header, commit, set) = build(&vs, &[0, 1, 2, 3]);
        assert!(matches!(
            verify_commit("osmosis-1", &header, &commit, &set),
            Err(CommitError::NotEnoughVotingPower { .. })
        ));
    }

    #[test]
    fn a_captured_cosmos_hub_header_reproduces_its_real_block_hash() {
        let header = Header {
            version_block: 11,
            version_app: 0,
            chain_id: "cosmoshub-4".to_string(),
            height: 32_160_042,
            time: Timestamp {
                seconds: 1_784_790_526,
                nanos: 911_027_138,
            },
            last_block_id: BlockId {
                hash: vec![
                    0x6e, 0x57, 0xdb, 0x7a, 0x84, 0x37, 0x3f, 0x2d, 0xa0, 0x79, 0xaf, 0x4d, 0x81,
                    0xcb, 0xd2, 0xf8, 0xe3, 0x36, 0x63, 0xb2, 0xcb, 0xae, 0x77, 0xa1, 0x7f, 0x2a,
                    0x69, 0x8b, 0xef, 0x79, 0x4b, 0x5c,
                ],
                part_total: 1,
                part_hash: vec![
                    0x92, 0xee, 0xbf, 0xe6, 0x79, 0x3f, 0xf6, 0x78, 0x37, 0xb0, 0xb3, 0xab, 0x5c,
                    0x0f, 0x2c, 0x67, 0x1e, 0x01, 0x83, 0xcb, 0x64, 0x36, 0xec, 0xb3, 0x26, 0xaa,
                    0x24, 0xa0, 0x01, 0x5d, 0xe1, 0x44,
                ],
            },
            last_commit_hash: vec![
                0xf3, 0x7e, 0xea, 0xcd, 0xaf, 0xb8, 0x62, 0xd5, 0x43, 0x08, 0xdb, 0x91, 0x0d, 0x9a,
                0x31, 0xaa, 0x56, 0x96, 0x94, 0x1b, 0x2e, 0xae, 0x43, 0xea, 0xb7, 0x56, 0x9c, 0x8d,
                0x2e, 0xd1, 0xa5, 0xcb,
            ],
            data_hash: vec![
                0x4d, 0xd0, 0x7d, 0x20, 0x44, 0x65, 0x1f, 0x4c, 0xc3, 0xc1, 0xd3, 0xab, 0x13, 0xdf,
                0xfd, 0xf0, 0x88, 0xf4, 0xcc, 0x9f, 0x82, 0x01, 0xc6, 0x66, 0xba, 0x68, 0x88, 0x35,
                0xa8, 0x92, 0x3c, 0xb8,
            ],
            validators_hash: vec![
                0xd3, 0x4a, 0xfa, 0x5e, 0x28, 0xd5, 0xce, 0xa2, 0x8a, 0xb8, 0x2e, 0xd3, 0xe2, 0x2c,
                0xde, 0xe9, 0x32, 0x81, 0x9a, 0x59, 0x4e, 0xcd, 0x49, 0xc9, 0xaa, 0x4c, 0xd9, 0x06,
                0x5b, 0x4e, 0x7d, 0xe6,
            ],
            next_validators_hash: vec![
                0xd3, 0x4a, 0xfa, 0x5e, 0x28, 0xd5, 0xce, 0xa2, 0x8a, 0xb8, 0x2e, 0xd3, 0xe2, 0x2c,
                0xde, 0xe9, 0x32, 0x81, 0x9a, 0x59, 0x4e, 0xcd, 0x49, 0xc9, 0xaa, 0x4c, 0xd9, 0x06,
                0x5b, 0x4e, 0x7d, 0xe6,
            ],
            consensus_hash: vec![
                0x20, 0xca, 0x5e, 0x3f, 0x42, 0xe0, 0x7a, 0x0c, 0xdb, 0x7b, 0xd9, 0x86, 0xef, 0xf1,
                0x94, 0x7a, 0x23, 0xfc, 0x27, 0xff, 0x47, 0x20, 0x43, 0x03, 0xe0, 0x82, 0xbc, 0x44,
                0xbb, 0x34, 0x8e, 0x0b,
            ],
            app_hash: vec![
                0x9d, 0xd7, 0xb9, 0x90, 0x57, 0x53, 0x35, 0xd2, 0x71, 0x23, 0xb9, 0x97, 0xae, 0x21,
                0x32, 0x72, 0x9d, 0x32, 0x3b, 0x8c, 0x14, 0xb7, 0xf2, 0xf3, 0xd2, 0x7a, 0xd1, 0xa5,
                0x76, 0x48, 0x70, 0x6c,
            ],
            last_results_hash: vec![
                0xd9, 0x07, 0x43, 0xd7, 0x5b, 0xd1, 0xbf, 0xfd, 0x11, 0x48, 0xce, 0xc4, 0xfb, 0x23,
                0x73, 0x87, 0xcb, 0x0f, 0xf6, 0xad, 0xe9, 0xd0, 0xbb, 0x99, 0x47, 0xaa, 0x72, 0x18,
                0x37, 0x93, 0x2b, 0x5f,
            ],
            evidence_hash: vec![
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ],
            proposer_address: vec![
                0x56, 0xb2, 0xf0, 0x53, 0xad, 0x13, 0x66, 0x42, 0xd3, 0xfc, 0x90, 0x98, 0xfb, 0x2d,
                0xd0, 0x14, 0x54, 0xf3, 0x96, 0xd5,
            ],
        };

        let captured_block_hash: [u8; 32] = [
            0x39, 0xd0, 0xd8, 0xda, 0xff, 0x22, 0x3c, 0x8d, 0x1d, 0x9c, 0x32, 0x04, 0x4d, 0x1b,
            0xcc, 0x8c, 0x74, 0x27, 0xaa, 0xcf, 0x04, 0x47, 0x81, 0xfd, 0x47, 0xa9, 0xf5, 0xd9,
            0x2c, 0x28, 0x38, 0x8d,
        ];
        assert_eq!(header.hash(), captured_block_hash);
    }

    #[test]
    fn a_captured_cosmos_hub_precommit_verifies_against_the_real_validator_signature() {
        let block_id_hash = vec![
            0x39, 0xd0, 0xd8, 0xda, 0xff, 0x22, 0x3c, 0x8d, 0x1d, 0x9c, 0x32, 0x04, 0x4d, 0x1b,
            0xcc, 0x8c, 0x74, 0x27, 0xaa, 0xcf, 0x04, 0x47, 0x81, 0xfd, 0x47, 0xa9, 0xf5, 0xd9,
            0x2c, 0x28, 0x38, 0x8d,
        ];
        let part_hash = vec![
            0x74, 0x0a, 0x3b, 0x0a, 0x95, 0x60, 0xc8, 0x2d, 0xba, 0x40, 0xb3, 0x5c, 0x14, 0x52,
            0xb5, 0xb6, 0xad, 0xe7, 0x9d, 0x65, 0xaa, 0x07, 0xb8, 0xcf, 0xd9, 0xce, 0x6d, 0xcb,
            0x43, 0x78, 0x73, 0x55,
        ];
        let vote = CanonicalVote {
            vote_type: PRECOMMIT_TYPE,
            height: 32_160_042,
            round: 0,
            block_id: BlockId {
                hash: block_id_hash,
                part_total: 1,
                part_hash,
            },
            timestamp: Timestamp {
                seconds: 1_784_790_532,
                nanos: 661_051_412,
            },
            chain_id: "cosmoshub-4".to_string(),
        };

        let pubkey: [u8; 32] = [
            0x92, 0x5a, 0xcb, 0x35, 0x7c, 0x71, 0x71, 0x7c, 0x75, 0xbf, 0x44, 0x6f, 0x7a, 0x58,
            0xfd, 0x64, 0x48, 0xda, 0xac, 0xff, 0x06, 0x5e, 0xf7, 0x8e, 0x44, 0x54, 0xa5, 0x18,
            0x99, 0x70, 0x01, 0x03,
        ];
        let signature: [u8; 64] = [
            0x58, 0x57, 0x0f, 0x2b, 0xdb, 0xec, 0xed, 0x56, 0xa0, 0xc5, 0x62, 0x76, 0x62, 0x5f,
            0x22, 0x50, 0x0e, 0xa5, 0x59, 0xc4, 0x6c, 0xc2, 0xe3, 0x9a, 0xa9, 0xf7, 0x0f, 0x2b,
            0xab, 0xe2, 0x29, 0xbb, 0x29, 0x48, 0x17, 0x3f, 0xb6, 0x82, 0xe3, 0x62, 0xa3, 0xc3,
            0x4f, 0x09, 0x6f, 0x97, 0x2f, 0x87, 0xb5, 0x2f, 0x14, 0x7a, 0x94, 0xe1, 0xe5, 0x89,
            0x6c, 0x7a, 0x21, 0xc2, 0xe9, 0xc7, 0xc9, 0x07,
        ];

        assert!(verify(&pubkey, &vote_sign_bytes(&vote), &signature));
    }
}
