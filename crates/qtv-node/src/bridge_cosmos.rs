// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::bridge::{Direction, Fact, FACT_VERSION};
use qlc_cosmos::chain::{ChainConfig, FAMILY};
use qlc_cosmos::commit::{BlockIdFlag, Commit, CommitSig, Header};
use qlc_cosmos::light::TrustedState;
use qlc_cosmos::proof::{ExistenceProof, InnerOp, LeafOp};
use qlc_cosmos::proto::{BlockId, Timestamp};
use qlc_cosmos::sha256::sha256;
use qlc_cosmos::validator::{ValidatorInfo, ValidatorSet};
use qlc_cosmos::verify_trustless_deposit;

pub const MAX_COSMOS_FIELD_BYTES: usize = 1 << 16;
pub const MAX_COSMOS_PATH: usize = 256;
pub const MAX_COSMOS_STORE_DEPTH: usize = 4;
pub const MAX_COSMOS_MINT_BYTES: usize = 1 << 21;
pub const MAX_COSMOS_SIGNERS: usize = 512;
pub const COSMOS_SLOT_MS: u64 = qtv_bft::params::SLOT_MS;

pub fn cosmos_source_chain(config_selector: u8) -> u32 {
    0xFFFF_FD00u32 | config_selector as u32
}

pub fn chain_now(genesis_time_secs: u64, height: u64) -> Timestamp {
    let elapsed_secs = height.saturating_mul(COSMOS_SLOT_MS) / 1000;
    Timestamp {
        seconds: genesis_time_secs.saturating_add(elapsed_secs) as i64,
        nanos: 0,
    }
}

fn config_for_selector(selector: u8) -> Option<ChainConfig> {
    FAMILY.get(selector as usize).copied()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Cursor<'a> {
        Cursor { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn i64(&mut self) -> Option<i64> {
        self.u64().map(|v| v as i64)
    }

    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }

    fn arr20(&mut self) -> Option<[u8; 20]> {
        self.take(20)?.try_into().ok()
    }

    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }

    fn bytes(&mut self) -> Option<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > MAX_COSMOS_FIELD_BYTES {
            return None;
        }
        Some(self.take(len)?.to_vec())
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn put_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn put_len(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}

fn encode_timestamp(out: &mut Vec<u8>, t: &Timestamp) {
    out.extend_from_slice(&t.seconds.to_le_bytes());
    out.extend_from_slice(&t.nanos.to_le_bytes());
}

fn decode_timestamp(cursor: &mut Cursor) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: cursor.i64()?,
        nanos: cursor.i32()?,
    })
}

fn encode_block_id(out: &mut Vec<u8>, id: &BlockId) {
    put_bytes(out, &id.hash);
    out.extend_from_slice(&id.part_total.to_le_bytes());
    put_bytes(out, &id.part_hash);
}

fn decode_block_id(cursor: &mut Cursor) -> Option<BlockId> {
    Some(BlockId {
        hash: cursor.bytes()?,
        part_total: cursor.u32()?,
        part_hash: cursor.bytes()?,
    })
}

fn encode_header(out: &mut Vec<u8>, h: &Header) {
    out.extend_from_slice(&h.version_block.to_le_bytes());
    out.extend_from_slice(&h.version_app.to_le_bytes());
    put_bytes(out, h.chain_id.as_bytes());
    out.extend_from_slice(&h.height.to_le_bytes());
    encode_timestamp(out, &h.time);
    encode_block_id(out, &h.last_block_id);
    put_bytes(out, &h.last_commit_hash);
    put_bytes(out, &h.data_hash);
    put_bytes(out, &h.validators_hash);
    put_bytes(out, &h.next_validators_hash);
    put_bytes(out, &h.consensus_hash);
    put_bytes(out, &h.app_hash);
    put_bytes(out, &h.last_results_hash);
    put_bytes(out, &h.evidence_hash);
    put_bytes(out, &h.proposer_address);
}

fn decode_header(cursor: &mut Cursor) -> Option<Header> {
    let version_block = cursor.u64()?;
    let version_app = cursor.u64()?;
    let chain_id = String::from_utf8(cursor.bytes()?).ok()?;
    let height = cursor.i64()?;
    let time = decode_timestamp(cursor)?;
    let last_block_id = decode_block_id(cursor)?;
    Some(Header {
        version_block,
        version_app,
        chain_id,
        height,
        time,
        last_block_id,
        last_commit_hash: cursor.bytes()?,
        data_hash: cursor.bytes()?,
        validators_hash: cursor.bytes()?,
        next_validators_hash: cursor.bytes()?,
        consensus_hash: cursor.bytes()?,
        app_hash: cursor.bytes()?,
        last_results_hash: cursor.bytes()?,
        evidence_hash: cursor.bytes()?,
        proposer_address: cursor.bytes()?,
    })
}

fn encode_flag(out: &mut Vec<u8>, flag: &BlockIdFlag) {
    out.push(match flag {
        BlockIdFlag::Absent => 0,
        BlockIdFlag::Commit => 1,
        BlockIdFlag::Nil => 2,
    });
}

fn decode_flag(cursor: &mut Cursor) -> Option<BlockIdFlag> {
    match cursor.u8()? {
        0 => Some(BlockIdFlag::Absent),
        1 => Some(BlockIdFlag::Commit),
        2 => Some(BlockIdFlag::Nil),
        _ => None,
    }
}

fn encode_commit_sig(out: &mut Vec<u8>, sig: &CommitSig) {
    encode_flag(out, &sig.flag);
    out.extend_from_slice(&sig.validator_address);
    encode_timestamp(out, &sig.timestamp);
    put_bytes(out, &sig.signature);
}

fn decode_commit_sig(cursor: &mut Cursor) -> Option<CommitSig> {
    Some(CommitSig {
        flag: decode_flag(cursor)?,
        validator_address: cursor.arr20()?,
        timestamp: decode_timestamp(cursor)?,
        signature: cursor.bytes()?,
    })
}

fn encode_commit(out: &mut Vec<u8>, commit: &Commit) {
    out.extend_from_slice(&commit.height.to_le_bytes());
    out.extend_from_slice(&commit.round.to_le_bytes());
    encode_block_id(out, &commit.block_id);
    put_len(out, commit.signatures.len());
    for sig in &commit.signatures {
        encode_commit_sig(out, sig);
    }
}

fn decode_commit(cursor: &mut Cursor) -> Option<Commit> {
    let height = cursor.i64()?;
    let round = cursor.i64()?;
    let block_id = decode_block_id(cursor)?;
    let count = cursor.u32()? as usize;
    if count > MAX_COSMOS_SIGNERS {
        return None;
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        signatures.push(decode_commit_sig(cursor)?);
    }
    Some(Commit {
        height,
        round,
        block_id,
        signatures,
    })
}

fn encode_validator_set(out: &mut Vec<u8>, set: &ValidatorSet) {
    put_len(out, set.validators.len());
    for v in &set.validators {
        out.extend_from_slice(&v.pubkey);
        out.extend_from_slice(&v.voting_power.to_le_bytes());
    }
}

fn decode_validator_set(cursor: &mut Cursor) -> Option<ValidatorSet> {
    let count = cursor.u32()? as usize;
    if count > MAX_COSMOS_SIGNERS {
        return None;
    }
    let mut validators = Vec::with_capacity(count);
    for _ in 0..count {
        let pubkey = cursor.arr32()?;
        let voting_power = cursor.u64()?;
        validators.push(ValidatorInfo { pubkey, voting_power });
    }
    Some(ValidatorSet { validators })
}

fn encode_existence(out: &mut Vec<u8>, proof: &ExistenceProof) {
    put_bytes(out, &proof.key);
    put_bytes(out, &proof.value);
    put_bytes(out, &proof.leaf.prefix);
    put_len(out, proof.path.len());
    for op in &proof.path {
        put_bytes(out, &op.prefix);
        put_bytes(out, &op.suffix);
    }
    match &proof.store {
        Some(inner) => {
            out.push(1);
            encode_existence(out, inner);
        }
        None => out.push(0),
    }
}

fn decode_existence(cursor: &mut Cursor, depth: usize) -> Option<ExistenceProof> {
    if depth > MAX_COSMOS_STORE_DEPTH {
        return None;
    }
    let key = cursor.bytes()?;
    let value = cursor.bytes()?;
    let leaf = LeafOp {
        prefix: cursor.bytes()?,
    };
    let path_len = cursor.u32()? as usize;
    if path_len > MAX_COSMOS_PATH {
        return None;
    }
    let mut path = Vec::with_capacity(path_len);
    for _ in 0..path_len {
        path.push(InnerOp {
            prefix: cursor.bytes()?,
            suffix: cursor.bytes()?,
        });
    }
    let store = match cursor.u8()? {
        0 => None,
        1 => Some(Box::new(decode_existence(cursor, depth + 1)?)),
        _ => return None,
    };
    Some(ExistenceProof {
        key,
        value,
        leaf,
        path,
        store,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosmosAnchor {
    pub config_selector: u8,
    pub trusted_height: i64,
    pub trusted_time: Timestamp,
    pub trusted_validators_hash: [u8; 32],
    pub asset_id: [u8; 16],
}

impl CosmosAnchor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 12 + 32 + 16);
        out.push(self.config_selector);
        out.extend_from_slice(&self.trusted_height.to_le_bytes());
        encode_timestamp(&mut out, &self.trusted_time);
        out.extend_from_slice(&self.trusted_validators_hash);
        out.extend_from_slice(&self.asset_id);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<CosmosAnchor> {
        let mut cursor = Cursor::new(bytes);
        let config_selector = cursor.u8()?;
        let trusted_height = cursor.i64()?;
        let trusted_time = decode_timestamp(&mut cursor)?;
        let trusted_validators_hash = cursor.arr32()?;
        let asset_id: [u8; 16] = cursor.take(16)?.try_into().ok()?;
        cursor.done().then_some(CosmosAnchor {
            config_selector,
            trusted_height,
            trusted_time,
            trusted_validators_hash,
            asset_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosmosMintProof {
    pub config_selector: u8,
    pub trusted_validators: ValidatorSet,
    pub header: Header,
    pub commit: Commit,
    pub signing_set: ValidatorSet,
    pub proof: ExistenceProof,
}

impl CosmosMintProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.config_selector);
        encode_validator_set(&mut out, &self.trusted_validators);
        encode_header(&mut out, &self.header);
        encode_commit(&mut out, &self.commit);
        encode_validator_set(&mut out, &self.signing_set);
        encode_existence(&mut out, &self.proof);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<CosmosMintProof> {
        let mut cursor = Cursor::new(bytes);
        let config_selector = cursor.u8()?;
        let trusted_validators = decode_validator_set(&mut cursor)?;
        let header = decode_header(&mut cursor)?;
        let commit = decode_commit(&mut cursor)?;
        let signing_set = decode_validator_set(&mut cursor)?;
        let proof = decode_existence(&mut cursor, 0)?;
        cursor.done().then_some(CosmosMintProof {
            config_selector,
            trusted_validators,
            header,
            commit,
            signing_set,
            proof,
        })
    }

    pub fn source_key(&self) -> (u32, [u8; 32]) {
        (
            cosmos_source_chain(self.config_selector),
            sha256(&self.proof.key),
        )
    }
}

pub fn verify_cosmos_mint(
    anchor: &CosmosAnchor,
    proof: &CosmosMintProof,
    dest_chain: u32,
    now: Timestamp,
) -> Option<Fact> {
    if proof.config_selector != anchor.config_selector {
        return None;
    }
    let cfg = config_for_selector(anchor.config_selector)?;
    if proof.trusted_validators.hash() != anchor.trusted_validators_hash {
        return None;
    }
    let trusted = TrustedState {
        height: anchor.trusted_height,
        time: anchor.trusted_time,
        header_hash: [0u8; 32],
        validators: proof.trusted_validators.clone(),
        next_validators_hash: Vec::new(),
    };
    let deposit = verify_trustless_deposit(
        &cfg,
        &trusted,
        &proof.header,
        &proof.commit,
        &proof.signing_set,
        &proof.proof,
        now,
    )
    .ok()?;
    if deposit.amount() == 0 {
        return None;
    }
    if deposit.asset_id() != anchor.asset_id {
        return None;
    }
    Some(Fact {
        version: FACT_VERSION,
        source_chain: cosmos_source_chain(anchor.config_selector),
        dest_chain,
        route_id: 0,
        direction: Direction::Deposit,
        nonce: 0,
        source_ref: deposit.source_ref(),
        asset_id: anchor.asset_id,
        amount: deposit.amount(),
        recipient: deposit.recipient(),
        finality_depth: deposit.confirmations(),
        observed_height: deposit.height(),
        expiry_height: u64::MAX,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_validator_set(n: usize) -> ValidatorSet {
        ValidatorSet {
            validators: (0..n)
                .map(|i| ValidatorInfo {
                    pubkey: [i as u8; 32],
                    voting_power: (i as u64 + 1) * 10,
                })
                .collect(),
        }
    }

    fn dummy_header() -> Header {
        Header {
            version_block: 11,
            version_app: 2,
            chain_id: "cosmoshub-4".to_string(),
            height: 18_500_000,
            time: Timestamp { seconds: 1_700_000_000, nanos: 9 },
            last_block_id: BlockId { hash: vec![0xaa; 32], part_total: 1, part_hash: vec![0xbb; 32] },
            last_commit_hash: vec![0x01; 32],
            data_hash: vec![0x02; 32],
            validators_hash: vec![0x03; 32],
            next_validators_hash: vec![0x04; 32],
            consensus_hash: vec![0x05; 32],
            app_hash: vec![0x06; 32],
            last_results_hash: vec![0x07; 32],
            evidence_hash: vec![0x08; 32],
            proposer_address: vec![0x09; 20],
        }
    }

    fn dummy_commit() -> Commit {
        Commit {
            height: 18_500_000,
            round: 0,
            block_id: BlockId { hash: vec![0xcc; 32], part_total: 1, part_hash: vec![0xdd; 32] },
            signatures: vec![
                CommitSig {
                    flag: BlockIdFlag::Commit,
                    validator_address: [0x11; 20],
                    timestamp: Timestamp { seconds: 1_700_000_001, nanos: 1 },
                    signature: vec![0x7a; 64],
                },
                CommitSig {
                    flag: BlockIdFlag::Absent,
                    validator_address: [0x22; 20],
                    timestamp: Timestamp { seconds: 1_700_000_001, nanos: 2 },
                    signature: vec![],
                },
                CommitSig {
                    flag: BlockIdFlag::Nil,
                    validator_address: [0x33; 20],
                    timestamp: Timestamp { seconds: 1_700_000_001, nanos: 3 },
                    signature: vec![0x9b; 64],
                },
            ],
        }
    }

    fn dummy_existence() -> ExistenceProof {
        ExistenceProof {
            key: b"bridge/deposits/0x1a2b".to_vec(),
            value: vec![0x5c; 64],
            leaf: LeafOp { prefix: vec![0x00, 0x02, 0x00] },
            path: vec![
                InnerOp { prefix: vec![0x01, 0x0a], suffix: vec![0x1b, 0x2c] },
                InnerOp { prefix: vec![0x01], suffix: vec![0x33, 0x44, 0x55] },
            ],
            store: Some(Box::new(ExistenceProof {
                key: b"bridge".to_vec(),
                value: vec![0x99; 32],
                leaf: LeafOp { prefix: vec![0x00] },
                path: vec![],
                store: None,
            })),
        }
    }

    fn dummy_proof() -> CosmosMintProof {
        CosmosMintProof {
            config_selector: 0,
            trusted_validators: dummy_validator_set(4),
            header: dummy_header(),
            commit: dummy_commit(),
            signing_set: dummy_validator_set(4),
            proof: dummy_existence(),
        }
    }

    #[test]
    fn anchor_round_trips_through_its_wire_encoding() {
        let anchor = CosmosAnchor {
            config_selector: 2,
            trusted_height: 18_400_000,
            trusted_time: Timestamp { seconds: 1_699_990_000, nanos: 123 },
            trusted_validators_hash: [0x9a; 32],
            asset_id: *b"qATOM.atom\0\0\0\0\0\0",
        };
        assert_eq!(CosmosAnchor::decode(&anchor.encode()), Some(anchor));
    }

    #[test]
    fn a_trailing_byte_on_the_anchor_is_refused() {
        let anchor = CosmosAnchor {
            config_selector: 0,
            trusted_height: 1,
            trusted_time: Timestamp { seconds: 2, nanos: 3 },
            trusted_validators_hash: [1; 32],
            asset_id: [2; 16],
        };
        let mut bytes = anchor.encode();
        bytes.push(0);
        assert_eq!(CosmosAnchor::decode(&bytes), None);
    }

    #[test]
    fn a_mint_proof_round_trips_through_its_wire_encoding() {
        let proof = dummy_proof();
        assert_eq!(CosmosMintProof::decode(&proof.encode()), Some(proof));
    }

    #[test]
    fn a_nested_store_proof_round_trips() {
        let proof = dummy_proof();
        let decoded = CosmosMintProof::decode(&proof.encode()).unwrap();
        assert!(decoded.proof.store.is_some());
        assert_eq!(decoded.proof.store.unwrap().key, b"bridge".to_vec());
    }

    #[test]
    fn the_source_key_is_per_chain_and_hashes_the_deposit_key() {
        let proof = dummy_proof();
        let (chain, reference) = proof.source_key();
        assert_eq!(chain, cosmos_source_chain(0));
        assert_eq!(reference, sha256(&proof.proof.key));
        assert_ne!(cosmos_source_chain(0), cosmos_source_chain(1));
    }

    #[test]
    fn a_signer_set_over_the_corridor_cap_is_refused_before_any_verification() {
        let mut proof = dummy_proof();
        proof.signing_set = ValidatorSet {
            validators: (0..(MAX_COSMOS_SIGNERS + 1))
                .map(|i| ValidatorInfo { pubkey: [i as u8; 32], voting_power: 1 })
                .collect(),
        };
        assert_eq!(
            CosmosMintProof::decode(&proof.encode()),
            None,
            "an oversized signing set is rejected at decode so it cannot force millions of ed25519 checks"
        );
    }

    #[test]
    fn a_commit_over_the_corridor_cap_is_refused_before_any_verification() {
        let mut proof = dummy_proof();
        proof.commit.signatures = (0..(MAX_COSMOS_SIGNERS + 1))
            .map(|i| CommitSig {
                flag: BlockIdFlag::Commit,
                validator_address: [i as u8; 20],
                timestamp: Timestamp { seconds: 1, nanos: 0 },
                signature: vec![0x11; 64],
            })
            .collect();
        assert_eq!(CosmosMintProof::decode(&proof.encode()), None);
    }

    #[test]
    fn the_chain_now_advances_from_genesis_by_slot_time() {
        let base = chain_now(1_700_000_000, 0);
        assert_eq!(base.seconds, 1_700_000_000);
        let later = chain_now(1_700_000_000, 1_000_000);
        assert!(later.seconds > base.seconds);
    }
}
