#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod chain;
pub mod deposit;
pub mod params;
pub mod retarget;
pub mod sha256;
pub mod tx;
pub mod work;

pub use chain::{
    bits_expectation, check_retarget_boundary, heavier, verify_chain, Checkpoint, ConfirmedDeposit,
    VerifiedChain,
};
pub use deposit::{verify_trustless_deposit, TrustlessDeposit};
pub use params::{network_params, Network, NetworkParams, BITCOIN, BITCOIN_CASH};
pub use retarget::compute_retarget;
pub use sha256::{double_sha256, sha256};
pub use work::{block_work, U256};

pub const HEADER_LEN: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpvError {
    ShortHeader,
    PowNotMet,
    TargetBelowFloor { index: usize },
    BrokenLink { index: usize },
    EmptyChain,
    MerkleMismatch,
    RetargetOnANonBoundary { index: usize },
    RetargetMismatch { index: usize },
    HeightOverflow,
    HeightOutOfRange,
    InsufficientConfirmations { have: u32, need: u32 },
    CheckpointNotInChain,
    CheckpointMismatch,
    InsufficientWork,
    CheckpointNotArmed,
    MalformedTransaction,
    TransactionMismatch,
    MerkleBranchTooLong,
}

pub const MAX_MERKLE_BRANCH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleStep {
    pub hash: [u8; 32],
    pub sibling_on_left: bool,
}

impl BlockHeader {
    pub fn parse(bytes: &[u8]) -> Result<BlockHeader, SpvError> {
        if bytes.len() < HEADER_LEN {
            return Err(SpvError::ShortHeader);
        }
        let mut prev_block = [0u8; 32];
        prev_block.copy_from_slice(&bytes[4..36]);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[36..68]);
        Ok(BlockHeader {
            version: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            prev_block,
            merkle_root,
            timestamp: u32::from_le_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]),
            bits: u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]),
            nonce: u32::from_le_bytes([bytes[76], bytes[77], bytes[78], bytes[79]]),
        })
    }

    pub fn serialize(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_block);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.timestamp.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn block_hash(&self) -> [u8; 32] {
        double_sha256(&self.serialize())
    }

    pub fn pow_hash_be(&self) -> [u8; 32] {
        let mut h = self.block_hash();
        h.reverse();
        h
    }

    pub fn target(&self) -> [u8; 32] {
        compact_to_target(self.bits)
    }

    pub fn meets_pow(&self) -> bool {
        self.pow_hash_be() <= self.target()
    }
}

pub fn compact_to_target(bits: u32) -> [u8; 32] {
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x007f_ffff;
    let mant_bytes = [(mant >> 16) as u8, (mant >> 8) as u8, mant as u8];
    let mut target = [0u8; 32];
    if (3..=32).contains(&exp) {
        let msb_index = 32 - exp;
        for (i, b) in mant_bytes.iter().enumerate() {
            let idx = msb_index + i;
            if idx < 32 {
                target[idx] = *b;
            }
        }
    } else if exp < 3 {
        let shift = 8 * (3 - exp);
        let v = mant >> shift;
        target[29] = (v >> 16) as u8;
        target[30] = (v >> 8) as u8;
        target[31] = v as u8;
    }
    target
}

pub fn merkle_root(txids: &[[u8; 32]]) -> Option<[u8; 32]> {
    if txids.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level[level.len() - 1];
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            let mut buf = [0u8; 64];
            buf[0..32].copy_from_slice(&pair[0]);
            buf[32..64].copy_from_slice(&pair[1]);
            next.push(double_sha256(&buf));
        }
        level = next;
    }
    Some(level[0])
}

pub fn fold_merkle_branch(txid: [u8; 32], branch: &[MerkleStep]) -> Result<[u8; 32], SpvError> {
    if branch.len() > MAX_MERKLE_BRANCH {
        return Err(SpvError::MerkleBranchTooLong);
    }
    let mut cur = txid;
    for step in branch {
        if step.hash == cur && step.sibling_on_left {
            return Err(SpvError::MerkleMismatch);
        }
        let mut buf = [0u8; 64];
        if step.sibling_on_left {
            buf[0..32].copy_from_slice(&step.hash);
            buf[32..64].copy_from_slice(&cur);
        } else {
            buf[0..32].copy_from_slice(&cur);
            buf[32..64].copy_from_slice(&step.hash);
        }
        cur = double_sha256(&buf);
    }
    Ok(cur)
}

pub fn verify_inclusion(
    header: &BlockHeader,
    txid: [u8; 32],
    branch: &[MerkleStep],
) -> Result<(), SpvError> {
    if !header.meets_pow() {
        return Err(SpvError::PowNotMet);
    }
    if fold_merkle_branch(txid, branch)? != header.merkle_root {
        return Err(SpvError::MerkleMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parse_never_panics_on_hostile_bytes() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut rng = || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        for _ in 0..200_000 {
            let len = (rng() % 160) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((rng() & 0xff) as u8);
            }
            let _ = BlockHeader::parse(&buf);
        }
    }

    fn from_hex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    const GENESIS: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    #[test]
    fn genesis_block_hash_matches_the_real_chain() {
        let header = BlockHeader::parse(&from_hex(GENESIS)).unwrap();
        assert_eq!(
            to_hex(&header.pow_hash_be()),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn genesis_meets_its_proof_of_work() {
        let header = BlockHeader::parse(&from_hex(GENESIS)).unwrap();
        assert!(header.meets_pow());
    }

    #[test]
    fn tampered_nonce_fails_proof_of_work() {
        let mut header = BlockHeader::parse(&from_hex(GENESIS)).unwrap();
        header.nonce = header.nonce.wrapping_add(1);
        assert!(!header.meets_pow());
    }

    #[test]
    fn genesis_target_is_the_known_value() {
        let header = BlockHeader::parse(&from_hex(GENESIS)).unwrap();
        assert_eq!(
            to_hex(&header.target()),
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn single_coinbase_merkle_root_equals_header_root() {
        let header = BlockHeader::parse(&from_hex(GENESIS)).unwrap();
        let coinbase = header.merkle_root;
        assert_eq!(merkle_root(&[coinbase]).unwrap(), header.merkle_root);
    }

    #[test]
    fn inclusion_of_the_coinbase_verifies_against_the_header() {
        let header = BlockHeader::parse(&from_hex(GENESIS)).unwrap();
        let coinbase = header.merkle_root;
        assert!(verify_inclusion(&header, coinbase, &[]).is_ok());
    }

    #[test]
    fn merkle_branch_folds_to_the_root_for_two_transactions() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let root = merkle_root(&[a, b]).unwrap();
        let branch = [MerkleStep {
            hash: b,
            sibling_on_left: false,
        }];
        assert_eq!(fold_merkle_branch(a, &branch).unwrap(), root);
    }

    #[test]
    fn a_branch_that_reuses_the_current_node_as_its_sibling_is_rejected() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let c = [0x33u8; 32];
        let root = merkle_root(&[a, b, c]).unwrap();

        let mut ab = [0u8; 64];
        ab[0..32].copy_from_slice(&a);
        ab[32..64].copy_from_slice(&b);
        let h_ab = double_sha256(&ab);

        let mut cc = [0u8; 64];
        cc[0..32].copy_from_slice(&c);
        cc[32..64].copy_from_slice(&c);
        let h_cc = double_sha256(&cc);

        let mut top = [0u8; 64];
        top[0..32].copy_from_slice(&h_ab);
        top[32..64].copy_from_slice(&h_cc);
        assert_eq!(double_sha256(&top), root);

        let branch = [
            MerkleStep {
                hash: c,
                sibling_on_left: false,
            },
            MerkleStep {
                hash: h_ab,
                sibling_on_left: true,
            },
        ];
        assert_eq!(fold_merkle_branch(c, &branch), Ok(root));

        let forged = [MerkleStep {
            hash: c,
            sibling_on_left: true,
        }];
        assert_eq!(
            fold_merkle_branch(c, &forged),
            Err(SpvError::MerkleMismatch)
        );
    }

    #[test]
    fn broken_link_is_detected() {
        let header = BlockHeader::parse(&from_hex(GENESIS)).unwrap();
        let mut second = header;
        second.prev_block = [0u8; 32];
        assert_eq!(
            crate::chain::verify_chain(&[header, second], 0, &crate::params::BITCOIN),
            Err(SpvError::BrokenLink { index: 1 })
        );
    }
}
