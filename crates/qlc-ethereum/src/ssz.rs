// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qlc_bitcoin::sha256;

pub const CHUNK: usize = 32;

pub fn zero_chunk() -> [u8; CHUNK] {
    [0u8; CHUNK]
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(left);
    buf[32..64].copy_from_slice(right);
    sha256(&buf)
}

pub fn uint64_root(value: u64) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[0..8].copy_from_slice(&value.to_le_bytes());
    chunk
}

fn next_power_of_two(n: usize) -> usize {
    let mut p = 1;
    while p < n {
        p <<= 1;
    }
    p
}

pub fn merkleize(chunks: &[[u8; 32]]) -> [u8; 32] {
    if chunks.is_empty() {
        return zero_chunk();
    }
    let width = next_power_of_two(chunks.len());
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(width);
    level.extend_from_slice(chunks);
    while level.len() < width {
        level.push(zero_chunk());
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

pub fn bytes48_root(pubkey: &[u8; 48]) -> [u8; 32] {
    let mut chunk0 = [0u8; 32];
    chunk0.copy_from_slice(&pubkey[0..32]);
    let mut chunk1 = [0u8; 32];
    chunk1[0..16].copy_from_slice(&pubkey[32..48]);
    hash_pair(&chunk0, &chunk1)
}

pub fn is_valid_merkle_branch(
    leaf: &[u8; 32],
    branch: &[[u8; 32]],
    depth: usize,
    index: u64,
    root: &[u8; 32],
) -> bool {
    if branch.len() != depth {
        return false;
    }
    let mut value = *leaf;
    for (i, sibling) in branch.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            value = hash_pair(sibling, &value);
        } else {
            value = hash_pair(&value, sibling);
        }
    }
    &value == root
}

pub fn merkle_root_from_branch(leaf: &[u8; 32], branch: &[[u8; 32]], index: u64) -> [u8; 32] {
    let mut value = *leaf;
    for (i, sibling) in branch.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            value = hash_pair(sibling, &value);
        } else {
            value = hash_pair(&value, sibling);
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_chunk_merkleizes_to_itself() {
        let c = [7u8; 32];
        assert_eq!(merkleize(&[c]), c);
    }

    #[test]
    fn two_chunks_merkleize_to_their_pair_hash() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(merkleize(&[a, b]), hash_pair(&a, &b));
    }

    #[test]
    fn five_chunks_pad_to_eight_leaves() {
        let chunks: Vec<[u8; 32]> = (0..5).map(|i| [i as u8; 32]).collect();
        let z = zero_chunk();
        let l01 = hash_pair(&chunks[0], &chunks[1]);
        let l23 = hash_pair(&chunks[2], &chunks[3]);
        let l45 = hash_pair(&chunks[4], &z);
        let l67 = hash_pair(&z, &z);
        let expected = hash_pair(&hash_pair(&l01, &l23), &hash_pair(&l45, &l67));
        assert_eq!(merkleize(&chunks), expected);
    }

    #[test]
    fn a_constructed_branch_verifies_at_its_index() {
        let leaf = [0x42u8; 32];
        let branch = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
        let index = 5u64;
        let root = merkle_root_from_branch(&leaf, &branch, index);
        assert!(is_valid_merkle_branch(&leaf, &branch, 3, index, &root));
    }

    #[test]
    fn a_branch_at_the_wrong_index_does_not_verify() {
        let leaf = [0x42u8; 32];
        let branch = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
        let root = merkle_root_from_branch(&leaf, &branch, 5);
        assert!(!is_valid_merkle_branch(&leaf, &branch, 3, 4, &root));
    }

    #[test]
    fn a_tampered_leaf_does_not_verify() {
        let leaf = [0x42u8; 32];
        let branch = [[0x01u8; 32], [0x02u8; 32]];
        let root = merkle_root_from_branch(&leaf, &branch, 1);
        let mut bad = leaf;
        bad[0] ^= 0xff;
        assert!(!is_valid_merkle_branch(&bad, &branch, 2, 1, &root));
    }

    #[test]
    fn a_branch_of_the_wrong_depth_is_refused() {
        let leaf = [0x42u8; 32];
        let branch = [[0x01u8; 32], [0x02u8; 32]];
        let root = merkle_root_from_branch(&leaf, &branch, 1);
        assert!(!is_valid_merkle_branch(&leaf, &branch, 3, 1, &root));
    }
}
