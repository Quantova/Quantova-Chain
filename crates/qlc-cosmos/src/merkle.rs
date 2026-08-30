// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::sha256::sha256;

pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + leaf.len());
    buf.push(0x00);
    buf.extend_from_slice(leaf);
    sha256(&buf)
}

pub fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 64);
    buf.push(0x01);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

fn largest_pow2_lt(n: usize) -> usize {
    let mut k = 1;
    while k < n - k {
        k *= 2;
    }
    k
}

pub fn merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256(&[]),
        1 => leaf_hash(&leaves[0]),
        n => {
            let k = largest_pow2_lt(n);
            let left = merkle_root(&leaves[..k]);
            let right = merkle_root(&leaves[k..]);
            inner_hash(&left, &right)
        }
    }
}

pub fn proof_aunts(leaves: &[Vec<u8>], index: usize) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = largest_pow2_lt(n);
    if index < k {
        let right = merkle_root(&leaves[k..]);
        let mut inner = proof_aunts(&leaves[..k], index);
        inner.push(right);
        inner
    } else {
        let left = merkle_root(&leaves[..k]);
        let mut inner = proof_aunts(&leaves[k..], index - k);
        inner.push(left);
        inner
    }
}

fn compute_root(
    index: usize,
    total: usize,
    leaf_hash: [u8; 32],
    aunts: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if total == 0 || index >= total {
        return None;
    }
    if total == 1 {
        if aunts.is_empty() {
            Some(leaf_hash)
        } else {
            None
        }
    } else {
        if aunts.is_empty() {
            return None;
        }
        let top = aunts[aunts.len() - 1];
        let rest = &aunts[..aunts.len() - 1];
        let k = largest_pow2_lt(total);
        if index < k {
            let left = compute_root(index, k, leaf_hash, rest)?;
            Some(inner_hash(&left, &top))
        } else {
            let right = compute_root(index - k, total - k, leaf_hash, rest)?;
            Some(inner_hash(&top, &right))
        }
    }
}

pub fn verify_inclusion(
    root: &[u8; 32],
    leaf: &[u8],
    index: usize,
    total: usize,
    aunts: &[[u8; 32]],
) -> bool {
    match compute_root(index, total, leaf_hash(leaf), aunts) {
        Some(r) => &r == root,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i as u8, 0xaa, 0xbb]).collect()
    }

    #[test]
    fn single_leaf_root_is_its_leaf_hash() {
        let l = leaves(1);
        assert_eq!(merkle_root(&l), leaf_hash(&l[0]));
    }

    #[test]
    fn two_leaf_root_is_the_inner_of_two_leaf_hashes() {
        let l = leaves(2);
        let expected = inner_hash(&leaf_hash(&l[0]), &leaf_hash(&l[1]));
        assert_eq!(merkle_root(&l), expected);
    }

    #[test]
    fn every_leaf_of_an_unbalanced_tree_proves_inclusion() {
        let l = leaves(7);
        let root = merkle_root(&l);
        for i in 0..7 {
            let aunts = proof_aunts(&l, i);
            assert!(
                verify_inclusion(&root, &l[i], i, 7, &aunts),
                "leaf {} failed",
                i
            );
        }
    }

    #[test]
    fn a_tampered_leaf_does_not_prove() {
        let l = leaves(5);
        let root = merkle_root(&l);
        let aunts = proof_aunts(&l, 2);
        let mut tampered = l[2].clone();
        tampered[0] ^= 0xff;
        assert!(!verify_inclusion(&root, &tampered, 2, 5, &aunts));
    }

    #[test]
    fn a_tampered_aunt_does_not_prove() {
        let l = leaves(5);
        let root = merkle_root(&l);
        let mut aunts = proof_aunts(&l, 2);
        aunts[0][0] ^= 0xff;
        assert!(!verify_inclusion(&root, &l[2], 2, 5, &aunts));
    }

    #[test]
    fn a_wrong_index_does_not_prove() {
        let l = leaves(6);
        let root = merkle_root(&l);
        let aunts = proof_aunts(&l, 4);
        assert!(!verify_inclusion(&root, &l[4], 1, 6, &aunts));
    }

    #[test]
    fn a_hostile_total_near_the_usize_ceiling_fails_closed_without_overflowing() {
        let leaf = [0x42u8; 32];
        let aunts = [[0u8; 32]];
        assert!(!verify_inclusion(&[0u8; 32], &leaf, 0, usize::MAX, &aunts));
        assert!(!verify_inclusion(
            &[0u8; 32],
            &leaf,
            0,
            (1usize << 63) + 1,
            &aunts
        ));
    }
}
