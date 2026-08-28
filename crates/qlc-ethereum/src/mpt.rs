// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::keccak::keccak256;
use crate::rlp::{self, Rlp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MptError {
    MissingNode,
    HashMismatch,
    BadNode,
    BadRef,
}

fn to_nibbles(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() * 2);
    for b in key {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

fn decode_hp(bytes: &[u8]) -> (Vec<u8>, bool) {
    if bytes.is_empty() {
        return (Vec::new(), false);
    }
    let flag = bytes[0] >> 4;
    let is_leaf = flag & 2 != 0;
    let odd = flag & 1 != 0;
    let mut nibbles = Vec::new();
    if odd {
        nibbles.push(bytes[0] & 0x0f);
    }
    for b in &bytes[1..] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    (nibbles, is_leaf)
}

fn branch_value(item: &Rlp) -> Option<Vec<u8>> {
    match item {
        Rlp::Bytes(b) if !b.is_empty() => Some(b.clone()),
        _ => None,
    }
}

fn resolve(item: &Rlp, proof: &[Vec<u8>], pi: &mut usize) -> Result<Option<Rlp>, MptError> {
    match item {
        Rlp::List(_) => Ok(Some(item.clone())),
        Rlp::Bytes(b) if b.is_empty() => Ok(None),
        Rlp::Bytes(b) if b.len() == 32 => {
            if *pi >= proof.len() {
                return Err(MptError::MissingNode);
            }
            if keccak256(&proof[*pi]).as_slice() != b.as_slice() {
                return Err(MptError::HashMismatch);
            }
            let node = rlp::decode(&proof[*pi]).map_err(|_| MptError::BadNode)?;
            *pi += 1;
            Ok(Some(node))
        }
        _ => Err(MptError::BadRef),
    }
}

pub fn verify_proof(
    root: &[u8; 32],
    key: &[u8],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, MptError> {
    let nibbles = to_nibbles(key);
    let mut pos = 0usize;
    if proof.is_empty() {
        return Err(MptError::MissingNode);
    }
    if &keccak256(&proof[0]) != root {
        return Err(MptError::HashMismatch);
    }
    let mut current = rlp::decode(&proof[0]).map_err(|_| MptError::BadNode)?;
    let mut pi = 1usize;

    loop {
        let items = current.as_list().ok_or(MptError::BadNode)?;
        match items.len() {
            17 => {
                if pos == nibbles.len() {
                    return Ok(branch_value(&items[16]));
                }
                let n = nibbles[pos] as usize;
                pos += 1;
                match resolve(&items[n], proof, &mut pi)? {
                    Some(node) => current = node,
                    None => return Ok(None),
                }
            }
            2 => {
                let path_bytes = items[0].as_bytes().ok_or(MptError::BadNode)?;
                let (path, is_leaf) = decode_hp(path_bytes);
                let remaining = &nibbles[pos..];
                if is_leaf {
                    if remaining == path.as_slice() {
                        return Ok(Some(items[1].as_bytes().ok_or(MptError::BadNode)?.to_vec()));
                    }
                    return Ok(None);
                }
                if remaining.len() < path.len() || &remaining[..path.len()] != path.as_slice() {
                    return Ok(None);
                }
                pos += path.len();
                match resolve(&items[1], proof, &mut pi)? {
                    Some(node) => current = node,
                    None => return Ok(None),
                }
            }
            _ => return Err(MptError::BadNode),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod builder {
    use super::*;

    #[derive(Debug, Clone)]
    pub enum Node {
        Leaf {
            path: Vec<u8>,
            value: Vec<u8>,
        },
        Extension {
            path: Vec<u8>,
            child: Box<Node>,
        },
        Branch {
            children: Vec<Option<Box<Node>>>,
            value: Option<Vec<u8>>,
        },
    }

    fn hp_encode(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
        let flag = if is_leaf { 2u8 } else { 0u8 };
        let mut out = Vec::new();
        let mut i;
        if nibbles.len() % 2 == 1 {
            out.push(((flag + 1) << 4) | nibbles[0]);
            i = 1;
        } else {
            out.push(flag << 4);
            i = 0;
        }
        while i < nibbles.len() {
            out.push((nibbles[i] << 4) | nibbles[i + 1]);
            i += 2;
        }
        out
    }

    fn common_prefix(entries: &[(Vec<u8>, Vec<u8>)]) -> usize {
        let first = &entries[0].0;
        let mut cp = 0;
        while cp < first.len() {
            let c = first[cp];
            for e in entries {
                if cp >= e.0.len() || e.0[cp] != c {
                    return cp;
                }
            }
            cp += 1;
        }
        cp
    }

    pub fn build(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Node {
        if entries.len() == 1 {
            return Node::Leaf {
                path: entries[0].0.clone(),
                value: entries[0].1.clone(),
            };
        }
        let cp = common_prefix(&entries);
        if cp > 0 {
            let prefix = entries[0].0[..cp].to_vec();
            let stripped: Vec<(Vec<u8>, Vec<u8>)> = entries
                .into_iter()
                .map(|(k, v)| (k[cp..].to_vec(), v))
                .collect();
            return Node::Extension {
                path: prefix,
                child: Box::new(build(stripped)),
            };
        }
        let mut groups: Vec<Vec<(Vec<u8>, Vec<u8>)>> = (0..16).map(|_| Vec::new()).collect();
        let mut value = None;
        for (k, v) in entries {
            if k.is_empty() {
                value = Some(v);
            } else {
                let n = k[0] as usize;
                groups[n].push((k[1..].to_vec(), v));
            }
        }
        let mut children: Vec<Option<Box<Node>>> = (0..16).map(|_| None).collect();
        for (i, g) in groups.into_iter().enumerate() {
            if !g.is_empty() {
                children[i] = Some(Box::new(build(g)));
            }
        }
        Node::Branch { children, value }
    }

    fn child_ref(node: &Node) -> Vec<u8> {
        let enc = encode_node(node);
        if enc.len() < 32 {
            enc
        } else {
            rlp::encode_bytes(&keccak256(&enc))
        }
    }

    pub fn encode_node(node: &Node) -> Vec<u8> {
        match node {
            Node::Leaf { path, value } => rlp::encode_list(&[
                rlp::encode_bytes(&hp_encode(path, true)),
                rlp::encode_bytes(value),
            ]),
            Node::Extension { path, child } => {
                rlp::encode_list(&[rlp::encode_bytes(&hp_encode(path, false)), child_ref(child)])
            }
            Node::Branch { children, value } => {
                let mut items: Vec<Vec<u8>> = Vec::with_capacity(17);
                for c in children {
                    match c {
                        Some(n) => items.push(child_ref(n)),
                        None => items.push(rlp::encode_bytes(&[])),
                    }
                }
                match value {
                    Some(v) => items.push(rlp::encode_bytes(v)),
                    None => items.push(rlp::encode_bytes(&[])),
                }
                rlp::encode_list(&items)
            }
        }
    }

    pub fn root_hash(node: &Node) -> [u8; 32] {
        keccak256(&encode_node(node))
    }

    fn prove_walk(node: &Node, nibbles: &[u8], out: &mut Vec<Vec<u8>>, is_root: bool) {
        let enc = encode_node(node);
        if is_root || enc.len() >= 32 {
            out.push(enc);
        }
        match node {
            Node::Leaf { .. } => {}
            Node::Extension { path, child } => {
                if nibbles.len() >= path.len() && &nibbles[..path.len()] == path.as_slice() {
                    prove_walk(child, &nibbles[path.len()..], out, false);
                }
            }
            Node::Branch { children, .. } => {
                if !nibbles.is_empty() {
                    let n = nibbles[0] as usize;
                    if let Some(c) = &children[n] {
                        prove_walk(c, &nibbles[1..], out, false);
                    }
                }
            }
        }
    }

    pub fn prove(node: &Node, key: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        prove_walk(node, &super::to_nibbles(key), &mut out, true);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::builder::*;
    use super::*;
    use crate::rlp::encode_uint;

    type Entry = (Vec<u8>, Vec<u8>);

    fn receipts_trie(count: usize) -> (Node, Vec<Entry>) {
        let mut entries: Vec<Entry> = Vec::new();
        for i in 0..count {
            let key = encode_uint(i as u64);
            let mut value = Vec::new();
            value.extend_from_slice(b"receipt-payload-must-exceed-thirty-two-bytes-");
            value.push(i as u8);
            entries.push((key, value));
        }
        let nibble_entries: Vec<Entry> = entries
            .iter()
            .map(|(k, v)| (to_nibbles(k), v.clone()))
            .collect();
        (build(nibble_entries), entries)
    }

    #[test]
    fn a_single_entry_trie_proof_verifies() {
        let (node, entries) = receipts_trie(1);
        let root = root_hash(&node);
        let proof = prove(&node, &entries[0].0);
        assert_eq!(
            verify_proof(&root, &entries[0].0, &proof),
            Ok(Some(entries[0].1.clone()))
        );
    }

    #[test]
    fn a_deposit_receipt_proof_verifies_against_the_root() {
        let (node, entries) = receipts_trie(6);
        let root = root_hash(&node);
        for (key, value) in &entries {
            let proof = prove(&node, key);
            assert_eq!(verify_proof(&root, key, &proof), Ok(Some(value.clone())));
        }
    }

    #[test]
    fn a_tampered_proof_node_fails_the_hash_check() {
        let (node, entries) = receipts_trie(6);
        let root = root_hash(&node);
        let mut proof = prove(&node, &entries[3].0);
        let last = proof.len() - 1;
        proof[last][5] ^= 0xff;
        assert_eq!(
            verify_proof(&root, &entries[3].0, &proof),
            Err(MptError::HashMismatch)
        );
    }

    #[test]
    fn a_tampered_root_fails_the_hash_check() {
        let (node, entries) = receipts_trie(6);
        let mut root = root_hash(&node);
        root[0] ^= 0xff;
        let proof = prove(&node, &entries[0].0);
        assert_eq!(
            verify_proof(&root, &entries[0].0, &proof),
            Err(MptError::HashMismatch)
        );
    }

    #[test]
    fn a_proof_for_one_key_does_not_prove_a_different_value() {
        let (node, entries) = receipts_trie(6);
        let root = root_hash(&node);
        let proof = prove(&node, &entries[2].0);
        let got = verify_proof(&root, &entries[2].0, &proof).unwrap().unwrap();
        assert_ne!(got, entries[3].1);
        assert_eq!(got, entries[2].1);
    }

    #[test]
    fn the_root_is_stable_across_rebuilds() {
        let (a, _) = receipts_trie(6);
        let (b, _) = receipts_trie(6);
        assert_eq!(root_hash(&a), root_hash(&b));
    }
}
