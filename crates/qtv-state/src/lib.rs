//! The state trie for the Quantova stack.
//!
//! The state trie is a sparse Merkle trie keyed by a fixed width key and hashed
//! with sha3 256. A leaf holds a value and each inner node holds the sha3 256
//! hash of its two children. The key is thirty two bytes, so the trie has two
//! hundred fifty six levels and a leaf sits at the end of the path that its key
//! bits spell out from the root. An empty subtree takes a fixed default hash,
//! and the default hashes climb from the empty leaf to the empty root by
//! hashing a default with itself at every level.
//!
//! The root is a thirty two byte value fixed by the set of key and value pairs
//! the trie holds, so the order in which inserts are applied never changes it.
//! A proof for a key is the value or an absence marker together with the sibling
//! hash at every level from the leaf to the root. A verifier recomputes the root
//! from the key, the claimed value or absence, and the siblings, and reports
//! whether it matches a given root. Because the trie is sparse an absent key
//! carries a proof of absence in the same shape as a present key carries a proof
//! of presence.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use qtv_codec::{Decode, Decoder, Encode, Encoder, Error};
use qtv_crypto::sha3;

/// The width in bytes of a trie key.
pub const KEY_LEN: usize = 32;

/// The width in bytes of a node hash and of the root.
pub const HASH_LEN: usize = 32;

/// The number of levels in the trie, one for every bit of the key.
pub const DEPTH: usize = KEY_LEN * 8;

/// A fixed width trie key.
pub type Key = [u8; KEY_LEN];

/// A node hash or a root, a thirty two byte value.
pub type Hash = [u8; HASH_LEN];

/// The hash that stands for an empty leaf, the bottom default of the trie.
pub const DEFAULT_LEAF: Hash = [0u8; HASH_LEN];

/// The bit of a key at a level, where level zero is the top bit of the first
/// byte and level two hundred fifty five is the low bit of the last byte.
fn key_bit(key: &Key, level: usize) -> u8 {
    (key[level >> 3] >> (7 - (level & 7))) & 1
}

/// The sha3 256 hash of a value, the leaf hash for a present key.
fn leaf_hash(value: &[u8]) -> Hash {
    sha3::sha3_256(value)
}

/// The sha3 256 hash of a left child followed by a right child.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut input = [0u8; HASH_LEN * 2];
    input[..HASH_LEN].copy_from_slice(left);
    input[HASH_LEN..].copy_from_slice(right);
    sha3::sha3_256(&input)
}

/// The default hash of an empty subtree at each level, from the empty root at
/// level zero down to the empty leaf at level two hundred fifty six.
fn default_hashes() -> Vec<Hash> {
    let mut defaults = vec![DEFAULT_LEAF; DEPTH + 1];
    let mut level = DEPTH;
    while level > 0 {
        level -= 1;
        defaults[level] = node_hash(&defaults[level + 1], &defaults[level + 1]);
    }
    defaults
}

/// A proof for a key. It carries the value when the key is present or nothing
/// when the key is absent, together with the sibling hash at every level from
/// the leaf to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    value: Option<Vec<u8>>,
    siblings: Vec<Hash>,
}

impl Proof {
    /// Assemble a proof from the value or an absence and the sibling hashes.
    pub fn new(value: Option<Vec<u8>>, siblings: Vec<Hash>) -> Self {
        Proof { value, siblings }
    }

    /// The value the proof claims for the key, or nothing for an absence.
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    /// The sibling hashes along the path from the leaf to the root.
    pub fn siblings(&self) -> &[Hash] {
        &self.siblings
    }

    /// Whether the proof claims the key is present.
    pub fn is_present(&self) -> bool {
        self.value.is_some()
    }
}

impl Encode for Proof {
    fn encode(&self, encoder: &mut Encoder) {
        self.value.encode(encoder);
        for sibling in &self.siblings {
            for &byte in sibling.iter() {
                encoder.put_u8(byte);
            }
        }
    }
}

impl Decode for Proof {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let value = Option::<Vec<u8>>::decode(decoder)?;
        let mut siblings = Vec::with_capacity(DEPTH);
        for _ in 0..DEPTH {
            let mut hash = [0u8; HASH_LEN];
            for slot in hash.iter_mut() {
                *slot = decoder.get_u8()?;
            }
            siblings.push(hash);
        }
        Ok(Proof { value, siblings })
    }
}

/// A sparse Merkle trie over a fixed width key. It maps each key to a value and
/// commits to the whole map through a single root.
#[derive(Debug, Clone)]
pub struct Trie {
    leaves: BTreeMap<Key, Vec<u8>>,
    defaults: Vec<Hash>,
}

impl Default for Trie {
    fn default() -> Self {
        Self::new()
    }
}

impl Trie {
    /// Start an empty trie.
    pub fn new() -> Self {
        Trie {
            leaves: BTreeMap::new(),
            defaults: default_hashes(),
        }
    }

    /// Bind a key to a value, replacing any value the key already held.
    pub fn insert(&mut self, key: Key, value: Vec<u8>) {
        self.leaves.insert(key, value);
    }

    /// The value a key holds, or nothing when the key is absent.
    pub fn get(&self, key: &Key) -> Option<&[u8]> {
        self.leaves.get(key).map(|value| value.as_slice())
    }

    /// The root of the trie, fixed by the set of key and value pairs it holds.
    pub fn root(&self) -> Hash {
        let entries = self.entries();
        self.subtree(&entries, 0)
    }

    /// A proof for a key against the current root. The proof carries the value
    /// when the key is present or an absence when the key is missing, together
    /// with the sibling hash at every level.
    pub fn prove(&self, key: &Key) -> Proof {
        let entries = self.entries();
        let mut slice = entries.as_slice();
        let mut siblings = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            let split = slice.partition_point(|entry| key_bit(&entry.0, level) == 0);
            let (left, right) = slice.split_at(split);
            if key_bit(key, level) == 0 {
                siblings.push(self.subtree(right, level + 1));
                slice = left;
            } else {
                siblings.push(self.subtree(left, level + 1));
                slice = right;
            }
        }
        let value = self.leaves.get(key).cloned();
        Proof { value, siblings }
    }

    /// The key and leaf hash pairs of the trie in key order.
    fn entries(&self) -> Vec<(Key, Hash)> {
        self.leaves
            .iter()
            .map(|(key, value)| (*key, leaf_hash(value)))
            .collect()
    }

    /// The hash of the subtree that holds the given entries at a level. The
    /// entries share the first level bits of their keys and stay in key order,
    /// so the split by the bit at this level keeps each side contiguous.
    fn subtree(&self, entries: &[(Key, Hash)], level: usize) -> Hash {
        if entries.is_empty() {
            return self.defaults[level];
        }
        if level == DEPTH {
            return entries[0].1;
        }
        let split = entries.partition_point(|entry| key_bit(&entry.0, level) == 0);
        let (left, right) = entries.split_at(split);
        let left_hash = self.subtree(left, level + 1);
        let right_hash = self.subtree(right, level + 1);
        node_hash(&left_hash, &right_hash)
    }
}

/// Recompute the root from a key, the value or absence the proof claims, and
/// the proof siblings, and report whether it matches the given root. A present
/// value starts from its leaf hash and an absence starts from the empty leaf, so
/// a proof of presence and a proof of absence verify in the same way.
pub fn verify(key: &Key, proof: &Proof, root: &Hash) -> bool {
    if proof.siblings.len() != DEPTH {
        return false;
    }
    let mut node = match &proof.value {
        Some(value) => leaf_hash(value),
        None => DEFAULT_LEAF,
    };
    let mut level = DEPTH;
    while level > 0 {
        level -= 1;
        let sibling = &proof.siblings[level];
        node = if key_bit(key, level) == 0 {
            node_hash(&node, sibling)
        } else {
            node_hash(sibling, &node)
        };
    }
    &node == root
}
