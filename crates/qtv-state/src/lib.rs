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

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

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

// A count of inner node hashes, kept only in test builds so a test can assert
// that a change rehashes a bounded set of nodes and not the whole trie.
#[cfg(test)]
thread_local! {
    static NODE_HASHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The sha3 256 hash of a left child followed by a right child.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    #[cfg(test)]
    NODE_HASHES.with(|count| count.set(count.get() + 1));
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

/// The key that shares the top `level` bits of a prefix and sets the bit at
/// `level` to one, the prefix of the right child of a node at that level.
fn with_bit(key: &Key, level: usize) -> Key {
    let mut out = *key;
    out[level >> 3] |= 1u8 << (7 - (level & 7));
    out
}

/// The largest key that shares the top `level` bits of a canonical prefix, the
/// upper bound of the subtree rooted at that prefix. Every bit at `level` and
/// below is set. At or past the leaf level there is no bit to set, so the prefix
/// is its own bound.
fn subtree_end(prefix: &Key, level: usize) -> Key {
    let byte = level >> 3;
    if byte >= KEY_LEN {
        return *prefix;
    }
    let mut out = *prefix;
    out[byte] |= 255u8 >> (level & 7);
    for slot in out.iter_mut().skip(byte + 1) {
        *slot = 255;
    }
    out
}

/// A node identifier: the level and the canonical prefix that shares the top
/// `level` bits of every key in the subtree, with the bits at `level` and below
/// set to zero. Every subtree has one identifier that no other subtree shares.
type NodeId = (u16, Key);

/// The hash of the subtree that holds a single leaf, climbing from the leaf hash
/// at the bottom up to `from_level`. At each level the lone leaf sits on the side
/// its key bit picks and the empty side takes the default of the level below.
fn chain_hash(defaults: &[Hash], key: &Key, leaf: Hash, from_level: usize) -> Hash {
    let mut hash = leaf;
    let mut level = DEPTH;
    while level > from_level {
        level -= 1;
        let default = defaults[level + 1];
        hash = if key_bit(key, level) == 0 {
            node_hash(&hash, &default)
        } else {
            node_hash(&default, &hash)
        };
    }
    hash
}

/// The hash of a subtree that no changed leaf touches, read without descending
/// into it. An empty subtree takes the default of its level, a subtree with a
/// single leaf takes that leaf climbed to this level, and a subtree with two or
/// more leaves takes its cached hash, which the last recompute fixed and no
/// change since has moved.
fn clean_hash(
    leaves: &BTreeMap<Key, Vec<u8>>,
    defaults: &[Hash],
    nodes: &HashMap<NodeId, Hash>,
    level: usize,
    prefix: Key,
) -> Hash {
    let end = subtree_end(&prefix, level);
    let mut range = leaves.range(prefix..=end);
    match (range.next(), range.next()) {
        (None, _) => defaults[level],
        (Some((key, value)), None) => chain_hash(defaults, key, leaf_hash(value), level),
        (Some(_), Some(_)) => *nodes
            .get(&(level as u16, prefix))
            .expect("a subtree with two or more leaves is a cached node"),
    }
}

/// Recompute the hash of the subtree rooted at `prefix` and `level`, descending
/// only where a changed key lies and reading every untouched sibling from the
/// cache. The changed keys are sorted and all share the top `level` bits, so the
/// split by the bit at this level keeps each side contiguous, matching the split
/// the full recompute makes. Each recomputed node updates its cache entry: a
/// subtree that now holds two or more leaves stores its hash, otherwise its entry
/// is dropped, so the cache always holds exactly the branch nodes.
fn recompute(
    leaves: &BTreeMap<Key, Vec<u8>>,
    defaults: &[Hash],
    nodes: &mut HashMap<NodeId, Hash>,
    level: usize,
    prefix: Key,
    changed: &[Key],
) -> Hash {
    if level == DEPTH {
        return match leaves.get(&prefix) {
            Some(value) => leaf_hash(value),
            None => defaults[DEPTH],
        };
    }
    let split = changed.partition_point(|key| key_bit(key, level) == 0);
    let (changed_left, changed_right) = changed.split_at(split);
    let right_prefix = with_bit(&prefix, level);
    let left = if changed_left.is_empty() {
        clean_hash(leaves, defaults, nodes, level + 1, prefix)
    } else {
        recompute(leaves, defaults, nodes, level + 1, prefix, changed_left)
    };
    let right = if changed_right.is_empty() {
        clean_hash(leaves, defaults, nodes, level + 1, right_prefix)
    } else {
        recompute(
            leaves,
            defaults,
            nodes,
            level + 1,
            right_prefix,
            changed_right,
        )
    };
    let hash = node_hash(&left, &right);
    let end = subtree_end(&prefix, level);
    let branch = leaves.range(prefix..=end).take(2).count() >= 2;
    let id = (level as u16, prefix);
    if branch {
        nodes.insert(id, hash);
    } else {
        nodes.remove(&id);
    }
    hash
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

/// The incremental state of a trie root: the cached hash of every branch node,
/// the last root, and the keys changed since that root was computed. It is held
/// behind a cell so that reading the root can fold in the pending changes without
/// a mutable handle, which keeps the read facing shape of the trie.
#[derive(Debug, Clone)]
struct RootCache {
    nodes: HashMap<NodeId, Hash>,
    root: Hash,
    changed: BTreeSet<Key>,
}

/// A sparse Merkle trie over a fixed width key. It maps each key to a value and
/// commits to the whole map through a single root. The root is kept incrementally:
/// an insert records the changed key, and the next root recomputes only the paths
/// from the changed leaves up to the root, reusing every untouched subtree hash,
/// so a block costs the changed count times the depth rather than the whole state.
#[derive(Debug, Clone)]
pub struct Trie {
    leaves: BTreeMap<Key, Vec<u8>>,
    defaults: Vec<Hash>,
    cache: RefCell<RootCache>,
    /// Keys changed since the last persist. A persisting node drains these to write back exactly the
    /// keys a block changed, accounts and protocol singletons alike, so a reload reconstructs the
    /// identical state. It is separate from the root cache's changed set, which is cleared on every
    /// root recomputation and so cannot track what still needs to reach disk.
    persist_dirty: BTreeSet<Key>,
}

impl Default for Trie {
    fn default() -> Self {
        Self::new()
    }
}

impl Trie {
    /// Start an empty trie.
    pub fn new() -> Self {
        let defaults = default_hashes();
        let cache = RootCache {
            nodes: HashMap::new(),
            root: defaults[0],
            changed: BTreeSet::new(),
        };
        Trie {
            leaves: BTreeMap::new(),
            defaults,
            cache: RefCell::new(cache),
            persist_dirty: BTreeSet::new(),
        }
    }

    /// Drain the keys changed since the last call. A persisting node writes exactly these back.
    pub fn take_persist_dirty(&mut self) -> Vec<Key> {
        std::mem::take(&mut self.persist_dirty).into_iter().collect()
    }

    /// Clear the persist set without persisting, for after genesis writes the whole state, or after a
    /// reload where the state is already on disk.
    pub fn clear_persist_dirty(&mut self) {
        self.persist_dirty.clear();
    }

    /// Bind a key to a value, replacing any value the key already held. The key
    /// is recorded as changed so the next root recomputes only its path.
    pub fn insert(&mut self, key: Key, value: Vec<u8>) {
        self.leaves.insert(key, value);
        self.cache.get_mut().changed.insert(key);
        self.persist_dirty.insert(key);
    }

    /// The value a key holds, or nothing when the key is absent.
    pub fn get(&self, key: &Key) -> Option<&[u8]> {
        self.leaves.get(key).map(|value| value.as_slice())
    }

    /// The whole leaf map, for a reader that wants to snapshot many keys across threads. This borrows
    /// the leaves immutably and never touches the root cache, so it is a pure read and safe to share
    /// across threads, unlike the trie itself which holds a single threaded root cache. A block
    /// executor uses this to read a layer's accounts in parallel before it applies the layer's writes.
    pub fn leaves(&self) -> &BTreeMap<Key, Vec<u8>> {
        &self.leaves
    }

    /// The root of the trie, fixed by the set of key and value pairs it holds.
    /// Only the paths from the keys changed since the last root are recomputed,
    /// and every other subtree hash is read from the cache, so the root is bit
    /// identical to a full recompute over the same leaves at a fraction of the
    /// cost. With no pending change the cached root is returned unchanged.
    pub fn root(&self) -> Hash {
        let mut cache = self.cache.borrow_mut();
        if cache.changed.is_empty() {
            return cache.root;
        }
        let changed: Vec<Key> = cache.changed.iter().copied().collect();
        let root = recompute(
            &self.leaves,
            &self.defaults,
            &mut cache.nodes,
            0,
            [0u8; KEY_LEN],
            &changed,
        );
        cache.root = root;
        cache.changed.clear();
        root
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

#[cfg(test)]
mod incremental {
    //! The incremental root must equal a full recompute over the same leaves for
    //! every state and every change set, an unchanged block must leave the root
    //! where it was, and a single change must rehash only the path from its leaf
    //! to the root. These tests fix all three.

    use super::*;

    /// A small deterministic generator, splitmix64, so the change sets are varied
    /// but the tests are reproducible without a dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(11400714819323198485);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(13787848793156543929);
            z = (z ^ (z >> 27)).wrapping_mul(10723151780598845931);
            z ^ (z >> 31)
        }

        fn key(&mut self) -> Key {
            let mut key = [0u8; KEY_LEN];
            for chunk in key.chunks_mut(8) {
                let bytes = self.next().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            key
        }

        fn value(&mut self) -> Vec<u8> {
            self.next().to_le_bytes().to_vec()
        }
    }

    /// The root computed by a full recursive walk over every leaf, the original
    /// commitment the incremental root must reproduce bit for bit. This is written
    /// out on its own so it shares no state with the incremental path.
    fn reference_root(leaves: &BTreeMap<Key, Vec<u8>>) -> Hash {
        let defaults = default_hashes();
        let entries: Vec<(Key, Hash)> = leaves
            .iter()
            .map(|(key, value)| (*key, leaf_hash(value)))
            .collect();
        fn walk(entries: &[(Key, Hash)], level: usize, defaults: &[Hash]) -> Hash {
            if entries.is_empty() {
                return defaults[level];
            }
            if level == DEPTH {
                return entries[0].1;
            }
            let split = entries.partition_point(|entry| key_bit(&entry.0, level) == 0);
            let (left, right) = entries.split_at(split);
            node_hash(
                &walk(left, level + 1, defaults),
                &walk(right, level + 1, defaults),
            )
        }
        walk(&entries, 0, &defaults)
    }

    /// The prefix that shares the top `level` bits of a key, the identifier a node
    /// on the path of the key carries at that level.
    fn ancestor_prefix(key: &Key, level: usize) -> Key {
        let mut out = *key;
        let byte = level >> 3;
        if byte < KEY_LEN {
            out[byte] &= !(255u8 >> (level & 7));
            for slot in out.iter_mut().skip(byte + 1) {
                *slot = 0;
            }
        }
        out
    }

    fn node_hashes() -> u64 {
        NODE_HASHES.with(|count| count.get())
    }

    fn reset_node_hashes() {
        NODE_HASHES.with(|count| count.set(0));
    }

    #[test]
    fn incremental_root_equals_full_recompute_across_random_change_sets() {
        let mut rng = Rng(72623859790382856);
        let mut trie = Trie::new();
        let mut mirror: BTreeMap<Key, Vec<u8>> = BTreeMap::new();
        let mut keys: Vec<Key> = Vec::new();

        // A base state of a few hundred accounts.
        for _ in 0..400 {
            let key = rng.key();
            let value = rng.value();
            trie.insert(key, value.clone());
            mirror.insert(key, value);
            keys.push(key);
        }
        assert_eq!(trie.root(), reference_root(&mirror));

        // Many blocks, each a random mix of fresh accounts and rewrites of
        // existing ones. After each block the incremental root and a full
        // recompute over the same leaves must be bit identical.
        for _ in 0..200 {
            let batch = (rng.next() % 40) as usize + 1;
            for _ in 0..batch {
                let fresh = keys.is_empty() || rng.next().is_multiple_of(2);
                let key = if fresh {
                    let key = rng.key();
                    keys.push(key);
                    key
                } else {
                    keys[(rng.next() as usize) % keys.len()]
                };
                let value = rng.value();
                trie.insert(key, value.clone());
                mirror.insert(key, value);
            }
            assert_eq!(trie.root(), reference_root(&mirror));
        }
    }

    #[test]
    fn a_block_that_changes_nothing_leaves_the_root_where_it_was() {
        let mut rng = Rng(2459584641779389781);
        let mut trie = Trie::new();
        for _ in 0..250 {
            trie.insert(rng.key(), rng.value());
        }
        let root = trie.root();

        // Reading the root again with no pending change returns the same bytes and
        // does not rehash a single node.
        reset_node_hashes();
        assert_eq!(trie.root(), root);
        assert_eq!(node_hashes(), 0);

        // Rewriting a key with the value it already holds recomputes its path but
        // lands on the same root, since the leaves are unchanged.
        let (key, value) = {
            let (key, value) = trie.leaves.iter().next().unwrap();
            (*key, value.clone())
        };
        trie.insert(key, value);
        assert_eq!(trie.root(), root);
    }

    #[test]
    fn a_single_change_rehashes_only_its_path_over_a_deep_tree() {
        let mut rng = Rng(11068027678940948070);
        let count = 20_000usize;
        let mut trie = Trie::new();
        let mut keys: Vec<Key> = Vec::with_capacity(count);
        for _ in 0..count {
            let key = rng.key();
            trie.insert(key, rng.value());
            keys.push(key);
        }

        // The cost of the first root over the whole state, the full recompute the
        // incremental path must beat.
        reset_node_hashes();
        let _ = trie.root();
        let full = node_hashes();
        assert!(
            full > count as u64,
            "a full recompute walks the whole state"
        );

        // Change one existing account and read the root again. Record which cached
        // nodes moved and how many hashes the update cost.
        let target = keys[keys.len() / 3];
        let before: HashMap<NodeId, Hash> = trie.cache.borrow().nodes.clone();
        reset_node_hashes();
        trie.insert(target, b"a new account record".to_vec());
        let _ = trie.root();
        let single = node_hashes();
        let after = trie.cache.borrow().nodes.clone();

        // Every cached node whose hash changed lies on the path of the changed
        // key: its prefix is the key masked to its level. Nothing off the path
        // moved.
        for (id, hash) in &after {
            let moved = before.get(id) != Some(hash);
            if moved {
                let (level, prefix) = *id;
                assert_eq!(
                    prefix,
                    ancestor_prefix(&target, level as usize),
                    "a moved node at level {level} is off the path of the changed key"
                );
            }
        }
        // No node dropped off the path either.
        for id in before.keys() {
            if !after.contains_key(id) {
                let (level, prefix) = *id;
                assert_eq!(prefix, ancestor_prefix(&target, level as usize));
            }
        }

        // The update touches a bounded number of hashes, on the order of the tree
        // depth, not the whole state. The path is at most the depth, plus the odd
        // lone sibling climbed from its leaf, so a few multiples of the depth is a
        // safe ceiling that still sits far under the full recompute.
        assert!(
            single <= 8 * DEPTH as u64,
            "a single change cost {single} hashes, more than a path"
        );
        assert!(
            single * 20 < full,
            "a single change cost {single} hashes against a full recompute of {full}"
        );
    }

    #[test]
    fn a_new_account_added_to_a_large_state_matches_a_full_recompute() {
        let mut rng = Rng(12379570966709706497);
        let mut trie = Trie::new();
        let mut mirror: BTreeMap<Key, Vec<u8>> = BTreeMap::new();
        for _ in 0..5_000 {
            let key = rng.key();
            let value = rng.value();
            trie.insert(key, value.clone());
            mirror.insert(key, value);
        }
        let _ = trie.root();

        let key = rng.key();
        let value = rng.value();
        trie.insert(key, value.clone());
        mirror.insert(key, value);
        assert_eq!(trie.root(), reference_root(&mirror));

        // The proof for the new account verifies against the incremental root.
        let root = trie.root();
        let proof = trie.prove(&key);
        assert!(verify(&key, &proof, &root));
    }
}
