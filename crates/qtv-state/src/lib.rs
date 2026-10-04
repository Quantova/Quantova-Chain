// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use qtv_codec::{Decode, Decoder, Encode, Encoder, Error};
use qtv_crypto::sha3;

pub const KEY_LEN: usize = 32;

pub const HASH_LEN: usize = 32;

pub const DEPTH: usize = KEY_LEN * 8;

pub type Key = [u8; KEY_LEN];

pub type Hash = [u8; HASH_LEN];

pub const DEFAULT_LEAF: Hash = [0u8; HASH_LEN];

fn key_bit(key: &Key, level: usize) -> u8 {
    (key[level >> 3] >> (7 - (level & 7))) & 1
}

const LEAF_DOMAIN: u8 = 0x00;
const NODE_DOMAIN: u8 = 0x01;

fn leaf_hash(value: &[u8]) -> Hash {
    let mut input = Vec::with_capacity(1 + value.len());
    input.push(LEAF_DOMAIN);
    input.extend_from_slice(value);
    sha3::sha3_256(&input)
}

#[cfg(test)]
thread_local! {
    static NODE_HASHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    #[cfg(test)]
    NODE_HASHES.with(|count| count.set(count.get() + 1));
    let mut input = [0u8; 1 + HASH_LEN * 2];
    input[0] = NODE_DOMAIN;
    input[1..1 + HASH_LEN].copy_from_slice(left);
    input[1 + HASH_LEN..].copy_from_slice(right);
    sha3::sha3_256(&input)
}

fn default_hashes() -> Vec<Hash> {
    let mut defaults = vec![DEFAULT_LEAF; DEPTH + 1];
    let mut level = DEPTH;
    while level > 0 {
        level -= 1;
        defaults[level] = node_hash(&defaults[level + 1], &defaults[level + 1]);
    }
    defaults
}

fn with_bit(key: &Key, level: usize) -> Key {
    let mut out = *key;
    out[level >> 3] |= 1u8 << (7 - (level & 7));
    out
}

fn prefix_at(key: &Key, level: usize) -> Key {
    let byte = level >> 3;
    let mut out = *key;
    if byte < KEY_LEN {
        out[byte] &= !(255u8 >> (level & 7));
        for slot in out.iter_mut().skip(byte + 1) {
            *slot = 0;
        }
    }
    out
}

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

type NodeId = (u16, Key);

const FOLD_FLOOR: usize = 4096;

#[derive(Clone, Copy)]
pub struct Leaves<'a> {
    base: &'a BTreeMap<Key, Vec<u8>>,
    delta: &'a BTreeMap<Key, Option<Vec<u8>>>,
}

impl<'a> Leaves<'a> {
    pub fn get(&self, key: &Key) -> Option<&'a Vec<u8>> {
        match self.delta.get(key) {
            Some(entry) => entry.as_ref(),
            None => self.base.get(key),
        }
    }

    pub fn contains_key(&self, key: &Key) -> bool {
        self.get(key).is_some()
    }

    pub fn range<R>(&self, range: R) -> LeafRange<'a>
    where
        R: std::ops::RangeBounds<Key> + Clone,
    {
        LeafRange {
            base: self.base.range(range.clone()).peekable(),
            delta: self.delta.range(range).peekable(),
        }
    }

    pub fn iter(&self) -> LeafRange<'a> {
        self.range::<std::ops::RangeFull>(..)
    }
}

pub struct LeafRange<'a> {
    base: std::iter::Peekable<std::collections::btree_map::Range<'a, Key, Vec<u8>>>,
    delta: std::iter::Peekable<std::collections::btree_map::Range<'a, Key, Option<Vec<u8>>>>,
}

impl<'a> Iterator for LeafRange<'a> {
    type Item = (&'a Key, &'a Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let from_delta = match (self.base.peek(), self.delta.peek()) {
                (None, None) => return None,
                (Some(_), None) => false,
                (None, Some(_)) => true,
                (Some((base_key, _)), Some((delta_key, _))) => {
                    if delta_key == base_key {
                        self.base.next();
                        true
                    } else {
                        delta_key < base_key
                    }
                }
            };
            if !from_delta {
                return self.base.next();
            }
            if let Some((key, Some(value))) = self.delta.next() {
                return Some((key, value));
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Nodes<'a> {
    base: &'a HashMap<NodeId, Hash>,
    delta: &'a HashMap<NodeId, Option<Hash>>,
}

impl Nodes<'_> {
    fn get(&self, id: &NodeId) -> Option<&Hash> {
        match self.delta.get(id) {
            Some(entry) => entry.as_ref(),
            None => self.base.get(id),
        }
    }
}

fn fold_into<K: Ord + Clone, V: Clone>(
    base: &mut Arc<BTreeMap<K, V>>,
    delta: &mut Arc<BTreeMap<K, Option<V>>>,
) {
    if delta.is_empty() {
        return;
    }
    let unique = Arc::get_mut(base).is_some();
    if !unique && delta.len() <= base.len() / 8 + FOLD_FLOOR {
        return;
    }
    let changes = std::mem::take(Arc::make_mut(delta));
    let target = Arc::make_mut(base);
    for (key, entry) in changes {
        match entry {
            Some(value) => {
                target.insert(key, value);
            }
            None => {
                target.remove(&key);
            }
        }
    }
}

fn fold_nodes(
    base: &mut Arc<HashMap<NodeId, Hash>>,
    delta: &mut Arc<HashMap<NodeId, Option<Hash>>>,
) {
    if delta.is_empty() {
        return;
    }
    let unique = Arc::get_mut(base).is_some();
    if !unique && delta.len() <= base.len() / 8 + FOLD_FLOOR {
        return;
    }
    let changes = std::mem::take(Arc::make_mut(delta));
    let target = Arc::make_mut(base);
    for (id, entry) in changes {
        match entry {
            Some(hash) => {
                target.insert(id, hash);
            }
            None => {
                target.remove(&id);
            }
        }
    }
}

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

fn clean_hash(
    leaves: Leaves<'_>,
    defaults: &[Hash],
    nodes: Nodes<'_>,
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

const PARALLEL_LEVELS: usize = 4;

const PARALLEL_MIN_CHANGED: usize = 32;

type NodeUpdate = (NodeId, Option<Hash>);

fn side(
    leaves: Leaves<'_>,
    defaults: &[Hash],
    nodes: Nodes<'_>,
    level: usize,
    prefix: Key,
    changed: &[Key],
    updates: &mut Vec<NodeUpdate>,
) -> Hash {
    if changed.is_empty() {
        clean_hash(leaves, defaults, nodes, level, prefix)
    } else {
        recompute(leaves, defaults, nodes, level, prefix, changed, updates)
    }
}

fn recompute(
    leaves: Leaves<'_>,
    defaults: &[Hash],
    nodes: Nodes<'_>,
    level: usize,
    prefix: Key,
    changed: &[Key],
    updates: &mut Vec<NodeUpdate>,
) -> Hash {
    if level == DEPTH {
        return match leaves.get(&prefix) {
            Some(value) => leaf_hash(value),
            None => defaults[DEPTH],
        };
    }
    if let [key] = changed {
        let end = subtree_end(&prefix, level);
        let mut range = leaves.range(prefix..=end);
        let only = range.next();
        if range.next().is_none() {
            for below in level..DEPTH {
                let id = (below as u16, prefix_at(key, below));
                if nodes.get(&id).is_some() {
                    updates.push((id, None));
                }
            }
            return match only {
                Some((leaf_key, value)) => chain_hash(defaults, leaf_key, leaf_hash(value), level),
                None => defaults[level],
            };
        }
    }
    let split = changed.partition_point(|key| key_bit(key, level) == 0);
    let (changed_left, changed_right) = changed.split_at(split);
    let right_prefix = with_bit(&prefix, level);
    let parallel = level < PARALLEL_LEVELS
        && changed.len() >= PARALLEL_MIN_CHANGED
        && !changed_left.is_empty()
        && !changed_right.is_empty();
    let (left, right) = if parallel {
        let (pair, right_updates) = std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let mut local = Vec::new();
                let hash = side(
                    leaves,
                    defaults,
                    nodes,
                    level + 1,
                    right_prefix,
                    changed_right,
                    &mut local,
                );
                (hash, local)
            });
            let left = side(
                leaves,
                defaults,
                nodes,
                level + 1,
                prefix,
                changed_left,
                updates,
            );
            let (right, local) = handle
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            ((left, right), local)
        });
        updates.extend(right_updates);
        pair
    } else {
        let left = side(
            leaves,
            defaults,
            nodes,
            level + 1,
            prefix,
            changed_left,
            updates,
        );
        let right = side(
            leaves,
            defaults,
            nodes,
            level + 1,
            right_prefix,
            changed_right,
            updates,
        );
        (left, right)
    };
    let hash = node_hash(&left, &right);
    let end = subtree_end(&prefix, level);
    let branch = leaves.range(prefix..=end).take(2).count() >= 2;
    let id = (level as u16, prefix);
    if branch {
        updates.push((id, Some(hash)));
    } else if nodes.get(&id).is_some() {
        updates.push((id, None));
    }
    hash
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    value: Option<Vec<u8>>,
    siblings: Vec<Hash>,
}

impl Proof {
    pub fn new(value: Option<Vec<u8>>, siblings: Vec<Hash>) -> Self {
        Proof { value, siblings }
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    pub fn siblings(&self) -> &[Hash] {
        &self.siblings
    }

    pub fn is_present(&self) -> bool {
        self.value.is_some()
    }
}

impl Encode for Proof {
    fn encode(&self, encoder: &mut Encoder) {
        self.value.encode(encoder);
        encoder.put_u32(self.siblings.len() as u32);
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
        let count = decoder.get_u32()? as usize;
        if count != DEPTH {
            return Err(Error::LengthOverrun {
                length: count as u64,
                found: DEPTH,
            });
        }
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

#[derive(Debug, Clone)]
struct RootCache {
    nodes: Arc<HashMap<NodeId, Hash>>,
    node_delta: Arc<HashMap<NodeId, Option<Hash>>>,
    root: Hash,
    changed: BTreeSet<Key>,
}

#[derive(Debug)]
pub struct Trie {
    leaves: Arc<BTreeMap<Key, Vec<u8>>>,
    delta: Arc<BTreeMap<Key, Option<Vec<u8>>>>,
    defaults: Vec<Hash>,
    cache: Mutex<RootCache>,
    persist_dirty: BTreeSet<Key>,
}

impl Clone for Trie {
    fn clone(&self) -> Self {
        Trie {
            leaves: Arc::clone(&self.leaves),
            delta: Arc::clone(&self.delta),
            defaults: self.defaults.clone(),
            cache: Mutex::new(
                self.cache
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            ),
            persist_dirty: self.persist_dirty.clone(),
        }
    }
}

impl Default for Trie {
    fn default() -> Self {
        Self::new()
    }
}

impl Trie {
    pub fn new() -> Self {
        let defaults = default_hashes();
        let cache = RootCache {
            nodes: Arc::new(HashMap::new()),
            node_delta: Arc::new(HashMap::new()),
            root: defaults[0],
            changed: BTreeSet::new(),
        };
        Trie {
            leaves: Arc::new(BTreeMap::new()),
            delta: Arc::new(BTreeMap::new()),
            defaults,
            cache: Mutex::new(cache),
            persist_dirty: BTreeSet::new(),
        }
    }

    pub fn take_persist_dirty(&mut self) -> Vec<Key> {
        std::mem::take(&mut self.persist_dirty)
            .into_iter()
            .collect()
    }

    pub fn clear_persist_dirty(&mut self) {
        self.persist_dirty.clear();
    }

    pub fn insert(&mut self, key: Key, value: Vec<u8>) {
        match Arc::get_mut(&mut self.leaves).filter(|_| self.delta.is_empty()) {
            Some(base) => {
                base.insert(key, value);
            }
            None => {
                Arc::make_mut(&mut self.delta).insert(key, Some(value));
            }
        }
        self.cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .changed
            .insert(key);
        self.persist_dirty.insert(key);
    }

    pub fn remove(&mut self, key: &Key) -> bool {
        let existed = self.leaves().contains_key(key);
        if existed {
            match Arc::get_mut(&mut self.leaves).filter(|_| self.delta.is_empty()) {
                Some(base) => {
                    base.remove(key);
                }
                None => {
                    Arc::make_mut(&mut self.delta).insert(*key, None);
                }
            }
            self.cache
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .changed
                .insert(*key);
            self.persist_dirty.insert(*key);
        }
        existed
    }

    pub fn get(&self, key: &Key) -> Option<&[u8]> {
        self.leaves().get(key).map(|value| value.as_slice())
    }

    pub fn leaves(&self) -> Leaves<'_> {
        Leaves {
            base: &self.leaves,
            delta: &self.delta,
        }
    }

    pub fn compact(&mut self) {
        fold_into(&mut self.leaves, &mut self.delta);
        let cache = self
            .cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        fold_nodes(&mut cache.nodes, &mut cache.node_delta);
    }

    pub fn root(&self) -> Hash {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.changed.is_empty() {
            return cache.root;
        }
        let changed: Vec<Key> = cache.changed.iter().copied().collect();
        let mut updates = Vec::new();
        let root = recompute(
            self.leaves(),
            &self.defaults,
            Nodes {
                base: &cache.nodes,
                delta: &cache.node_delta,
            },
            0,
            [0u8; KEY_LEN],
            &changed,
            &mut updates,
        );
        let cache = &mut *cache;
        match Arc::get_mut(&mut cache.nodes).filter(|_| cache.node_delta.is_empty()) {
            Some(base) => {
                for (id, hash) in updates {
                    match hash {
                        Some(hash) => {
                            base.insert(id, hash);
                        }
                        None => {
                            base.remove(&id);
                        }
                    }
                }
            }
            None => {
                let delta = Arc::make_mut(&mut cache.node_delta);
                for (id, hash) in updates {
                    delta.insert(id, hash);
                }
            }
        }
        cache.root = root;
        cache.changed.clear();
        root
    }

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
        let value = self.leaves().get(key).cloned();
        Proof { value, siblings }
    }

    fn entries(&self) -> Vec<(Key, Hash)> {
        self.leaves()
            .iter()
            .map(|(key, value)| (*key, leaf_hash(value)))
            .collect()
    }

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

    use super::*;

    #[test]
    fn leaf_and_node_hashes_live_in_separate_domains() {
        let a = [0x11u8; HASH_LEN];
        let b = [0x22u8; HASH_LEN];
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&a);
        concatenated.extend_from_slice(&b);
        assert_ne!(leaf_hash(&concatenated), node_hash(&a, &b));
    }

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

        for _ in 0..400 {
            let key = rng.key();
            let value = rng.value();
            trie.insert(key, value.clone());
            mirror.insert(key, value);
            keys.push(key);
        }
        assert_eq!(trie.root(), reference_root(&mirror));

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

        reset_node_hashes();
        assert_eq!(trie.root(), root);
        assert_eq!(node_hashes(), 0);

        let (key, value) = {
            let (key, value) = trie.leaves().iter().next().unwrap();
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

        reset_node_hashes();
        let _ = trie.root();
        let full = node_hashes();
        assert!(
            full > count as u64,
            "a full recompute walks the whole state"
        );

        let target = keys[keys.len() / 3];
        let before: HashMap<NodeId, Hash> = trie
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .nodes
            .as_ref()
            .clone();
        reset_node_hashes();
        trie.insert(target, b"a new account record".to_vec());
        let _ = trie.root();
        let single = node_hashes();
        let after: HashMap<NodeId, Hash> = trie
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .nodes
            .as_ref()
            .clone();

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
        for id in before.keys() {
            if !after.contains_key(id) {
                let (level, prefix) = *id;
                assert_eq!(prefix, ancestor_prefix(&target, level as usize));
            }
        }

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
    fn a_removed_leaf_frees_its_slot_and_returns_the_root() {
        let mut rng = Rng(987654321);
        let mut trie = Trie::new();
        for _ in 0..64 {
            trie.insert(rng.key(), rng.value());
        }
        let before = trie.root();

        let key = rng.key();
        trie.insert(key, b"a transient account".to_vec());
        assert!(trie.get(&key).is_some());
        assert_ne!(trie.root(), before, "the inserted leaf moved the root");

        assert!(trie.remove(&key), "the leaf was present and removed");
        assert!(trie.get(&key).is_none(), "the slot is freed after removal");
        assert_eq!(
            trie.root(),
            before,
            "removal returns the root to its prior value"
        );
        assert!(
            !trie.remove(&key),
            "removing an absent key reports nothing removed"
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

        let root = trie.root();
        let proof = trie.prove(&key);
        assert!(verify(&key, &proof, &root));
    }
}
