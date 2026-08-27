// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use qtv_codec::{to_bytes, Decode, Decoder, Encode, Encoder, Error};
use qtv_state::{Hash, Key, Trie};

use crate::log::{frame_len, Log};

const TAG_ENTRY: u8 = 1;
const TAG_COMMIT: u8 = 2;
const TAG_DELETE: u8 = 3;

fn put_fixed(encoder: &mut Encoder, value: &[u8; 32]) {
    for &byte in value.iter() {
        encoder.put_u8(byte);
    }
}

fn get_fixed(decoder: &mut Decoder<'_>) -> Result<[u8; 32], Error> {
    let mut value = [0u8; 32];
    for slot in value.iter_mut() {
        *slot = decoder.get_u8()?;
    }
    Ok(value)
}

enum StateRecord {
    Entry { key: Key, value: Vec<u8> },
    Commit { height: u64, root: Hash },
    Delete { key: Key },
}

impl Encode for StateRecord {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            StateRecord::Entry { key, value } => {
                encoder.put_tag(TAG_ENTRY);
                put_fixed(encoder, key);
                encoder.put_bytes(value);
            }
            StateRecord::Commit { height, root } => {
                encoder.put_tag(TAG_COMMIT);
                encoder.put_u64(*height);
                put_fixed(encoder, root);
            }
            StateRecord::Delete { key } => {
                encoder.put_tag(TAG_DELETE);
                put_fixed(encoder, key);
            }
        }
    }
}

impl Decode for StateRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        match decoder.get_tag()? {
            TAG_ENTRY => {
                let key = get_fixed(decoder)?;
                let value = decoder.get_bytes()?.to_vec();
                Ok(StateRecord::Entry { key, value })
            }
            TAG_COMMIT => {
                let height = decoder.get_u64()?;
                let root = get_fixed(decoder)?;
                Ok(StateRecord::Commit { height, root })
            }
            TAG_DELETE => {
                let key = get_fixed(decoder)?;
                Ok(StateRecord::Delete { key })
            }
            tag => Err(Error::UnknownTag { tag }),
        }
    }
}

#[derive(Debug)]
pub struct StateStore {
    log: Log,
    entries: BTreeMap<Key, Vec<u8>>,
    head: Option<Hash>,
    committed_height: Option<u64>,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (log, frames) = Log::open(path)?;
        let mut store = StateStore {
            log,
            entries: BTreeMap::new(),
            head: None,
            committed_height: None,
        };
        let total_len: u64 = frames.iter().map(|frame| frame_len(frame.len())).sum();
        let mut pending: Vec<(Key, Option<Vec<u8>>)> = Vec::new();
        let mut committed_len: u64 = 0;
        let mut offset: u64 = 0;
        for frame in &frames {
            offset += frame_len(frame.len());
            match qtv_codec::from_bytes(frame) {
                Ok(StateRecord::Entry { key, value }) => {
                    pending.push((key, Some(value)));
                }
                Ok(StateRecord::Delete { key }) => {
                    pending.push((key, None));
                }
                Ok(StateRecord::Commit { height, root }) => {
                    for (key, value) in pending.drain(..) {
                        match value {
                            Some(value) => {
                                store.entries.insert(key, value);
                            }
                            None => {
                                store.entries.remove(&key);
                            }
                        }
                    }
                    store.head = Some(root);
                    store.committed_height = Some(height);
                    committed_len = offset;
                }
                Err(_) => break,
            }
        }
        if committed_len < total_len {
            store.log.truncate(committed_len)?;
        }
        Ok(store)
    }

    pub fn put_account(&mut self, key: Key, value: Vec<u8>) -> io::Result<()> {
        let record = StateRecord::Entry {
            key,
            value: value.clone(),
        };
        self.log.append(&to_bytes(&record))?;
        self.entries.insert(key, value);
        Ok(())
    }

    pub fn delete_account(&mut self, key: Key) -> io::Result<()> {
        let record = StateRecord::Delete { key };
        self.log.append(&to_bytes(&record))?;
        self.entries.remove(&key);
        Ok(())
    }

    pub fn commit(&mut self, height: u64, root: Hash) -> io::Result<()> {
        let record = StateRecord::Commit { height, root };
        self.log.append(&to_bytes(&record))?;
        self.log.sync()?;
        self.head = Some(root);
        self.committed_height = Some(height);
        Ok(())
    }

    pub fn account(&self, key: &Key) -> Option<&[u8]> {
        self.entries.get(key).map(|value| value.as_slice())
    }

    pub fn head(&self) -> Option<Hash> {
        self.head
    }

    pub fn committed_height(&self) -> Option<u64> {
        self.committed_height
    }

    pub fn accounts(&self) -> impl Iterator<Item = (&Key, &[u8])> {
        self.entries
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
    }

    pub fn load_trie(&self) -> Trie {
        let mut trie = Trie::new();
        for (key, value) in &self.entries {
            trie.insert(*key, value.clone());
        }
        trie
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use qtv_state::KEY_LEN;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "qtv-store-state-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        path
    }

    fn key(index: u8) -> Key {
        let mut key = [0u8; KEY_LEN];
        key[0] = index;
        key[KEY_LEN - 1] = index.wrapping_mul(7);
        key
    }

    fn account(nonce: u64, balance: u64) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_u64(nonce);
        encoder.put_u64(balance);
        encoder.into_bytes()
    }

    #[test]
    fn an_absent_file_opens_empty() {
        let path = temp_path("absent");
        let store = StateStore::open(&path).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.head(), None);
        assert_eq!(store.committed_height(), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_committed_state_is_read_back_under_the_same_root_across_a_reopen() {
        let path = temp_path("commit");
        let accounts = [
            (key(1), account(0, 100)),
            (key(2), account(3, 5_000)),
            (key(3), account(9, 42)),
            (key(200), account(1, 7)),
        ];

        let mut trie = Trie::new();
        for (k, value) in &accounts {
            trie.insert(*k, value.clone());
        }
        let root = trie.root();

        {
            let mut store = StateStore::open(&path).unwrap();
            for (k, value) in &accounts {
                store.put_account(*k, value.clone()).unwrap();
            }
            store.commit(1, root).unwrap();
        }

        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.head(), Some(root));
        assert_eq!(store.committed_height(), Some(1));
        assert_eq!(store.len(), accounts.len());
        for (k, value) in &accounts {
            assert_eq!(store.account(k), Some(value.as_slice()));
        }
        assert_eq!(store.load_trie().root(), root);

        for (k, value) in &accounts {
            assert_eq!(store.load_trie().get(k), Some(value.as_slice()));
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_reopened_head_matches_before_the_restart() {
        let path = temp_path("head");
        let head_before;
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 1)).unwrap();
            let root = store.load_trie().root();
            store.commit(1, root).unwrap();
            store.put_account(key(2), account(0, 2)).unwrap();
            let root = store.load_trie().root();
            store.commit(2, root).unwrap();
            head_before = store.head();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.head(), head_before);
        assert_eq!(store.committed_height(), Some(2));
        assert_eq!(store.load_trie().root(), head_before.unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_rewritten_key_reopens_to_its_latest_value() {
        let path = temp_path("rewrite");
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 100)).unwrap();
            store.put_account(key(1), account(1, 250)).unwrap();
            let root = store.load_trie().root();
            store.commit(1, root).unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.account(&key(1)), Some(account(1, 250).as_slice()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_deleted_key_stays_absent_across_a_reopen_under_the_absent_slot_root() {
        let path = temp_path("delete-reopen");
        let mut removed = Trie::new();
        removed.insert(key(2), account(0, 200));
        let removed_root = removed.root();
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 100)).unwrap();
            store.put_account(key(2), account(0, 200)).unwrap();
            let mut both = Trie::new();
            both.insert(key(1), account(0, 100));
            both.insert(key(2), account(0, 200));
            store.commit(1, both.root()).unwrap();
            store.delete_account(key(1)).unwrap();
            store.commit(2, removed_root).unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.committed_height(), Some(2));
        assert_eq!(store.account(&key(1)), None);
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.load_trie().root(),
            removed_root,
            "a deleted key must reopen absent, not resurrected with an empty value"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn entries_written_after_the_last_commit_are_discarded_on_reopen() {
        let path = temp_path("uncommitted-tail");
        let committed_root;
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 100)).unwrap();
            let root = store.load_trie().root();
            store.commit(1, root).unwrap();
            committed_root = root;
            store.put_account(key(2), account(0, 200)).unwrap();
            store.put_account(key(1), account(1, 999)).unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.committed_height(), Some(1));
        assert_eq!(store.head(), Some(committed_root));
        assert_eq!(store.load_trie().root(), committed_root);
        assert_eq!(store.len(), 1);
        assert_eq!(store.account(&key(1)), Some(account(0, 100).as_slice()));
        assert_eq!(store.account(&key(2)), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_uncommitted_tail_is_physically_removed_and_a_later_commit_is_clean() {
        let path = temp_path("truncate-then-append");
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 1)).unwrap();
            let root = store.load_trie().root();
            store.commit(1, root).unwrap();
            store.put_account(key(9), account(9, 9)).unwrap();
        }
        let root_two;
        {
            let mut store = StateStore::open(&path).unwrap();
            assert_eq!(store.committed_height(), Some(1));
            assert_eq!(store.len(), 1);
            store.put_account(key(2), account(0, 2)).unwrap();
            let root = store.load_trie().root();
            store.commit(2, root).unwrap();
            root_two = root;
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.committed_height(), Some(2));
        assert_eq!(store.head(), Some(root_two));
        assert_eq!(store.len(), 2);
        assert_eq!(store.account(&key(9)), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_crash_before_any_commit_recovers_to_empty() {
        let path = temp_path("no-commit");
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 1)).unwrap();
            store.put_account(key(2), account(0, 2)).unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.committed_height(), None);
        assert_eq!(store.head(), None);
        assert!(store.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_flipped_byte_in_a_committed_height_rolls_back_to_the_prior_one() {
        let path = temp_path("mid-corrupt");
        let root_two;
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 1)).unwrap();
            let root = store.load_trie().root();
            store.commit(1, root).unwrap();
            store.put_account(key(2), account(0, 2)).unwrap();
            let root = store.load_trie().root();
            store.commit(2, root).unwrap();
            root_two = root;
            store.put_account(key(3), account(0, 3)).unwrap();
            let root = store.load_trie().root();
            store.commit(3, root).unwrap();
        }
        {
            let mut bytes = std::fs::read(&path).unwrap();
            let target = bytes.len() - 100;
            bytes[target] ^= 0xFF;
            std::fs::write(&path, &bytes).unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.committed_height(), Some(2));
        assert_eq!(store.head(), Some(root_two));
        assert_eq!(store.load_trie().root(), root_two);
        assert_eq!(store.account(&key(3)), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_flipped_byte_inside_the_last_commit_marker_drops_it() {
        let path = temp_path("marker-corrupt");
        let root_one;
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 1)).unwrap();
            let root = store.load_trie().root();
            store.commit(1, root).unwrap();
            root_one = root;
            store.put_account(key(2), account(0, 2)).unwrap();
            let root = store.load_trie().root();
            store.commit(2, root).unwrap();
        }
        {
            let mut bytes = std::fs::read(&path).unwrap();
            let target = bytes.len() - 20;
            bytes[target] ^= 0x01;
            std::fs::write(&path, &bytes).unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.committed_height(), Some(1));
        assert_eq!(store.head(), Some(root_one));
        assert_eq!(store.account(&key(2)), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_truncated_commit_marker_falls_back_to_the_prior_height() {
        let path = temp_path("torn-marker");
        let root_one;
        {
            let mut store = StateStore::open(&path).unwrap();
            store.put_account(key(1), account(0, 1)).unwrap();
            let root = store.load_trie().root();
            store.commit(1, root).unwrap();
            root_one = root;
            store.put_account(key(2), account(0, 2)).unwrap();
            let root = store.load_trie().root();
            store.commit(2, root).unwrap();
        }
        {
            let len = std::fs::metadata(&path).unwrap().len();
            let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len(len - 5).unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.committed_height(), Some(1));
        assert_eq!(store.head(), Some(root_one));
        assert_eq!(store.account(&key(1)), Some(account(0, 1).as_slice()));
        assert_eq!(store.account(&key(2)), None);
        std::fs::remove_file(&path).ok();
    }
}
