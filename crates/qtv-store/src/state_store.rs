// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use qtv_codec::{to_bytes, Decode, Decoder, Encode, Encoder, Error};
use qtv_state::{Hash, Key, Trie};

use crate::log::{frame_len, sync_parent_dir, Log};

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

/// A log below this size is left alone, because rewriting a small file buys
/// nothing and a fresh chain would otherwise compact on every open.
const COMPACT_FLOOR_BYTES: u64 = 64 * 1024 * 1024;

/// Compact once the log costs this many times what the live set needs. Four
/// means the log is three quarters superseded copies before it is rewritten.
const COMPACT_RATIO: u64 = 4;

#[derive(Debug)]
pub struct StateStore {
    log: Log,
    path: PathBuf,
    entries: BTreeMap<Key, Vec<u8>>,
    head: Option<Hash>,
    committed_height: Option<u64>,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        // Stream the log rather than materialising every frame first. Holding the
        // whole log in a Vec and then building the live set from it meant a log too
        // big for memory could never be opened, so it could never be compacted back
        // down either, which is the state that traps a node with a large history.
        let mut entries: BTreeMap<Key, Vec<u8>> = BTreeMap::new();
        let mut head: Option<Hash> = None;
        let mut committed_height: Option<u64> = None;
        let mut pending: Vec<(Key, Option<Vec<u8>>)> = Vec::new();
        let mut committed_len: u64 = 0;
        let mut total_len: u64 = 0;
        let log = Log::open_scanned(&path, |frame, _start, end_offset| {
            total_len = end_offset;
            match qtv_codec::from_bytes::<StateRecord>(frame) {
                Ok(StateRecord::Entry { key, value }) => {
                    pending.push((key, Some(value)));
                    true
                }
                Ok(StateRecord::Delete { key }) => {
                    pending.push((key, None));
                    true
                }
                Ok(StateRecord::Commit { height, root }) => {
                    for (key, value) in pending.drain(..) {
                        match value {
                            Some(value) => {
                                entries.insert(key, value);
                            }
                            None => {
                                entries.remove(&key);
                            }
                        }
                    }
                    head = Some(root);
                    committed_height = Some(height);
                    committed_len = end_offset;
                    true
                }
                Err(_) => false,
            }
        })?;
        let mut store = StateStore {
            log,
            path,
            entries,
            head,
            committed_height,
        };
        if committed_len < total_len {
            store.log.truncate(committed_len)?;
        }
        if store.should_compact(committed_len) {
            // Compaction is an optimisation, never a correctness requirement. A store
            // that cannot be rewritten, for want of disk or a read only mount, still
            // holds every committed byte, so refusing to boot over it would turn a
            // housekeeping failure into a halted validator that cannot restart.
            if let Err(e) = store.compact() {
                eprintln!("state log compaction skipped at open: {e}");
            }
        }
        Ok(store)
    }

    /// The bytes a freshly written log would occupy for the current live set.
    fn live_bytes(&self) -> u64 {
        self.entries
            .values()
            .map(|value| {
                frame_len(
                    to_bytes(&StateRecord::Entry {
                        key: [0u8; qtv_state::KEY_LEN],
                        value: value.clone(),
                    })
                    .len(),
                )
            })
            .sum()
    }

    fn should_compact(&self, on_disk: u64) -> bool {
        if on_disk < COMPACT_FLOOR_BYTES {
            return false;
        }
        let live = self.live_bytes().max(1);
        on_disk / live >= COMPACT_RATIO
    }

    /// Compact only when the log has become mostly superseded copies.
    ///
    /// Cheap enough for the block loop to call on a schedule: it stats the file
    /// and returns immediately unless a rewrite is actually warranted. Returns
    /// whether a rewrite happened.
    pub fn compact_if_bloated(&mut self) -> io::Result<bool> {
        let on_disk = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if !self.should_compact(on_disk) {
            return Ok(false);
        }
        // Never propagate a compaction failure into the block loop. The chain is
        // correct without compaction, it simply uses more disk until the next attempt.
        if let Err(e) = self.compact() {
            eprintln!("state log compaction skipped: {e}");
            return Ok(false);
        }
        Ok(true)
    }

    /// Rewrite the log so it holds one entry per live key and a single commit.
    ///
    /// The in-memory map is already the compacted state, so this replays to the
    /// identical trie. The rewrite lands in a sibling file and is renamed over
    /// the original, so an interrupted compaction leaves the previous log whole.
    pub fn compact(&mut self) -> io::Result<()> {
        let (height, root) = match (self.committed_height, self.head) {
            (Some(height), Some(root)) => (height, root),
            // Nothing has been committed, so there is no state worth keeping.
            _ => return Ok(()),
        };
        let mut temp = self.path.clone().into_os_string();
        temp.push(".compact");
        let temp = PathBuf::from(temp);
        // A temp file left by an interrupted earlier attempt is not state, drop it.
        if temp.exists() {
            std::fs::remove_file(&temp)?;
        }
        // The fresh handle is kept open ACROSS the rename and installed directly.
        // Reopening the path afterwards used to sit between the rename and the
        // install: the rename had already unlinked the old file, so a reopen that
        // failed left `self.log` writing into an inode with no name, and every
        // append after it was lost on the next restart while the node went on
        // finalizing blocks. A descriptor follows the inode through a rename, so
        // there is nothing left to fail here.
        let (mut fresh, _) = Log::open(&temp)?;
        for (key, value) in &self.entries {
            let record = StateRecord::Entry {
                key: *key,
                value: value.clone(),
            };
            fresh.append(&to_bytes(&record))?;
        }
        fresh.append(&to_bytes(&StateRecord::Commit { height, root }))?;
        fresh.sync()?;
        std::fs::rename(&temp, &self.path)?;
        // The rename itself has to reach the disk, otherwise a crash here can
        // leave a directory entry pointing at neither file.
        sync_parent_dir(&self.path);
        self.log = fresh;
        Ok(())
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

    #[test]
    fn compaction_keeps_every_live_value_and_the_same_root() {
        let path = temp_path("compaction-keeps-values");
        let mut store = StateStore::open(&path).expect("open");
        for index in 0..16u8 {
            store
                .put_account(key(index), account(index as u64, 100 + index as u64))
                .expect("put");
        }
        store.commit(1, [7u8; 32]).expect("commit");
        // Rewrite every key many times so the log is mostly superseded copies.
        for round in 1..40u64 {
            for index in 0..16u8 {
                store
                    .put_account(key(index), account(round, 100 + index as u64))
                    .expect("put");
            }
            store.commit(1 + round, [8u8; 32]).expect("commit");
        }
        let before_root = store.load_trie().root();
        let before_len = store.len();
        let before_bytes = std::fs::metadata(&path).expect("stat").len();

        store.compact().expect("compact");

        assert_eq!(store.load_trie().root(), before_root, "root changed");
        assert_eq!(store.len(), before_len, "live count changed");
        let after_bytes = std::fs::metadata(&path).expect("stat").len();
        assert!(
            after_bytes < before_bytes,
            "compaction did not shrink the log, {before_bytes} -> {after_bytes}"
        );

        // and it survives a reopen
        drop(store);
        let reopened = StateStore::open(&path).expect("reopen");
        assert_eq!(
            reopened.load_trie().root(),
            before_root,
            "root changed on reopen"
        );
        assert_eq!(reopened.len(), before_len, "count changed on reopen");
        assert_eq!(reopened.committed_height(), Some(40), "height changed");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_key_deleted_before_compaction_stays_absent_afterwards() {
        let path = temp_path("compaction-honours-deletes");
        let mut store = StateStore::open(&path).expect("open");
        store.put_account(key(1), account(1, 10)).expect("put");
        store.put_account(key(2), account(2, 20)).expect("put");
        store.commit(1, [1u8; 32]).expect("commit");
        store.delete_account(key(1)).expect("delete");
        store.commit(2, [2u8; 32]).expect("commit");

        store.compact().expect("compact");
        assert!(store.account(&key(1)).is_none(), "deleted key came back");
        assert!(store.account(&key(2)).is_some(), "live key lost");

        drop(store);
        let reopened = StateStore::open(&path).expect("reopen");
        assert!(
            reopened.account(&key(1)).is_none(),
            "deleted key came back on reopen"
        );
        assert!(
            reopened.account(&key(2)).is_some(),
            "live key lost on reopen"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_interrupted_compaction_leaves_the_original_log_untouched() {
        let path = temp_path("compaction-interrupted");
        let mut store = StateStore::open(&path).expect("open");
        store.put_account(key(1), account(1, 10)).expect("put");
        store.commit(1, [3u8; 32]).expect("commit");
        let root = store.load_trie().root();
        drop(store);
        let original = std::fs::read(&path).expect("read");

        // A temp file left behind by a compaction that died midway must not be
        // mistaken for state, and must not stop a later compaction.
        let mut temp = path.clone().into_os_string();
        temp.push(".compact");
        let temp = std::path::PathBuf::from(temp);
        std::fs::write(&temp, b"a partial write from a dead process").expect("write temp");

        let reopened = StateStore::open(&path).expect("reopen");
        assert_eq!(reopened.load_trie().root(), root, "state changed");
        assert_eq!(
            std::fs::read(&path).expect("read"),
            original,
            "log was altered"
        );

        let mut store = StateStore::open(&path).expect("reopen again");
        store.compact().expect("compact over a stale temp");
        assert_eq!(
            store.load_trie().root(),
            root,
            "root changed after compaction"
        );
        assert!(!temp.exists(), "temp file survived compaction");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn compacting_an_empty_store_is_a_no_op() {
        let path = temp_path("compaction-empty");
        let mut store = StateStore::open(&path).expect("open");
        store.compact().expect("compact");
        assert!(store.is_empty(), "empty store gained entries");
        assert_eq!(
            store.committed_height(),
            None,
            "empty store gained a height"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_small_log_is_left_alone_by_the_open_time_trigger() {
        let path = temp_path("compaction-floor");
        let mut store = StateStore::open(&path).expect("open");
        store.put_account(key(1), account(1, 10)).expect("put");
        store.commit(1, [4u8; 32]).expect("commit");
        for round in 2..50u64 {
            store.put_account(key(1), account(round, 10)).expect("put");
            store.commit(round, [4u8; 32]).expect("commit");
        }
        let before = std::fs::metadata(&path).expect("stat").len();
        assert!(before < COMPACT_FLOOR_BYTES, "test log unexpectedly large");
        drop(store);
        let reopened = StateStore::open(&path).expect("reopen");
        let after = std::fs::metadata(&path).expect("stat").len();
        assert_eq!(before, after, "a small log should not be rewritten on open");
        assert_eq!(reopened.committed_height(), Some(49));
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod compaction_survives_the_rename {
    use super::*;

    #[test]
    fn writes_after_a_compaction_land_in_the_file_that_is_reopened() {
        let dir = std::env::temp_dir().join(format!("qtv-compact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.log");

        let mut s = StateStore::open(&path).unwrap();
        for i in 0..64u64 {
            let mut k = [0u8; 32];
            k[24..].copy_from_slice(&i.to_be_bytes());
            // Rewrite each key repeatedly so the log goes mostly stale.
            for v in 0..8u64 {
                s.put_account(k, v.to_be_bytes().to_vec()).unwrap();
            }
        }
        s.commit(1, [7u8; 32]).unwrap();
        // What this covers: compaction round trips, and a write made through the
        // handle compaction installed still survives a restart.
        //
        // What it does NOT cover, stated plainly because the first version of this
        // test was cited as evidence for a fix it could not detect: the failure the
        // fix removes is a reopen of `self.path` FAILING after the rename has already
        // unlinked the old file. Forcing that needs a descriptor limit this crate
        // cannot lower without `unsafe`, which the workspace forbids. The guarantee is
        // structural instead, and it is worth stating: `compact` holds the fresh
        // handle across the rename and installs it directly, so there is no fallible
        // call between the two for a failure to land in.
        s.compact().unwrap();

        // The write below goes through the handle the compaction installed. If that
        // handle still pointed at the unlinked pre rename inode it would be accepted
        // here and gone after the reopen.
        let mut late = [0u8; 32];
        late[31] = 0xEE;
        s.put_account(late, vec![1, 2, 3]).unwrap();
        s.commit(2, [8u8; 32]).unwrap();
        drop(s);

        let reopened = StateStore::open(&path).unwrap();
        assert_eq!(
            reopened.account(&late).map(|v| v.to_vec()),
            Some(vec![1, 2, 3]),
            "a write made after compaction must survive a restart"
        );
        assert_eq!(reopened.committed_height(), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
