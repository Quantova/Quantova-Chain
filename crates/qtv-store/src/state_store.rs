//! The file backed state store.
//!
//! The account state is the set of leaves of the qtv-state sparse Merkle trie.
//! Each leaf is a value keyed by its thirty two byte hash, the trie key. This
//! store appends two kinds of record to its log. An entry record binds a key to a
//! value, and the latest entry for a key wins. A commit record fixes the state
//! root a set of entries was committed under, and the last commit is the head.
//!
//! On open the log is scanned once. The entries rebuild the in memory map, latest
//! wins, and the last commit becomes the head. A trie rebuilt from the entries
//! reproduces the head root, so a state committed under a root is fully readable
//! after reopening from disk.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use qtv_codec::{to_bytes, Decode, Decoder, Encode, Encoder, Error};
use qtv_state::{Hash, Key, Trie};

use crate::log::Log;

/// The record tag that binds a key to a value.
const TAG_ENTRY: u8 = 1;
/// The record tag that fixes the committed state root.
const TAG_COMMIT: u8 = 2;

/// Append a fixed width thirty two byte value as its raw bytes in order.
fn put_fixed(encoder: &mut Encoder, value: &[u8; 32]) {
    for &byte in value.iter() {
        encoder.put_u8(byte);
    }
}

/// Read a fixed width thirty two byte value as its raw bytes in order.
fn get_fixed(decoder: &mut Decoder<'_>) -> Result<[u8; 32], Error> {
    let mut value = [0u8; 32];
    for slot in value.iter_mut() {
        *slot = decoder.get_u8()?;
    }
    Ok(value)
}

/// One state record: an entry that binds a key to a value, or a commit that fixes
/// the state root the entries so far were committed under.
enum StateRecord {
    Entry { key: Key, value: Vec<u8> },
    Commit { root: Hash },
}

impl Encode for StateRecord {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            StateRecord::Entry { key, value } => {
                encoder.put_tag(TAG_ENTRY);
                put_fixed(encoder, key);
                encoder.put_bytes(value);
            }
            StateRecord::Commit { root } => {
                encoder.put_tag(TAG_COMMIT);
                put_fixed(encoder, root);
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
                let root = get_fixed(decoder)?;
                Ok(StateRecord::Commit { root })
            }
            tag => Err(Error::UnknownTag { tag }),
        }
    }
}

/// A file backed store of the account state, the leaves of the sparse Merkle
/// trie keyed by their hash, together with the head root they were committed
/// under.
#[derive(Debug)]
pub struct StateStore {
    log: Log,
    entries: BTreeMap<Key, Vec<u8>>,
    head: Option<Hash>,
}

impl StateStore {
    /// Open the state store at a path, creating the file when absent, and rebuild
    /// the entries and the head from the records. An absent or truncated file
    /// opens as an empty store.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (log, frames) = Log::open(path)?;
        let mut store = StateStore {
            log,
            entries: BTreeMap::new(),
            head: None,
        };
        for frame in &frames {
            match qtv_codec::from_bytes(frame) {
                Ok(StateRecord::Entry { key, value }) => {
                    store.entries.insert(key, value);
                }
                Ok(StateRecord::Commit { root }) => {
                    store.head = Some(root);
                }
                Err(_) => break,
            }
        }
        Ok(store)
    }

    /// Bind a key to a value, replacing any value the key already held. The value
    /// enters the log through the canonical encoding, so a read returns the exact
    /// bytes that were written.
    pub fn put_account(&mut self, key: Key, value: Vec<u8>) -> io::Result<()> {
        let record = StateRecord::Entry {
            key,
            value: value.clone(),
        };
        self.log.append(&to_bytes(&record))?;
        self.entries.insert(key, value);
        Ok(())
    }

    /// Fix the state root the entries so far were committed under. The last commit
    /// is the head the store reopens to.
    pub fn commit(&mut self, root: Hash) -> io::Result<()> {
        let record = StateRecord::Commit { root };
        self.log.append(&to_bytes(&record))?;
        self.head = Some(root);
        Ok(())
    }

    /// The value a key holds, or nothing when the key is absent.
    pub fn account(&self, key: &Key) -> Option<&[u8]> {
        self.entries.get(key).map(|value| value.as_slice())
    }

    /// The head root, the last root a state was committed under, or nothing when
    /// no commit was made.
    pub fn head(&self) -> Option<Hash> {
        self.head
    }

    /// The key and value pairs the store holds, in key order.
    pub fn accounts(&self) -> impl Iterator<Item = (&Key, &[u8])> {
        self.entries
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
    }

    /// A trie rebuilt from the entries. After a full commit its root equals the
    /// head, so the store reproduces the committed state root from disk.
    pub fn load_trie(&self) -> Trie {
        let mut trie = Trie::new();
        for (key, value) in &self.entries {
            trie.insert(*key, value.clone());
        }
        trie
    }

    /// The number of entries the store holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries.
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

    /// A trie key from an index, standing in for a canonical address payload.
    fn key(index: u8) -> Key {
        let mut key = [0u8; KEY_LEN];
        key[0] = index;
        key[KEY_LEN - 1] = index.wrapping_mul(7);
        key
    }

    /// An account value, a nonce and a balance in canonical encoding.
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
            store.commit(root).unwrap();
        }

        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.head(), Some(root));
        assert_eq!(store.len(), accounts.len());
        for (k, value) in &accounts {
            assert_eq!(store.account(k), Some(value.as_slice()));
        }
        assert_eq!(store.load_trie().root(), root);

        // Every account the trie holds is reachable under the reopened root.
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
            store.commit(root).unwrap();
            store.put_account(key(2), account(0, 2)).unwrap();
            let root = store.load_trie().root();
            store.commit(root).unwrap();
            head_before = store.head();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.head(), head_before);
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
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.account(&key(1)), Some(account(1, 250).as_slice()));
        std::fs::remove_file(&path).ok();
    }
}
