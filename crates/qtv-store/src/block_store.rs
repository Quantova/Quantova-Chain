//! The file backed block store.
//!
//! Each finalized block is appended to the log as one record: the height, the
//! header hash, and the canonical block encoding. The block encoding is stored
//! whole, so a read returns the exact bytes that were written. Two in memory
//! indexes, one by height and one by hash, point at the stored encoding, so a
//! block is fetched by either. On open the log is scanned once and both indexes
//! and the head height are rebuilt from the records.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use qtv_block::{Block, ROOT_LEN};
use qtv_codec::{to_bytes, Decode, Decoder, Encode, Encoder, Error};

use crate::log::Log;

/// A header hash or a height keyed digest, a thirty two byte value.
type Hash = [u8; ROOT_LEN];

/// Append a thirty two byte value as its raw bytes in order.
fn put_hash(encoder: &mut Encoder, hash: &Hash) {
    for &byte in hash.iter() {
        encoder.put_u8(byte);
    }
}

/// Read a thirty two byte value as its raw bytes in order.
fn get_hash(decoder: &mut Decoder<'_>) -> Result<Hash, Error> {
    let mut hash = [0u8; ROOT_LEN];
    for slot in hash.iter_mut() {
        *slot = decoder.get_u8()?;
    }
    Ok(hash)
}

/// One stored block: the height and header hash it is indexed by, and the
/// canonical block encoding kept whole.
struct BlockRecord {
    height: u64,
    hash: Hash,
    block: Vec<u8>,
}

impl Encode for BlockRecord {
    fn encode(&self, encoder: &mut Encoder) {
        self.height.encode(encoder);
        put_hash(encoder, &self.hash);
        encoder.put_bytes(&self.block);
    }
}

impl Decode for BlockRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let height = u64::decode(decoder)?;
        let hash = get_hash(decoder)?;
        let block = decoder.get_bytes()?.to_vec();
        Ok(BlockRecord {
            height,
            hash,
            block,
        })
    }
}

/// A file backed store of finalized blocks, indexed by height and by hash.
#[derive(Debug)]
pub struct BlockStore {
    log: Log,
    blocks: Vec<Vec<u8>>,
    by_height: BTreeMap<u64, usize>,
    by_hash: BTreeMap<Hash, usize>,
    head_height: Option<u64>,
}

impl BlockStore {
    /// Open the block store at a path, creating the file when absent, and rebuild
    /// the indexes and the head height from the records. An absent or truncated
    /// file opens as an empty store.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (log, frames) = Log::open(path)?;
        let mut store = BlockStore {
            log,
            blocks: Vec::new(),
            by_height: BTreeMap::new(),
            by_hash: BTreeMap::new(),
            head_height: None,
        };
        for frame in &frames {
            let record: BlockRecord = match qtv_codec::from_bytes(frame) {
                Ok(record) => record,
                Err(_) => break,
            };
            store.index(record);
        }
        Ok(store)
    }

    /// Append a finalized block, then index it by height and by hash. The block
    /// enters the log through the canonical encoding, so a read returns the exact
    /// bytes that were written.
    pub fn put_block(&mut self, block: &Block) -> io::Result<()> {
        let record = BlockRecord {
            height: block.header().height(),
            hash: block.header_hash(),
            block: to_bytes(block),
        };
        self.log.append(&to_bytes(&record))?;
        self.index(record);
        Ok(())
    }

    /// The canonical encoding of the block at a height, or nothing when no block
    /// sits at that height.
    pub fn block_by_height(&self, height: u64) -> Option<&[u8]> {
        self.by_height
            .get(&height)
            .map(|&index| self.blocks[index].as_slice())
    }

    /// The canonical encoding of the block with a header hash, or nothing when no
    /// block carries that hash.
    pub fn block_by_hash(&self, hash: &Hash) -> Option<&[u8]> {
        self.by_hash
            .get(hash)
            .map(|&index| self.blocks[index].as_slice())
    }

    /// The head height, the greatest height the store holds, or nothing when the
    /// store is empty.
    pub fn head_height(&self) -> Option<u64> {
        self.head_height
    }

    /// The number of blocks the store holds.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the store holds no blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Record a decoded block in the indexes and advance the head height.
    fn index(&mut self, record: BlockRecord) {
        let index = self.blocks.len();
        self.by_height.insert(record.height, index);
        self.by_hash.insert(record.hash, index);
        self.head_height = Some(match self.head_height {
            Some(current) => current.max(record.height),
            None => record.height,
        });
        self.blocks.push(record.block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use qtv_block::{Header, ROOT_LEN};
    use qtv_tx::{Body, Call, Wrapper};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "qtv-store-block-{}-{}-{}",
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

    fn block(height: u64, tag: u8) -> Block {
        let mut root = [0u8; ROOT_LEN];
        root[0] = tag;
        let header = Header::new(
            height,
            [height as u8; ROOT_LEN],
            root,
            qtv_block::empty_transaction_root(),
            qtv_block::empty_transaction_root(),
            [7u8; ROOT_LEN],
            format!("proposer-{tag}"),
            1_000 + height,
        );
        let wrapper = Wrapper::new(
            Body::new(
                "sender".to_string(),
                height,
                21_000,
                5,
                Call::new("target".to_string(), vec![tag, tag]),
            ),
            qtv_tx::SCHEME_LATTICE,
            vec![tag; 4],
        );
        Block::new(header, vec![tag; 8], vec![wrapper])
    }

    #[test]
    fn an_absent_file_opens_empty() {
        let path = temp_path("absent");
        let store = BlockStore::open(&path).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.head_height(), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_block_round_trips_by_height_and_by_hash_across_a_reopen() {
        let path = temp_path("roundtrip");
        let first = block(1, 0xA1);
        let second = block(2, 0xB2);
        {
            let mut store = BlockStore::open(&path).unwrap();
            store.put_block(&first).unwrap();
            store.put_block(&second).unwrap();
        }
        let store = BlockStore::open(&path).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.block_by_height(1), Some(to_bytes(&first).as_slice()));
        assert_eq!(store.block_by_height(2), Some(to_bytes(&second).as_slice()));
        assert_eq!(
            store.block_by_hash(&first.header_hash()),
            Some(to_bytes(&first).as_slice())
        );
        assert_eq!(
            store.block_by_hash(&second.header_hash()),
            Some(to_bytes(&second).as_slice())
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_reopened_head_matches_before_the_restart() {
        let path = temp_path("head");
        let head_before;
        {
            let mut store = BlockStore::open(&path).unwrap();
            store.put_block(&block(5, 1)).unwrap();
            store.put_block(&block(6, 2)).unwrap();
            store.put_block(&block(7, 3)).unwrap();
            head_before = store.head_height();
        }
        let store = BlockStore::open(&path).unwrap();
        assert_eq!(store.head_height(), head_before);
        assert_eq!(store.head_height(), Some(7));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_missing_height_or_hash_reads_as_absent() {
        let path = temp_path("absent-key");
        let mut store = BlockStore::open(&path).unwrap();
        store.put_block(&block(1, 9)).unwrap();
        assert_eq!(store.block_by_height(2), None);
        assert_eq!(store.block_by_hash(&[0u8; ROOT_LEN]), None);
        std::fs::remove_file(&path).ok();
    }
}
