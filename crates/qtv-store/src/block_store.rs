// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use qtv_block::{Block, ROOT_LEN};
use qtv_codec::{to_bytes, Decode, Decoder, Encode, Encoder, Error};

use crate::log::{frame_len, Log};

type Hash = [u8; ROOT_LEN];

fn put_hash(encoder: &mut Encoder, hash: &Hash) {
    for &byte in hash.iter() {
        encoder.put_u8(byte);
    }
}

fn get_hash(decoder: &mut Decoder<'_>) -> Result<Hash, Error> {
    let mut hash = [0u8; ROOT_LEN];
    for slot in hash.iter_mut() {
        *slot = decoder.get_u8()?;
    }
    Ok(hash)
}

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

#[derive(Debug)]
pub struct BlockStore {
    log: Log,
    blocks: Vec<Vec<u8>>,
    heights: Vec<u64>,
    hashes: Vec<Hash>,
    ends: Vec<u64>,
    by_height: BTreeMap<u64, usize>,
    by_hash: BTreeMap<Hash, usize>,
    head_height: Option<u64>,
    len_on_disk: u64,
}

impl BlockStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (log, frames) = Log::open(path)?;
        let mut store = BlockStore {
            log,
            blocks: Vec::new(),
            heights: Vec::new(),
            hashes: Vec::new(),
            ends: Vec::new(),
            by_height: BTreeMap::new(),
            by_hash: BTreeMap::new(),
            head_height: None,
            len_on_disk: 0,
        };
        let mut offset = 0u64;
        for frame in &frames {
            offset += frame_len(frame.len());
            let record: BlockRecord = match qtv_codec::from_bytes(frame) {
                Ok(record) => record,
                Err(_) => break,
            };
            store.index(record, offset);
        }
        Ok(store)
    }

    pub fn put_block(&mut self, block: &Block) -> io::Result<()> {
        let record = BlockRecord {
            height: block.header().height(),
            hash: block.header_hash(),
            block: to_bytes(block),
        };
        let framed = to_bytes(&record);
        self.log.append(&framed)?;
        let end = self.len_on_disk + frame_len(framed.len());
        self.index(record, end);
        Ok(())
    }

    pub fn sync(&mut self) -> io::Result<()> {
        self.log.sync()
    }

    pub fn truncate_to_height(&mut self, height: u64) -> io::Result<()> {
        let keep = self.heights.iter().take_while(|&&h| h <= height).count();
        if keep == self.blocks.len() {
            return Ok(());
        }
        let new_len = if keep == 0 { 0 } else { self.ends[keep - 1] };
        self.log.truncate(new_len)?;
        self.blocks.truncate(keep);
        self.heights.truncate(keep);
        self.hashes.truncate(keep);
        self.ends.truncate(keep);
        self.len_on_disk = new_len;
        self.by_height.clear();
        self.by_hash.clear();
        self.head_height = None;
        for index in 0..self.blocks.len() {
            self.by_height.insert(self.heights[index], index);
            self.by_hash.insert(self.hashes[index], index);
            self.head_height = Some(match self.head_height {
                Some(current) => current.max(self.heights[index]),
                None => self.heights[index],
            });
        }
        Ok(())
    }

    pub fn block_by_height(&self, height: u64) -> Option<&[u8]> {
        self.by_height
            .get(&height)
            .map(|&index| self.blocks[index].as_slice())
    }

    pub fn block_by_hash(&self, hash: &Hash) -> Option<&[u8]> {
        self.by_hash
            .get(hash)
            .map(|&index| self.blocks[index].as_slice())
    }

    pub fn head_height(&self) -> Option<u64> {
        self.head_height
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn index(&mut self, record: BlockRecord, end: u64) {
        let index = self.blocks.len();
        self.by_height.insert(record.height, index);
        self.by_hash.insert(record.hash, index);
        self.head_height = Some(match self.head_height {
            Some(current) => current.max(record.height),
            None => record.height,
        });
        self.heights.push(record.height);
        self.hashes.push(record.hash);
        self.ends.push(end);
        self.len_on_disk = end;
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
        let first = block(1, 161);
        let second = block(2, 178);
        {
            let mut store = BlockStore::open(&path).unwrap();
            store.put_block(&first).unwrap();
            store.put_block(&second).unwrap();
            store.sync().unwrap();
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
            store.sync().unwrap();
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

    #[test]
    fn truncating_to_a_height_drops_the_orphan_blocks_above_it() {
        let path = temp_path("truncate");
        let first = block(1, 10);
        let second = block(2, 20);
        {
            let mut store = BlockStore::open(&path).unwrap();
            store.put_block(&first).unwrap();
            store.put_block(&second).unwrap();
            store.put_block(&block(3, 30)).unwrap();
            store.sync().unwrap();
            store.truncate_to_height(2).unwrap();
            assert_eq!(store.head_height(), Some(2));
            assert_eq!(store.len(), 2);
            assert_eq!(store.block_by_height(3), None);
        }
        let mut store = BlockStore::open(&path).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.head_height(), Some(2));
        assert_eq!(store.block_by_height(1), Some(to_bytes(&first).as_slice()));
        assert_eq!(store.block_by_height(2), Some(to_bytes(&second).as_slice()));
        assert_eq!(store.block_by_height(3), None);
        let third = block(3, 33);
        store.put_block(&third).unwrap();
        store.sync().unwrap();
        let store = BlockStore::open(&path).unwrap();
        assert_eq!(store.len(), 3);
        assert_eq!(store.block_by_height(3), Some(to_bytes(&third).as_slice()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn truncating_at_or_above_the_head_keeps_every_block() {
        let path = temp_path("truncate-noop");
        let mut store = BlockStore::open(&path).unwrap();
        store.put_block(&block(1, 1)).unwrap();
        store.put_block(&block(2, 2)).unwrap();
        store.sync().unwrap();
        store.truncate_to_height(2).unwrap();
        assert_eq!(store.len(), 2);
        store.truncate_to_height(9).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.head_height(), Some(2));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn truncating_below_the_first_block_empties_the_store() {
        let path = temp_path("truncate-all");
        {
            let mut store = BlockStore::open(&path).unwrap();
            store.put_block(&block(1, 1)).unwrap();
            store.put_block(&block(2, 2)).unwrap();
            store.sync().unwrap();
            store.truncate_to_height(0).unwrap();
            assert!(store.is_empty());
            assert_eq!(store.head_height(), None);
        }
        let store = BlockStore::open(&path).unwrap();
        assert!(store.is_empty());
        std::fs::remove_file(&path).ok();
    }
}
