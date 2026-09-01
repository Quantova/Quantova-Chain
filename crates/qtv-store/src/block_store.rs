// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use qtv_block::{Block, ROOT_LEN};
use qtv_codec::{to_bytes, Decode, Decoder, Encode, Encoder, Error, LENGTH_WIDTH};

use crate::log::{frame_len, Log, CHECKSUM_WIDTH};

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
    heights: Vec<u64>,
    hashes: Vec<Hash>,
    starts: Vec<u64>,
    lens: Vec<u64>,
    by_hash: BTreeMap<Hash, usize>,
    head_height: Option<u64>,
    len_on_disk: u64,
}

impl BlockStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut heights: Vec<u64> = Vec::new();
        let mut hashes: Vec<Hash> = Vec::new();
        let mut starts: Vec<u64> = Vec::new();
        let mut lens: Vec<u64> = Vec::new();
        let mut by_hash: BTreeMap<Hash, usize> = BTreeMap::new();
        let mut head_height: Option<u64> = None;
        let mut len_on_disk = 0u64;
        let log = Log::open_scanned(path, |payload, payload_start, end| {
            let record: BlockRecord = match qtv_codec::from_bytes(payload) {
                Ok(record) => record,
                Err(_) => return false,
            };
            by_hash.insert(record.hash, heights.len());
            head_height = Some(match head_height {
                Some(current) => current.max(record.height),
                None => record.height,
            });
            heights.push(record.height);
            hashes.push(record.hash);
            starts.push(payload_start);
            lens.push(payload.len() as u64);
            len_on_disk = end;
            true
        })?;
        Ok(BlockStore {
            log,
            heights,
            hashes,
            starts,
            lens,
            by_hash,
            head_height,
            len_on_disk,
        })
    }

    pub fn put_block(&mut self, block: &Block) -> io::Result<()> {
        let record = BlockRecord {
            height: block.header().height(),
            hash: block.header_hash(),
            block: to_bytes(block),
        };
        let framed = to_bytes(&record);
        self.log.append(&framed)?;
        let payload_start = self.len_on_disk + LENGTH_WIDTH as u64;
        let end = self.len_on_disk + frame_len(framed.len());
        self.by_hash.insert(record.hash, self.heights.len());
        self.head_height = Some(match self.head_height {
            Some(current) => current.max(record.height),
            None => record.height,
        });
        self.heights.push(record.height);
        self.hashes.push(record.hash);
        self.starts.push(payload_start);
        self.lens.push(framed.len() as u64);
        self.len_on_disk = end;
        Ok(())
    }

    pub fn sync(&mut self) -> io::Result<()> {
        self.log.sync()
    }

    pub fn truncate_to_height(&mut self, height: u64) -> io::Result<()> {
        let keep = self.heights.iter().take_while(|&&h| h <= height).count();
        if keep == self.heights.len() {
            return Ok(());
        }
        let new_len = if keep == 0 {
            0
        } else {
            self.starts[keep - 1] + self.lens[keep - 1] + CHECKSUM_WIDTH as u64
        };
        self.log.truncate(new_len)?;
        self.heights.truncate(keep);
        self.hashes.truncate(keep);
        self.starts.truncate(keep);
        self.lens.truncate(keep);
        self.len_on_disk = new_len;
        self.by_hash.clear();
        self.head_height = None;
        for index in 0..self.heights.len() {
            self.by_hash.insert(self.hashes[index], index);
            self.head_height = Some(match self.head_height {
                Some(current) => current.max(self.heights[index]),
                None => self.heights[index],
            });
        }
        Ok(())
    }

    pub fn block_by_height(&self, height: u64) -> Option<Vec<u8>> {
        let index = self.heights.binary_search(&height).ok()?;
        self.read_block(index)
    }

    pub fn block_by_hash(&self, hash: &Hash) -> Option<Vec<u8>> {
        let index = *self.by_hash.get(hash)?;
        self.read_block(index)
    }

    fn read_block(&self, index: usize) -> Option<Vec<u8>> {
        let payload = self
            .log
            .read_payload(*self.starts.get(index)?, *self.lens.get(index)?)
            .ok()?;
        let record: BlockRecord = qtv_codec::from_bytes(&payload).ok()?;
        Some(record.block)
    }

    pub fn head_height(&self) -> Option<u64> {
        self.head_height
    }

    pub fn len(&self) -> usize {
        self.heights.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heights.is_empty()
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
        assert_eq!(store.block_by_height(1), Some(to_bytes(&first)));
        assert_eq!(store.block_by_height(2), Some(to_bytes(&second)));
        assert_eq!(
            store.block_by_hash(&first.header_hash()),
            Some(to_bytes(&first))
        );
        assert_eq!(
            store.block_by_hash(&second.header_hash()),
            Some(to_bytes(&second))
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
        assert_eq!(store.block_by_height(1), Some(to_bytes(&first)));
        assert_eq!(store.block_by_height(2), Some(to_bytes(&second)));
        assert_eq!(store.block_by_height(3), None);
        let third = block(3, 33);
        store.put_block(&third).unwrap();
        store.sync().unwrap();
        let store = BlockStore::open(&path).unwrap();
        assert_eq!(store.len(), 3);
        assert_eq!(store.block_by_height(3), Some(to_bytes(&third)));
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
