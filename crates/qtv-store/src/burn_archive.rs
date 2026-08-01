// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::collections::BTreeMap;
use std::io;
use std::ops::Bound;
use std::path::Path;

use qtv_codec::{Decoder, Encoder, Error};

use crate::log::Log;

pub const MAX_HEIGHTS_AFTER: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnArchiveEntry {
    pub height: u64,
    pub header_bytes: Vec<u8>,
    pub certificate: Vec<u8>,
    pub events: Vec<Vec<u8>>,
}

impl BurnArchiveEntry {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_u64(self.height);
        encoder.put_bytes(&self.header_bytes);
        encoder.put_bytes(&self.certificate);
        encoder.put_u64(self.events.len() as u64);
        for leaf in &self.events {
            encoder.put_bytes(leaf);
        }
        encoder.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        let height = decoder.get_u64()?;
        let header_bytes = decoder.get_bytes()?.to_vec();
        let certificate = decoder.get_bytes()?.to_vec();
        let count = decoder.get_u64()?;
        let mut events = Vec::new();
        for _ in 0..count {
            events.push(decoder.get_bytes()?.to_vec());
        }
        decoder.finish()?;
        Ok(BurnArchiveEntry {
            height,
            header_bytes,
            certificate,
            events,
        })
    }
}

#[derive(Debug)]
pub struct BurnArchive {
    log: Log,
    by_height: BTreeMap<u64, BurnArchiveEntry>,
}

impl BurnArchive {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (log, frames) = Log::open(path)?;
        let mut by_height = BTreeMap::new();
        for frame in &frames {
            match BurnArchiveEntry::decode(frame) {
                Ok(entry) => {
                    by_height.insert(entry.height, entry);
                }
                Err(_) => break,
            }
        }
        Ok(BurnArchive { log, by_height })
    }

    pub fn append(&mut self, entry: BurnArchiveEntry) -> io::Result<()> {
        // Each entry is one self-contained frame, so append and sync commit it atomically.
        self.log.append(&entry.encode())?;
        self.log.sync()?;
        self.by_height.insert(entry.height, entry);
        Ok(())
    }

    pub fn entry(&self, height: u64) -> Option<&BurnArchiveEntry> {
        self.by_height.get(&height)
    }

    pub fn contains(&self, height: u64) -> bool {
        self.by_height.contains_key(&height)
    }

    pub fn heights_after(&self, cursor: u64) -> Vec<u64> {
        self.by_height
            .range((Bound::Excluded(cursor), Bound::Unbounded))
            .take(MAX_HEIGHTS_AFTER)
            .map(|(height, _)| *height)
            .collect()
    }

    pub fn heights(&self) -> Vec<u64> {
        self.by_height.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.by_height.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_height.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "qtv-store-burn-{}-{}-{}",
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

    fn entry(height: u64, tag: u8) -> BurnArchiveEntry {
        BurnArchiveEntry {
            height,
            header_bytes: vec![tag; 12],
            certificate: vec![tag ^ 0x55; 20],
            events: vec![vec![0x01, tag], vec![0x02, tag, tag], vec![tag]],
        }
    }

    #[test]
    fn an_appended_entry_is_retrievable_by_height() {
        let path = temp_path("retrieve");
        let mut archive = BurnArchive::open(&path).unwrap();
        assert!(archive.is_empty());
        let written = entry(7, 0xAB);
        archive.append(written.clone()).unwrap();
        assert_eq!(archive.entry(7), Some(&written));
        assert!(archive.entry(6).is_none());
        assert!(archive.contains(7));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_archive_survives_a_reopen() {
        let path = temp_path("reopen");
        let first = entry(3, 0x11);
        let second = entry(9, 0x22);
        {
            let mut archive = BurnArchive::open(&path).unwrap();
            archive.append(first.clone()).unwrap();
            archive.append(second.clone()).unwrap();
        }
        let archive = BurnArchive::open(&path).unwrap();
        assert_eq!(archive.len(), 2);
        assert_eq!(archive.entry(3), Some(&first));
        assert_eq!(archive.entry(9), Some(&second));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn heights_after_returns_burn_heights_in_order() {
        let path = temp_path("cursor");
        let mut archive = BurnArchive::open(&path).unwrap();
        archive.append(entry(12, 1)).unwrap();
        archive.append(entry(4, 2)).unwrap();
        archive.append(entry(30, 3)).unwrap();
        archive.append(entry(19, 4)).unwrap();
        assert_eq!(archive.heights_after(0), vec![4, 12, 19, 30]);
        assert_eq!(archive.heights_after(12), vec![19, 30]);
        assert_eq!(archive.heights_after(30), Vec::<u64>::new());
        std::fs::remove_file(&path).ok();
    }
}
