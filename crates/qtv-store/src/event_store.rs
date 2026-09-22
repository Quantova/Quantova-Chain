// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io;
use std::path::Path;

use qtv_codec::{Decoder, Encoder, Error, LENGTH_WIDTH};

use crate::log::{frame_len, Log, CHECKSUM_WIDTH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub height: u64,
    pub events: Vec<Vec<u8>>,
}

impl EventRecord {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_u64(self.height);
        encoder.put_u64(self.events.len() as u64);
        for leaf in &self.events {
            encoder.put_bytes(leaf);
        }
        encoder.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        let height = decoder.get_u64()?;
        let count = decoder.get_u64()?;
        let mut events = Vec::new();
        for _ in 0..count {
            events.push(decoder.get_bytes()?.to_vec());
        }
        decoder.finish()?;
        Ok(EventRecord { height, events })
    }
}

#[derive(Debug)]
pub struct EventStore {
    log: Log,
    heights: Vec<u64>,
    starts: Vec<u64>,
    lens: Vec<u64>,
    len_on_disk: u64,
}

impl EventStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut heights: Vec<u64> = Vec::new();
        let mut starts: Vec<u64> = Vec::new();
        let mut lens: Vec<u64> = Vec::new();
        let mut len_on_disk = 0u64;
        let log = Log::open_scanned_strict(path, |payload, payload_start, end| {
            let record = match EventRecord::decode(payload) {
                Ok(record) => record,
                Err(_) => return false,
            };
            heights.push(record.height);
            starts.push(payload_start);
            lens.push(payload.len() as u64);
            len_on_disk = end;
            true
        })?;
        Ok(EventStore {
            log,
            heights,
            starts,
            lens,
            len_on_disk: len_on_disk.max(crate::log::HEADER_LEN),
        })
    }

    pub fn put_events(&mut self, height: u64, events: &[Vec<u8>]) -> io::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        if self.heights.last().is_some_and(|&last| height < last) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "events are appended in height order",
            ));
        }
        let record = EventRecord {
            height,
            events: events.to_vec(),
        };
        let framed = record.encode();
        self.log.append(&framed)?;
        let payload_start = self.len_on_disk + LENGTH_WIDTH as u64;
        self.len_on_disk += frame_len(framed.len());
        self.heights.push(height);
        self.starts.push(payload_start);
        self.lens.push(framed.len() as u64);
        Ok(())
    }

    pub fn events_at(&self, height: u64) -> Option<Vec<Vec<u8>>> {
        let end = self.heights.partition_point(|&h| h <= height);
        let index = end.checked_sub(1)?;
        if self.heights[index] != height {
            return None;
        }
        let payload = self
            .log
            .read_payload(self.starts[index], self.lens[index])
            .ok()?;
        EventRecord::decode(&payload).ok().map(|r| r.events)
    }

    pub fn sync(&mut self) -> io::Result<()> {
        self.log.sync()
    }

    pub fn truncate_to_height(&mut self, height: u64) -> io::Result<()> {
        let keep = self.heights.iter().take_while(|&&h| h <= height).count();
        if keep == self.heights.len() {
            return Ok(());
        }
        let len = if keep == 0 {
            self.log.data_start()
        } else {
            self.starts[keep - 1] + self.lens[keep - 1] + CHECKSUM_WIDTH as u64
        };
        self.log.truncate(len)?;
        self.heights.truncate(keep);
        self.starts.truncate(keep);
        self.lens.truncate(keep);
        self.len_on_disk = len;
        Ok(())
    }

    pub fn head_height(&self) -> Option<u64> {
        self.heights.last().copied()
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

    fn leaf(tag: u8, len: usize) -> Vec<u8> {
        vec![tag; len]
    }

    #[test]
    fn events_come_back_after_the_store_is_reopened() {
        let dir = std::env::temp_dir().join(format!("qtv-events-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        {
            let mut store = EventStore::open(&dir).expect("opens");
            store
                .put_events(1, &[leaf(1, 4), leaf(2, 8)])
                .expect("puts");
            store.put_events(2, &[leaf(3, 16)]).expect("puts");
            store.put_events(3, &[]).expect("puts");
            store.sync().expect("syncs");
        }
        let store = EventStore::open(&dir).expect("reopens");
        assert_eq!(store.events_at(1), Some(vec![leaf(1, 4), leaf(2, 8)]));
        assert_eq!(store.events_at(2), Some(vec![leaf(3, 16)]));
        assert_eq!(
            store.events_at(3),
            None,
            "a block with no events is never written"
        );
        assert_eq!(store.events_at(99), None, "an unknown height reads as none");
        assert_eq!(store.head_height(), Some(2));
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn a_truncation_drops_only_the_heights_above_it() {
        let dir = std::env::temp_dir().join(format!("qtv-events-trunc-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let mut store = EventStore::open(&dir).expect("opens");
        for h in 1..=5u64 {
            store.put_events(h, &[leaf(h as u8, 4)]).expect("puts");
        }
        store.truncate_to_height(3).expect("truncates");
        assert_eq!(store.head_height(), Some(3));
        assert_eq!(store.events_at(3), Some(vec![leaf(3, 4)]));
        assert_eq!(store.events_at(4), None, "a rolled back height is gone");

        store.sync().expect("syncs");
        drop(store);
        let store = EventStore::open(&dir).expect("reopens");
        assert_eq!(store.head_height(), Some(3));
        assert_eq!(store.events_at(4), None);
        let _ = std::fs::remove_file(&dir);
    }
}
