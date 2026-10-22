// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use qtv_codec::{Decoder, Encoder, Error};

use crate::log::Log;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterArchiveEntry {
    pub epoch: u64,
    pub height: u64,
    pub roster: Vec<u8>,
    pub proof: Vec<u8>,
}

impl RosterArchiveEntry {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_u64(self.epoch);
        encoder.put_u64(self.height);
        encoder.put_bytes(&self.roster);
        encoder.put_bytes(&self.proof);
        encoder.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        let epoch = decoder.get_u64()?;
        let height = decoder.get_u64()?;
        let roster = decoder.get_bytes()?.to_vec();
        let proof = decoder.get_bytes()?.to_vec();
        decoder.finish()?;
        Ok(RosterArchiveEntry {
            epoch,
            height,
            roster,
            proof,
        })
    }
}

#[derive(Debug)]
pub struct RosterArchive {
    log: Log,
    by_epoch: BTreeMap<u64, (u64, u64)>,
}

impl RosterArchive {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut by_epoch: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        let log = Log::open_scanned_strict(path, |payload, payload_start, _end| {
            match RosterArchiveEntry::decode(payload) {
                Ok(entry) => {
                    by_epoch.insert(entry.epoch, (payload_start, payload.len() as u64));
                    true
                }
                Err(_) => false,
            }
        })?;
        Ok(RosterArchive { log, by_epoch })
    }

    pub fn append(&mut self, entry: RosterArchiveEntry) -> io::Result<()> {
        if self.by_epoch.contains_key(&entry.epoch) {
            return Ok(());
        }
        let payload = entry.encode();
        let start = self.log.next_payload_start()?;
        self.log.append(&payload)?;
        self.log.sync()?;
        self.by_epoch
            .insert(entry.epoch, (start, payload.len() as u64));
        Ok(())
    }

    pub fn truncate_to_height(&mut self, height: u64) -> io::Result<()> {
        let mut cut: Option<u64> = None;
        for (&epoch, &(start, _)) in &self.by_epoch {
            let stale = self.entry(epoch).is_none_or(|entry| entry.height > height);
            if stale {
                let frame = start.saturating_sub(qtv_codec::LENGTH_WIDTH as u64);
                cut = Some(cut.map_or(frame, |c| c.min(frame)));
            }
        }
        let Some(cut) = cut else {
            return Ok(());
        };
        self.log.truncate(cut)?;
        self.by_epoch.retain(|_, (start, _)| *start < cut);
        Ok(())
    }

    pub fn entry(&self, epoch: u64) -> Option<RosterArchiveEntry> {
        let (start, len) = *self.by_epoch.get(&epoch)?;
        let payload = self.log.read_payload(start, len).ok()?;
        RosterArchiveEntry::decode(&payload).ok()
    }
}
