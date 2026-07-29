// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use qtv_codec::{Encoder, LENGTH_WIDTH};

/// Trailing per-frame checksum so bit rot and a truncated tail are caught at scan time, not read back as state.
pub(crate) const CHECKSUM_WIDTH: usize = 4;

/// The on disk size of a frame holding `payload_len` bytes, being the length
/// prefix, the payload, and the checksum.
pub(crate) fn frame_len(payload_len: usize) -> u64 {
    (LENGTH_WIDTH + payload_len + CHECKSUM_WIDTH) as u64
}

#[derive(Debug)]
pub struct Log {
    file: File,
}

impl Log {
    pub fn open(path: impl AsRef<Path>) -> io::Result<(Self, Vec<Vec<u8>>)> {
        let path = path.as_ref();
        let existed = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (frames, clean) = scan(&bytes);
        if clean < bytes.len() as u64 {
            // A partial or corrupt tail is dropped so the file holds only whole,
            // checksum verified frames, and the truncation is made durable.
            file.set_len(clean)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        if !existed {
            // A newly created file is only durable once its directory entry is,
            // so fsync the containing directory before the first commit lands.
            sync_parent_dir(path);
        }
        Ok((Log { file }, frames))
    }

    /// Append a framed record. The bytes reach the page cache but are not made
    /// durable here. Callers force durability at a commit boundary with `sync`.
    pub fn append(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut encoder = Encoder::new();
        encoder.put_bytes(payload);
        let mut framed = encoder.into_bytes();
        let checksum = checksum(&framed);
        framed.extend_from_slice(&checksum.to_le_bytes());
        self.file.write_all(&framed)?;
        Ok(())
    }

    /// Flush appended records to stable storage. This is the durability point of
    /// a per-height commit.
    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    /// Cut the log back to `len` bytes and make it durable, discarding a partially written height.
    pub fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.seek(SeekFrom::End(0))?;
        self.file.sync_data()?;
        Ok(())
    }
}

fn sync_parent_dir(path: &Path) {
    // Best effort: harden the directory entry so a freshly created log is not lost by name. Not fatal if unsupported.
    if let Some(parent) = path.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// A table driven CRC32 (IEEE 802.3), the standard integrity check for a write
/// ahead log. It detects torn writes and bit rot. It is not a cryptographic MAC.
const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

fn checksum(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[index];
    }
    crc ^ 0xFFFF_FFFF
}

/// Read whole, checksum-verified frames, stopping at the first truncated or corrupt one; returns the clean prefix length.
fn scan(bytes: &[u8]) -> (Vec<Vec<u8>>, u64) {
    let mut frames = Vec::new();
    let mut pos = 0usize;
    let mut clean = 0u64;
    loop {
        if bytes.len() - pos < LENGTH_WIDTH {
            break;
        }
        let mut length_bytes = [0u8; LENGTH_WIDTH];
        length_bytes.copy_from_slice(&bytes[pos..pos + LENGTH_WIDTH]);
        let length = u64::from_le_bytes(length_bytes);
        let payload_start = pos + LENGTH_WIDTH;
        let available = bytes.len() - payload_start;
        if length > available as u64 {
            // The payload runs past the end of the file, a torn tail.
            break;
        }
        let length = length as usize;
        if available - length < CHECKSUM_WIDTH {
            // The checksum did not make it to disk, a torn tail.
            break;
        }
        let payload_end = payload_start + length;
        let frame_end = payload_end + CHECKSUM_WIDTH;
        let stored = u32::from_le_bytes(
            bytes[payload_end..frame_end]
                .try_into()
                .expect("checksum slice is four bytes"),
        );
        if stored != checksum(&bytes[pos..payload_end]) {
            // Bit rot in the length, payload, or checksum, so stop at the last
            // good record and read nothing beyond a corrupt frame.
            break;
        }
        frames.push(bytes[payload_start..payload_end].to_vec());
        pos = frame_end;
        clean = pos as u64;
    }
    (frames, clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "qtv-store-log-{}-{}-{}",
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

    #[test]
    fn an_absent_file_opens_empty() {
        let path = temp_path("absent");
        let (_log, frames) = Log::open(&path).unwrap();
        assert!(frames.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn frames_reopen_in_order() {
        let path = temp_path("order");
        {
            let (mut log, frames) = Log::open(&path).unwrap();
            assert!(frames.is_empty());
            log.append(b"first").unwrap();
            log.append(b"second").unwrap();
            log.append(b"third").unwrap();
            log.sync().unwrap();
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(
            frames,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_torn_tail_is_dropped_and_truncated() {
        let path = temp_path("torn");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"whole").unwrap();
            log.sync().unwrap();
        }
        {
            // A half written frame: a length prefix and one payload byte, with no
            // room for the payload it claims nor its checksum.
            use std::io::Write;
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            let mut encoder = Encoder::new();
            encoder.put_u64(64);
            encoder.put_u8(1);
            file.write_all(encoder.as_slice()).unwrap();
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(frames, vec![b"whole".to_vec()]);
        // The torn tail is gone from disk, so a second open agrees.
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(frames, vec![b"whole".to_vec()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_append_after_a_torn_tail_stays_contiguous() {
        let path = temp_path("recover");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"kept").unwrap();
            log.sync().unwrap();
        }
        {
            use std::io::Write;
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[9u8, 9, 9]).unwrap();
        }
        {
            let (mut log, frames) = Log::open(&path).unwrap();
            assert_eq!(frames, vec![b"kept".to_vec()]);
            log.append(b"next").unwrap();
            log.sync().unwrap();
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(frames, vec![b"kept".to_vec(), b"next".to_vec()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_flipped_payload_byte_is_detected_and_the_record_dropped() {
        let path = temp_path("bitrot");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"alpha").unwrap();
            log.append(b"bravo").unwrap();
            log.sync().unwrap();
        }
        // Flip a bit inside the second record's payload (it begins at byte 25).
        {
            let mut bytes = std::fs::read(&path).unwrap();
            let target = frame_len(5) as usize + LENGTH_WIDTH;
            bytes[target] ^= 0x01;
            std::fs::write(&path, &bytes).unwrap();
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(frames, vec![b"alpha".to_vec()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_flipped_checksum_byte_is_detected() {
        let path = temp_path("checksum-rot");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"only").unwrap();
            log.sync().unwrap();
        }
        {
            let mut bytes = std::fs::read(&path).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x80;
            std::fs::write(&path, &bytes).unwrap();
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert!(frames.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_corrupt_middle_frame_stops_the_scan_there() {
        let path = temp_path("middle");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"one").unwrap();
            log.append(b"two").unwrap();
            log.append(b"three").unwrap();
            log.sync().unwrap();
        }
        // Corrupt the second record. Everything from it onward is unreadable.
        {
            let mut bytes = std::fs::read(&path).unwrap();
            let target = frame_len(3) as usize + LENGTH_WIDTH;
            bytes[target] ^= 0xFF;
            std::fs::write(&path, &bytes).unwrap();
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(frames, vec![b"one".to_vec()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let path = temp_path("empty-payload");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"").unwrap();
            log.append(b"after").unwrap();
            log.sync().unwrap();
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(frames, vec![Vec::<u8>::new(), b"after".to_vec()]);
        std::fs::remove_file(&path).ok();
    }
}
