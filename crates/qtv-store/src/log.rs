// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use qtv_codec::{Encoder, LENGTH_WIDTH};

pub(crate) const CHECKSUM_WIDTH: usize = 4;

pub(crate) fn frame_len(payload_len: usize) -> u64 {
    (LENGTH_WIDTH + payload_len + CHECKSUM_WIDTH) as u64
}

#[derive(Debug)]
pub struct Log {
    file: File,
    reader: Mutex<File>,
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
            file.set_len(clean)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        if !existed {
            sync_parent_dir(path);
        }
        let reader = Mutex::new(OpenOptions::new().read(true).open(path)?);
        Ok((Log { file, reader }, frames))
    }

    pub fn open_scanned<F>(path: impl AsRef<Path>, mut visit: F) -> io::Result<Self>
    where
        F: FnMut(&[u8], u64, u64) -> bool,
    {
        let path = path.as_ref();
        let existed = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let total = file.metadata()?.len();
        let mut stream = BufReader::new(file.try_clone()?);
        let mut pos = 0u64;
        let mut clean = 0u64;
        let mut payload: Vec<u8> = Vec::new();
        loop {
            if total.saturating_sub(pos) < LENGTH_WIDTH as u64 {
                break;
            }
            let mut length_bytes = [0u8; LENGTH_WIDTH];
            if stream.read_exact(&mut length_bytes).is_err() {
                break;
            }
            let length = u64::from_le_bytes(length_bytes);
            let payload_start = pos + LENGTH_WIDTH as u64;
            let available = total - payload_start;
            if length > available || available - length < CHECKSUM_WIDTH as u64 {
                break;
            }
            payload.clear();
            payload.resize(length as usize, 0u8);
            if stream.read_exact(&mut payload).is_err() {
                break;
            }
            let mut checksum_bytes = [0u8; CHECKSUM_WIDTH];
            if stream.read_exact(&mut checksum_bytes).is_err() {
                break;
            }
            if u32::from_le_bytes(checksum_bytes) != checksum_parts(&[&length_bytes, &payload]) {
                break;
            }
            let end = payload_start + length + CHECKSUM_WIDTH as u64;
            if !visit(&payload, payload_start, end) {
                break;
            }
            pos = end;
            clean = end;
        }
        drop(stream);
        if clean < total {
            file.set_len(clean)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        if !existed {
            sync_parent_dir(path);
        }
        let reader = Mutex::new(OpenOptions::new().read(true).open(path)?);
        Ok(Log { file, reader })
    }

    pub fn read_payload(&self, payload_start: u64, payload_len: u64) -> io::Result<Vec<u8>> {
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "log reader poisoned"))?;
        reader.seek(SeekFrom::Start(payload_start))?;
        let mut payload = vec![0u8; payload_len as usize];
        reader.read_exact(&mut payload)?;
        Ok(payload)
    }

    pub fn append(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut encoder = Encoder::new();
        encoder.put_bytes(payload);
        let mut framed = encoder.into_bytes();
        let checksum = checksum(&framed);
        framed.extend_from_slice(&checksum.to_le_bytes());
        self.file.write_all(&framed)?;
        Ok(())
    }

    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    pub fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.seek(SeekFrom::End(0))?;
        self.file.sync_data()?;
        Ok(())
    }
}

pub(crate) fn sync_parent_dir(path: &Path) {
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

fn checksum_parts(parts: &[&[u8]]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for part in parts {
        for &byte in part.iter() {
            let index = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC_TABLE[index];
        }
    }
    crc ^ 0xFFFF_FFFF
}

fn checksum(bytes: &[u8]) -> u32 {
    checksum_parts(&[bytes])
}

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
            break;
        }
        let length = length as usize;
        if available - length < CHECKSUM_WIDTH {
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
            use std::io::Write;
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            let mut encoder = Encoder::new();
            encoder.put_u64(64);
            encoder.put_u8(1);
            file.write_all(encoder.as_slice()).unwrap();
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(frames, vec![b"whole".to_vec()]);
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
