// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use qtv_codec::{Encoder, LENGTH_WIDTH};

pub(crate) const MAX_RESYNC_PROBES: u32 = 1 << 24;

pub(crate) const CHECKSUM_WIDTH: usize = 4;

const MAX_PROBE_BYTES: u64 = 64 * 1024 * 1024;

const MAGIC: &[u8; 8] = b"QTVLOG02";
const SALT_LEN: usize = 16;
pub(crate) const HEADER_LEN: u64 = (MAGIC.len() + SALT_LEN) as u64;

type Salt = [u8; SALT_LEN];

fn prepare_header(file: &mut File) -> io::Result<Salt> {
    let len = file.metadata()?.len();
    if len < HEADER_LEN {
        let mut salt = [0u8; SALT_LEN];
        qtv_crypto::rng::fill_random(&mut salt);
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(MAGIC)?;
        file.write_all(&salt)?;
        file.sync_data()?;
        return Ok(salt);
    }
    let mut header = [0u8; HEADER_LEN as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    if &header[..MAGIC.len()] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a log of this format",
        ));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&header[MAGIC.len()..]);
    Ok(salt)
}

pub(crate) fn frame_len(payload_len: usize) -> u64 {
    (LENGTH_WIDTH + payload_len + CHECKSUM_WIDTH) as u64
}

#[derive(Debug)]
pub struct Log {
    file: File,
    reader: Mutex<File>,
    salt: Salt,
}

fn a_well_formed_frame_follows(
    stream: &mut BufReader<File>,
    salt: &Salt,
    from: u64,
    total: u64,
) -> io::Result<bool> {
    let mut at = from;
    let mut probed = 0u32;
    let mut budget = MAX_PROBE_BYTES;
    while at + LENGTH_WIDTH as u64 <= total {
        if probed >= MAX_RESYNC_PROBES {
            return Err(corrupt_middle());
        }
        match frame_is_well_formed(stream, salt, at, total, budget)? {
            Probe::Found => return Ok(true),
            Probe::Missed(spent) => budget -= spent,
            Probe::OverBudget => return Err(corrupt_middle()),
        }
        at += 1;
        probed += 1;
    }
    Ok(false)
}

enum Probe {
    Found,
    Missed(u64),
    OverBudget,
}

fn corrupt_middle() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "a log frame is unreadable with intact frames behind it, so the log is corrupt in \
         the middle rather than torn at the tail; refusing to open so the records after it \
         are not discarded",
    )
}

fn read_part(stream: &mut BufReader<File>, buf: &mut [u8]) -> io::Result<bool> {
    match stream.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(err) => Err(err),
    }
}

fn frame_is_well_formed(
    stream: &mut BufReader<File>,
    salt: &Salt,
    at: u64,
    total: u64,
    budget: u64,
) -> io::Result<Probe> {
    if total.saturating_sub(at) < LENGTH_WIDTH as u64 {
        return Ok(Probe::Missed(0));
    }
    stream.seek(SeekFrom::Start(at))?;
    let mut length_bytes = [0u8; LENGTH_WIDTH];
    if !read_part(stream, &mut length_bytes)? {
        return Ok(Probe::Missed(0));
    }
    let length = u64::from_le_bytes(length_bytes);
    let payload_start = at + LENGTH_WIDTH as u64;
    let available = total.saturating_sub(payload_start);
    if length > available || available - length < CHECKSUM_WIDTH as u64 {
        return Ok(Probe::Missed(0));
    }
    if length > budget {
        return Ok(Probe::OverBudget);
    }
    let mut payload = vec![0u8; length as usize];
    if !read_part(stream, &mut payload)? {
        return Ok(Probe::Missed(length));
    }
    let mut checksum_bytes = [0u8; CHECKSUM_WIDTH];
    if !read_part(stream, &mut checksum_bytes)? {
        return Ok(Probe::Missed(length));
    }
    if u32::from_le_bytes(checksum_bytes) == checksum_parts(&[salt, &length_bytes, &payload]) {
        Ok(Probe::Found)
    } else {
        Ok(Probe::Missed(length))
    }
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
        let salt = prepare_header(&mut file)?;
        file.seek(SeekFrom::Start(HEADER_LEN))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (frames, clean, stop) = scan(&salt, &bytes);
        let clean = clean + HEADER_LEN;
        if clean < HEADER_LEN + bytes.len() as u64 {
            if stop == ScanStop::Corrupt {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "log has a corrupt frame mid-stream; refusing to silently discard the \
                     records after it, which would roll finalized state back. Recover the log \
                     manually",
                ));
            }
            file.set_len(clean)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        if !existed {
            sync_parent_dir(path);
        }
        let reader = Mutex::new(OpenOptions::new().read(true).open(path)?);
        Ok((Log { file, reader, salt }, frames))
    }

    pub fn open_scanned<F>(path: impl AsRef<Path>, visit: F) -> io::Result<Self>
    where
        F: FnMut(&[u8], u64, u64) -> bool,
    {
        Self::scan_open(path, visit, false)
    }

    pub fn open_scanned_strict<F>(path: impl AsRef<Path>, visit: F) -> io::Result<Self>
    where
        F: FnMut(&[u8], u64, u64) -> bool,
    {
        Self::scan_open(path, visit, true)
    }

    pub fn open_scanned_keeping_tail<F>(path: impl AsRef<Path>, visit: F) -> io::Result<Self>
    where
        F: FnMut(&[u8], u64, u64) -> bool,
    {
        Self::scan_open_inner(path, visit, false, false)
    }

    pub fn open_scanned_keeping_tail_strict<F>(path: impl AsRef<Path>, visit: F) -> io::Result<Self>
    where
        F: FnMut(&[u8], u64, u64) -> bool,
    {
        Self::scan_open_parts(path, visit, false, true, false)
    }

    fn scan_open<F>(path: impl AsRef<Path>, visit: F, strict: bool) -> io::Result<Self>
    where
        F: FnMut(&[u8], u64, u64) -> bool,
    {
        Self::scan_open_parts(path, visit, strict, strict, true)
    }

    fn scan_open_inner<F>(
        path: impl AsRef<Path>,
        visit: F,
        strict: bool,
        truncate_tail: bool,
    ) -> io::Result<Self>
    where
        F: FnMut(&[u8], u64, u64) -> bool,
    {
        Self::scan_open_parts(path, visit, strict, strict, truncate_tail)
    }

    fn scan_open_parts<F>(
        path: impl AsRef<Path>,
        mut visit: F,
        strict_frames: bool,
        strict_decode: bool,
        truncate_tail: bool,
    ) -> io::Result<Self>
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
        let salt = prepare_header(&mut file)?;
        let total = file.metadata()?.len();
        let mut stream = BufReader::new(file.try_clone()?);
        stream.seek(SeekFrom::Start(HEADER_LEN))?;
        let mut pos = HEADER_LEN;
        let mut clean = HEADER_LEN;
        let mut payload: Vec<u8> = Vec::new();
        loop {
            if total.saturating_sub(pos) < LENGTH_WIDTH as u64 {
                break;
            }
            let mut length_bytes = [0u8; LENGTH_WIDTH];
            if !read_part(&mut stream, &mut length_bytes)? {
                break;
            }
            let length = u64::from_le_bytes(length_bytes);
            let payload_start = pos + LENGTH_WIDTH as u64;
            let available = total - payload_start;
            if length > available || available - length < CHECKSUM_WIDTH as u64 {
                if strict_frames
                    && a_well_formed_frame_follows(&mut stream, &salt, payload_start, total)?
                {
                    return Err(corrupt_middle());
                }
                break;
            }
            payload.clear();
            payload.resize(length as usize, 0u8);
            if !read_part(&mut stream, &mut payload)? {
                break;
            }
            let mut checksum_bytes = [0u8; CHECKSUM_WIDTH];
            if !read_part(&mut stream, &mut checksum_bytes)? {
                break;
            }
            if u32::from_le_bytes(checksum_bytes)
                != checksum_parts(&[&salt, &length_bytes, &payload])
            {
                if strict_frames
                    && a_well_formed_frame_follows(&mut stream, &salt, payload_start, total)?
                {
                    return Err(corrupt_middle());
                }
                break;
            }
            let end = payload_start + length + CHECKSUM_WIDTH as u64;
            if !visit(&payload, payload_start, end) {
                if strict_decode {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a checksum clean log frame does not decode; refusing to open so the \
                         records after it are not discarded",
                    ));
                }
                break;
            }
            pos = end;
            clean = end;
        }
        drop(stream);
        if truncate_tail && clean < total {
            file.set_len(clean)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        if !existed {
            sync_parent_dir(path);
        }
        let reader = Mutex::new(OpenOptions::new().read(true).open(path)?);
        Ok(Log { file, reader, salt })
    }

    pub fn read_payload(&self, payload_start: u64, payload_len: u64) -> io::Result<Vec<u8>> {
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| io::Error::other("log reader poisoned"))?;
        reader.seek(SeekFrom::Start(payload_start))?;
        let mut payload = vec![0u8; payload_len as usize];
        reader.read_exact(&mut payload)?;
        Ok(payload)
    }

    pub fn next_payload_start(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len() + LENGTH_WIDTH as u64)
    }

    pub fn append(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut encoder = Encoder::new();
        encoder.put_bytes(payload);
        let mut framed = encoder.into_bytes();
        let checksum = checksum_parts(&[&self.salt, &framed]);
        framed.extend_from_slice(&checksum.to_le_bytes());
        let before = self.file.metadata()?.len();
        if let Err(err) = self.file.write_all(&framed) {
            let _ = self.truncate(before);
            return Err(err);
        }
        Ok(())
    }

    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    pub fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    pub fn data_start(&self) -> u64 {
        HEADER_LEN
    }

    pub fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len.max(HEADER_LEN))?;
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

fn valid_frame_at(salt: &Salt, bytes: &[u8], pos: usize) -> bool {
    if bytes.len().saturating_sub(pos) < LENGTH_WIDTH {
        return false;
    }
    let mut length_bytes = [0u8; LENGTH_WIDTH];
    length_bytes.copy_from_slice(&bytes[pos..pos + LENGTH_WIDTH]);
    let length = u64::from_le_bytes(length_bytes) as usize;
    let payload_start = pos + LENGTH_WIDTH;
    let available = bytes.len() - payload_start;
    if length > available || available - length < CHECKSUM_WIDTH {
        return false;
    }
    let payload_end = payload_start + length;
    let frame_end = payload_end + CHECKSUM_WIDTH;
    let stored = u32::from_le_bytes(
        bytes[payload_end..frame_end]
            .try_into()
            .expect("checksum slice is four bytes"),
    );
    stored == checksum_parts(&[salt, &bytes[pos..payload_end]])
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanStop {
    TornTail,
    Corrupt,
}

fn scan(salt: &Salt, bytes: &[u8]) -> (Vec<Vec<u8>>, u64, ScanStop) {
    let mut frames = Vec::new();
    let mut pos = 0usize;
    let mut clean = 0u64;
    let stop = loop {
        if bytes.len() - pos < LENGTH_WIDTH {
            break ScanStop::TornTail;
        }
        let mut length_bytes = [0u8; LENGTH_WIDTH];
        length_bytes.copy_from_slice(&bytes[pos..pos + LENGTH_WIDTH]);
        let length = u64::from_le_bytes(length_bytes);
        let payload_start = pos + LENGTH_WIDTH;
        let available = bytes.len() - payload_start;
        if length > available as u64 {
            break ScanStop::TornTail;
        }
        let length = length as usize;
        if available - length < CHECKSUM_WIDTH {
            break ScanStop::TornTail;
        }
        let payload_end = payload_start + length;
        let frame_end = payload_end + CHECKSUM_WIDTH;
        let stored = u32::from_le_bytes(
            bytes[payload_end..frame_end]
                .try_into()
                .expect("checksum slice is four bytes"),
        );
        if stored != checksum_parts(&[salt, &bytes[pos..payload_end]]) {
            if valid_frame_at(salt, bytes, frame_end) {
                break ScanStop::Corrupt;
            }
            break ScanStop::TornTail;
        }
        frames.push(bytes[payload_start..payload_end].to_vec());
        pos = frame_end;
        clean = pos as u64;
    };
    (frames, clean, stop)
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
            let target = HEADER_LEN as usize + frame_len(5) as usize + LENGTH_WIDTH;
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
            let target = HEADER_LEN as usize + frame_len(3) as usize + LENGTH_WIDTH;
            bytes[target] ^= 0xFF;
            std::fs::write(&path, &bytes).unwrap();
        }
        let err = Log::open(&path).expect_err("mid-log corruption must not silently truncate");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_scanned_open_refuses_mid_log_corruption_instead_of_truncating() {
        let path = temp_path("scanned-middle");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"one").unwrap();
            log.append(b"two").unwrap();
            log.append(b"three").unwrap();
            log.sync().unwrap();
        }
        let before = std::fs::metadata(&path).unwrap().len();
        {
            let mut bytes = std::fs::read(&path).unwrap();
            let target = HEADER_LEN as usize + frame_len(3) as usize + LENGTH_WIDTH;
            bytes[target] ^= 0xFF;
            std::fs::write(&path, &bytes).unwrap();
        }
        let err = Log::open_scanned_strict(&path, |_, _, _| true)
            .expect_err("a scanned open must not silently discard the frames behind a bad one");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            before,
            "the log was truncated despite refusing to open"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_flipped_length_prefix_is_refused_like_any_other_mid_log_corruption() {
        for flip in [0usize, 7] {
            let path = temp_path(&format!("len-flip-{flip}"));
            {
                let (mut log, _frames) = Log::open(&path).unwrap();
                log.append(b"one").unwrap();
                log.append(b"two").unwrap();
                log.append(b"three").unwrap();
                log.sync().unwrap();
            }
            let before = std::fs::metadata(&path).unwrap().len();
            {
                let mut bytes = std::fs::read(&path).unwrap();
                let target = HEADER_LEN as usize + frame_len(3) as usize + flip;
                bytes[target] ^= 0x01;
                std::fs::write(&path, &bytes).unwrap();
            }
            let err = Log::open_scanned_strict(&path, |_, _, _| true).expect_err(
                "a corrupt length prefix must not silently discard the frames behind it",
            );
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                before,
                "the log was truncated despite refusing to open"
            );
            std::fs::remove_file(&path).ok();
        }
    }

    #[test]
    fn a_scanned_open_still_truncates_a_torn_tail() {
        let path = temp_path("scanned-tail");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"one").unwrap();
            log.append(b"two").unwrap();
            log.sync().unwrap();
        }
        {
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.truncate(bytes.len() - 2);
            std::fs::write(&path, &bytes).unwrap();
        }
        let mut seen = Vec::new();
        Log::open_scanned_strict(&path, |payload, _, _| {
            seen.push(payload.to_vec());
            true
        })
        .expect("a torn tail still opens");
        assert_eq!(seen, vec![b"one".to_vec()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_frame_planted_inside_a_torn_tail_does_not_read_as_mid_log_corruption() {
        let path = temp_path("planted-tail");
        {
            let (mut log, _frames) = Log::open(&path).unwrap();
            log.append(b"kept").unwrap();
            log.sync().unwrap();
        }
        {
            use std::io::Write;
            let mut planted = Encoder::new();
            planted.put_bytes(b"evil!");
            let mut planted = planted.into_bytes();
            let crc = checksum_parts(&[&planted]);
            planted.extend_from_slice(&crc.to_le_bytes());
            let mut torn = Encoder::new();
            torn.put_u64(4_096);
            let mut torn = torn.into_bytes();
            torn.extend_from_slice(&[0u8; 7]);
            torn.extend_from_slice(&planted);
            torn.extend_from_slice(&[1u8; 9]);
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&torn).unwrap();
        }
        let mut seen = Vec::new();
        Log::open_scanned_strict(&path, |payload, _, _| {
            seen.push(payload.to_vec());
            true
        })
        .expect("a torn tail opens whatever its partial payload holds");
        assert_eq!(seen, vec![b"kept".to_vec()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn every_log_carries_its_own_salt() {
        let one = temp_path("salt-one");
        let two = temp_path("salt-two");
        let (a, _) = Log::open(&one).unwrap();
        let (b, _) = Log::open(&two).unwrap();
        assert_ne!(a.salt, b.salt);
        drop(a);
        let (again, _) = Log::open(&one).unwrap();
        let first = std::fs::read(&one).unwrap();
        assert_eq!(&first[..MAGIC.len()], MAGIC);
        assert_eq!(&first[MAGIC.len()..HEADER_LEN as usize], &again.salt);
        std::fs::remove_file(&one).ok();
        std::fs::remove_file(&two).ok();
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
