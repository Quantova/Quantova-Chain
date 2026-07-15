//! The append log the block store and the state store share.
//!
//! A log is a single file that holds a sequence of frames. A frame is a fixed
//! width length followed by that many payload bytes, the same length delimiting
//! the qtv-codec byte string uses. An append writes one frame and flushes it. On
//! open the file is scanned once into the whole run of payloads, in order.
//!
//! An append that was interrupted leaves a torn tail: a length without its bytes
//! or a length that overruns the file. The scan stops at the last whole frame and
//! the file is truncated back to it, so the log stays append only and a reopen
//! reads exactly the frames that were committed. An absent file opens empty.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use qtv_codec::{Decoder, Encoder, LENGTH_WIDTH};

/// A file backed append log of length delimited frames.
#[derive(Debug)]
pub struct Log {
    file: File,
}

impl Log {
    /// Open the log at a path, creating it when absent, and return the log
    /// together with every whole frame in order. A torn tail from an interrupted
    /// append is dropped and the file is truncated back to the last whole frame,
    /// so the next append stays contiguous.
    pub fn open(path: impl AsRef<Path>) -> io::Result<(Self, Vec<Vec<u8>>)> {
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
        }
        file.seek(SeekFrom::End(0))?;
        Ok((Log { file }, frames))
    }

    /// Append one frame, the payload length in canonical fixed width followed by
    /// the payload bytes, and flush it so a committed frame reaches disk.
    pub fn append(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut encoder = Encoder::new();
        encoder.put_bytes(payload);
        self.file.write_all(encoder.as_slice())?;
        self.file.flush()?;
        Ok(())
    }
}

/// Read every whole frame from a buffer and report the byte length the whole
/// frames cover. A short length field or a length that overruns the remaining
/// bytes marks a torn tail, so the scan stops and the clean length is the offset
/// before the torn frame.
fn scan(bytes: &[u8]) -> (Vec<Vec<u8>>, u64) {
    let mut decoder = Decoder::new(bytes);
    let mut frames = Vec::new();
    let mut clean = 0usize;
    while decoder.remaining() >= LENGTH_WIDTH {
        match decoder.get_bytes() {
            Ok(payload) => {
                frames.push(payload.to_vec());
                clean = bytes.len() - decoder.remaining();
            }
            Err(_) => break,
        }
    }
    (frames, clean as u64)
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
        }
        // Append a length that promises more bytes than follow, the shape of an
        // append that stopped after the length field.
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
        // The torn tail was truncated, so a reopen still reads only the whole frame.
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
        }
        let (_log, frames) = Log::open(&path).unwrap();
        assert_eq!(frames, vec![b"kept".to_vec(), b"next".to_vec()]);
        std::fs::remove_file(&path).ok();
    }
}
