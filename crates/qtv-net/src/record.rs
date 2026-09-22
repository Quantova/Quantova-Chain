// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_wipe::Zeroize;
use std::io::{Read, Write};

use qtv_crypto::chacha20poly1305::{self, KEY_BYTES, NONCE_BYTES, TAG_BYTES};

use crate::{Error, Result};

pub(crate) const MAX_RECORD_PLAINTEXT: usize = 1 << 20;

const LENGTH_PREFIX: usize = 4;

fn record_nonce(iv: &[u8; NONCE_BYTES], sequence: u64) -> [u8; NONCE_BYTES] {
    let mut nonce = *iv;
    for (slot, byte) in nonce[NONCE_BYTES - 8..]
        .iter_mut()
        .zip(sequence.to_be_bytes())
    {
        *slot ^= byte;
    }
    nonce
}

pub struct Sealer {
    key: [u8; KEY_BYTES],
    iv: [u8; NONCE_BYTES],
    sequence: u64,
    torn: bool,
}

impl Drop for Sealer {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Sealer {
    pub fn new(key: [u8; KEY_BYTES], iv: [u8; NONCE_BYTES]) -> Self {
        Self {
            key,
            iv,
            sequence: 0,
            torn: false,
        }
    }

    pub fn seal<W: Write>(&mut self, writer: &mut W, plaintext: &[u8]) -> Result<()> {
        if self.torn {
            return Err(Error::Handshake(
                "a previous record was only part written, so this stream can no longer be framed",
            ));
        }
        if plaintext.len() > MAX_RECORD_PLAINTEXT {
            return Err(Error::Handshake("record plaintext exceeds the size bound"));
        }
        if self.sequence == u64::MAX {
            return Err(Error::Handshake("record sequence exhausted"));
        }
        let sequence = self.sequence;
        self.sequence += 1;
        let nonce = record_nonce(&self.iv, sequence);
        let aad = sequence.to_be_bytes();
        let (ciphertext, tag) = chacha20poly1305::seal(&self.key, &nonce, &aad, plaintext);

        let length = (ciphertext.len() + TAG_BYTES) as u32;
        let mut frame = Vec::with_capacity(LENGTH_PREFIX + ciphertext.len() + TAG_BYTES);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&tag);
        if let Err(e) = writer.write_all(&frame) {
            self.torn = true;
            return Err(e.into());
        }
        if let Err(e) = writer.flush() {
            self.torn = true;
            return Err(e.into());
        }
        Ok(())
    }
}

fn fill<R: Read>(reader: &mut R, buf: &mut [u8], mid_frame: bool) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::from(
                    std::io::ErrorKind::UnexpectedEof,
                )))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if filled == 0 && !mid_frame => return Err(Error::Io(e)),
            Err(_) => return Err(Error::Record),
        }
    }
    Ok(())
}

pub struct Opener {
    key: [u8; KEY_BYTES],
    iv: [u8; NONCE_BYTES],
    sequence: u64,
}

impl Drop for Opener {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Opener {
    pub fn new(key: [u8; KEY_BYTES], iv: [u8; NONCE_BYTES]) -> Self {
        Self {
            key,
            iv,
            sequence: 0,
        }
    }

    pub fn open<R: Read>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        let mut length_bytes = [0u8; LENGTH_PREFIX];
        fill(reader, &mut length_bytes, false)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if !(TAG_BYTES..=MAX_RECORD_PLAINTEXT + TAG_BYTES).contains(&length) {
            return Err(Error::Handshake("record length is out of range"));
        }

        let mut body = vec![0u8; length];
        fill(reader, &mut body, true)?;
        let split = length - TAG_BYTES;
        let tag: [u8; TAG_BYTES] = body[split..]
            .try_into()
            .expect("the record body holds a full tag");
        let ciphertext = &body[..split];

        let nonce = record_nonce(&self.iv, self.sequence);
        let aad = self.sequence.to_be_bytes();
        match chacha20poly1305::open(&self.key, &nonce, &aad, ciphertext, &tag) {
            Some(plaintext) => {
                self.sequence += 1;
                Ok(plaintext)
            }
            None => Err(Error::Record),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direction() -> ([u8; KEY_BYTES], [u8; NONCE_BYTES]) {
        ([7u8; KEY_BYTES], [3u8; NONCE_BYTES])
    }

    #[test]
    fn seals_and_opens_in_order() {
        let (key, iv) = direction();
        let mut sealer = Sealer::new(key, iv);
        let mut opener = Opener::new(key, iv);
        let mut wire = Vec::new();
        sealer.seal(&mut wire, b"first").unwrap();
        sealer.seal(&mut wire, b"second").unwrap();
        let mut reader = wire.as_slice();
        assert_eq!(opener.open(&mut reader).unwrap(), b"first");
        assert_eq!(opener.open(&mut reader).unwrap(), b"second");
    }

    #[test]
    fn a_tampered_record_fails_to_open() {
        let (key, iv) = direction();
        let mut sealer = Sealer::new(key, iv);
        let mut wire = Vec::new();
        sealer.seal(&mut wire, b"payload").unwrap();
        wire[LENGTH_PREFIX] ^= 1;
        let mut opener = Opener::new(key, iv);
        let mut reader = wire.as_slice();
        assert!(matches!(opener.open(&mut reader), Err(Error::Record)));
    }

    #[test]
    fn a_replayed_record_fails_to_open() {
        let (key, iv) = direction();
        let mut sealer = Sealer::new(key, iv);
        let mut first = Vec::new();
        sealer.seal(&mut first, b"once").unwrap();

        let mut opener = Opener::new(key, iv);
        let mut reader = first.as_slice();
        assert_eq!(opener.open(&mut reader).unwrap(), b"once");
        let mut replay = first.as_slice();
        assert!(matches!(opener.open(&mut replay), Err(Error::Record)));
    }

    struct Stalls<'a> {
        bytes: &'a [u8],
        stall_after: usize,
        read: usize,
    }

    impl Read for Stalls<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.read >= self.stall_after || self.read >= self.bytes.len() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let end = self.stall_after.min(self.bytes.len());
            let n = buf.len().min(end - self.read);
            buf[..n].copy_from_slice(&self.bytes[self.read..self.read + n]);
            self.read += n;
            Ok(n)
        }
    }

    #[test]
    fn a_deadline_before_a_record_is_a_timeout_but_one_inside_it_is_fatal() {
        let (key, iv) = direction();
        let mut sealer = Sealer::new(key, iv);
        let mut wire = Vec::new();
        sealer.seal(&mut wire, b"payload").unwrap();

        let mut opener = Opener::new(key, iv);
        let mut idle = Stalls {
            bytes: &wire,
            stall_after: 0,
            read: 0,
        };
        assert!(
            opener.open(&mut idle).unwrap_err().is_timeout(),
            "no byte of the record was read, so the link is only quiet"
        );

        for stall_after in [2, LENGTH_PREFIX, LENGTH_PREFIX + 3] {
            let mut opener = Opener::new(key, iv);
            let mut torn = Stalls {
                bytes: &wire,
                stall_after,
                read: 0,
            };
            let error = opener.open(&mut torn).unwrap_err();
            assert!(
                !error.is_timeout(),
                "a deadline {stall_after} bytes into a record leaves the stream unframeable"
            );
        }
    }

    #[test]
    fn a_reordered_record_fails_to_open() {
        let (key, iv) = direction();
        let mut sealer = Sealer::new(key, iv);
        let mut first = Vec::new();
        sealer.seal(&mut first, b"one").unwrap();
        let mut second = Vec::new();
        sealer.seal(&mut second, b"two").unwrap();

        let mut opener = Opener::new(key, iv);
        let mut reader = second.as_slice();
        assert!(matches!(opener.open(&mut reader), Err(Error::Record)));
    }
}
