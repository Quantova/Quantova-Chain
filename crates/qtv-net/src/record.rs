//! The ChaCha20-Poly1305 record layer.
//!
//! Each direction of the channel is a sender and a receiver that share a
//! directional key and a starting nonce. The sender seals every message under a
//! nonce offset by a monotonic sequence number, binds the same sequence number as
//! associated data, and writes a length framed record. The receiver opens the
//! next record under the sequence number it expects, so a reordered, replayed, or
//! tampered record does not open and the channel tears down.

use std::io::{Read, Write};

use qtv_crypto::chacha20poly1305::{self, KEY_BYTES, NONCE_BYTES, TAG_BYTES};

use crate::{Error, Result};

/// The largest plaintext one record carries, one mebibyte.
const MAX_RECORD_PLAINTEXT: usize = 1 << 20;

/// The width of the big endian record length prefix.
const LENGTH_PREFIX: usize = 4;

/// Offset the starting nonce by the record sequence number. The counter occupies
/// the low eight bytes so a nonce never repeats within a direction.
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

/// The sending half of one direction.
pub struct Sealer {
    key: [u8; KEY_BYTES],
    iv: [u8; NONCE_BYTES],
    sequence: u64,
}

impl Sealer {
    /// Start a sender from a directional key and its starting nonce.
    pub fn new(key: [u8; KEY_BYTES], iv: [u8; NONCE_BYTES]) -> Self {
        Self {
            key,
            iv,
            sequence: 0,
        }
    }

    /// Seal `plaintext` and write the framed record to `writer`.
    pub fn seal<W: Write>(&mut self, writer: &mut W, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_RECORD_PLAINTEXT {
            return Err(Error::Handshake("record plaintext exceeds the size bound"));
        }
        let nonce = record_nonce(&self.iv, self.sequence);
        let aad = self.sequence.to_be_bytes();
        let (ciphertext, tag) = chacha20poly1305::seal(&self.key, &nonce, &aad, plaintext);

        let length = (ciphertext.len() + TAG_BYTES) as u32;
        let mut frame = Vec::with_capacity(LENGTH_PREFIX + ciphertext.len() + TAG_BYTES);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&tag);
        writer.write_all(&frame)?;
        writer.flush()?;

        self.sequence += 1;
        Ok(())
    }
}

/// The receiving half of one direction.
pub struct Opener {
    key: [u8; KEY_BYTES],
    iv: [u8; NONCE_BYTES],
    sequence: u64,
}

impl Opener {
    /// Start a receiver from a directional key and its starting nonce.
    pub fn new(key: [u8; KEY_BYTES], iv: [u8; NONCE_BYTES]) -> Self {
        Self {
            key,
            iv,
            sequence: 0,
        }
    }

    /// Read one framed record from `reader` and return its plaintext. A record
    /// that fails to open leaves the sequence untouched and returns an error.
    pub fn open<R: Read>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        let mut length_bytes = [0u8; LENGTH_PREFIX];
        reader.read_exact(&mut length_bytes)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if !(TAG_BYTES..=MAX_RECORD_PLAINTEXT + TAG_BYTES).contains(&length) {
            return Err(Error::Handshake("record length is out of range"));
        }

        let mut body = vec![0u8; length];
        reader.read_exact(&mut body)?;
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
