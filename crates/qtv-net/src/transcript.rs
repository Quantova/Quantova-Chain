//! The handshake transcript.
//!
//! Every handshake field is absorbed in order and the SHA3-256 hash binds the
//! identities, the ephemeral key exchange, and the ciphertext. A signature over
//! the hash authenticates the whole exchange, and the key schedule feeds on the
//! same hash, so both peers agree on keys only if they agree on every byte that
//! was said. A tampered field changes the hash and the signature no longer
//! verifies.

use qtv_crypto::sha3;

/// The domain label that opens every transcript, so a hash from this protocol is
/// never mistaken for one from another.
pub const LABEL: &[u8] = b"qtv-net/handshake/v1";

/// A running handshake transcript.
pub struct Transcript {
    buffer: Vec<u8>,
}

impl Transcript {
    /// Open a transcript with the protocol label.
    pub fn new() -> Self {
        Self {
            buffer: LABEL.to_vec(),
        }
    }

    /// Absorb a handshake field in order.
    pub fn absorb(&mut self, field: &[u8]) {
        self.buffer.extend_from_slice(field);
    }

    /// The SHA3-256 hash of everything absorbed so far.
    pub fn hash(&self) -> [u8; 32] {
        sha3::sha3_256(&self.buffer)
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
