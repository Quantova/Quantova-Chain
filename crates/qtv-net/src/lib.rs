//! The post-quantum authenticated secure channel for the Quantova stack.
//!
//! Two peers open a channel over a standard library stream and run a
//! post-quantum handshake. Each peer holds a long term ML-DSA identity key whose
//! public part is its peer identity. The initiator encapsulates to the responder
//! ephemeral ML-KEM public key to establish a shared secret, both peers sign the
//! handshake transcript with their identity key so each authenticates the other,
//! and both derive directional session keys and starting nonces from the shared
//! secret and the transcript with SHAKE. Once the handshake completes the channel
//! seals every message with ChaCha20-Poly1305 under the derived directional key,
//! a monotonic per direction nonce, and the sequence number bound as associated
//! data, so a reordered, replayed, or tampered record fails to open.
//!
//! The only cryptographic dependency is qtv-crypto. The key exchange is ML-KEM,
//! the authentication is ML-DSA, the key schedule is SHAKE, and the channel
//! cipher is ChaCha20-Poly1305. There is no classical cryptography and no X25519.

#![forbid(unsafe_code)]

mod identity;

pub use identity::{Identity, PeerId};

use std::fmt;

/// A channel error.
#[derive(Debug)]
pub enum Error {
    /// The underlying stream failed or closed.
    Io(std::io::Error),
    /// A handshake message was malformed or a record frame was out of range.
    Handshake(&'static str),
    /// An identity signature over the transcript failed to verify, so the peer
    /// is not who it claims to be or the transcript was tampered with.
    Authentication,
    /// The authenticated peer did not match the pinned identity.
    UnexpectedPeer,
    /// A record failed to open, which a tampered, replayed, or reordered record
    /// all produce. The channel is torn down.
    Record,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "stream error: {err}"),
            Error::Handshake(reason) => write!(f, "malformed handshake: {reason}"),
            Error::Authentication => write!(f, "identity signature did not verify"),
            Error::UnexpectedPeer => write!(f, "authenticated peer did not match the pin"),
            Error::Record => write!(f, "record failed to open"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

/// A channel result.
pub type Result<T> = std::result::Result<T, Error>;

/// Fill `out` with bytes from the operating system entropy source. The handshake
/// draws the ML-KEM encapsulation randomness, the ephemeral key seeds, and the
/// ML-DSA signing randomness from here.
pub(crate) fn fill_random(out: &mut [u8]) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Read;
    let mut source = File::open("/dev/urandom")?;
    source.read_exact(out)
}
