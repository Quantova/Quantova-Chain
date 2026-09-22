// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

mod channel;
pub mod erasure;
mod handshake;
mod identity;
pub mod keyschedule;
mod pipe;
pub mod record;
mod transcript;

pub use channel::{Channel, MAX_MESSAGE};
pub use erasure::{Coded, Commitment, Shard, ShardProof};
pub use identity::{Identity, PeerId};
pub use keyschedule::{DirKey, SessionKeys};
pub use pipe::{duplex, DuplexStream};

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Handshake(&'static str),
    Authentication,
    UnexpectedPeer,
    Record,
    MessageTooLarge,
    BadFragment,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "stream error: {err}"),
            Error::Handshake(reason) => write!(f, "malformed handshake: {reason}"),
            Error::Authentication => write!(f, "identity signature did not verify"),
            Error::UnexpectedPeer => write!(f, "authenticated peer did not match the pin"),
            Error::Record => write!(f, "record failed to open"),
            Error::MessageTooLarge => write!(f, "message exceeds the channel limit"),
            Error::BadFragment => write!(f, "malformed message fragment"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Whether this is a read deadline expiring rather than a broken link, so a caller
    /// can wake, re-check its own state, and keep the connection.
    pub fn is_timeout(&self) -> bool {
        match self {
            Error::Io(err) => matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            _ => false,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// One entropy source for the whole stack. Reading /dev/urandom straight returns
/// predictable bytes on a boot whose pool is not seeded, and those bytes become a session
/// key and a decapsulation secret.
pub(crate) fn fill_random(out: &mut [u8]) -> std::io::Result<()> {
    qtv_crypto::rng::fill_random(out);
    Ok(())
}
