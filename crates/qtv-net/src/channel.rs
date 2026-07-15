//! The encrypted channel over a stream.

use std::io::{Read, Write};

use crate::identity::PeerId;
use crate::keyschedule::SessionKeys;
use crate::record::{Opener, Sealer};
use crate::Result;

/// Which side of the handshake a channel took, so it knows which directional key
/// seals and which opens.
#[derive(Clone, Copy)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

/// A post-quantum secure channel over a stream.
///
/// Once the handshake completes the channel seals every message it sends and
/// opens every message it receives, each under the directional key, nonce, and
/// sequence number for that direction. A record that fails to open returns an
/// error, and the caller drops the channel.
pub struct Channel<S> {
    stream: S,
    peer: PeerId,
    binding: [u8; 32],
    sealer: Sealer,
    opener: Opener,
}

impl<S> Channel<S> {
    pub(crate) fn new(stream: S, role: Role, peer: PeerId, keys: SessionKeys) -> Self {
        let (send, receive) = match role {
            Role::Initiator => (keys.initiator_to_responder, keys.responder_to_initiator),
            Role::Responder => (keys.responder_to_initiator, keys.initiator_to_responder),
        };
        Self {
            stream,
            peer,
            binding: keys.exporter,
            sealer: Sealer::new(send.key, send.iv),
            opener: Opener::new(receive.key, receive.iv),
        }
    }

    /// The authenticated identity of the far peer.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer
    }

    /// The channel binding both peers derive alike, a handle to this session.
    pub fn channel_binding(&self) -> &[u8; 32] {
        &self.binding
    }

    /// Recover the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> Channel<S> {
    /// Seal `message` and write it to the stream as one record.
    pub fn send(&mut self, message: &[u8]) -> Result<()> {
        self.sealer.seal(&mut self.stream, message)
    }

    /// Read and open the next record from the stream.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        self.opener.open(&mut self.stream)
    }
}
