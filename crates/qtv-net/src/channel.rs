// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{Read, Write};

use crate::identity::PeerId;
use crate::keyschedule::SessionKeys;
use crate::record::{Opener, Sealer};
use crate::Result;

#[derive(Clone, Copy)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

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

    pub fn peer_id(&self) -> &PeerId {
        &self.peer
    }

    pub fn channel_binding(&self) -> &[u8; 32] {
        &self.binding
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> Channel<S> {
    pub fn send(&mut self, message: &[u8]) -> Result<()> {
        self.sealer.seal(&mut self.stream, message)
    }

    pub fn recv(&mut self) -> Result<Vec<u8>> {
        self.opener.open(&mut self.stream)
    }
}

/// How long a live link may be silent before its reader wakes to re-check whether it
/// is still wanted. Not a liveness requirement, just a bound on how long a dead or
/// superseded link can hold a thread.
pub const POST_HANDSHAKE_READ: std::time::Duration = std::time::Duration::from_secs(20);

impl Channel<std::net::TcpStream> {
    pub(crate) fn set_deadline(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)
    }

    /// A live link still gets a read deadline. With none, a reader blocks in recv for
    /// ever on a peer that simply stops sending, so a superseded or silent link holds a
    /// thread and a socket until the process dies.
    pub(crate) fn set_post_handshake(&self) -> std::io::Result<()> {
        self.stream.set_read_timeout(Some(POST_HANDSHAKE_READ))?;
        self.stream
            .set_write_timeout(Some(std::time::Duration::from_millis(250)))
    }
}
