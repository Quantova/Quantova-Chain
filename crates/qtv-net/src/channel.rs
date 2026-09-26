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
    partial: Vec<u8>,
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
            partial: Vec::new(),
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

pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

const FRAGMENT_FINAL: u8 = 0;
const FRAGMENT_MORE: u8 = 1;
const FRAGMENT_PAYLOAD: usize = crate::record::MAX_RECORD_PLAINTEXT - 1;

impl<S: Read + Write> Channel<S> {
    pub fn send(&mut self, message: &[u8]) -> Result<()> {
        if message.len() > MAX_MESSAGE {
            return Err(crate::Error::MessageTooLarge);
        }
        let mut chunks = message.chunks(FRAGMENT_PAYLOAD).peekable();
        if chunks.peek().is_none() {
            return self.sealer.seal(&mut self.stream, &[FRAGMENT_FINAL]);
        }
        let mut record = Vec::with_capacity(FRAGMENT_PAYLOAD + 1);
        while let Some(chunk) = chunks.next() {
            record.clear();
            record.push(if chunks.peek().is_some() {
                FRAGMENT_MORE
            } else {
                FRAGMENT_FINAL
            });
            record.extend_from_slice(chunk);
            self.sealer.seal(&mut self.stream, &record)?;
        }
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            let record = self.opener.open(&mut self.stream)?;
            let (&flag, payload) = record.split_first().ok_or(crate::Error::BadFragment)?;
            if self.partial.len() + payload.len() > MAX_MESSAGE {
                self.partial = Vec::new();
                return Err(crate::Error::MessageTooLarge);
            }
            self.partial.extend_from_slice(payload);
            match flag {
                FRAGMENT_FINAL => return Ok(std::mem::take(&mut self.partial)),
                FRAGMENT_MORE if !payload.is_empty() => {}
                _ => {
                    self.partial = Vec::new();
                    return Err(crate::Error::BadFragment);
                }
            }
        }
    }
}

pub const POST_HANDSHAKE_READ: std::time::Duration = std::time::Duration::from_secs(20);

pub const POST_HANDSHAKE_WRITE: std::time::Duration = std::time::Duration::from_secs(10);

impl Channel<std::net::TcpStream> {
    pub(crate) fn set_deadline(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)
    }

    pub(crate) fn set_post_handshake(&self) -> std::io::Result<()> {
        self.stream.set_read_timeout(Some(POST_HANDSHAKE_READ))?;
        self.stream.set_write_timeout(Some(POST_HANDSHAKE_WRITE))
    }
}

#[cfg(test)]
mod fragment_tests {
    use super::*;
    use crate::{duplex, Identity};
    use std::thread;

    fn pair() -> (Channel<crate::DuplexStream>, Channel<crate::DuplexStream>) {
        let (client_stream, server_stream) = duplex();
        let responder = Identity::from_seed(&[22u8; 32]);
        let server = thread::spawn(move || Channel::accept(server_stream, &responder).unwrap());
        let client = Channel::connect(client_stream, &Identity::from_seed(&[11u8; 32])).unwrap();
        (client, server.join().unwrap())
    }

    fn round_trip(len: usize) {
        let (mut client, mut server) = pair();
        let message: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let sent = message.clone();
        let writer = thread::spawn(move || {
            client.send(&sent).unwrap();
            client
        });
        let received = server.recv().unwrap();
        let _client = writer.join().unwrap();
        assert_eq!(received.len(), len);
        assert_eq!(received, message, "a {len} byte message arrives whole");
    }

    #[test]
    fn a_message_larger_than_one_record_arrives_whole() {
        round_trip(3 * 1024 * 1024 + 17);
    }

    #[test]
    fn messages_at_the_record_edges_and_the_empty_message_arrive_whole() {
        round_trip(0);
        round_trip(FRAGMENT_PAYLOAD);
        round_trip(FRAGMENT_PAYLOAD + 1);
    }

    #[test]
    fn a_message_past_the_channel_limit_is_refused_before_it_is_sent() {
        let (mut client, _server) = pair();
        let too_big = vec![0u8; MAX_MESSAGE + 1];
        assert!(matches!(
            client.send(&too_big),
            Err(crate::Error::MessageTooLarge)
        ));
    }
}
