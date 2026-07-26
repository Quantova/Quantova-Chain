// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use qtv_crypto::{ml_dsa, ml_kem};

use crate::channel::{Channel, Role};
use crate::identity::{Identity, PeerId};
use crate::keyschedule;
use crate::transcript::Transcript;
use crate::{fill_random, Error, Result};

const INITIATOR_CONTEXT: &[u8] = b"qtv-net initiator";

const RESPONDER_CONTEXT: &[u8] = b"qtv-net responder";

impl<S: Read + Write> Channel<S> {
    pub fn connect(stream: S, identity: &Identity) -> Result<Self> {
        initiate(stream, identity, None)
    }

    pub fn connect_pinned(stream: S, identity: &Identity, peer: &PeerId) -> Result<Self> {
        initiate(stream, identity, Some(peer))
    }

    pub fn accept(stream: S, identity: &Identity) -> Result<Self> {
        respond(stream, identity, None)
    }

    pub fn accept_pinned(stream: S, identity: &Identity, peer: &PeerId) -> Result<Self> {
        respond(stream, identity, Some(peer))
    }
}

// A handshake over a raw socket must not block forever on a peer that opens the
// connection and then stalls. These constructors hold a read and write deadline
// over the handshake, so a slow or silent peer is dropped instead of pinning the
// acceptor, then lift the deadline so the settled channel keeps its blocking reads.
impl Channel<TcpStream> {
    pub fn accept_with_timeout(
        stream: TcpStream,
        identity: &Identity,
        timeout: Duration,
    ) -> Result<Self> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let channel = respond(stream, identity, None)?;
        channel.set_deadline(None)?;
        Ok(channel)
    }

    pub fn connect_with_timeout(
        stream: TcpStream,
        identity: &Identity,
        timeout: Duration,
    ) -> Result<Self> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let channel = initiate(stream, identity, None)?;
        channel.set_deadline(None)?;
        Ok(channel)
    }

    pub fn connect_pinned_with_timeout(
        stream: TcpStream,
        identity: &Identity,
        peer: &PeerId,
        timeout: Duration,
    ) -> Result<Self> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let channel = initiate(stream, identity, Some(peer))?;
        channel.set_deadline(None)?;
        Ok(channel)
    }
}

fn read_array<const N: usize, R: Read>(reader: &mut R) -> Result<[u8; N]> {
    let mut buffer = [0u8; N];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn initiate<S: Read + Write>(
    mut stream: S,
    identity: &Identity,
    expected: Option<&PeerId>,
) -> Result<Channel<S>> {
    let mut client_random = [0u8; 32];
    fill_random(&mut client_random)?;

    let mut transcript = Transcript::new();
    transcript.absorb(identity.public());
    transcript.absorb(&client_random);

    let mut hello = Vec::with_capacity(ml_dsa::PUBLIC_KEY_BYTES + client_random.len());
    hello.extend_from_slice(identity.public());
    hello.extend_from_slice(&client_random);
    stream.write_all(&hello)?;
    stream.flush()?;

    let responder_public: ml_dsa::PublicKey = read_array(&mut stream)?;
    let encaps_key: ml_kem::EncapsKey = read_array(&mut stream)?;
    let server_random: [u8; 32] = read_array(&mut stream)?;
    let responder_signature: ml_dsa::Signature = read_array(&mut stream)?;

    transcript.absorb(&responder_public);
    transcript.absorb(&encaps_key);
    transcript.absorb(&server_random);
    let server_bound = transcript.hash();
    if !ml_dsa::verify(
        &responder_public,
        &server_bound,
        &responder_signature,
        RESPONDER_CONTEXT,
    ) {
        return Err(Error::Authentication);
    }

    let peer = PeerId::from_public(&responder_public);
    if expected.is_some_and(|pin| &peer != pin) {
        return Err(Error::UnexpectedPeer);
    }

    let mut kem_random = [0u8; 32];
    fill_random(&mut kem_random)?;
    let (shared_secret, ciphertext) = ml_kem::encaps(&encaps_key, &kem_random);
    transcript.absorb(&ciphertext);
    let final_bound = transcript.hash();

    let initiator_signature = identity.sign(&final_bound, INITIATOR_CONTEXT)?;

    let mut finish = Vec::with_capacity(ml_kem::CIPHERTEXT_BYTES + ml_dsa::SIGNATURE_BYTES);
    finish.extend_from_slice(&ciphertext);
    finish.extend_from_slice(&initiator_signature);
    stream.write_all(&finish)?;
    stream.flush()?;

    let keys = keyschedule::derive(&shared_secret, &final_bound);
    Ok(Channel::new(stream, Role::Initiator, peer, keys))
}

fn respond<S: Read + Write>(
    mut stream: S,
    identity: &Identity,
    expected: Option<&PeerId>,
) -> Result<Channel<S>> {
    let mut kem_seed = [0u8; 32];
    let mut kem_z = [0u8; 32];
    fill_random(&mut kem_seed)?;
    fill_random(&mut kem_z)?;
    let (encaps_key, decaps_key) = ml_kem::keygen(&kem_seed, &kem_z);

    let initiator_public: ml_dsa::PublicKey = read_array(&mut stream)?;
    let client_random: [u8; 32] = read_array(&mut stream)?;

    let peer = PeerId::from_public(&initiator_public);
    if expected.is_some_and(|pin| &peer != pin) {
        return Err(Error::UnexpectedPeer);
    }

    let mut transcript = Transcript::new();
    transcript.absorb(&initiator_public);
    transcript.absorb(&client_random);

    let mut server_random = [0u8; 32];
    fill_random(&mut server_random)?;
    transcript.absorb(identity.public());
    transcript.absorb(&encaps_key);
    transcript.absorb(&server_random);
    let server_bound = transcript.hash();
    let responder_signature = identity.sign(&server_bound, RESPONDER_CONTEXT)?;

    let mut hello = Vec::with_capacity(
        ml_dsa::PUBLIC_KEY_BYTES
            + ml_kem::ENCAPS_KEY_BYTES
            + server_random.len()
            + ml_dsa::SIGNATURE_BYTES,
    );
    hello.extend_from_slice(identity.public());
    hello.extend_from_slice(&encaps_key);
    hello.extend_from_slice(&server_random);
    hello.extend_from_slice(&responder_signature);
    stream.write_all(&hello)?;
    stream.flush()?;

    let ciphertext: ml_kem::Ciphertext = read_array(&mut stream)?;
    let initiator_signature: ml_dsa::Signature = read_array(&mut stream)?;
    transcript.absorb(&ciphertext);
    let final_bound = transcript.hash();
    if !ml_dsa::verify(
        &initiator_public,
        &final_bound,
        &initiator_signature,
        INITIATOR_CONTEXT,
    ) {
        return Err(Error::Authentication);
    }

    let shared_secret = ml_kem::decaps(&decaps_key, &ciphertext);
    let keys = keyschedule::derive(&shared_secret, &final_bound);
    Ok(Channel::new(stream, Role::Responder, peer, keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duplex;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Instant;

    #[test]
    fn peers_complete_the_handshake_and_agree() {
        let (client_stream, server_stream) = duplex();
        let initiator = Identity::from_seed(&[11u8; 32]);
        let responder = Identity::from_seed(&[22u8; 32]);
        let responder_for_thread = responder.clone();

        let server =
            thread::spawn(move || Channel::accept(server_stream, &responder_for_thread).unwrap());
        let client = Channel::connect(client_stream, &initiator).unwrap();
        let server = server.join().unwrap();

        assert_eq!(client.channel_binding(), server.channel_binding());
        assert_eq!(client.peer_id(), &responder.peer_id());
        assert_eq!(server.peer_id(), &initiator.peer_id());
    }

    #[test]
    fn a_silent_peer_does_not_wedge_the_bounded_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let responder = Identity::from_seed(&[7u8; 32]);
        let server = thread::spawn(move || {
            let (stream, _peer) = listener.accept().unwrap();
            let start = Instant::now();
            let outcome =
                Channel::accept_with_timeout(stream, &responder, Duration::from_millis(200));
            (outcome.is_err(), start.elapsed())
        });

        // Connect and then send nothing, the classic slow loris.
        let _idle = TcpStream::connect(address).unwrap();
        let (errored, elapsed) = server.join().unwrap();
        assert!(errored, "a silent peer must be dropped, not admitted");
        assert!(
            elapsed < Duration::from_secs(5),
            "the bounded accept must return near its timeout, took {elapsed:?}"
        );
    }

    #[test]
    fn a_bounded_handshake_settles_and_keeps_carrying_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let responder = Identity::from_seed(&[9u8; 32]);
        let responder_id = responder.peer_id();
        let server = thread::spawn(move || {
            let (stream, _peer) = listener.accept().unwrap();
            let mut channel =
                Channel::accept_with_timeout(stream, &responder, Duration::from_secs(5)).unwrap();
            let seen = channel.recv().unwrap();
            channel.send(b"ack").unwrap();
            seen
        });

        let initiator = Identity::from_seed(&[8u8; 32]);
        let stream = TcpStream::connect(address).unwrap();
        let mut client =
            Channel::connect_with_timeout(stream, &initiator, Duration::from_secs(5)).unwrap();
        assert_eq!(client.peer_id(), &responder_id);
        client.send(b"bounded hello").unwrap();
        assert_eq!(client.recv().unwrap(), b"ack");
        assert_eq!(server.join().unwrap(), b"bounded hello");
    }
}
