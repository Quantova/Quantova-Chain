// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{self, Read, Write};
use std::thread;

use qtv_crypto::{ml_dsa, ml_kem};
use qtv_net::{duplex, Channel, Error, Identity};

fn identity(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

struct FlipWrite<S> {
    inner: S,
    position: u64,
    target: u64,
}

impl<S> FlipWrite<S> {
    fn at(inner: S, target: u64) -> Self {
        Self {
            inner,
            position: 0,
            target,
        }
    }
}

impl<S: Write> Write for FlipWrite<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut framed = data.to_vec();
        let span = self.position..self.position + framed.len() as u64;
        if span.contains(&self.target) {
            framed[(self.target - self.position) as usize] ^= 1;
        }
        self.position += framed.len() as u64;
        self.inner.write_all(&framed)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: Read> Read for FlipWrite<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.inner.read(out)
    }
}

const SERVER_HELLO_ENCAPS_OFFSET: u64 = ml_dsa::PUBLIC_KEY_BYTES as u64;
const SERVER_HELLO_SIGNATURE_OFFSET: u64 =
    (ml_dsa::PUBLIC_KEY_BYTES + ml_kem::ENCAPS_KEY_BYTES + 32) as u64;

const CLIENT_HANDSHAKE_BYTES: u64 =
    (ml_dsa::PUBLIC_KEY_BYTES + 32 + ml_kem::CIPHERTEXT_BYTES + ml_dsa::SIGNATURE_BYTES) as u64;

#[test]
fn a_tampered_transcript_is_rejected() {
    let (client_stream, server_stream) = duplex();
    let corrupted = FlipWrite::at(server_stream, SERVER_HELLO_ENCAPS_OFFSET);
    let responder = identity(6);
    let server = thread::spawn(move || Channel::accept(corrupted, &responder));

    let outcome = Channel::connect(client_stream, &identity(5));
    assert!(matches!(outcome, Err(Error::Authentication)));
    assert!(server.join().unwrap().is_err());
}

#[test]
fn a_wrong_identity_signature_is_rejected() {
    let (client_stream, server_stream) = duplex();
    let corrupted = FlipWrite::at(server_stream, SERVER_HELLO_SIGNATURE_OFFSET);
    let responder = identity(8);
    let server = thread::spawn(move || Channel::accept(corrupted, &responder));

    let outcome = Channel::connect(client_stream, &identity(7));
    assert!(matches!(outcome, Err(Error::Authentication)));
    assert!(server.join().unwrap().is_err());
}

#[test]
fn a_man_in_the_middle_without_the_identity_key_cannot_authenticate() {
    let (client_stream, server_stream) = duplex();
    let victim = identity(9);
    let expected = victim.peer_id();
    let attacker = identity(200);
    let server = thread::spawn(move || Channel::accept(server_stream, &attacker));

    let outcome = Channel::connect_pinned(client_stream, &identity(10), &expected);
    assert!(matches!(outcome, Err(Error::UnexpectedPeer)));
    let _ = server.join().unwrap();
}

#[test]
fn a_tampered_record_tears_down_the_channel() {
    let (client_stream, server_stream) = duplex();
    let corrupted = FlipWrite::at(client_stream, CLIENT_HANDSHAKE_BYTES + 4);
    let responder = identity(12);
    let responder_side = responder.clone();
    let server = thread::spawn(move || Channel::accept(server_stream, &responder_side).unwrap());

    let mut client = Channel::connect(corrupted, &identity(11)).unwrap();
    let mut server = server.join().unwrap();

    client.send(b"block announcement").unwrap();
    assert!(matches!(server.recv(), Err(Error::Record)));
}
