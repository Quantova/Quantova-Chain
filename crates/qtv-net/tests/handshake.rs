// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Two peers complete the handshake and agree on the session.

use std::thread;

use qtv_net::{duplex, Channel, Identity};

fn identity(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

#[test]
fn two_peers_derive_the_same_session() {
    let (client_stream, server_stream) = duplex();
    let initiator = identity(1);
    let responder = identity(2);
    let responder_side = responder.clone();

    let server = thread::spawn(move || Channel::accept(server_stream, &responder_side).unwrap());
    let client = Channel::connect(client_stream, &initiator).unwrap();
    let server = server.join().unwrap();

    // Both peers derived the same channel binding from the ML-KEM shared secret
    // and the handshake transcript, so they agree on the derived session.
    assert_eq!(client.channel_binding(), server.channel_binding());

    // Each authenticated the other, so each learned the far peer true identity.
    assert_eq!(client.peer_id(), &responder.peer_id());
    assert_eq!(server.peer_id(), &initiator.peer_id());
    assert_eq!(client.peer_id().public(), responder.public());
    assert_eq!(server.peer_id().public(), initiator.public());
}

#[test]
fn a_pinned_peer_is_accepted_when_it_matches() {
    let (client_stream, server_stream) = duplex();
    let initiator = identity(3);
    let responder = identity(4);
    let responder_side = responder.clone();
    let expected = responder.peer_id();

    let server = thread::spawn(move || Channel::accept(server_stream, &responder_side).unwrap());
    let client = Channel::connect_pinned(client_stream, &initiator, &expected).unwrap();
    let server = server.join().unwrap();

    assert_eq!(client.peer_id(), &expected);
    assert_eq!(client.channel_binding(), server.channel_binding());
}
