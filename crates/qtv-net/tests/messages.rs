// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::thread;

use qtv_net::{duplex, Channel, DuplexStream, Identity};

fn peer_pair() -> (Channel<DuplexStream>, Channel<DuplexStream>) {
    let (client_stream, server_stream) = duplex();
    let initiator = Identity::from_seed(&[1u8; 32]);
    let responder = Identity::from_seed(&[2u8; 32]);
    let server = thread::spawn(move || Channel::accept(server_stream, &responder).unwrap());
    let client = Channel::connect(client_stream, &initiator).unwrap();
    let server = server.join().unwrap();
    (client, server)
}

#[test]
fn a_sealed_message_opens_and_matches() {
    let (mut client, mut server) = peer_pair();
    client.send(b"block announcement").unwrap();
    assert_eq!(server.recv().unwrap(), b"block announcement");
}

#[test]
fn messages_flow_both_ways_in_order() {
    let (mut client, mut server) = peer_pair();
    client.send(b"one").unwrap();
    client.send(b"two").unwrap();
    server.send(b"ack one").unwrap();

    assert_eq!(server.recv().unwrap(), b"one");
    assert_eq!(server.recv().unwrap(), b"two");
    assert_eq!(client.recv().unwrap(), b"ack one");
}

#[test]
fn an_empty_and_a_large_message_round_trip() {
    let (mut client, mut server) = peer_pair();
    client.send(b"").unwrap();
    assert_eq!(server.recv().unwrap(), b"");

    let large = vec![165u8; 200_000];
    client.send(&large).unwrap();
    assert_eq!(server.recv().unwrap(), large);
}
