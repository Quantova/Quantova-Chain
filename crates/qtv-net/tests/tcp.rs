//! The channel runs over a real TCP stream, not only the in memory duplex.

use std::net::{TcpListener, TcpStream};
use std::thread;

use qtv_net::{Channel, Identity};

#[test]
fn handshake_and_message_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let responder = Identity::from_seed(&[42u8; 32]);
    let responder_side = responder.clone();
    let server = thread::spawn(move || {
        let (stream, _peer) = listener.accept().unwrap();
        let mut channel = Channel::accept(stream, &responder_side).unwrap();
        let received = channel.recv().unwrap();
        channel.send(b"ack").unwrap();
        (channel.peer_id().clone(), received)
    });

    let initiator = Identity::from_seed(&[24u8; 32]);
    let stream = TcpStream::connect(address).unwrap();
    let mut client = Channel::connect(stream, &initiator).unwrap();

    assert_eq!(client.peer_id(), &responder.peer_id());
    client.send(b"hello over tcp").unwrap();

    let (seen_by_server, received) = server.join().unwrap();
    assert_eq!(received, b"hello over tcp");
    assert_eq!(seen_by_server, initiator.peer_id());
    assert_eq!(client.recv().unwrap(), b"ack");
}
