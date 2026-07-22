
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use qtv_devnet::node::node_peer_id;
use qtv_net::{Channel, Identity};

use crate::util::{hex, log};

const HELLO_TAG: &[u8; 8] = b"QTVGEN01";

const HELLO_LEN: usize = 8 + 32;

pub struct Mesh {
    pub send: Vec<Option<Channel<TcpStream>>>,
    pub inbound: Receiver<(usize, Vec<u8>)>,
    pub up: Vec<bool>,
}

pub fn build_mesh(
    listener: TcpListener,
    peer_addrs: &[Option<String>],
    idx: usize,
    n: usize,
    identity: &Identity,
    genesis_hash: [u8; 32],
) -> Mesh {
    let mut up = vec![false; n];
    up[idx] = true;
    for (q, addr) in peer_addrs.iter().enumerate() {
        if q != idx && addr.is_some() {
            up[q] = true;
        }
    }
    let up_peers = up.iter().enumerate().filter(|&(q, &u)| q != idx && u).count();

    let (inbound_tx, inbound_rx) = mpsc::channel::<(usize, Vec<u8>)>();
    let (accepted_tx, accepted_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();

    let identity_acc = identity.clone();
    let up_acc = up.clone();
    let acceptor = thread::spawn(move || {
        for _ in 0..up_peers {
            let (stream, _) = listener.accept().expect("accept an inbound peer connection");
            let channel = match Channel::accept(stream, &identity_acc) {
                Ok(channel) => channel,
                Err(_) => continue,
            };
            let peer = channel.peer_id().clone();
            let from = (0..n).find(|&q| {
                q != idx && up_acc.get(q).copied().unwrap_or(false) && node_peer_id(q as u64 + 1) == peer
            });
            if let Some(from) = from {
                let _ = accepted_tx.send((from, channel));
            }
        }
    });

    let hello = hello_frame(&genesis_hash);
    let mut send: Vec<Option<Channel<TcpStream>>> = (0..n).map(|_| None).collect();
    for (q, addr) in peer_addrs.iter().enumerate() {
        let (q, addr) = match addr {
            Some(addr) if q != idx => (q, addr),
            _ => continue,
        };
        let stream = loop {
            match TcpStream::connect(addr) {
                Ok(stream) => break stream,
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        };
        let peer = node_peer_id(q as u64 + 1);
        let mut channel =
            Channel::connect_pinned(stream, identity, &peer).expect("initiator handshake");
        if channel.send(&hello).is_err() {
            log(&format!("could not greet peer {}, dropping it", q + 1));
            continue;
        }
        send[q] = Some(channel);
    }

    acceptor.join().expect("the acceptor thread joins");

    spawn_readers(&accepted_rx, up_peers, inbound_tx, genesis_hash);

    Mesh {
        send,
        inbound: inbound_rx,
        up,
    }
}

fn hello_frame(genesis_hash: &[u8; 32]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HELLO_LEN);
    frame.extend_from_slice(HELLO_TAG);
    frame.extend_from_slice(genesis_hash);
    frame
}

fn hello_ok(frame: &[u8], genesis_hash: &[u8; 32]) -> bool {
    frame.len() == HELLO_LEN && &frame[..8] == HELLO_TAG && &frame[8..] == genesis_hash
}

fn spawn_readers(
    accepted_rx: &Receiver<(usize, Channel<TcpStream>)>,
    up_peers: usize,
    inbound_tx: Sender<(usize, Vec<u8>)>,
    genesis_hash: [u8; 32],
) {
    for _ in 0..up_peers {
        let Ok((from, mut channel)) = accepted_rx.recv() else {
            break;
        };
        let out = inbound_tx.clone();
        thread::spawn(move || {
            match channel.recv() {
                Ok(frame) if hello_ok(&frame, &genesis_hash) => {}
                Ok(frame) => {
                    log(&format!(
                        "refusing peer {}: its genesis hash {} is not ours, wrong chain",
                        from + 1,
                        hex(frame.get(8..).unwrap_or(&[]))
                    ));
                    return;
                }
                Err(_) => return,
            }
            while let Ok(bytes) = channel.recv() {
                if out.send((from, bytes)).is_err() {
                    break;
                }
            }
        });
    }
    drop(inbound_tx);
}
