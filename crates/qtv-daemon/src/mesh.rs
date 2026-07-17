//! The real qtv-net post quantum mesh, generalised from the harness build for a
//! standalone daemon and given a chain id refusal on top.
//!
//! Each up pair holds two connections, one sealed record stream per direction: this
//! process dials an outbound connection to each peer it sends on, and accepts an
//! inbound connection from each peer a reader thread reads. Both directions run the
//! real ML-KEM and ML-DSA pinned handshake, so a peer that cannot prove the identity
//! its genesis validator id derives is refused at the handshake. On top of that, the
//! first frame of every connection is this node's genesis hash, and a reader that
//! sees a peer whose genesis hash is not its own drops that peer, so a node built on
//! a different chain id, validator set, or fund cannot feed this one consensus
//! records. A peer this node has no address for is neither dialled nor awaited, so a
//! single node network, which lists no peers, stands up its mesh with no peers and
//! finalises as its own supermajority.

use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use qtv_devnet::node::net_identity;
use qtv_net::{Channel, Identity};

use crate::util::{hex, log};

/// The tag ahead of the genesis hash in the mesh hello frame, so a hello is never
/// mistaken for a wire message and a truncated frame is caught by length.
const HELLO_TAG: &[u8; 8] = b"QTVGEN01";

/// The length of a hello frame, the tag followed by the thirty two byte genesis
/// hash.
const HELLO_LEN: usize = 8 + 32;

/// The built mesh handed to the round driver: the outbound sealed channel to each
/// peer indexed by validator index, the single inbound record queue the reader
/// threads feed, and which validator indices are up from this node's view.
pub struct Mesh {
    /// The outbound sealed channel to each peer, `None` for this node's own slot, for
    /// a validator this node has no address for, and for a peer refused at the hello.
    /// Only the driver's main thread sends on these.
    pub send: Vec<Option<Channel<TcpStream>>>,
    /// Inbound sealed records, `(from index, plaintext)`, one reader thread per up
    /// peer feeding this queue.
    pub inbound: Receiver<(usize, Vec<u8>)>,
    /// Whether each validator index is up from this node's view, this node and every
    /// peer it holds an authenticated same genesis connection to.
    pub up: Vec<bool>,
}

/// Build the mesh. `peer_addrs` is indexed by validator index, `id - 1`, holding the
/// dial address of each peer this node connects to and `None` for this node's own
/// slot and for any validator it has no address for. `idx` is this node's own index,
/// `n` the validator set size from genesis, `identity` this node's derived network
/// key, and `genesis_hash` the network identity a peer is pinned against.
pub fn build_mesh(
    listener: TcpListener,
    peer_addrs: &[Option<String>],
    idx: usize,
    n: usize,
    identity: &Identity,
    genesis_hash: [u8; 32],
) -> Mesh {
    // The up set: this node, plus every validator index it holds an address for. A
    // validator with no address is down from this node's view, neither dialled nor
    // awaited, so a missing peer never stalls the mesh standing up.
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

    // Accept the inbound connection from each up peer on its own thread, so accepting
    // and dialling proceed together and neither side deadlocks waiting on the other.
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
            // Match the authenticated peer to its validator index by the identity its
            // id derives, so a record is tagged with the validator it truly came from
            // rather than the socket it arrived on.
            let from = (0..n).find(|&q| {
                q != idx && up_acc.get(q).copied().unwrap_or(false) && net_identity(q as u64 + 1).peer_id() == peer
            });
            if let Some(from) = from {
                let _ = accepted_tx.send((from, channel));
            }
        }
    });

    // Dial an outbound channel to each up peer at its address, sending this node's
    // hello as the first frame. A peer still coming up refuses the connection, so a
    // short retry covers the process start ordering across hosts.
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
        let peer = net_identity(q as u64 + 1).peer_id();
        let mut channel =
            Channel::connect_pinned(stream, identity, &peer).expect("initiator handshake");
        if channel.send(&hello).is_err() {
            log(&format!("could not greet peer {}, dropping it", q + 1));
            continue;
        }
        send[q] = Some(channel);
    }

    acceptor.join().expect("the acceptor thread joins");

    // Spawn one reader thread per accepted inbound channel. The reader's first act is
    // to read the peer's hello and check it against this node's genesis hash; a peer
    // on a different genesis is logged and dropped, its records never reaching the
    // queue. Only then does the reader feed the sealed records onward.
    spawn_readers(&accepted_rx, up_peers, inbound_tx, genesis_hash);

    Mesh {
        send,
        inbound: inbound_rx,
        up,
    }
}

/// The hello frame this node sends first on every outbound connection: the tag and
/// this node's genesis hash.
fn hello_frame(genesis_hash: &[u8; 32]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HELLO_LEN);
    frame.extend_from_slice(HELLO_TAG);
    frame.extend_from_slice(genesis_hash);
    frame
}

/// Whether a received first frame is a well formed hello carrying this node's own
/// genesis hash, the check that refuses a peer on a different chain id or genesis.
fn hello_ok(frame: &[u8], genesis_hash: &[u8; 32]) -> bool {
    frame.len() == HELLO_LEN && &frame[..8] == HELLO_TAG && &frame[8..] == genesis_hash
}

/// Take each accepted inbound channel and spawn its reader thread. The reader checks
/// the peer's hello before it forwards a single record, so a wrong genesis peer is
/// refused as its first frame is read.
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
