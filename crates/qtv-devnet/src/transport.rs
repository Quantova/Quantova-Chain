//! The secure channel mesh the nodes gossip over.
//!
//! Every pair of nodes shares one qtv-net channel, established by the ML-KEM and
//! ML-DSA handshake with each side pinned to the other identity, so a peer without
//! the right identity key is refused. After the handshake a message travels the
//! channel sealed with ChaCha20-Poly1305 and a per direction sequence, so a
//! tampered or reordered record does not open.
//!
//! The mesh routes a sealed message from one node to another and tracks how many
//! records are in flight on each directed edge. A broadcast seals the message once
//! per peer, and a drain opens exactly the records that were sent, so the driver
//! moves messages between the channels in lockstep without blocking on a channel
//! that has nothing waiting. Every byte still passes through the qtv-net seal and
//! open, so the mesh is the wire, not a shortcut around it.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::thread;

use qtv_net::{duplex, Channel, DuplexStream, Identity, Result};

/// A secure channel mesh over a set of nodes indexed by position. The link
/// `(owner, peer)` is the owner channel toward that peer; the two endpoints of a
/// pair are `(i, j)` and `(j, i)`.
pub struct Mesh<S> {
    node_count: usize,
    links: BTreeMap<(usize, usize), Channel<S>>,
    pending: BTreeMap<(usize, usize), usize>,
}

impl<S> Mesh<S> {
    /// A mesh over the given established links.
    pub fn from_links(node_count: usize, links: BTreeMap<(usize, usize), Channel<S>>) -> Self {
        Mesh {
            node_count,
            links,
            pending: BTreeMap::new(),
        }
    }

    /// The number of nodes the mesh connects.
    pub fn node_count(&self) -> usize {
        self.node_count
    }
}

impl<S: Read + Write> Mesh<S> {
    /// Seal `bytes` and send them from one node to another over their channel,
    /// recording one record in flight on that edge.
    pub fn send(&mut self, from: usize, to: usize, bytes: &[u8]) -> Result<()> {
        let channel = self
            .links
            .get_mut(&(from, to))
            .expect("a mesh link exists for every ordered pair");
        channel.send(bytes)?;
        *self.pending.entry((from, to)).or_insert(0) += 1;
        Ok(())
    }

    /// Broadcast a message from one node to each listed peer, skipping itself.
    pub fn broadcast(&mut self, from: usize, bytes: &[u8], peers: &[usize]) -> Result<()> {
        for &to in peers {
            if to != from {
                self.send(from, to, bytes)?;
            }
        }
        Ok(())
    }

    /// Open every record waiting for `receiver` from each listed sender, in sender
    /// order, returning the sender index and the plaintext of each. Exactly the
    /// records that were sent are read, so the drain never blocks on an empty edge.
    pub fn drain(&mut self, receiver: usize, senders: &[usize]) -> Result<Vec<(usize, Vec<u8>)>> {
        let mut out = Vec::new();
        for &from in senders {
            if from == receiver {
                continue;
            }
            let count = self.pending.insert((from, receiver), 0).unwrap_or(0);
            let channel = self
                .links
                .get_mut(&(receiver, from))
                .expect("a mesh link exists for every ordered pair");
            for _ in 0..count {
                out.push((from, channel.recv()?));
            }
        }
        Ok(out)
    }
}

/// Stand up a full mesh over in memory duplex streams, one channel per pair, each
/// side running the pinned post-quantum handshake on its own thread so the two
/// sides complete together.
pub fn connect_duplex_mesh(identities: &[Identity]) -> Result<Mesh<DuplexStream>> {
    let n = identities.len();
    let mut links = BTreeMap::new();
    for i in 0..n {
        for j in (i + 1)..n {
            let (near, far) = duplex();
            let id_near = identities[i].clone();
            let id_far = identities[j].clone();
            let peer_near = identities[i].peer_id();
            let peer_far = identities[j].peer_id();
            let accepting =
                thread::spawn(move || Channel::accept_pinned(far, &id_far, &peer_near));
            let channel_i = Channel::connect_pinned(near, &id_near, &peer_far)?;
            let channel_j = accepting.join().expect("the accept thread joins")?;
            links.insert((i, j), channel_i);
            links.insert((j, i), channel_j);
        }
    }
    Ok(Mesh::from_links(n, links))
}
