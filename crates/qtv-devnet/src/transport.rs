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

    /// An empty mesh over a node count, to be filled with links as the overlay is
    /// formed. Discovery establishes the bootstrap links first, then the overlay
    /// adds a bounded neighbor link per node.
    pub fn empty(node_count: usize) -> Self {
        Mesh::from_links(node_count, BTreeMap::new())
    }

    /// The number of nodes the mesh connects.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Whether a channel is established on the directed edge from `from` to `to`.
    pub fn has_edge(&self, from: usize, to: usize) -> bool {
        self.links.contains_key(&(from, to))
    }

    /// Add an established pair of channels for the undirected edge between `i` and
    /// `j`, one channel in each direction. A discovered overlay edge is added here
    /// once its pinned handshake has authenticated both endpoints.
    pub fn add_link(&mut self, i: usize, j: usize, channel_ij: Channel<S>, channel_ji: Channel<S>) {
        self.links.insert((i, j), channel_ij);
        self.links.insert((j, i), channel_ji);
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

    /// The number of sealed records in flight on the directed edge from `from` to
    /// `to`, not yet opened by the receiver.
    pub fn pending(&self, from: usize, to: usize) -> usize {
        self.pending.get(&(from, to)).copied().unwrap_or(0)
    }

    /// Open exactly one record waiting for `to` from `from`, in send order. The
    /// round loop calls this once per delivery event, so a sealed record crosses
    /// the channel at the logical time its event fires while the edge stays in
    /// send order. Panics if no record is in flight on the edge.
    pub fn recv_one(&mut self, to: usize, from: usize) -> Result<Vec<u8>> {
        let count = self
            .pending
            .get_mut(&(from, to))
            .filter(|c| **c > 0)
            .expect("a delivery event fires only for a record in flight");
        *count -= 1;
        let channel = self
            .links
            .get_mut(&(to, from))
            .expect("a mesh link exists for every ordered pair");
        channel.recv()
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

/// Run the pinned post-quantum handshake between two identities over a fresh in
/// memory duplex, each side on its own thread so the two complete together. The
/// initiator and responder each pin the other identity, so the returned channels
/// are authenticated: a peer that cannot prove the identity is refused here, which
/// is where a discovered peer is trusted or dropped. Returns the `i` to `j`
/// channel and the `j` to `i` channel.
pub fn connect_duplex_pair(
    id_i: &Identity,
    id_j: &Identity,
) -> Result<(Channel<DuplexStream>, Channel<DuplexStream>)> {
    let (near, far) = duplex();
    let id_near = id_i.clone();
    let id_far = id_j.clone();
    let peer_near = id_i.peer_id();
    let peer_far = id_j.peer_id();
    let accepting = thread::spawn(move || Channel::accept_pinned(far, &id_far, &peer_near));
    let channel_i = Channel::connect_pinned(near, &id_near, &peer_far)?;
    let channel_j = accepting.join().expect("the accept thread joins")?;
    Ok((channel_i, channel_j))
}

/// Stand up a full mesh over in memory duplex streams, one channel per pair. Used
/// where the operator wires every pair by hand rather than discovering the overlay.
pub fn connect_duplex_mesh(identities: &[Identity]) -> Result<Mesh<DuplexStream>> {
    let n = identities.len();
    let mut mesh = Mesh::empty(n);
    for i in 0..n {
        for j in (i + 1)..n {
            let (channel_i, channel_j) = connect_duplex_pair(&identities[i], &identities[j])?;
            mesh.add_link(i, j, channel_i, channel_j);
        }
    }
    Ok(mesh)
}

/// Stand up channels for exactly the given undirected overlay edges over in memory
/// duplex streams, so the mesh is a bounded overlay rather than a full mesh.
pub fn connect_duplex_overlay(
    identities: &[Identity],
    edges: &[(usize, usize)],
) -> Result<Mesh<DuplexStream>> {
    let mut mesh = Mesh::empty(identities.len());
    for &(i, j) in edges {
        if !mesh.has_edge(i, j) {
            let (channel_i, channel_j) = connect_duplex_pair(&identities[i], &identities[j])?;
            mesh.add_link(i, j, channel_i, channel_j);
        }
    }
    Ok(mesh)
}
