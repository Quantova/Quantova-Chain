// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::thread;

use qtv_net::{duplex, Channel, DuplexStream, Identity, Result};

pub struct Mesh<S> {
    node_count: usize,
    links: BTreeMap<(usize, usize), Channel<S>>,
    pending: BTreeMap<(usize, usize), usize>,
}

impl<S> Mesh<S> {
    pub fn from_links(node_count: usize, links: BTreeMap<(usize, usize), Channel<S>>) -> Self {
        Mesh {
            node_count,
            links,
            pending: BTreeMap::new(),
        }
    }

    pub fn empty(node_count: usize) -> Self {
        Mesh::from_links(node_count, BTreeMap::new())
    }

    pub fn node_count(&self) -> usize {
        self.node_count
    }

    pub fn has_edge(&self, from: usize, to: usize) -> bool {
        self.links.contains_key(&(from, to))
    }

    pub fn add_link(&mut self, i: usize, j: usize, channel_ij: Channel<S>, channel_ji: Channel<S>) {
        self.links.insert((i, j), channel_ij);
        self.links.insert((j, i), channel_ji);
    }
}

impl<S: Read + Write> Mesh<S> {
    pub fn send(&mut self, from: usize, to: usize, bytes: &[u8]) -> Result<()> {
        let channel = self
            .links
            .get_mut(&(from, to))
            .expect("a mesh link exists for every ordered pair");
        channel.send(bytes)?;
        *self.pending.entry((from, to)).or_insert(0) += 1;
        Ok(())
    }

    pub fn broadcast(&mut self, from: usize, bytes: &[u8], peers: &[usize]) -> Result<()> {
        for &to in peers {
            if to != from {
                self.send(from, to, bytes)?;
            }
        }
        Ok(())
    }

    pub fn pending(&self, from: usize, to: usize) -> usize {
        self.pending.get(&(from, to)).copied().unwrap_or(0)
    }

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
