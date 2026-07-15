//! The devnet driver: an asynchronous per node round loop over a logical clock,
//! run over a discovered bounded gossip overlay rather than a full mesh.
//!
//! Each node runs its own round on the logical clock rather than in lockstep. A
//! node acts when a sealed message arrives or a view timeout fires, not when a
//! central driver steps every node together. The driver owns the nodes, the
//! secure channel mesh, the clock, and the delivery schedule; it seals each
//! outgoing message onto the channels and schedules its delivery, and it fires the
//! view timeouts. Every byte still passes through the qtv-net seal and open, so
//! the mesh is the wire, not a shortcut around it.
//!
//! The nodes do not link to every peer. A node discovers the network from a small
//! set of bootstrap peers, then keeps a bounded neighbor set drawn as a ring
//! lattice over the discovered peers. A message is relayed to a node's neighbors,
//! and each node remembers the messages it has seen so it relays each one at most
//! once and never loops. A connected overlay of bounded degree has a bounded
//! diameter, so a proposal or attestation from any node still reaches every node.
//!
//! Leader liveness comes from the timeout. The leader of a view proposes within
//! its slot; a node that sees no valid proposal by its timeout advances the view,
//! and the next leader in rotation proposes, routing around a silent or offline
//! leader. Progress continues while an honest supermajority is online. A node
//! stages at most one block per height and never attests a second, so no two nodes
//! finalize different blocks at one height under reordering or view changes. A node
//! finalizes only once every online committee member has attested its staged
//! block, and an attestation arriving by several overlay paths is de duplicated by
//! its content id and counted once, so the overlay never lets a node finalize
//! without genuinely receiving a supermajority.
//!
//! Transaction gossip floods the overlay at once before a round, since a
//! transaction only has to reach the leader mempool before it proposes; the
//! logical clock models the consensus round, where the asynchrony, the timeouts,
//! and the view changes live.

use std::collections::BTreeSet;
use std::io::{Read, Write};

use qtv_net::{DuplexStream, Identity};
use qtv_node::mempool::Reject;
use qtv_tx::Wrapper;

use crate::clock::{Clock, Event};
use crate::config::DevnetConfig;
use crate::discovery::{PeerEntry, PeerTable};
use crate::network::Network;
use crate::node::{leader_for, net_identity, DevNode, Height, RoundError, View};
use crate::overlay::{ring_lattice, Seen};
use crate::transport::{connect_duplex_pair, Mesh};
use crate::wire::{gossip_id, Message};

/// The most views a height rotates through before the loop gives up on it. A run
/// that exhausts this bound without finalizing has stalled, which happens only
/// when the online set is below a supermajority. Rotating through the committee
/// several times is enough to reach an honest online leader when one exists.
const MAX_VIEW: View = 16;

/// A running devnet: the nodes, the overlay they gossip over, the logical clock and
/// delivery schedule the round turns over, and which nodes are active this stretch.
pub struct Devnet<S> {
    nodes: Vec<DevNode>,
    mesh: Mesh<S>,
    config: DevnetConfig,
    active: Vec<bool>,
    clock: Clock,
    network: Network,
    msg_seq: u64,
    /// Each node's discovered view of the network.
    peers: Vec<PeerTable>,
    /// Each node's bounded neighbor set, by node index, symmetric.
    overlay: Vec<Vec<usize>>,
    /// Each node's record of the gossip messages it has already seen, so a message
    /// arriving by several paths is relayed and counted once.
    seen: Vec<Seen>,
}

impl Devnet<DuplexStream> {
    /// Stand up a devnet over an in memory duplex overlay. The nodes discover the
    /// network from their bootstrap peers, then link only to their overlay
    /// neighbors, so the mesh is a bounded overlay rather than a full mesh.
    pub fn over_duplex(config: DevnetConfig) -> Result<Self, RoundError> {
        let n = config.nodes.len();
        let identities: Vec<Identity> = config.nodes.iter().map(|c| net_identity(c.id)).collect();
        let addresses: Vec<String> = config.nodes.iter().map(|c| c.address.clone()).collect();
        let bootstrap = bootstrap_adjacency(&config);

        // Establish only the bootstrap channels; the overlay channels are added once
        // discovery has learned who the peers are.
        let mut mesh = Mesh::empty(n);
        for i in 0..n {
            for &j in &bootstrap[i] {
                if i < j && !mesh.has_edge(i, j) {
                    let (channel_i, channel_j) =
                        connect_duplex_pair(&identities[i], &identities[j])?;
                    mesh.add_link(i, j, channel_i, channel_j);
                }
            }
        }

        // Seed each node with itself and its bootstrap peers.
        let mut peers = vec![PeerTable::new(); n];
        for i in 0..n {
            peers[i].insert(PeerEntry::from_identity(
                &identities[i],
                addresses[i].clone(),
            ));
            for &j in &bootstrap[i] {
                peers[i].insert(PeerEntry::from_identity(
                    &identities[j],
                    addresses[j].clone(),
                ));
            }
        }

        let mut nodes = Vec::with_capacity(n);
        for node_config in &config.nodes {
            nodes.push(DevNode::open(node_config, &config)?);
        }
        let active = config.nodes.iter().map(|n| n.online).collect();

        let mut devnet = Devnet {
            nodes,
            mesh,
            config,
            active,
            clock: Clock::new(),
            network: Network::synchronous(),
            msg_seq: 0,
            peers,
            overlay: vec![Vec::new(); n],
            seen: vec![Seen::new(); n],
        };
        devnet.discover(&bootstrap)?;
        devnet.form_overlay(&identities)?;
        Ok(devnet)
    }

    /// Flood every node's known peer set over the bootstrap channels until no node
    /// learns a new peer, the fixpoint at which every node on a connected bootstrap
    /// graph knows the whole network. Each report is a sealed qtv-net record, so a
    /// discovered peer arrives over an authenticated channel.
    fn discover(&mut self, bootstrap: &[Vec<usize>]) -> Result<(), RoundError> {
        loop {
            for (i, neighbors) in bootstrap.iter().enumerate() {
                let list: Vec<PeerEntry> = self.peers[i].entries().cloned().collect();
                let bytes = Message::Peers(list).encode();
                for &j in neighbors {
                    self.mesh.send(i, j, &bytes)?;
                }
            }
            let mut changed = false;
            for (j, neighbors) in bootstrap.iter().enumerate() {
                for &i in neighbors {
                    let count = self.mesh.pending(i, j);
                    for _ in 0..count {
                        let bytes = self.mesh.recv_one(j, i)?;
                        if let Ok(Message::Peers(list)) = Message::decode(&bytes) {
                            for entry in list {
                                if self.peers[j].insert(entry) {
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }

    /// Draw the ring lattice over the discovered peers and establish a channel for
    /// each overlay edge not already a bootstrap edge. Both endpoints of every edge
    /// run the pinned handshake, so a peer that cannot prove its identity is refused
    /// here rather than trusted from its discovery claim alone.
    fn form_overlay(&mut self, identities: &[Identity]) -> Result<(), RoundError> {
        let overlay = overlay_from_identities(identities, self.config.fanout);
        for i in 0..overlay.len() {
            for &j in &overlay[i] {
                if i < j && !self.mesh.has_edge(i, j) {
                    let (channel_i, channel_j) =
                        connect_duplex_pair(&identities[i], &identities[j])?;
                    self.mesh.add_link(i, j, channel_i, channel_j);
                }
            }
        }
        self.overlay = overlay;
        Ok(())
    }
}

impl<S> Devnet<S> {
    /// Build a devnet from a configuration and an already established mesh. The
    /// operator wired the mesh by hand, so every node already knows every peer; the
    /// overlay is drawn from the configured identities at the configured fanout over
    /// the links the mesh provides.
    pub fn from_parts(config: DevnetConfig, mesh: Mesh<S>) -> Result<Self, RoundError> {
        let n = config.nodes.len();
        let identities: Vec<Identity> = config.nodes.iter().map(|c| net_identity(c.id)).collect();
        let mut nodes = Vec::with_capacity(n);
        for node_config in &config.nodes {
            nodes.push(DevNode::open(node_config, &config)?);
        }
        let active = config.nodes.iter().map(|n| n.online).collect();

        let mut peers = vec![PeerTable::new(); n];
        for table in &mut peers {
            for (k, identity) in identities.iter().enumerate() {
                table.insert(PeerEntry::from_identity(
                    identity,
                    config.nodes[k].address.clone(),
                ));
            }
        }
        let overlay = overlay_from_identities(&identities, config.fanout);

        Ok(Devnet {
            nodes,
            mesh,
            config,
            active,
            clock: Clock::new(),
            network: Network::synchronous(),
            msg_seq: 0,
            peers,
            overlay,
            seen: vec![Seen::new(); n],
        })
    }

    /// The number of nodes in the devnet.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the devnet holds no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The node at an index.
    pub fn node(&self, index: usize) -> &DevNode {
        &self.nodes[index]
    }

    /// All nodes, in index order.
    pub fn nodes(&self) -> &[DevNode] {
        &self.nodes
    }

    /// The index of the node with a consensus id.
    pub fn index_of(&self, id: u64) -> Option<usize> {
        self.nodes.iter().position(|n| n.id() == id)
    }

    /// Submit a transaction to a node by index.
    pub fn submit(&mut self, index: usize, transaction: Wrapper) -> Result<(), Reject> {
        self.nodes[index].submit(transaction)
    }

    /// Set whether a node takes part in the coming rounds. An inactive node
    /// neither proposes, attests, nor exchanges messages, modelling an offline
    /// node, and is never slashed.
    pub fn set_active(&mut self, index: usize, active: bool) {
        self.active[index] = active;
    }

    /// Make a node a silent leader: online and attesting, but withholding its
    /// proposal when it leads, so a timeout must route around it.
    pub fn set_silent(&mut self, index: usize, silent: bool) {
        self.nodes[index].set_silent(silent);
    }

    /// Replace the delivery schedule the round loop stamps records with, for
    /// example a reordering schedule or one with a shorter view timeout.
    pub fn set_network(&mut self, network: Network) {
        self.network = network;
    }

    /// The peers a node has discovered.
    pub fn known_peer_count(&self, index: usize) -> usize {
        self.peers[index].len()
    }

    /// The identity fingerprints a node has discovered, in order.
    pub fn known_peer_fingerprints(&self, index: usize) -> Vec<[u8; 32]> {
        self.peers[index].fingerprints()
    }

    /// A node's own identity fingerprint, the handle its peers discover it by.
    pub fn identity_fingerprint(&self, index: usize) -> [u8; 32] {
        *self.nodes[index].peer_id().fingerprint()
    }

    /// A node's overlay neighbors, by index.
    pub fn neighbors(&self, index: usize) -> &[usize] {
        &self.overlay[index]
    }

    /// The number of neighbors a node keeps in the overlay.
    pub fn neighbor_count(&self, index: usize) -> usize {
        self.overlay[index].len()
    }

    /// The largest neighbor count across the overlay, the bound that must stay below
    /// the `n - 1` of a full mesh for the overlay to be bounded.
    pub fn max_neighbor_count(&self) -> usize {
        self.overlay.iter().map(Vec::len).max().unwrap_or(0)
    }

    /// The number of distinct gossip messages a node has seen, the size of its de
    /// duplication record.
    pub fn seen_count(&self, index: usize) -> usize {
        self.seen[index].len()
    }

    /// The active node indices, ascending.
    fn active_indices(&self) -> Vec<usize> {
        (0..self.nodes.len()).filter(|&i| self.active[i]).collect()
    }

    /// The height the active nodes are producing next.
    pub fn height(&self) -> Height {
        self.active_indices()
            .first()
            .map(|&i| self.nodes[i].height())
            .unwrap_or(0)
    }
}

impl<S: Read + Write> Devnet<S> {
    /// The leader elected for the current height at view zero, without producing
    /// it. Used to tell whether the next block would be proposed by an online node.
    pub fn peek_leader(&self) -> Result<u64, RoundError> {
        self.leader_at(0)
    }

    /// The leader of the current height at a view, following the rotation a
    /// timeout walks.
    pub fn leader_at(&self, view: View) -> Result<u64, RoundError> {
        let repr = *self
            .active_indices()
            .first()
            .ok_or(RoundError::NoCommittee)?;
        Ok(leader_for(&self.nodes[repr].select()?, view))
    }

    /// Flood every node's pending transactions across the overlay, so a transaction
    /// submitted to one node reaches every node, and the leader, through the
    /// neighbors rather than over a direct link to each. A node forwards a
    /// transaction only the first time it admits it, so the flood reaches a fixpoint
    /// and cannot loop. This is delivered at once rather than over the logical clock,
    /// since a transaction only has to reach the leader mempool before it proposes.
    fn gossip_transactions(&mut self, active: &[usize]) -> Result<(), RoundError> {
        let n = self.nodes.len();
        let mut seen_tx: Vec<BTreeSet<[u8; 32]>> = vec![BTreeSet::new(); n];
        let mut frontier: Vec<(usize, Vec<u8>)> = Vec::new();
        for &i in active {
            for transaction in self.nodes[i].take_outbox() {
                let bytes = Message::Tx(transaction).encode();
                if seen_tx[i].insert(gossip_id(&bytes)) {
                    frontier.push((i, bytes));
                }
            }
        }
        while !frontier.is_empty() {
            for (from, bytes) in &frontier {
                let neighbors = self.overlay[*from].clone();
                for to in neighbors {
                    if active.contains(&to) {
                        self.mesh.send(*from, to, bytes)?;
                    }
                }
            }
            let mut next: Vec<(usize, Vec<u8>)> = Vec::new();
            for &to in active {
                let neighbors = self.overlay[to].clone();
                for from in neighbors {
                    if !active.contains(&from) {
                        continue;
                    }
                    let count = self.mesh.pending(from, to);
                    for _ in 0..count {
                        let bytes = self.mesh.recv_one(to, from)?;
                        if seen_tx[to].insert(gossip_id(&bytes)) {
                            if let Ok(Message::Tx(transaction)) = Message::decode(&bytes) {
                                self.nodes[to].admit_gossiped(transaction);
                            }
                            next.push((to, bytes));
                        }
                    }
                }
            }
            frontier = next;
        }
        Ok(())
    }

    /// Seal `bytes` from a node to each active overlay neighbor and schedule the
    /// delivery on the logical clock, skipping one neighbor. Each edge stays in send
    /// order; the schedule may reorder records across edges.
    fn spread(
        &mut self,
        at_node: usize,
        exclude: Option<usize>,
        bytes: &[u8],
        active: &[usize],
    ) -> Result<(), RoundError> {
        let neighbors = self.overlay[at_node].clone();
        for to in neighbors {
            if Some(to) == exclude || !active.contains(&to) {
                continue;
            }
            self.mesh.send(at_node, to, bytes)?;
            let at = self.clock.now() + self.network.delay(self.msg_seq);
            self.msg_seq += 1;
            self.clock
                .schedule(at, Event::Deliver { from: at_node, to });
        }
        Ok(())
    }

    /// A node emits its own message onto the overlay. The message is marked seen so a
    /// copy that circles back through a neighbor is dropped rather than relayed again.
    fn originate(
        &mut self,
        from: usize,
        message: &Message,
        active: &[usize],
    ) -> Result<(), RoundError> {
        let bytes = message.encode();
        self.seen[from].mark(gossip_id(&bytes));
        self.spread(from, None, &bytes, active)
    }

    /// Enter a node's current view: offer and gossip its proposal if it leads, and
    /// arm its view timeout unless it has run out of views.
    fn enter_round(&mut self, i: usize, active: &[usize]) -> Result<(), RoundError> {
        let selection = self.nodes[i].select()?;
        let online = self.active[i];
        let messages = self.nodes[i].enter_round(&selection, online);
        for message in &messages {
            self.originate(i, message, active)?;
        }
        if online && self.nodes[i].view() < MAX_VIEW {
            let at = self.clock.now() + self.network.view_timeout();
            let event = Event::Timeout {
                node: i,
                height: self.nodes[i].height(),
                view: self.nodes[i].view(),
            };
            self.clock.schedule(at, event);
        }
        Ok(())
    }

    /// Try to finalize a node's staged block, and enter its next height if it
    /// finalized and is still below the ceiling. A node finalizes only once every
    /// online committee member has attested its staged block, so every node
    /// aggregates the same set of attestations into the same byte identical
    /// certificate rather than the first quorum it happened to see.
    fn settle(&mut self, i: usize, ceiling: Height, active: &[usize]) -> Result<(), RoundError> {
        let selection = self.nodes[i].select()?;
        let online: Vec<u64> = selection
            .members
            .iter()
            .copied()
            .filter(|&id| self.index_of(id).is_some_and(|idx| self.active[idx]))
            .collect();
        if !self.nodes[i].has_attestations_from(&online) {
            return Ok(());
        }
        if self.nodes[i].try_finalize(&selection)? && self.nodes[i].height() < ceiling {
            self.enter_round(i, active)?;
        }
        Ok(())
    }

    /// Deliver a proposal to a node, gossip the attestation it returns, then try to
    /// finalize. Over the overlay a proposal is relayed, so the record arrives from a
    /// neighbor rather than from the leader directly. The node authenticates it by
    /// the proposer named in the header, which it re-executes and checks against the
    /// leader of the proposal's view, not by the relaying peer, so the proposer id
    /// the node checks against is the leader of the view whatever neighbor forwarded
    /// the record.
    fn deliver_proposal(
        &mut self,
        to: usize,
        proposal: crate::wire::Proposal,
        ceiling: Height,
        active: &[usize],
    ) -> Result<(), RoundError> {
        let selection = self.nodes[to].select()?;
        let proposer = leader_for(&selection, proposal.view);
        let messages = self.nodes[to].on_proposal(&selection, proposer, proposal);
        for message in &messages {
            self.originate(to, message, active)?;
        }
        self.settle(to, ceiling, active)?;
        Ok(())
    }

    /// Act on one event: open a delivered record, relay it onward across the overlay
    /// the first time this node sees it, and dispatch it to the consensus layer; or
    /// fire a view timeout and, if it advanced the view, enter the new one and pick
    /// up any proposal that arrived ahead of it.
    fn handle_event(
        &mut self,
        event: Event,
        ceiling: Height,
        active: &[usize],
    ) -> Result<(), RoundError> {
        match event {
            Event::Deliver { from, to } => {
                if !self.active[to] || self.mesh.pending(from, to) == 0 {
                    return Ok(());
                }
                let bytes = self.mesh.recv_one(to, from)?;
                let message = match Message::decode(&bytes) {
                    Ok(message) => message,
                    Err(_) => return Ok(()),
                };
                // A message seen before arrived by another path: it has already been
                // relayed and counted, so drop it rather than relay or count it twice.
                if !self.seen[to].mark(gossip_id(&bytes)) {
                    return Ok(());
                }
                self.spread(to, Some(from), &bytes, active)?;
                match message {
                    Message::Tx(transaction) => self.nodes[to].admit_gossiped(transaction),
                    Message::Proposal(proposal) => {
                        self.deliver_proposal(to, proposal, ceiling, active)?
                    }
                    Message::Attest(attestation) => {
                        self.nodes[to].on_attestation(*attestation);
                        self.settle(to, ceiling, active)?;
                    }
                    Message::Peers(_) => {}
                }
            }
            Event::Timeout { node, height, view } => {
                if !self.active[node]
                    || self.nodes[node].height() != height
                    || self.nodes[node].view() != view
                    || self.nodes[node].height() >= ceiling
                    || self.nodes[node].view() >= MAX_VIEW
                {
                    return Ok(());
                }
                if self.nodes[node].on_timeout(view) {
                    self.enter_round(node, active)?;
                    if let Some(proposal) = self.nodes[node].take_buffered_proposal() {
                        self.deliver_proposal(node, proposal, ceiling, active)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Turn the logical clock until every active node reaches the ceiling height or
    /// the clock falls idle. No node proposes at or beyond the ceiling, so the
    /// active nodes settle at exactly the ceiling and every sealed record in flight
    /// is opened, leaving the overlay clean for the next drive.
    fn drive_to(&mut self, ceiling: Height) -> Result<(), RoundError> {
        let active = self.active_indices();
        if active.is_empty() {
            return Ok(());
        }
        for &i in &active {
            if self.nodes[i].height() < ceiling {
                self.enter_round(i, &active)?;
            }
        }
        while let Some(event) = self.clock.next_event() {
            self.handle_event(event, ceiling, &active)?;
        }
        Ok(())
    }

    /// Drive the active nodes until they all reach a target height. Returns whether
    /// they reached it; a false return is a stall, the online set below a
    /// supermajority, and the nodes hold at the height they had.
    pub fn drive(&mut self, target: Height) -> Result<bool, RoundError> {
        let active = self.active_indices();
        if active.is_empty() {
            return Ok(false);
        }
        self.gossip_transactions(&active)?;
        self.drive_to(target)?;
        Ok(active.iter().all(|&i| self.nodes[i].height() >= target))
    }

    /// Produce and finalize one height across all active nodes over the round loop.
    /// Every node commits the same finalized block from the attestations it
    /// aggregated, whichever view finalized it.
    pub fn step(&mut self) -> Result<(), RoundError> {
        let active = self.active_indices();
        if active.is_empty() {
            return Ok(());
        }
        let ceiling = self.height() + 1;
        self.gossip_transactions(&active)?;
        self.drive_to(ceiling)?;
        Ok(())
    }

    /// Produce a run of heights in order.
    pub fn run(&mut self, heights: u64) -> Result<(), RoundError> {
        for _ in 0..heights {
            self.step()?;
        }
        Ok(())
    }

    /// Restart a node from its store while the overlay stays up. The node reopens its
    /// block store and state store, rebuilds its ledger, beacon, and parent link
    /// from the last finalized block, and rejoins at the next height. Its overlay
    /// neighbors and channels are unchanged.
    pub fn restart_node(&mut self, index: usize) -> Result<(), RoundError> {
        self.nodes[index] = DevNode::open(&self.config.nodes[index], &self.config)?;
        Ok(())
    }
}

/// The symmetric bootstrap adjacency of a config: an undirected edge for every
/// bootstrap peer a node names, dropping ids that name no node and self loops.
fn bootstrap_adjacency(config: &DevnetConfig) -> Vec<Vec<usize>> {
    let n = config.nodes.len();
    let mut sets: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for (i, node) in config.nodes.iter().enumerate() {
        for &peer_id in &node.bootstrap {
            if let Some(j) = config.nodes.iter().position(|c| c.id == peer_id) {
                if j != i {
                    sets[i].insert(j);
                    sets[j].insert(i);
                }
            }
        }
    }
    sets.into_iter().map(|s| s.into_iter().collect()).collect()
}

/// The symmetric overlay neighbor sets, by node index, drawn as a ring lattice over
/// the node indices ordered by identity fingerprint. The order is a function of the
/// identities alone, so every node draws the same overlay from the peers it
/// discovered.
fn overlay_from_identities(identities: &[Identity], fanout: usize) -> Vec<Vec<usize>> {
    let n = identities.len();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&a, &b| {
        identities[a]
            .peer_id()
            .fingerprint()
            .cmp(identities[b].peer_id().fingerprint())
    });
    let position_adjacency = ring_lattice(n, fanout);
    let mut overlay = vec![Vec::new(); n];
    for (p, positions) in position_adjacency.iter().enumerate() {
        let mut neighbors: Vec<usize> = positions.iter().map(|&q| order[q]).collect();
        neighbors.sort_unstable();
        overlay[order[p]] = neighbors;
    }
    overlay
}
