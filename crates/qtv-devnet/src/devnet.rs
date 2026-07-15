//! The devnet driver: an asynchronous per node round loop over a logical clock.
//!
//! Each node runs its own round on the logical clock rather than in lockstep. A
//! node acts when a sealed message arrives or a view timeout fires, not when a
//! central driver steps every node together. The driver owns the nodes, the
//! secure channel mesh, the clock, and the delivery schedule; it seals each
//! outgoing message onto the channels and schedules its delivery, and it fires the
//! view timeouts. Every byte still passes through the qtv-net seal and open, so
//! the mesh is the wire, not a shortcut around it.
//!
//! Leader liveness comes from the timeout. The leader of a view proposes within
//! its slot; a node that sees no valid proposal by its timeout advances the view,
//! and the next leader in rotation proposes, routing around a silent or offline
//! leader. Progress continues while an honest supermajority is online. A node
//! stages at most one block per height and never attests a second, so no two nodes
//! finalize different blocks at one height under reordering or view changes.
//!
//! Transaction gossip is delivered at once before a round, since the bounded
//! gossip overlay is deferred; the logical clock models the consensus round, where
//! the asynchrony, the timeouts, and the view changes live.

use std::io::{Read, Write};

use qtv_net::{DuplexStream, Identity};
use qtv_node::mempool::Reject;
use qtv_tx::Wrapper;

use crate::clock::{Clock, Event};
use crate::config::DevnetConfig;
use crate::network::Network;
use crate::node::{leader_for, net_identity, DevNode, Height, RoundError, View};
use crate::transport::{connect_duplex_mesh, Mesh};
use crate::wire::Message;

/// The most views a height rotates through before the loop gives up on it. A run
/// that exhausts this bound without finalizing has stalled, which happens only
/// when the online set is below a supermajority. Rotating through the committee
/// several times is enough to reach an honest online leader when one exists.
const MAX_VIEW: View = 16;

/// A running devnet: the nodes, the mesh they gossip over, the logical clock and
/// delivery schedule the round turns over, and which nodes are active this stretch.
pub struct Devnet<S> {
    nodes: Vec<DevNode>,
    mesh: Mesh<S>,
    config: DevnetConfig,
    active: Vec<bool>,
    clock: Clock,
    network: Network,
    msg_seq: u64,
}

impl Devnet<DuplexStream> {
    /// Stand up a devnet over an in memory duplex mesh, one pinned post-quantum
    /// channel per pair of nodes.
    pub fn over_duplex(config: DevnetConfig) -> Result<Self, RoundError> {
        let identities: Vec<Identity> = config.nodes.iter().map(|n| net_identity(n.id)).collect();
        let mesh = connect_duplex_mesh(&identities)?;
        Devnet::from_parts(config, mesh)
    }
}

impl<S> Devnet<S> {
    /// Build a devnet from a configuration and an already established mesh. Each
    /// node opens its stores and either initializes from genesis or reloads its
    /// finalized chain. The clock starts at zero over a synchronous schedule.
    pub fn from_parts(config: DevnetConfig, mesh: Mesh<S>) -> Result<Self, RoundError> {
        let mut nodes = Vec::with_capacity(config.nodes.len());
        for node_config in &config.nodes {
            nodes.push(DevNode::open(node_config, &config)?);
        }
        let active = config.nodes.iter().map(|n| n.online).collect();
        Ok(Devnet {
            nodes,
            mesh,
            config,
            active,
            clock: Clock::new(),
            network: Network::synchronous(),
            msg_seq: 0,
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

    /// Gossip every node pending transactions to the active peers and admit the
    /// ones that arrive, so a transaction submitted to one node reaches the leader.
    /// The bounded gossip overlay is deferred, so this delivers at once rather than
    /// over the logical clock.
    fn gossip_transactions(&mut self, active: &[usize]) -> Result<(), RoundError> {
        for &i in active {
            for transaction in self.nodes[i].take_outbox() {
                let bytes = Message::Tx(transaction).encode();
                self.mesh.broadcast(i, &bytes, active)?;
            }
        }
        for &j in active {
            for (_, bytes) in self.mesh.drain(j, active)? {
                if let Ok(Message::Tx(transaction)) = Message::decode(&bytes) {
                    self.nodes[j].admit_gossiped(transaction);
                }
            }
        }
        Ok(())
    }

    /// Seal a message from a node to each active peer and schedule its delivery on
    /// the logical clock. Each edge stays in send order; the schedule may reorder
    /// records across edges.
    fn broadcast(
        &mut self,
        from: usize,
        message: &Message,
        active: &[usize],
    ) -> Result<(), RoundError> {
        let bytes = message.encode();
        for &to in active {
            if to == from {
                continue;
            }
            self.mesh.send(from, to, &bytes)?;
            let at = self.clock.now() + self.network.delay(self.msg_seq);
            self.msg_seq += 1;
            self.clock.schedule(at, Event::Deliver { from, to });
        }
        Ok(())
    }

    /// Enter a node current view: offer and gossip its proposal if it leads, and
    /// arm its view timeout unless it has run out of views.
    fn enter_round(&mut self, i: usize, active: &[usize]) -> Result<(), RoundError> {
        let selection = self.nodes[i].select()?;
        let online = self.active[i];
        let messages = self.nodes[i].enter_round(&selection, online);
        for message in messages {
            self.broadcast(i, &message, active)?;
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

    /// Try to finalize a node staged block, and enter its next height if it
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

    /// Deliver a proposal to a node from the sending node index, and gossip the
    /// attestation it returns, then try to finalize. The node checks the proposal
    /// against the leader of its view, so the sender consensus id is what it sees.
    fn deliver_proposal(
        &mut self,
        to: usize,
        from: usize,
        proposal: crate::wire::Proposal,
        ceiling: Height,
        active: &[usize],
    ) -> Result<(), RoundError> {
        let from_id = self.nodes[from].id();
        let selection = self.nodes[to].select()?;
        let messages = self.nodes[to].on_proposal(&selection, from_id, proposal);
        for message in messages {
            self.broadcast(to, &message, active)?;
        }
        self.settle(to, ceiling, active)?;
        Ok(())
    }

    /// Act on one event: open and dispatch a delivered record, or fire a view
    /// timeout and, if it advanced the view, enter the new one and pick up any
    /// proposal that arrived ahead of it.
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
                match Message::decode(&bytes) {
                    Ok(Message::Tx(transaction)) => self.nodes[to].admit_gossiped(transaction),
                    Ok(Message::Proposal(proposal)) => {
                        self.deliver_proposal(to, from, proposal, ceiling, active)?
                    }
                    Ok(Message::Attest(attestation)) => {
                        self.nodes[to].on_attestation(*attestation);
                        self.settle(to, ceiling, active)?;
                    }
                    Err(_) => {}
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
                        let leader_id = leader_for(&self.nodes[node].select()?, proposal.view);
                        if let Some(from) = self.index_of(leader_id) {
                            self.deliver_proposal(node, from, proposal, ceiling, active)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Turn the logical clock until every active node reaches the ceiling height or
    /// the clock falls idle. No node proposes at or beyond the ceiling, so the
    /// active nodes settle at exactly the ceiling and every sealed record in flight
    /// is opened, leaving the mesh clean for the next drive.
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

    /// Restart a node from its store while the mesh stays up. The node reopens its
    /// block store and state store, rebuilds its ledger, beacon, and parent link
    /// from the last finalized block, and rejoins at the next height.
    pub fn restart_node(&mut self, index: usize) -> Result<(), RoundError> {
        self.nodes[index] = DevNode::open(&self.config.nodes[index], &self.config)?;
        Ok(())
    }
}
