//! The devnet driver that sequences the round over the mesh.
//!
//! The driver owns the nodes and the secure channel mesh and runs each height in
//! lockstep phases: gossip the pending transactions, select the committee, have
//! the leader propose and every other node accept, have the online committee
//! members attest, and have every node aggregate the entitled supermajority and
//! finalize. Every message between the phases travels the mesh sealed, so the
//! driver is the devnet harness that moves the wire forward, not a path around it.
//!
//! Committee selection is a pure function of the shared beacon, so the driver
//! computes it once per height and hands it to every node rather than paying the
//! sortition on each; every active node holds the same beacon, so the result is
//! the one each would compute for itself.

use std::io::{Read, Write};

use qtv_attest::Attestation;
use qtv_net::{DuplexStream, Identity};
use qtv_node::mempool::Reject;
use qtv_tx::Wrapper;

use crate::config::DevnetConfig;
use crate::node::{net_identity, DevNode, Height, RoundError};
use crate::transport::{connect_duplex_mesh, Mesh};
use crate::wire::Message;

/// A running devnet: the nodes, the mesh they gossip over, and which nodes are
/// active this stretch.
pub struct Devnet<S> {
    nodes: Vec<DevNode>,
    mesh: Mesh<S>,
    config: DevnetConfig,
    active: Vec<bool>,
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
    /// finalized chain.
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
    /// The leader elected for the current height, without producing it. Used to
    /// tell whether the next block would be proposed by an online node.
    pub fn peek_leader(&self) -> Result<u64, RoundError> {
        let repr = *self
            .active_indices()
            .first()
            .ok_or(RoundError::NoCommittee)?;
        Ok(self.nodes[repr].select()?.leader)
    }

    /// Gossip every node pending transactions to the active peers and admit the
    /// ones that arrive, so a transaction submitted to one node reaches the leader.
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

    /// Produce and finalize one height across all active nodes. Every node commits
    /// the same finalized block from the attestations it aggregated.
    pub fn step(&mut self) -> Result<(), RoundError> {
        let active = self.active_indices();
        if active.is_empty() {
            return Ok(());
        }

        self.gossip_transactions(&active)?;

        let selection = self.nodes[active[0]].select()?;
        let leader_index = self
            .nodes
            .iter()
            .position(|n| n.id() == selection.leader)
            .ok_or(RoundError::NotFinalized)?;
        if !self.active[leader_index] {
            return Err(RoundError::LeaderOffline);
        }

        let proposal = self.nodes[leader_index].build_proposal(&selection);
        let proposal_bytes = Message::Proposal(proposal).encode();
        self.mesh
            .broadcast(leader_index, &proposal_bytes, &active)?;
        for &j in &active {
            if j == leader_index {
                continue;
            }
            let mut accepted = false;
            for (from, bytes) in self.mesh.drain(j, &active)? {
                if from != leader_index {
                    continue;
                }
                if let Ok(Message::Proposal(proposal)) = Message::decode(&bytes) {
                    self.nodes[j].accept_proposal(&selection, &proposal)?;
                    accepted = true;
                }
            }
            if !accepted {
                return Err(RoundError::ProposalRejected);
            }
        }

        let mut own: Vec<(usize, Attestation)> = Vec::with_capacity(active.len());
        for &i in &active {
            own.push((i, self.nodes[i].attest()?));
        }
        for (i, attestation) in &own {
            let bytes = Message::Attest(Box::new(attestation.clone())).encode();
            self.mesh.broadcast(*i, &bytes, &active)?;
        }

        for &j in &active {
            let mut attestations: Vec<Attestation> = own
                .iter()
                .filter(|(i, _)| *i == j)
                .map(|(_, attestation)| attestation.clone())
                .collect();
            for (_, bytes) in self.mesh.drain(j, &active)? {
                if let Ok(Message::Attest(attestation)) = Message::decode(&bytes) {
                    attestations.push(*attestation);
                }
            }
            self.nodes[j].finalize(&selection, &attestations)?;
        }
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
