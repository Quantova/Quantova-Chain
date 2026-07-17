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
use qtv_node::mempool::{Admitted, Reject};
use qtv_tx::Wrapper;

use qtv_block::Block as ChainBlock;

use crate::clock::{Clock, Event, Time};
use crate::coded::{code_proposal, ProposalAssembler};
use crate::config::DevnetConfig;
use crate::discovery::{PeerEntry, PeerTable};
use crate::network::Network;
use crate::node::{leader_for, net_identity, DevNode, Height, RoundError, SyncError, View};
use crate::overlay::{ring_lattice, Seen};
use crate::transport::{connect_duplex_pair, Mesh};
use crate::wire::{gossip_id, CodedProposal, Message, Proposal};

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
    /// The network partition, a group id per node. Records cross only within a
    /// group, so two groups model a split; one group is the healed network.
    partition: Vec<usize>,
    /// Each node's reassembly buffer for coded proposal shards, so a proposal
    /// disseminated as shards is rebuilt from any k of them and checked against the
    /// header before it reaches the consensus layer.
    assemblers: Vec<ProposalAssembler>,
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
            partition: vec![0; n],
            assemblers: vec![ProposalAssembler::new(); n],
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
            partition: vec![0; n],
            assemblers: vec![ProposalAssembler::new(); n],
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
    pub fn submit(&mut self, index: usize, transaction: Wrapper) -> Result<Admitted, Reject> {
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

    /// Split the network into groups by a group id per node index. A record crosses
    /// only within a group, so two groups model a partition where neither side
    /// hears the other. Each side runs its round but reaches no supermajority alone.
    pub fn set_partition(&mut self, groups: &[usize]) {
        assert_eq!(groups.len(), self.nodes.len(), "a group id per node");
        self.partition = groups.to_vec();
    }

    /// Heal the network: every node returns to one group, so records cross freely
    /// again and the split ends.
    pub fn heal(&mut self) {
        self.partition = vec![0; self.nodes.len()];
    }

    /// Whether two nodes are in the same partition group, so a record may cross
    /// between them.
    fn same_group(&self, i: usize, j: usize) -> bool {
        self.partition[i] == self.partition[j]
    }

    /// Replace the delivery schedule the round loop stamps records with, for
    /// example a reordering schedule or one with a shorter view timeout.
    pub fn set_network(&mut self, network: Network) {
        self.network = network;
    }

    /// The view timeout of the current schedule, the logical time a node waits at a
    /// view before it rotates. A test picks a `drive_window` deadline against this.
    pub fn view_timeout(&self) -> Time {
        self.network.view_timeout()
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

    /// The finalized blocks a node would serve for a range, each carrying its
    /// finality certificate. Exposed so a test can take a genuine served block and
    /// alter it before feeding it back to the verifier.
    pub fn served_blocks(&self, index: usize, from: Height, to: Height) -> Vec<ChainBlock> {
        self.nodes[index].serve_blocks(from, to)
    }

    /// Feed a finalized block to a node's trustless sync verifier directly,
    /// returning whether it was accepted. A verified block advances the node; a
    /// forged one is refused and the node is left untouched.
    pub fn apply_synced(&mut self, index: usize, block: ChainBlock) -> Result<(), SyncError> {
        self.nodes[index].apply_synced_block(block)
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
                    if active.contains(&to) && self.same_group(*from, to) {
                        self.mesh.send(*from, to, bytes)?;
                    }
                }
            }
            let mut next: Vec<(usize, Vec<u8>)> = Vec::new();
            for &to in active {
                let neighbors = self.overlay[to].clone();
                for from in neighbors {
                    if !active.contains(&from) || !self.same_group(from, to) {
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
            if Some(to) == exclude || !active.contains(&to) || !self.same_group(at_node, to) {
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

    /// Disseminate a block proposal over the overlay as its erasure coded shards
    /// rather than one whole record. The block the proposal's header commits to is
    /// coded into k data shards and n minus k parity shards under a SHA3 commitment,
    /// and each shard is emitted as its own gossip message within the transport record
    /// bound, so a block larger than the record limit is carried as shards and rebuilt
    /// on receipt from any k of them. Each shard floods the overlay once, keyed by its
    /// own content id, exactly as a whole message does.
    fn originate_proposal(
        &mut self,
        from: usize,
        proposal: Proposal,
        active: &[usize],
    ) -> Result<(), RoundError> {
        for coded in code_proposal(&proposal)? {
            self.originate(from, &Message::CodedProposal(Box::new(coded)), active)?;
        }
        Ok(())
    }

    /// Enter a node's current view: offer and gossip its proposal if it leads, and
    /// arm its view timeout unless it has run out of views.
    fn enter_round(&mut self, i: usize, active: &[usize]) -> Result<(), RoundError> {
        let selection = self.nodes[i].select()?;
        let online = self.active[i];
        let messages = self.nodes[i].enter_round(&selection, online);
        for message in messages {
            match message {
                // A proposal disseminates as its erasure coded shards, not one whole
                // record, so a block wider than the record bound is carried as shards.
                Message::Proposal(proposal) => self.originate_proposal(i, proposal, active)?,
                other => self.originate(i, &other, active)?,
            }
        }
        // Past view zero a node announces its move as a view change record. This is
        // what lets the leader gather a quorum, and what lets a peer that was
        // partitioned away learn the move once the split heals and the node re-enters.
        if online && self.nodes[i].view() > 0 {
            let record = self.nodes[i].make_view_change(self.nodes[i].view());
            self.nodes[i].collect_view_change(&selection, record.clone());
            self.originate(i, &Message::ViewChange(Box::new(record)), active)?;
        }
        // A later view leader offers its proposal only once it holds a quorum of
        // view change records, so entering the view may already let it propose.
        if online {
            self.try_justified_proposal(i, active)?;
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

    /// Let the leader of a later view offer its justified proposal once it holds a
    /// quorum of view change records for that view. It builds the proposal at most
    /// once per view, staging and attesting the block it selects, then gossips both.
    fn try_justified_proposal(&mut self, i: usize, active: &[usize]) -> Result<(), RoundError> {
        if !self.active[i] {
            return Ok(());
        }
        let selection = self.nodes[i].select()?;
        let view = self.nodes[i].view();
        if view == 0 || leader_for(&selection, view) != self.nodes[i].id() {
            return Ok(());
        }
        if self.nodes[i].staged_view() == Some(view) {
            return Ok(());
        }
        if let Some(proposal) = self.nodes[i].build_justified_proposal(&selection, view) {
            self.originate_proposal(i, proposal, active)?;
            if let Some(attestation) = self.nodes[i].attest_staged() {
                self.originate(i, &Message::Attest(Box::new(attestation)), active)?;
            }
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

    /// Admit one coded proposal shard at a node. The shard is verified against the
    /// commitment before it is used, and once k verified shards for one proposal are
    /// in hand the block is reconstructed and checked against the header exactly as the
    /// coded block path does, then the rebuilt proposal follows the same delivery path
    /// a whole proposal would. A shard that fails its commitment, or a full set that
    /// fails reconstruction or its header check, is refused and dropped, so nothing
    /// about the disperser is trusted.
    fn deliver_coded_proposal(
        &mut self,
        to: usize,
        coded: CodedProposal,
        ceiling: Height,
        active: &[usize],
    ) -> Result<(), RoundError> {
        match self.assemblers[to].admit(coded) {
            Some(Ok(proposal)) => self.deliver_proposal(to, proposal, ceiling, active)?,
            // A refused coded proposal never reaches the consensus layer; the view
            // times out and rotates as it would for a silent leader.
            Some(Err(_)) | None => {}
        }
        Ok(())
    }

    /// Collect a view change record at a node. It joins the view change when a
    /// blocking set of records has reached a later view, announcing its own move so
    /// the whole committee converges on one view after a split, and it lets the
    /// leader of that view offer its justified proposal once the quorum is in hand.
    fn deliver_view_change(
        &mut self,
        to: usize,
        record: crate::wire::ViewChange,
        ceiling: Height,
        active: &[usize],
    ) -> Result<(), RoundError> {
        let selection = self.nodes[to].select()?;
        self.nodes[to].collect_view_change(&selection, record);
        if let Some(target) = self.nodes[to].view_sync_target(&selection) {
            if target > self.nodes[to].view() {
                // A blocking set has reached a later view: join it, keeping any lock.
                // Entering the view announces this node's own move and lets it
                // propose if it leads and already holds the quorum.
                self.nodes[to].jump_to(target);
                self.enter_round(to, active)?;
            }
        }
        self.try_justified_proposal(to, active)?;
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
                    Message::CodedProposal(coded) => {
                        self.deliver_coded_proposal(to, *coded, ceiling, active)?
                    }
                    Message::Attest(attestation) => {
                        self.nodes[to].on_attestation(*attestation);
                        self.settle(to, ceiling, active)?;
                    }
                    Message::ViewChange(record) => {
                        self.deliver_view_change(to, *record, ceiling, active)?;
                    }
                    // Discovery and the sync request and response do not gossip over
                    // the round clock, so they never arrive on this path.
                    Message::Peers(_)
                    | Message::Status(_)
                    | Message::GetBlocks { .. }
                    | Message::Blocks(_) => {}
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
                    // The node advanced without a lock. Entering the new view
                    // announces the move as a view change record.
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

    /// Catch every active node behind the tip up to the highest active node over
    /// the overlay channels. A node behind the tip asks an active neighbor that is
    /// ahead for the finalized blocks it is missing, and it commits each only after
    /// verifying the certificate, the parent link, and the re-executed state root
    /// itself, trusting nothing about the serving peer. Runs to a fixpoint, so a
    /// node several heights behind catches up in successive batches, and every
    /// verified block advances it one height until the active set holds one height.
    /// A node that cannot reach an active neighbor ahead of it holds where it is.
    pub fn sync(&mut self) -> Result<(), RoundError> {
        let active = self.active_indices();
        loop {
            let target = active
                .iter()
                .map(|&i| self.nodes[i].sync_height())
                .max()
                .unwrap_or(0);
            if active
                .iter()
                .all(|&i| self.nodes[i].sync_height() >= target)
            {
                break;
            }
            let mut progressed = false;
            for &i in &active {
                let height = self.nodes[i].sync_height();
                if height >= target {
                    continue;
                }
                let server = self.overlay[i].iter().copied().find(|&j| {
                    self.active[j] && self.same_group(i, j) && self.nodes[j].sync_height() > height
                });
                let Some(j) = server else {
                    continue;
                };
                let to = self.nodes[j].sync_height() - 1;
                let request = Message::GetBlocks { from: height, to }.encode();
                self.mesh.send(i, j, &request)?;
                let asked = self.mesh.recv_one(j, i)?;
                let (from, to) = match Message::decode(&asked) {
                    Ok(Message::GetBlocks { from, to }) => (from, to),
                    _ => continue,
                };
                let blocks = self.nodes[j].serve_blocks(from, to);
                let response = Message::Blocks(blocks).encode();
                self.mesh.send(j, i, &response)?;
                let served = self.mesh.recv_one(i, j)?;
                let Ok(Message::Blocks(blocks)) = Message::decode(&served) else {
                    continue;
                };
                for block in blocks {
                    if self.nodes[i].apply_synced_block(block).is_err() {
                        break;
                    }
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(())
    }

    /// Turn the logical clock only up to a deadline, so a test can run a split for a
    /// bounded stretch and then heal it before every timer has fired. Enters the
    /// round for each active node, then processes exactly the events scheduled at or
    /// before the deadline. Nothing forces finality; a partitioned side simply acts
    /// and holds.
    pub fn drive_window(&mut self, ceiling: Height, deadline: Time) -> Result<(), RoundError> {
        let active = self.active_indices();
        if active.is_empty() {
            return Ok(());
        }
        for &i in &active {
            if self.nodes[i].height() < ceiling {
                self.enter_round(i, &active)?;
            }
        }
        while let Some(time) = self.clock.peek_time() {
            if time > deadline {
                break;
            }
            let event = self.clock.next_event().expect("a peeked event pops");
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
        self.sync()?;
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
        self.sync()?;
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
