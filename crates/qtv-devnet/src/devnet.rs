// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
use crate::node::{leader_for, p2p_identity, DevNode, Height, RoundError, SyncError, View};
use crate::overlay::{ring_lattice, Seen};
use crate::transport::{connect_duplex_pair, Mesh};
use crate::wire::{gossip_id, CodedProposal, Message, Proposal, RegisterNote, RevealNote};

const MAX_VIEW: View = 16;

pub struct Devnet<S> {
    nodes: Vec<DevNode>,
    mesh: Mesh<S>,
    config: DevnetConfig,
    active: Vec<bool>,
    clock: Clock,
    network: Network,
    msg_seq: u64,
    peers: Vec<PeerTable>,
    overlay: Vec<Vec<usize>>,
    seen: Vec<Seen>,
    partition: Vec<usize>,
    assemblers: Vec<ProposalAssembler>,
}

impl Devnet<DuplexStream> {
    pub fn over_duplex(config: DevnetConfig) -> Result<Self, RoundError> {
        let n = config.nodes.len();
        let identities: Vec<Identity> = config
            .nodes
            .iter()
            .map(|c| p2p_identity(&c.secret))
            .collect();
        let addresses: Vec<String> = config.nodes.iter().map(|c| c.address.clone()).collect();
        let bootstrap = bootstrap_adjacency(&config);

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
        devnet.exchange_reveals();
        Ok(devnet)
    }

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
    pub fn from_parts(config: DevnetConfig, mesh: Mesh<S>) -> Result<Self, RoundError> {
        let n = config.nodes.len();
        let identities: Vec<Identity> = config
            .nodes
            .iter()
            .map(|c| p2p_identity(&c.secret))
            .collect();
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

        let mut devnet = Devnet {
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
        };
        devnet.exchange_reveals();
        Ok(devnet)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn node(&self, index: usize) -> &DevNode {
        &self.nodes[index]
    }

    pub fn nodes(&self) -> &[DevNode] {
        &self.nodes
    }

    pub fn index_of(&self, id: u64) -> Option<usize> {
        self.nodes.iter().position(|n| n.id() == id)
    }

    pub fn submit(&mut self, index: usize, transaction: Wrapper) -> Result<Admitted, Reject> {
        self.nodes[index].submit(transaction)
    }

    pub fn set_active(&mut self, index: usize, active: bool) {
        self.active[index] = active;
    }

    pub fn set_silent(&mut self, index: usize, silent: bool) {
        self.nodes[index].set_silent(silent);
    }

    pub fn set_partition(&mut self, groups: &[usize]) {
        assert_eq!(groups.len(), self.nodes.len(), "a group id per node");
        self.partition = groups.to_vec();
    }

    pub fn heal(&mut self) {
        self.partition = vec![0; self.nodes.len()];
    }

    fn same_group(&self, i: usize, j: usize) -> bool {
        self.partition[i] == self.partition[j]
    }

    pub fn set_network(&mut self, network: Network) {
        self.network = network;
    }

    pub fn view_timeout(&self) -> Time {
        self.network.view_timeout()
    }

    pub fn known_peer_count(&self, index: usize) -> usize {
        self.peers[index].len()
    }

    pub fn known_peer_fingerprints(&self, index: usize) -> Vec<[u8; 32]> {
        self.peers[index].fingerprints()
    }

    pub fn identity_fingerprint(&self, index: usize) -> [u8; 32] {
        *self.nodes[index].peer_id().fingerprint()
    }

    pub fn neighbors(&self, index: usize) -> &[usize] {
        &self.overlay[index]
    }

    pub fn neighbor_count(&self, index: usize) -> usize {
        self.overlay[index].len()
    }

    pub fn max_neighbor_count(&self) -> usize {
        self.overlay.iter().map(Vec::len).max().unwrap_or(0)
    }

    pub fn seen_count(&self, index: usize) -> usize {
        self.seen[index].len()
    }

    fn active_indices(&self) -> Vec<usize> {
        (0..self.nodes.len()).filter(|&i| self.active[i]).collect()
    }

    fn exchange_reveals(&mut self) {
        let notes: Vec<RevealNote> = (0..self.nodes.len())
            .filter_map(|i| self.nodes[i].own_reveal_note())
            .collect();
        for node in &mut self.nodes {
            for note in &notes {
                node.collect_reveal(note.clone());
            }
        }
    }

    fn exchange_registrations(&mut self) {
        let notes: Vec<RegisterNote> = (0..self.nodes.len())
            .filter_map(|i| self.nodes[i].own_registration_note())
            .collect();
        if notes.is_empty() {
            return;
        }
        for node in &mut self.nodes {
            for note in &notes {
                node.collect_registration(note.clone());
            }
            node.apply_registrations();
        }
    }

    pub fn height(&self) -> Height {
        self.active_indices()
            .first()
            .map(|&i| self.nodes[i].height())
            .unwrap_or(0)
    }

    pub fn served_blocks(&self, index: usize, from: Height, to: Height) -> Vec<ChainBlock> {
        self.nodes[index].serve_blocks(from, to)
    }

    pub fn apply_synced(&mut self, index: usize, block: ChainBlock) -> Result<(), SyncError> {
        self.nodes[index].apply_synced_block(block)
    }
}

impl<S: Read + Write> Devnet<S> {
    pub fn peek_leader(&self) -> Result<u64, RoundError> {
        self.leader_at(0)
    }

    pub fn leader_at(&self, view: View) -> Result<u64, RoundError> {
        let repr = *self
            .active_indices()
            .first()
            .ok_or(RoundError::NoCommittee)?;
        Ok(leader_for(&self.nodes[repr].select()?, view))
    }

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

    fn enter_round(&mut self, i: usize, active: &[usize]) -> Result<(), RoundError> {
        let selection = self.nodes[i].select()?;
        let online = self.active[i];
        let messages = self.nodes[i].enter_round(&selection, online);
        for message in messages {
            match message {
                Message::Proposal(proposal) => self.originate_proposal(i, *proposal, active)?,
                other => self.originate(i, &other, active)?,
            }
        }
        if online && self.nodes[i].view() > 0 {
            let view = self.nodes[i].view();
            let record = self.nodes[i].make_view_change(view);
            self.nodes[i].collect_view_change(&selection, record.clone());
            self.originate(i, &Message::ViewChange(Box::new(record)), active)?;
        }
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
            for message in self.nodes[i].prevote_staged() {
                self.originate(i, &message, active)?;
            }
        }
        Ok(())
    }

    fn settle(&mut self, i: usize, ceiling: Height, active: &[usize]) -> Result<(), RoundError> {
        let selection = self.nodes[i].select()?;
        if !self.nodes[i].has_finality_threshold(selection.tau) {
            return Ok(());
        }
        if self.nodes[i].try_finalize(&selection)? && self.nodes[i].height() < ceiling {
            self.enter_round(i, active)?;
        }
        Ok(())
    }

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

    fn deliver_coded_proposal(
        &mut self,
        to: usize,
        coded: CodedProposal,
        ceiling: Height,
        active: &[usize],
    ) -> Result<(), RoundError> {
        let Ok(selection) = self.nodes[to].select() else {
            return Ok(());
        };
        if !self.nodes[to].coded_auth_ok(&selection, &coded) {
            return Ok(());
        }
        match self.assemblers[to].admit(coded) {
            Some(Ok(proposal)) => self.deliver_proposal(to, proposal, ceiling, active)?,
            Some(Err(_)) | None => {}
        }
        Ok(())
    }

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
                self.nodes[to].jump_to(target);
                self.enter_round(to, active)?;
            }
        }
        self.try_justified_proposal(to, active)?;
        self.settle(to, ceiling, active)?;
        Ok(())
    }

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
                if !self.seen[to].mark(gossip_id(&bytes)) {
                    return Ok(());
                }
                self.spread(to, Some(from), &bytes, active)?;
                match message {
                    Message::Tx(transaction) => self.nodes[to].admit_gossiped(transaction),
                    Message::Proposal(proposal) => {
                        self.deliver_proposal(to, *proposal, ceiling, active)?
                    }
                    Message::CodedProposal(coded) => {
                        self.deliver_coded_proposal(to, *coded, ceiling, active)?
                    }
                    Message::Prevote(prevote) => {
                        let selection = self.nodes[to].select()?;
                        for message in self.nodes[to].on_prevote(&selection, *prevote) {
                            self.originate(to, &message, active)?;
                        }
                        self.settle(to, ceiling, active)?;
                    }
                    Message::Attest(attestation) => {
                        self.nodes[to].on_attestation(*attestation);
                        self.settle(to, ceiling, active)?;
                    }
                    Message::ViewChange(record) => {
                        self.deliver_view_change(to, *record, ceiling, active)?;
                    }
                    Message::Reveal(note) => {
                        self.nodes[to].collect_reveal(*note);
                    }
                    Message::Register(note) => {
                        self.nodes[to].collect_registration(*note);
                        self.nodes[to].apply_registrations();
                    }
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
                    self.enter_round(node, active)?;
                    if let Some(proposal) = self.nodes[node].take_buffered_proposal() {
                        self.deliver_proposal(node, proposal, ceiling, active)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn drive_to(&mut self, ceiling: Height) -> Result<(), RoundError> {
        let active = self.active_indices();
        if active.is_empty() {
            return Ok(());
        }
        self.exchange_registrations();
        self.exchange_reveals();
        for &i in &active {
            if self.nodes[i].height() < ceiling {
                self.enter_round(i, &active)?;
            }
        }
        while let Some(event) = self.clock.next_event() {
            self.handle_event(event, ceiling, &active)?;
        }
        self.exchange_reveals();
        Ok(())
    }

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
        self.exchange_reveals();
        Ok(())
    }

    pub fn drive_window(&mut self, ceiling: Height, deadline: Time) -> Result<(), RoundError> {
        let active = self.active_indices();
        if active.is_empty() {
            return Ok(());
        }
        self.exchange_registrations();
        self.exchange_reveals();
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
        self.exchange_reveals();
        Ok(())
    }

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

    pub fn run(&mut self, heights: u64) -> Result<(), RoundError> {
        for _ in 0..heights {
            self.step()?;
        }
        Ok(())
    }

    pub fn restart_node(&mut self, index: usize) -> Result<(), RoundError> {
        self.nodes[index] = DevNode::open(&self.config.nodes[index], &self.config)?;
        self.exchange_reveals();
        Ok(())
    }
}

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
