// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use qtv_devnet::coded::{code_proposal, ProposalAssembler};
use qtv_devnet::node::node_peer_id;
use qtv_devnet::wire::Message;
use qtv_devnet::{leader_for, DevNode};
use qtv_net::{Channel, Identity};
use qtv_node::consensus::Selection;

use qtv_loopback::message_height;

type MeshChannels = (Vec<Option<Channel<TcpStream>>>, Receiver<(usize, Vec<u8>)>);

#[derive(Clone, Copy, Default)]
pub struct PhaseTimers {
    pub wait: Duration,
    pub build: Duration,
    pub verify: Duration,
    pub aggregate: Duration,
    pub finalise: Duration,
    pub flood: Duration,
}

pub enum HeightOutcome {
    Final {
        elapsed: Duration,
        txs: usize,
        rotated: bool,
        phases: PhaseTimers,
        fill: Duration,
    },
    Stalled,
}

const MAX_BUFFERED_FRAMES: usize = 8192;
const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;

fn buffer_bounded(buffered: &mut Vec<(usize, Vec<u8>)>, from: usize, frame: Vec<u8>) {
    if frame.len() > MAX_BUFFERED_BYTES {
        return;
    }
    let mut total: usize = buffered.iter().map(|(_, f)| f.len()).sum();
    while !buffered.is_empty()
        && (buffered.len() + 1 > MAX_BUFFERED_FRAMES || total + frame.len() > MAX_BUFFERED_BYTES)
    {
        let (_, dropped) = buffered.remove(0);
        total = total.saturating_sub(dropped.len());
    }
    buffered.push((from, frame));
}

pub struct Runtime {
    pub idx: usize,
    pub n: usize,
    pub node: DevNode,
    pub send: Vec<Option<Channel<TcpStream>>>,
    pub inbound: Receiver<(usize, Vec<u8>)>,
    pub assembler: ProposalAssembler,
    pub buffered: Vec<(usize, Vec<u8>)>,
    pub senders_n: usize,
    pub up: Vec<bool>,
    pub slow: Duration,
    pub view_timeout: Duration,
    pub stall: Duration,
    pub phase: PhaseTimers,
}

impl Runtime {
    fn i_am_up(&self) -> bool {
        self.up.get(self.idx).copied().unwrap_or(false)
    }

    fn online(&self, selection: &Selection) -> Vec<u64> {
        selection
            .members
            .iter()
            .copied()
            .filter(|&id| self.up.get((id - 1) as usize).copied().unwrap_or(false))
            .collect()
    }

    fn broadcast(&mut self, bytes: &[u8]) {
        if !self.slow.is_zero() {
            thread::sleep(self.slow);
        }
        for q in 0..self.n {
            if q == self.idx {
                continue;
            }
            if let Some(channel) = self.send[q].as_mut() {
                let _ = channel.send(bytes);
            }
        }
    }

    fn emit(&mut self, message: Message) {
        match message {
            Message::Proposal(proposal) => {
                if let Ok(shards) = code_proposal(&proposal) {
                    for shard in shards {
                        let bytes = Message::CodedProposal(Box::new(shard)).encode();
                        self.broadcast(&bytes);
                    }
                }
            }
            other => {
                let bytes = other.encode();
                self.broadcast(&bytes);
            }
        }
    }

    fn expected_reveal_ids(&self) -> Vec<u64> {
        (0..self.n)
            .filter(|&q| self.up.get(q).copied().unwrap_or(false))
            .map(|q| q as u64 + 1)
            .collect()
    }

    /// At an epoch boundary publish this node's signed re registration of its rotated one
    /// time root, gather the peers' re registrations, and re form the committee. A no op in
    /// the genesis epoch, whose roots the roster already carries.
    fn disseminate_registrations(&mut self) {
        if self.node.epoch() == 0 {
            return;
        }
        if self.i_am_up() {
            if let Some(note) = self.node.own_registration_note() {
                let bytes = Message::Register(Box::new(note)).encode();
                self.broadcast(&bytes);
            }
        }
        let expected: Vec<u64> = self
            .expected_reveal_ids()
            .into_iter()
            .filter(|&id| id != self.node.id())
            .collect();
        let deadline = Instant::now() + self.view_timeout;
        while Instant::now() < deadline {
            let have = self.node.collected_registration_ids();
            if expected.iter().all(|id| have.contains(id)) {
                break;
            }
            match self.inbound.recv_timeout(Duration::from_millis(10)) {
                Ok((_, bytes)) => match Message::decode(&bytes) {
                    Ok(Message::Register(note)) => {
                        self.node.collect_registration(*note);
                    }
                    Ok(_) => buffer_bounded(&mut self.buffered, 0, bytes),
                    Err(_) => {}
                },
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self.node.apply_registrations();
    }

    /// Publish this node's own reveal for the height and gather the peers' reveals,
    /// until the up set is heard from or a bounded window elapses.
    fn disseminate_reveals(&mut self) {
        if self.i_am_up() {
            if let Some(note) = self.node.own_reveal_note() {
                let bytes = Message::Reveal(Box::new(note)).encode();
                self.broadcast(&bytes);
            }
        }
        let expected = self.expected_reveal_ids();
        let deadline = Instant::now() + self.view_timeout;
        while Instant::now() < deadline {
            let have = self.node.collected_reveal_ids();
            if expected.iter().all(|id| have.contains(id)) {
                break;
            }
            match self.inbound.recv_timeout(Duration::from_millis(10)) {
                Ok((_, bytes)) => match Message::decode(&bytes) {
                    Ok(Message::Reveal(note)) => {
                        if self.node.collect_reveal((*note).clone()) {
                            self.broadcast(&Message::Reveal(note).encode());
                        }
                    }
                    Ok(_) => buffer_bounded(&mut self.buffered, 0, bytes),
                    Err(_) => {}
                },
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn enter_current_view(&mut self, selection: &Selection, view: u64) {
        let up = self.i_am_up();
        let messages = self.node.enter_round(selection, up);
        for message in messages {
            self.emit(message);
        }
        if up && view > 0 {
            let record = self.node.make_view_change(view);
            self.node.collect_view_change(selection, record.clone());
            self.emit(Message::ViewChange(Box::new(record)));
        }
        if up {
            self.try_justified(selection);
        }
        let _ = self.settle(selection);
    }

    fn on_view_timeout(&mut self, selection: &Selection) {
        let target = self.node.view() + 1;
        let record = self.node.make_view_change(target);
        self.node.collect_view_change(selection, record.clone());
        self.emit(Message::ViewChange(Box::new(record)));
        if let Some(sync) = self.node.view_sync_target(selection) {
            if sync > self.node.view() {
                self.node.jump_to(sync);
            }
        }
        self.try_justified(selection);
        let _ = self.settle(selection);
    }

    fn try_justified(&mut self, selection: &Selection) {
        let view = self.node.view();
        if view == 0 || leader_for(selection, view) != self.node.id() {
            return;
        }
        if self.node.staged_view() == Some(view) {
            return;
        }
        if let Some(proposal) = self.node.build_justified_proposal(selection, view) {
            self.emit(Message::Proposal(proposal));
            for message in self.node.prevote_staged() {
                self.emit(message);
            }
        }
    }

    fn dispatch(&mut self, message: Message, selection: &Selection) {
        match message {
            Message::Tx(transaction) => self.node.admit_gossiped(transaction),
            Message::CodedProposal(coded) => {
                if let Some(Ok(proposal)) = self.assembler.admit(*coded) {
                    let proposer = leader_for(selection, proposal.view);
                    let verify_start = Instant::now();
                    let out = self.node.on_proposal(selection, proposer, proposal);
                    self.phase.verify += verify_start.elapsed();
                    for message in out {
                        self.emit(message);
                    }
                }
            }
            Message::Proposal(proposal) => {
                let proposer = leader_for(selection, proposal.view);
                let verify_start = Instant::now();
                let out = self.node.on_proposal(selection, proposer, proposal);
                self.phase.verify += verify_start.elapsed();
                for message in out {
                    self.emit(message);
                }
            }
            Message::Prevote(prevote) => {
                let aggregate_start = Instant::now();
                let out = self.node.on_prevote(selection, *prevote);
                self.phase.aggregate += aggregate_start.elapsed();
                for message in out {
                    self.emit(message);
                }
            }
            Message::Attest(attestation) => {
                let aggregate_start = Instant::now();
                self.node.on_attestation(*attestation);
                self.phase.aggregate += aggregate_start.elapsed();
            }
            Message::ViewChange(record) => {
                self.node.collect_view_change(selection, *record);
                if let Some(target) = self.node.view_sync_target(selection) {
                    if target > self.node.view() {
                        self.node.jump_to(target);
                    }
                }
                self.try_justified(selection);
            }
            Message::Reveal(note) => {
                if self.node.collect_reveal((*note).clone()) {
                    self.broadcast(&Message::Reveal(note).encode());
                }
            }
            Message::Register(note) => {
                if self.node.collect_registration(*note) {
                    self.node.apply_registrations();
                }
            }
            Message::Peers(_)
            | Message::Status(_)
            | Message::GetBlocks { .. }
            | Message::Blocks(_) => {}
        }
        let _ = self.settle(selection);
    }

    fn settle(&mut self, selection: &Selection) -> bool {
        if !self.node.has_finality_threshold(selection.tau) {
            return false;
        }
        let finalise_start = Instant::now();
        let finalized = self.node.try_finalize(selection).unwrap_or(false);
        self.phase.finalise += finalise_start.elapsed();
        finalized
    }

    fn sort_fill_record(
        bytes: Vec<u8>,
        start_height: u64,
        gossiped: &mut Vec<qtv_tx::Wrapper>,
        buffered: &mut Vec<(usize, Vec<u8>)>,
    ) {
        match Message::decode(&bytes) {
            Ok(Message::Tx(transaction)) => gossiped.push(transaction),
            Ok(other) => match message_height(&other) {
                Some(h) if h < start_height => {}
                _ => buffer_bounded(buffered, 0, bytes),
            },
            Err(_) => {}
        }
    }

    pub fn drive_height(
        &mut self,
        batch: Option<Vec<qtv_tx::Wrapper>>,
    ) -> Result<HeightOutcome, String> {
        let start_height = self.node.height();
        self.disseminate_registrations();
        self.disseminate_reveals();
        let selection = self.node.select().map_err(|e| format!("select: {e:?}"))?;

        let fill_start = Instant::now();

        if let Some(batch) = batch {
            for transaction in &batch {
                let bytes = Message::Tx(transaction.clone()).encode();
                self.broadcast(&bytes);
            }
            self.node.submit_batch(batch);
        }

        let fill_deadline = fill_start + self.stall;
        let mut gossiped: Vec<qtv_tx::Wrapper> = Vec::new();
        while self.node.mempool_len() < self.senders_n && Instant::now() < fill_deadline {
            match self.inbound.recv_timeout(Duration::from_millis(20)) {
                Ok((_, bytes)) => {
                    Self::sort_fill_record(bytes, start_height, &mut gossiped, &mut self.buffered);
                    while let Ok((_, bytes)) = self.inbound.try_recv() {
                        Self::sort_fill_record(
                            bytes,
                            start_height,
                            &mut gossiped,
                            &mut self.buffered,
                        );
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if !gossiped.is_empty() {
                self.node.admit_gossiped_batch(std::mem::take(&mut gossiped));
            }
        }
        if !gossiped.is_empty() {
            self.node.admit_gossiped_batch(gossiped);
        }
        let fill = fill_start.elapsed();

        let start = Instant::now();
        self.phase = PhaseTimers::default();

        let buffered = std::mem::take(&mut self.buffered);
        for (_, bytes) in buffered {
            match Message::decode(&bytes) {
                Ok(message) => match message_height(&message) {
                    Some(h) if h == start_height => self.dispatch(message, &selection),
                    Some(h) if h > start_height => buffer_bounded(&mut self.buffered, 0, bytes),
                    _ => {}
                },
                Err(_) => {}
            }
        }

        let mut entered_view: Option<u64> = None;
        let mut view_deadline = start + self.view_timeout;
        let mut rotated = false;

        loop {
            if self.node.height() > start_height {
                let txs = self
                    .node
                    .chain()
                    .last()
                    .map(|b| b.block.body().len())
                    .unwrap_or(0);
                return Ok(HeightOutcome::Final {
                    elapsed: start.elapsed(),
                    txs,
                    rotated,
                    phases: self.phase,
                    fill,
                });
            }
            if start.elapsed() >= self.stall {
                if std::env::var("QTV_WA_DEBUG").is_ok() {
                    eprintln!(
                        "[validator {}] STALL at height {start_height} view {} mempool {} staged {:?} online {:?}",
                        self.idx,
                        self.node.view(),
                        self.node.mempool_len(),
                        self.node.staged_view(),
                        self.online(&selection),
                    );
                }
                return Ok(HeightOutcome::Stalled);
            }

            let view = self.node.view();
            if view > 0 {
                rotated = true;
            }
            let leads = leader_for(&selection, view) == self.node.id();
            let ready_to_enter = entered_view != Some(view)
                && (!(view == 0 && leads) || self.node.mempool_len() >= self.senders_n);
            if self.i_am_up() && ready_to_enter {
                let build_start = Instant::now();
                self.enter_current_view(&selection, view);
                self.phase.build += build_start.elapsed();
                entered_view = Some(view);
                view_deadline = Instant::now() + self.view_timeout;
            }

            if self.i_am_up() && entered_view == Some(view) && Instant::now() >= view_deadline {
                self.on_view_timeout(&selection);
                view_deadline = Instant::now() + self.view_timeout;
            }

            let wait_start = Instant::now();
            let received = self.inbound.recv_timeout(Duration::from_millis(20));
            self.phase.wait += wait_start.elapsed();
            match received {
                Ok((_, bytes)) => {
                    let message = match Message::decode(&bytes) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    match message_height(&message) {
                        Some(h) if h > start_height => buffer_bounded(&mut self.buffered, 0, bytes),
                        Some(h) if h < start_height => {}
                        _ => self.dispatch(message, &selection),
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Ok(HeightOutcome::Stalled);
                }
            }
        }
    }
}

pub fn build_mesh(
    listener: TcpListener,
    addrs: &[String],
    idx: usize,
    n: usize,
    up: &[bool],
    identity: &Identity,
) -> MeshChannels {
    let (inbound_tx, inbound_rx) = mpsc::channel::<(usize, Vec<u8>)>();
    let (accepted_tx, accepted_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();

    let up_peers = (0..n)
        .filter(|&q| q != idx && up.get(q).copied().unwrap_or(false))
        .count();

    let identity_acc = identity.clone();
    let up_ids: Vec<bool> = up.to_vec();
    let acceptor = thread::spawn(move || {
        let mut accepted = 0usize;
        while accepted < up_peers {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) => continue,
            };
            let channel = match Channel::accept(stream, &identity_acc) {
                Ok(channel) => channel,
                Err(_) => continue,
            };
            let peer = channel.peer_id().clone();
            let from = match (0..n).find(|&q| {
                q != idx
                    && up_ids.get(q).copied().unwrap_or(false)
                    && node_peer_id(q as u64 + 1) == peer
            }) {
                Some(from) => from,
                None => continue,
            };
            if accepted_tx.send((from, channel)).is_err() {
                break;
            }
            accepted += 1;
        }
    });

    let mut send: Vec<Option<Channel<TcpStream>>> = (0..n).map(|_| None).collect();
    for q in 0..n {
        if q == idx || !up.get(q).copied().unwrap_or(false) {
            continue;
        }
        let addr = &addrs[q];
        let stream = loop {
            match TcpStream::connect(addr) {
                Ok(stream) => break stream,
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        };
        let peer = node_peer_id(q as u64 + 1);
        let channel =
            Channel::connect_pinned(stream, identity, &peer).expect("initiator handshake");
        send[q] = Some(channel);
    }

    acceptor.join().expect("the acceptor thread joins");

    for _ in 0..up_peers {
        let (from, mut channel) = accepted_rx.recv().expect("an accepted inbound channel");
        let out = inbound_tx.clone();
        thread::spawn(move || {
            while let Ok(bytes) = channel.recv() {
                if out.send((from, bytes)).is_err() {
                    break;
                }
            }
        });
    }
    drop(inbound_tx);
    (send, inbound_rx)
}
