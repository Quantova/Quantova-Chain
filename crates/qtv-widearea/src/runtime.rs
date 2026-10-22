// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::net::TcpStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use qtv_devnet::coded::{code_proposal, ProposalAssembler};
use qtv_devnet::wire::Message;
use qtv_devnet::{leader_for, DevNode};
use qtv_net::Channel;
use qtv_node::consensus::Selection;

use qtv_loopback::message_height;

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

pub const MESH_JOIN_TIMEOUT: Duration = Duration::from_secs(300);

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

    fn disseminate_registrations(&mut self) {
        let Some(note) = self.node.own_registration_note() else {
            return;
        };
        if self.i_am_up() {
            let bytes = Message::Register(Box::new(note)).encode();
            self.broadcast(&bytes);
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
                Ok((src, bytes)) => match Message::decode(&bytes) {
                    Ok(Message::Register(note)) => {
                        if self.node.collect_registration((*note).clone()) {
                            self.broadcast(&Message::Register(note).encode());
                        }
                    }
                    Ok(_) => buffer_bounded(&mut self.buffered, src, bytes),
                    Err(_) => {}
                },
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self.node.apply_registrations();
    }

    fn disseminate_reveals(&mut self) {
        if self.i_am_up() {
            if let Some(note) = self.node.own_reveal_note() {
                let bytes = Message::Reveal(Box::new(note)).encode();
                self.broadcast(&bytes);
            }
        }
        let height = self.node.height();
        for (src, bytes) in std::mem::take(&mut self.buffered) {
            match Message::decode(&bytes) {
                Ok(Message::Reveal(note)) if note.height == height => {
                    if self.node.collect_reveal((*note).clone()) {
                        self.broadcast(&Message::Reveal(note).encode());
                    }
                }
                Ok(_) => buffer_bounded(&mut self.buffered, src, bytes),
                Err(_) => {}
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
                Ok((src, bytes)) => match Message::decode(&bytes) {
                    Ok(Message::Reveal(note)) => {
                        if self.node.collect_reveal((*note).clone()) {
                            self.broadcast(&Message::Reveal(note).encode());
                        }
                    }
                    Ok(_) => buffer_bounded(&mut self.buffered, src, bytes),
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
            if let Some(record) = self.node.make_view_change(view) {
                self.node.collect_view_change(selection, record.clone());
                self.emit(Message::ViewChange(Box::new(record)));
            }
        }
        if up {
            self.try_justified(selection);
        }
        let _ = self.settle(selection);
    }

    fn on_view_timeout(&mut self, selection: &Selection) {
        let target = self.node.view() + 1;
        if let Some(record) = self.node.make_view_change(target) {
            self.node.collect_view_change(selection, record.clone());
            self.emit(Message::ViewChange(Box::new(record)));
        }
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
            self.emit(Message::Proposal(Box::new(proposal)));
            for message in self.node.prevote_staged() {
                self.emit(message);
            }
        }
    }

    fn dispatch(&mut self, message: Message, selection: &Selection, source: u64) {
        match message {
            Message::Tx(transaction) => self.node.admit_gossiped(transaction),
            Message::CodedProposal(coded) => {
                let verify_start = Instant::now();
                let outcome = {
                    let node = &self.node;
                    self.assembler
                        .admit(*coded, source, |c| node.coded_auth_ok(selection, c))
                };
                for signed in self.assembler.take_observed() {
                    self.node.observe_signed_proposal(
                        signed.view,
                        &signed.header_hash,
                        &signed.commitment,
                        &signed.auth,
                    );
                }
                self.phase.verify += verify_start.elapsed();
                if let Some(Ok(proposal)) = outcome {
                    let proposer = leader_for(selection, proposal.view);
                    let out = self.node.on_proposal(selection, proposer, proposal);
                    for message in out {
                        self.emit(message);
                    }
                }
            }
            Message::Proposal(proposal) => {
                let proposer = leader_for(selection, proposal.view);
                let verify_start = Instant::now();
                let out = self.node.on_proposal(selection, proposer, *proposal);
                self.phase.verify += verify_start.elapsed();
                for message in out {
                    self.emit(message);
                }
            }
            Message::Prevote(prevote) => {
                let aggregate_start = Instant::now();
                let out = self.node.on_prevote_note(selection, *prevote);
                self.phase.aggregate += aggregate_start.elapsed();
                for message in out {
                    self.emit(message);
                }
            }
            Message::Attest(attestation) => {
                let aggregate_start = Instant::now();
                if self.node.on_attestation((*attestation).clone()) {
                    self.broadcast(&Message::Attest(attestation).encode());
                }
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
                if self.node.collect_registration((*note).clone()) {
                    self.broadcast(&Message::Register(note).encode());
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
        if !self.node.has_finality_threshold(selection) {
            return false;
        }
        let finalise_start = Instant::now();
        let finalized = self.node.try_finalize(selection).unwrap_or(false);
        self.phase.finalise += finalise_start.elapsed();
        finalized
    }

    fn sort_fill_record(
        src: usize,
        bytes: Vec<u8>,
        start_height: u64,
        gossiped: &mut Vec<qtv_tx::Wrapper>,
        buffered: &mut Vec<(usize, Vec<u8>)>,
    ) {
        match Message::decode(&bytes) {
            Ok(Message::Tx(transaction)) => gossiped.push(transaction),
            Ok(other) => match message_height(&other) {
                Some(h) if h < start_height => {}
                _ => buffer_bounded(buffered, src, bytes),
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
        let selection = self
            .node
            .freeze_committee()
            .map_err(|e| format!("select: {e:?}"))?;

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
                Ok((src, bytes)) => {
                    Self::sort_fill_record(
                        src,
                        bytes,
                        start_height,
                        &mut gossiped,
                        &mut self.buffered,
                    );
                    while let Ok((src, bytes)) = self.inbound.try_recv() {
                        Self::sort_fill_record(
                            src,
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
                self.node
                    .admit_gossiped_batch(std::mem::take(&mut gossiped));
            }
        }
        if !gossiped.is_empty() {
            self.node.admit_gossiped_batch(gossiped);
        }
        let fill = fill_start.elapsed();

        let start = Instant::now();
        self.phase = PhaseTimers::default();

        let buffered = std::mem::take(&mut self.buffered);
        self.assembler.tick();
        for (src, bytes) in buffered {
            match Message::decode(&bytes) {
                Ok(message) => match message_height(&message) {
                    Some(h) if h == start_height => self.dispatch(message, &selection, src as u64),
                    Some(h) if h > start_height => buffer_bounded(&mut self.buffered, src, bytes),
                    _ => {}
                },
                Err(_) => {}
            }
        }

        let mut entered_view: Option<u64> = None;
        let mut view_deadline = start + self.view_timeout;
        let mut rotated = false;
        let mut last_tick = Instant::now();

        loop {
            if last_tick.elapsed() >= Duration::from_millis(20) {
                self.assembler.tick();
                last_tick = Instant::now();
            }
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
                Ok((src, bytes)) => {
                    let message = match Message::decode(&bytes) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    match message_height(&message) {
                        Some(h) if h > start_height => {
                            buffer_bounded(&mut self.buffered, src, bytes)
                        }
                        Some(h) if h < start_height => {}
                        _ => self.dispatch(message, &selection, src as u64),
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
