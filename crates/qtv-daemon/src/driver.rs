// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::collections::VecDeque;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use qtv_devnet::coded::{code_proposal, ProposalAssembler};
use qtv_devnet::wire::Message;
use qtv_devnet::{leader_for, DevNode};
use qtv_net::Channel;
use qtv_node::consensus::Selection;

use qtv_gateway::{GatewayCall, NodeContext};

use crate::mesh::Mesh;
use crate::util::{hex, log};

const TICK: Duration = Duration::from_millis(20);

// Bound the ahead-of-height replay buffer by frame count and total bytes.
const MAX_BUFFERED_FRAMES: usize = 8192;

const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;

/// Ahead-of-height replay buffer; oldest frames are evicted when a ceiling is hit.
#[derive(Default)]
struct FrameBuffer {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
}

impl FrameBuffer {
    fn push(&mut self, frame: Vec<u8>) {
        // A frame larger than the whole byte budget can never fit, so refuse it.
        if frame.len() > MAX_BUFFERED_BYTES {
            return;
        }
        while !self.frames.is_empty()
            && (self.frames.len() + 1 > MAX_BUFFERED_FRAMES
                || self.bytes + frame.len() > MAX_BUFFERED_BYTES)
        {
            if let Some(dropped) = self.frames.pop_front() {
                self.bytes -= dropped.len();
            }
        }
        self.bytes += frame.len();
        self.frames.push_back(frame);
    }

    /// Drain the buffer for a replay pass, leaving it empty.
    fn take(&mut self) -> VecDeque<Vec<u8>> {
        self.bytes = 0;
        std::mem::take(&mut self.frames)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.frames.len()
    }

    #[cfg(test)]
    fn byte_len(&self) -> usize {
        self.bytes
    }
}

pub struct Driver {
    node: DevNode,
    idx: usize,
    n: usize,
    send: Vec<Option<Channel<TcpStream>>>,
    inbound: Receiver<(usize, Vec<u8>)>,
    up: Vec<bool>,
    assembler: ProposalAssembler,
    buffered: FrameBuffer,
    budget: u64,
    rpc_context: Option<NodeContext>,
    rpc_requests: Option<Receiver<GatewayCall>>,
}

impl Driver {
    pub fn new(node: DevNode, idx: usize, mesh: Mesh) -> Driver {
        Driver {
            node,
            idx,
            n: mesh.up.len(),
            send: mesh.send,
            inbound: mesh.inbound,
            up: mesh.up,
            assembler: ProposalAssembler::new(),
            buffered: FrameBuffer::default(),
            budget: u64::MAX,
            rpc_context: None,
            rpc_requests: None,
        }
    }

    pub fn attach_rpc(&mut self, context: NodeContext, requests: Receiver<GatewayCall>) {
        self.rpc_context = Some(context);
        self.rpc_requests = Some(requests);
    }

    fn serve_rpc(&mut self) {
        // Cap RPC calls served per consensus tick so a backlog cannot stall block production.
        const RPC_CALLS_PER_TICK: usize = 128;
        let Some(requests) = self.rpc_requests.as_ref() else {
            return;
        };
        let calls: Vec<GatewayCall> = std::iter::from_fn(|| requests.try_recv().ok())
            .take(RPC_CALLS_PER_TICK)
            .collect();
        let Some(context) = self.rpc_context.as_ref() else {
            return;
        };
        for call in calls {
            let request = call.request;
            let node = &mut self.node;
            // Serve on the consensus thread, but firewall a handler panic so it cannot unwind the thread
            // and halt block production. RPC handlers touch only the local mempool buffer, never the
            // committed state trie, so swallowing a panic keeps the node producing without corrupting
            // consensus state; the caller sees a dropped reply and times out.
            let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                qtv_gateway::handle(context, node, request)
            }));
            if let Ok(result) = served {
                let _ = call.reply.send(result);
            }
        }
    }

    pub fn run(
        &mut self,
        block_interval: Duration,
        view_timeout: Duration,
        stopped: &AtomicBool,
    ) -> Result<(), String> {
        while !stopped.load(Ordering::SeqCst) {
            self.halt_if_fatal()?;
            if self.node.height() >= self.budget {
                log(&format!(
                    "reached the configured height cap {}, halting cleanly",
                    self.budget.saturating_sub(1)
                ));
                return Ok(());
            }
            self.drive_one_height(block_interval, view_timeout, stopped)?;
        }
        Ok(())
    }

    /// Stop the node loudly the moment a safety guard trips. A double sign refusal from the
    /// persistent watermark or a finality violation from the finality ledger is not
    /// something the driver rides through, it halts the node and surfaces the reason.
    fn halt_if_fatal(&self) -> Result<(), String> {
        match self.node.fatal() {
            Some(fatal) => {
                let reason = format!(
                    "FATAL safety guard tripped {fatal:?}, the node halts and will not sign or \
                     finalise another height"
                );
                log(&reason);
                Err(reason)
            }
            None => Ok(()),
        }
    }

    fn drive_one_height(
        &mut self,
        block_interval: Duration,
        view_timeout: Duration,
        stopped: &AtomicBool,
    ) -> Result<(), String> {
        let start_height = self.node.height();
        self.disseminate_registrations(view_timeout);
        self.disseminate_reveals(view_timeout);
        let selection = self.node.select().map_err(|e| {
            format!(
                "cannot select a committee at height {start_height}: {e:?}. too few validators \
                 re registered their rotated one time root this epoch to draw a committee"
            )
        })?;

        let height_start = Instant::now();
        let mut entered_view: Option<u64> = None;
        let mut view_deadline = Instant::now() + view_timeout;

        self.replay_buffered(start_height, &selection);

        loop {
            if stopped.load(Ordering::SeqCst) {
                return Ok(());
            }
            self.halt_if_fatal()?;
            self.serve_rpc();
            if self.node.height() > start_height {
                self.log_finalized();
                return Ok(());
            }

            let view = self.node.view();
            let leads = leader_for(&selection, view) == self.node.id();
            let interval_elapsed = height_start.elapsed() >= block_interval;
            let ready =
                entered_view != Some(view) && (!(view == 0 && leads) || interval_elapsed);
            if ready {
                self.enter_current_view(&selection, view);
                entered_view = Some(view);
                view_deadline = Instant::now() + view_timeout;
            }

            if entered_view == Some(view) && Instant::now() >= view_deadline {
                self.on_view_timeout(&selection);
                view_deadline = Instant::now() + view_timeout;
            }

            match self.inbound.recv_timeout(TICK) {
                Ok((_, bytes)) => self.handle_incoming(bytes, start_height, &selection),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => thread::sleep(TICK),
            }
        }
    }

    /// At an epoch boundary publish this node's signed re registration of its rotated one
    /// time root and gather the peers' re registrations, until the up set is heard from or
    /// the window elapses, then re form the committee from the rotated roots. A no op in
    /// the genesis epoch, whose roots the roster already carries.
    fn disseminate_registrations(&mut self, window: Duration) {
        if self.node.epoch() == 0 {
            return;
        }
        if let Some(note) = self.node.own_registration_note() {
            let bytes = Message::Register(Box::new(note)).encode();
            self.broadcast(&bytes);
        }
        let expected: Vec<u64> = (0..self.n)
            .filter(|&q| q != self.idx && self.up.get(q).copied().unwrap_or(false))
            .map(|q| q as u64 + 1)
            .collect();
        let deadline = Instant::now() + window;
        while Instant::now() < deadline {
            let have = self.node.collected_registration_ids();
            if expected.iter().all(|id| have.contains(id)) {
                break;
            }
            match self.inbound.recv_timeout(TICK) {
                Ok((_, bytes)) => {
                    if let Ok(Message::Register(note)) = Message::decode(&bytes) {
                        self.node.collect_registration(*note);
                    } else {
                        self.buffered.push(bytes);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self.node.apply_registrations();
    }

    /// Publish this node's own reveal for the height and gather the peers' reveals,
    /// until the up set is heard from or the window elapses.
    fn disseminate_reveals(&mut self, window: Duration) {
        if let Some(note) = self.node.own_reveal_note() {
            let bytes = Message::Reveal(Box::new(note)).encode();
            self.broadcast(&bytes);
        }
        let expected: Vec<u64> = (0..self.n)
            .filter(|&q| self.up.get(q).copied().unwrap_or(false))
            .map(|q| q as u64 + 1)
            .collect();
        let deadline = Instant::now() + window;
        while Instant::now() < deadline {
            let have = self.node.collected_reveal_ids();
            if expected.iter().all(|id| have.contains(id)) {
                break;
            }
            match self.inbound.recv_timeout(TICK) {
                Ok((_, bytes)) => {
                    if let Ok(Message::Reveal(note)) = Message::decode(&bytes) {
                        self.node.collect_reveal(*note);
                    } else {
                        self.buffered.push(bytes);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn enter_current_view(&mut self, selection: &Selection, view: u64) {
        let messages = self.node.enter_round(selection, true);
        for message in messages {
            self.emit(message);
        }
        if view > 0 {
            let record = self.node.make_view_change(view);
            self.node.collect_view_change(selection, record.clone());
            self.emit(Message::ViewChange(Box::new(record)));
        }
        self.try_justified(selection);
        self.settle(selection);
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
        self.settle(selection);
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
                    let out = self.node.on_proposal(selection, proposer, proposal);
                    for message in out {
                        self.emit(message);
                    }
                }
            }
            Message::Proposal(proposal) => {
                let proposer = leader_for(selection, proposal.view);
                let out = self.node.on_proposal(selection, proposer, proposal);
                for message in out {
                    self.emit(message);
                }
            }
            Message::Prevote(prevote) => {
                let out = self.node.on_prevote(selection, *prevote);
                for message in out {
                    self.emit(message);
                }
            }
            Message::Attest(attestation) => self.node.on_attestation(*attestation),
            Message::ViewChange(record) => {
                self.node.collect_view_change(selection, *record);
                if let Some(target) = self.node.view_sync_target(selection) {
                    if target > self.node.view() {
                        self.node.jump_to(target);
                    }
                }
                self.try_justified(selection);
            }
            Message::Reveal(note) => self.node.collect_reveal(*note),
            Message::Register(note) => {
                self.node.collect_registration(*note);
                self.node.apply_registrations();
            }
            Message::Peers(_)
            | Message::Status(_)
            | Message::GetBlocks { .. }
            | Message::Blocks(_) => {}
        }
        self.settle(selection);
    }

    fn settle(&mut self, selection: &Selection) {
        let online = self.online(selection);
        if !self.node.has_attestations_from(&online) {
            return;
        }
        let _ = self.node.try_finalize(selection);
    }

    fn handle_incoming(&mut self, bytes: Vec<u8>, start_height: u64, selection: &Selection) {
        let message = match Message::decode(&bytes) {
            Ok(message) => message,
            Err(_) => return,
        };
        match message_height(&message) {
            Some(h) if h > start_height => self.buffered.push(bytes),
            Some(h) if h < start_height => {}
            _ => self.dispatch(message, selection),
        }
    }

    fn replay_buffered(&mut self, start_height: u64, selection: &Selection) {
        let buffered = self.buffered.take();
        for bytes in buffered {
            let Ok(message) = Message::decode(&bytes) else {
                continue;
            };
            match message_height(&message) {
                Some(h) if h == start_height => self.dispatch(message, selection),
                Some(h) if h > start_height => self.buffered.push(bytes),
                _ => {}
            }
        }
    }

    fn online(&self, selection: &Selection) -> Vec<u64> {
        selection
            .members
            .iter()
            .copied()
            .filter(|&id| self.up.get((id - 1) as usize).copied().unwrap_or(false))
            .collect()
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

    fn broadcast(&mut self, bytes: &[u8]) {
        for q in 0..self.n {
            if q == self.idx {
                continue;
            }
            if let Some(channel) = self.send[q].as_mut() {
                let _ = channel.send(bytes);
            }
        }
    }

    fn log_finalized(&self) {
        let height = self.node.height().saturating_sub(1);
        let root = hex(&self.node.ledger().q_root());
        let (txs, id) = self
            .node
            .chain()
            .last()
            .map(|block| (block.block.body().len(), block.id()))
            .unwrap_or((0, String::new()));
        log(&format!(
            "finalised height {height} txs {txs} q_root {root} block {id}"
        ));
    }
}

fn message_height(message: &Message) -> Option<u64> {
    match message {
        Message::Proposal(p) => Some(p.header.height()),
        Message::CodedProposal(c) => Some(c.header.height()),
        Message::Attest(a) => Some(a.height),
        Message::Prevote(a) => Some(a.height),
        Message::ViewChange(v) => Some(v.height),
        Message::Reveal(r) => Some(r.height),
        Message::Register(r) => Some(r.height),
        Message::Tx(_)
        | Message::Peers(_)
        | Message::Status(_)
        | Message::GetBlocks { .. }
        | Message::Blocks(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameBuffer, MAX_BUFFERED_BYTES, MAX_BUFFERED_FRAMES};

    // The one invariant every case must uphold: the held frame count and the held byte
    // count both stay at or under their ceilings, whatever a peer streams at the buffer.
    fn within_ceilings(buffer: &FrameBuffer) {
        assert!(
            buffer.len() <= MAX_BUFFERED_FRAMES,
            "frame count {} breached the ceiling {}",
            buffer.len(),
            MAX_BUFFERED_FRAMES
        );
        assert!(
            buffer.byte_len() <= MAX_BUFFERED_BYTES,
            "held bytes {} breached the ceiling {}",
            buffer.byte_len(),
            MAX_BUFFERED_BYTES
        );
    }

    #[test]
    fn a_flood_of_tiny_ahead_frames_stays_within_the_count_ceiling() {
        let mut buffer = FrameBuffer::default();
        // Stream far more small frames than the count ceiling, as an ahead of height
        // flood would. The buffer must never grow past the ceiling.
        for _ in 0..(MAX_BUFFERED_FRAMES * 4) {
            buffer.push(vec![7u8; 32]);
            within_ceilings(&buffer);
        }
        assert_eq!(buffer.len(), MAX_BUFFERED_FRAMES);
    }

    #[test]
    fn a_flood_of_large_ahead_frames_stays_within_the_byte_ceiling() {
        let mut buffer = FrameBuffer::default();
        // Near record sized frames, enough of them to demand many times the byte ceiling.
        let frame = vec![3u8; 1024 * 1024];
        for _ in 0..((MAX_BUFFERED_BYTES / frame.len()) * 4) {
            buffer.push(frame.clone());
            within_ceilings(&buffer);
        }
        // The byte ceiling, not the count ceiling, is what binds a large frame flood.
        assert!(buffer.len() < MAX_BUFFERED_FRAMES);
        assert!(buffer.byte_len() + frame.len() > MAX_BUFFERED_BYTES);
    }

    #[test]
    fn mixed_frame_sizes_cannot_bypass_either_ceiling() {
        let mut buffer = FrameBuffer::default();
        // Interleave a tiny frame and a large frame, the shape an attacker would try to
        // slip a payload past a single dimension bound. Both ceilings must hold every step.
        for round in 0..5000 {
            buffer.push(vec![1u8; 16]);
            within_ceilings(&buffer);
            buffer.push(vec![2u8; 200 * 1024]);
            within_ceilings(&buffer);
            if round % 1000 == 0 {
                buffer.push(vec![9u8; 900 * 1024]);
                within_ceilings(&buffer);
            }
        }
    }

    #[test]
    fn the_count_ceiling_holds_exactly_at_and_over_the_boundary() {
        let mut buffer = FrameBuffer::default();
        for _ in 0..MAX_BUFFERED_FRAMES {
            buffer.push(vec![0u8; 8]);
        }
        assert_eq!(buffer.len(), MAX_BUFFERED_FRAMES, "the buffer fills to the ceiling");
        // One frame over the boundary evicts the oldest rather than growing the buffer.
        buffer.push(vec![0u8; 8]);
        assert_eq!(buffer.len(), MAX_BUFFERED_FRAMES, "the ceiling holds one frame over");
        within_ceilings(&buffer);
    }

    #[test]
    fn an_oversized_single_frame_is_refused_and_leaves_the_buffer_intact() {
        let mut buffer = FrameBuffer::default();
        buffer.push(vec![5u8; 4096]);
        let before_frames = buffer.len();
        let before_bytes = buffer.byte_len();
        // A frame larger than the whole byte budget can never be held, so it is dropped
        // without evicting what is already buffered.
        buffer.push(vec![6u8; MAX_BUFFERED_BYTES + 1]);
        assert_eq!(buffer.len(), before_frames, "the oversized frame was not stored");
        assert_eq!(buffer.byte_len(), before_bytes, "no bytes were charged for it");
        within_ceilings(&buffer);
    }

    #[test]
    fn eviction_keeps_the_freshest_frames() {
        let mut buffer = FrameBuffer::default();
        // Tag frames with a running counter in the first bytes, overflow the count ceiling,
        // then confirm the survivors are the most recent ones, oldest first.
        let total = MAX_BUFFERED_FRAMES + 100;
        for tag in 0..total as u64 {
            let mut frame = tag.to_le_bytes().to_vec();
            frame.resize(64, 0);
            buffer.push(frame);
        }
        let held = buffer.take();
        assert_eq!(held.len(), MAX_BUFFERED_FRAMES);
        let first_tag = u64::from_le_bytes(held.front().unwrap()[..8].try_into().unwrap());
        let last_tag = u64::from_le_bytes(held.back().unwrap()[..8].try_into().unwrap());
        assert_eq!(first_tag, (total - MAX_BUFFERED_FRAMES) as u64);
        assert_eq!(last_tag, (total - 1) as u64);
    }

    #[test]
    fn take_empties_the_buffer_and_resets_the_byte_count() {
        let mut buffer = FrameBuffer::default();
        for _ in 0..64 {
            buffer.push(vec![4u8; 1000]);
        }
        assert!(buffer.byte_len() > 0);
        let held = buffer.take();
        assert_eq!(held.len(), 64);
        assert_eq!(buffer.len(), 0, "the buffer is empty after a drain");
        assert_eq!(buffer.byte_len(), 0, "the byte count resets on a drain");
    }
}
