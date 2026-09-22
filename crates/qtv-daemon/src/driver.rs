// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::VecDeque;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{
    channel, sync_channel, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError,
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use qtv_devnet::coded::{code_proposal, ProposalAssembler};
use qtv_devnet::wire::{wrapper_from_bytes, Message};
use qtv_devnet::{leader_for, DevNode};
use qtv_net::Channel;
use qtv_node::consensus::Selection;
use qtv_node::fee::FeeParams;
use qtv_node::ledger::Ledger;
use qtv_node::mempool::{admission_hint, AdmitHint};
use qtv_tx::Wrapper;

use qtv_gateway::{ClientError, GatewayCall, Json, NodeContext, Request};

const VERIFY_WORKERS: usize = 4;

struct VerifyJob {
    wrapper: Wrapper,
    ledger: Arc<Ledger>,
    fee_params: FeeParams,
    tx_id: String,
    reply: Sender<Result<Json, ClientError>>,
}

struct VerifyDone {
    wrapper: Wrapper,
    // None means verification panicked on a malformed submission. The consensus thread
    // then rejects it outright rather than re-running the same panic inline.
    hint: Option<AdmitHint>,
    tx_id: String,
    reply: Sender<Result<Json, ClientError>>,
}

// A pool of worker threads that run every submitted transaction's heavy verification
// off the consensus thread. Signed transactions have their post quantum signature
// checked, and feeless bridge submissions have their operator and foreign chain proofs
// checked, all against a ledger snapshot. The consensus thread only finalises admission
// with the returned verdict, so a burst of submissions cannot delay block production.
// Block execution re-verifies every bridge operation, so the snapshot verdict is only a
// spam filter and can never move value on a stale read.
fn queue_verify(jobs: &SyncSender<VerifyJob>, job: VerifyJob) {
    if let Err(TrySendError::Full(job) | TrySendError::Disconnected(job)) = jobs.try_send(job) {
        let _ = job.reply.send(Ok(qtv_gateway::submit_reply(
            Err(qtv_node::mempool::Reject::RateLimited),
            &job.tx_id,
        )));
    }
}

fn start_verify_pool() -> (SyncSender<VerifyJob>, Receiver<VerifyDone>) {
    let (job_tx, job_rx) = sync_channel::<VerifyJob>(4096);
    let (done_tx, done_rx) = channel::<VerifyDone>();
    let job_rx = Arc::new(Mutex::new(job_rx));
    let workers = thread::available_parallelism()
        .map(|n| n.get().min(VERIFY_WORKERS))
        .unwrap_or(1)
        .max(1);
    for _ in 0..workers {
        let job_rx = Arc::clone(&job_rx);
        let done_tx = done_tx.clone();
        thread::spawn(move || loop {
            let job = {
                let guard = match job_rx.lock() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };
                guard.recv()
            };
            let VerifyJob {
                wrapper,
                ledger,
                fee_params,
                tx_id,
                reply,
            } = match job {
                Ok(job) => job,
                Err(_) => return,
            };
            let hint = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                admission_hint(&wrapper, &ledger, &fee_params)
            }))
            .ok();
            let done = VerifyDone {
                wrapper,
                hint,
                tx_id,
                reply,
            };
            if done_tx.send(done).is_err() {
                return;
            }
        });
    }
    (job_tx, done_rx)
}

use crate::mesh::Mesh;
use crate::util::{hex, log};

const TICK: Duration = Duration::from_millis(20);
// New transactions forwarded to peers per pass of the round loop. The rest stay in this
// node's mempool and go into its own blocks.
const MAX_GOSSIP_PER_TICK: usize = 256;

const MAX_BUFFERED_FRAMES: usize = 8192;

const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;

const CATCH_UP_SPAN: u64 = 64;

#[derive(Default)]
struct FrameBuffer {
    frames: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
}

impl FrameBuffer {
    fn heaviest_source(&self) -> Option<u64> {
        let mut tally: Vec<(u64, usize)> = Vec::new();
        for (source, frame) in self.frames.iter() {
            match tally.iter_mut().find(|(id, _)| id == source) {
                Some((_, bytes)) => *bytes += frame.len(),
                None => tally.push((*source, frame.len())),
            }
        }
        tally
            .into_iter()
            .max_by_key(|&(_, bytes)| bytes)
            .map(|(id, _)| id)
    }

    fn evict_one(&mut self, incoming: u64) {
        let target = self.heaviest_source().unwrap_or(incoming);
        if let Some(at) = self.frames.iter().position(|(source, _)| *source == target) {
            if let Some((_, dropped)) = self.frames.remove(at) {
                self.bytes -= dropped.len();
                return;
            }
        }
        if let Some((_, dropped)) = self.frames.pop_front() {
            self.bytes -= dropped.len();
        }
    }

    fn push(&mut self, source: u64, frame: Vec<u8>) {
        if frame.len() > MAX_BUFFERED_BYTES {
            return;
        }
        while !self.frames.is_empty()
            && (self.frames.len() + 1 > MAX_BUFFERED_FRAMES
                || self.bytes + frame.len() > MAX_BUFFERED_BYTES)
        {
            self.evict_one(source);
        }
        self.bytes += frame.len();
        self.frames.push_back((source, frame));
    }

    fn take(&mut self) -> VecDeque<(u64, Vec<u8>)> {
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
    queued_bytes: std::sync::Arc<crate::mesh::InboundBudget>,
    up: Vec<bool>,
    rejoined: Receiver<(usize, Channel<TcpStream>)>,
    down: SyncSender<usize>,
    assembler: ProposalAssembler,
    buffered: FrameBuffer,
    budget: u64,
    rpc_context: Option<NodeContext>,
    rpc_requests: Option<Receiver<GatewayCall>>,
    verify_jobs: Option<SyncSender<VerifyJob>>,
    verify_done: Option<Receiver<VerifyDone>>,
    verify_snapshot: Option<(u64, Arc<Ledger>)>,
}

impl Driver {
    /// Hand queued bytes back to the mesh budget as soon as a frame leaves the queue.
    fn release_queued(&self, from: usize, len: usize) {
        self.queued_bytes.release(from, len);
    }

    fn decode_queued(
        &self,
        from: usize,
        bytes: &[u8],
    ) -> Result<Message, qtv_devnet::wire::DecodeError> {
        self.release_queued(from, bytes.len());
        Message::decode(bytes)
    }

    pub fn new(node: DevNode, idx: usize, mesh: Mesh) -> Driver {
        Driver {
            node,
            idx,
            n: mesh.up.len(),
            send: mesh.send,
            inbound: mesh.inbound,
            queued_bytes: mesh.queued_bytes,
            up: mesh.up,
            rejoined: mesh.rejoined,
            down: mesh.down,
            assembler: ProposalAssembler::new(),
            buffered: FrameBuffer::default(),
            budget: u64::MAX,
            rpc_context: None,
            rpc_requests: None,
            verify_jobs: None,
            verify_done: None,
            verify_snapshot: None,
        }
    }

    pub fn attach_rpc(&mut self, context: NodeContext, requests: Receiver<GatewayCall>) {
        self.rpc_context = Some(context);
        self.rpc_requests = Some(requests);
    }

    fn serve_rpc(&mut self) {
        const RPC_CALLS_PER_TICK: usize = 128;
        if self.verify_jobs.is_none() {
            let (jobs, done) = start_verify_pool();
            self.verify_jobs = Some(jobs);
            self.verify_done = Some(done);
        }
        // Finalise any submissions the verify pool has now checked. Admission is cheap
        // here because the post quantum verify already ran on a worker thread; the
        // verdict is carried back as a hint and reused unless the sender key changed.
        let completed: Vec<VerifyDone> = self
            .verify_done
            .as_ref()
            .map(|done| {
                std::iter::from_fn(|| done.try_recv().ok())
                    .take(RPC_CALLS_PER_TICK)
                    .collect()
            })
            .unwrap_or_default();
        for done in completed {
            let result = match done.hint {
                Some(hint) => self.node.submit_hinted(done.wrapper, Some(hint)),
                // Verification panicked on this submission. Reject it outright rather
                // than re-running the same panic on the consensus thread.
                None => Err(qtv_node::mempool::Reject::BadCall),
            };
            let _ = done
                .reply
                .send(Ok(qtv_gateway::submit_reply(result, &done.tx_id)));
        }

        let calls: Vec<GatewayCall> = match self.rpc_requests.as_ref() {
            Some(requests) => std::iter::from_fn(|| requests.try_recv().ok())
                .take(RPC_CALLS_PER_TICK)
                .collect(),
            None => return,
        };
        if self.rpc_context.is_none() {
            return;
        }

        // Refresh the read-only ledger snapshot the workers verify against, at most
        // once per block and only when there is a submission to serve. The snapshot is
        // shared by reference count, so each job clone is cheap.
        let fee_params = self.node.fee_params();
        if calls
            .iter()
            .any(|call| matches!(call.request, Request::Submit(_)))
        {
            let height = self.node.height();
            if self.verify_snapshot.as_ref().map(|(h, _)| *h) != Some(height) {
                self.verify_snapshot = Some((height, Arc::new(self.node.ledger_snapshot())));
            }
        }
        let snapshot = self.verify_snapshot.as_ref().map(|(_, l)| Arc::clone(l));

        for call in calls {
            // A submission has its heavy verification run on the pool against a ledger
            // snapshot rather than inline, so a post quantum signature or a bridge proof
            // never competes with block production.
            if let Request::Submit(bytes) = &call.request {
                if let (Some(ledger), Some(jobs)) = (snapshot.as_ref(), self.verify_jobs.as_ref()) {
                    if let Ok(wrapper) = wrapper_from_bytes(bytes) {
                        let job = VerifyJob {
                            tx_id: wrapper.id(),
                            wrapper,
                            ledger: Arc::clone(ledger),
                            fee_params,
                            reply: call.reply.clone(),
                        };
                        queue_verify(jobs, job);
                        continue;
                    }
                }
            }
            let context = self.rpc_context.as_ref().unwrap();
            let request = call.request;
            let node = &mut self.node;
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
        let selection = match self.node.select() {
            Ok(selection) => selection,
            Err(e) => {
                // A transient partition or a too-thin reveal set must not terminate the
                // daemon. Log the reason, back off one view, and let the outer loop
                // re-disseminate and retry rather than forcing a manual restart.
                let reason = match self.node.saturation_shortfall() {
                    Some((count, lightest, floor, total)) => format!(
                        "cannot select a committee at height {start_height}: {e:?}. {count} \
                         validator(s) hold less than the {floor} of {total} total stake this \
                         roster needs, the lightest at {lightest}; a stake imbalance"
                    ),
                    None => format!(
                        "cannot select a committee at height {start_height}: {e:?}. too few \
                         validators re registered their rotated one time root this epoch"
                    ),
                };
                log(&format!("{reason}; retrying next round"));
                std::thread::sleep(view_timeout);
                return Ok(());
            }
        };

        let height_start = Instant::now();
        let mut entered_view: Option<u64> = None;
        let mut view_deadline = Instant::now() + view_timeout;

        self.assembler.tick();
        self.replay_buffered(start_height, &selection);

        let mut last_tick = Instant::now();
        loop {
            if stopped.load(Ordering::SeqCst) {
                return Ok(());
            }
            if last_tick.elapsed() >= TICK {
                self.assembler.tick();
                last_tick = Instant::now();
                self.adopt_rejoined();
            }
            self.halt_if_fatal()?;
            self.serve_rpc();
            self.gossip_outbox();
            if self.node.height() > start_height {
                self.log_finalized();
                return Ok(());
            }

            let view = self.node.view();
            let leads = leader_for(&selection, view) == self.node.id();
            let interval_elapsed = height_start.elapsed() >= block_interval;
            let ready = entered_view != Some(view) && (!(view == 0 && leads) || interval_elapsed);
            if ready {
                self.enter_current_view(&selection, view);
                entered_view = Some(view);
                view_deadline = Instant::now() + view_timeout;
            }

            if entered_view == Some(view) && Instant::now() >= view_deadline {
                self.on_view_timeout(&selection);
                self.request_catch_up();
                view_deadline = Instant::now() + view_timeout;
            }

            match self.inbound.recv_timeout(TICK) {
                Ok((source, bytes)) => {
                    self.release_queued(source, bytes.len());
                    self.handle_incoming(bytes, start_height, &selection, source as u64)
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => thread::sleep(TICK),
            }
        }
    }

    /// Take up any link the redialler has re-established. A peer that went away and
    /// came back is put straight back into the round rather than staying dropped for
    /// the life of the process.
    fn adopt_rejoined(&mut self) {
        while let Ok((q, channel)) = self.rejoined.try_recv() {
            if q < self.send.len() {
                // Only the transport is restored here. `up` is NOT link health, it is
                // the membership of the reveal barrier that decides which set every
                // node calls select() on, so moving it from one node's view of a
                // socket would let two nodes form different committees.
                self.send[q] = Some(channel);
            }
        }
    }

    fn disseminate_registrations(&mut self, window: Duration) {
        // Outside the registration window nothing a peer sends can count, so do not wait.
        let Some(note) = self.node.own_registration_note() else {
            return;
        };
        let bytes = Message::Register(Box::new(note)).encode();
        self.broadcast(&bytes);
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
                Ok((source, bytes)) => match self.decode_queued(source, &bytes) {
                    Ok(Message::Register(note)) => {
                        if self.node.collect_registration((*note).clone()) {
                            self.broadcast(&Message::Register(note).encode());
                        }
                    }
                    Ok(_) => self.buffered.push(source as u64, bytes),
                    Err(_) => {}
                },
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self.node.apply_registrations();
    }

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
                Ok((source, bytes)) => match self.decode_queued(source, &bytes) {
                    Ok(Message::Reveal(note)) => {
                        if self.node.collect_reveal((*note).clone()) {
                            self.broadcast(&Message::Reveal(note).encode());
                        }
                    }
                    Ok(_) => self.buffered.push(source as u64, bytes),
                    Err(_) => {}
                },
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
                self.assembler.set_round_height(self.node.height());
                let outcome = {
                    let node = &self.node;
                    self.assembler
                        .admit(*coded, source, |c| node.coded_auth_ok(selection, c))
                };
                if let Some(Ok(proposal)) = outcome {
                    let proposer = leader_for(selection, proposal.view);
                    let out = self.node.on_proposal(selection, proposer, proposal);
                    for message in out {
                        self.emit(message);
                    }
                }
            }
            Message::Proposal(_) => {}
            Message::Prevote(prevote) => {
                let out = self.node.on_prevote(selection, *prevote);
                for message in out {
                    self.emit(message);
                }
            }
            Message::Attest(attestation) => {
                if self.node.on_attestation((*attestation).clone()) {
                    self.broadcast(&Message::Attest(attestation).encode());
                }
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
            Message::GetBlocks { from, to } => {
                let blocks = self.node.serve_blocks(from, to);
                if !blocks.is_empty() {
                    let reply = Message::Blocks(blocks).encode();
                    self.send_one(source as usize, &reply);
                }
            }
            Message::Blocks(blocks) => {
                for block in blocks {
                    if self.node.apply_synced_block(block).is_err() {
                        break;
                    }
                }
            }
            Message::Peers(_) | Message::Status(_) => {}
        }
        self.settle(selection);
    }

    fn settle(&mut self, selection: &Selection) {
        if !self.node.has_finality_threshold(selection) {
            return;
        }
        let _ = self.node.try_finalize(selection);
    }

    fn handle_incoming(
        &mut self,
        bytes: Vec<u8>,
        start_height: u64,
        selection: &Selection,
        source: u64,
    ) {
        let message = match Message::decode(&bytes) {
            Ok(message) => message,
            Err(_) => return,
        };
        match message_height(&message) {
            Some(h) if h > start_height => self.buffered.push(source, bytes),
            Some(h) if h < start_height => {}
            _ => self.dispatch(message, selection, source),
        }
    }

    fn replay_buffered(&mut self, start_height: u64, selection: &Selection) {
        let buffered = self.buffered.take();
        for (source, bytes) in buffered {
            let Ok(message) = Message::decode(&bytes) else {
                continue;
            };
            match message_height(&message) {
                Some(h) if h == start_height => self.dispatch(message, selection, source),
                Some(h) if h > start_height => self.buffered.push(source, bytes),
                _ => {}
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

    fn send_one(&mut self, q: usize, bytes: &[u8]) {
        if q == self.idx || q >= self.send.len() {
            return;
        }
        if let Some(channel) = self.send[q].as_mut() {
            let _ = channel.send(bytes);
        }
    }

    // Frames parked for a height above ours mean peers have moved on without us. Without
    // this the node waits on a round the rest of the set already finalised, forever.
    fn request_catch_up(&mut self) {
        let Some(source) = self.buffered.heaviest_source() else {
            return;
        };
        let from = self.node.height();
        let request = Message::GetBlocks {
            from,
            to: from + CATCH_UP_SPAN,
        }
        .encode();
        self.send_one(source as usize, &request);
    }

    // Pass what this node admitted to its peers, so a transaction does not wait for the
    // node it was sent to to lead. One hop: a peer admits it and does not forward it again.
    fn gossip_outbox(&mut self) {
        for transaction in self
            .node
            .take_outbox()
            .into_iter()
            .take(MAX_GOSSIP_PER_TICK)
        {
            let bytes = Message::Tx(transaction).encode();
            self.broadcast(&bytes);
        }
    }

    fn broadcast(&mut self, bytes: &[u8]) {
        for q in 0..self.n {
            if q == self.idx {
                continue;
            }
            // A message too large to carry is this node's to drop, not a sign the link is
            // dead. Tearing every link down for it would cut the node off from its peers.
            let failed = match self.send[q].as_mut() {
                Some(channel) => match channel.send(bytes) {
                    Ok(()) | Err(qtv_net::Error::MessageTooLarge) => false,
                    Err(_) => true,
                },
                None => false,
            };
            if failed {
                // Drop the transport and ask for it to be redialled. `up` is left
                // alone on purpose: it is the reveal barrier's membership, shared
                // across nodes, and shrinking it from one node's failed write is a
                // consensus divergence, not a bookkeeping tidy up.
                self.send[q] = None;
                let _ = self.down.try_send(q);
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
    use super::{
        message_height, queue_verify, FrameBuffer, VerifyJob, MAX_BUFFERED_BYTES,
        MAX_BUFFERED_FRAMES,
    };
    use qtv_devnet::wire::Message;

    #[test]
    fn a_full_verify_pool_refuses_rather_than_verifying_on_the_consensus_thread() {
        let account = qtv_account::derive(&[7u8; qtv_account::MASTER_SEED_LEN], 0);
        let body = qtv_tx::Body::new(
            account.address(),
            0,
            1_000,
            1,
            qtv_tx::Call::new(account.address(), Vec::new()),
        );
        let wrapper = qtv_tx::sign(&account, &body);
        let job = |reply| VerifyJob {
            tx_id: wrapper.id(),
            wrapper: wrapper.clone(),
            ledger: std::sync::Arc::new(qtv_node::ledger::Ledger::new()),
            fee_params: qtv_node::fee::FeeParams::devnet(),
            reply,
        };
        let (jobs, _held) = std::sync::mpsc::sync_channel::<VerifyJob>(1);
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        queue_verify(&jobs, job(first_tx));
        assert!(first_rx.try_recv().is_err(), "a free slot takes the job");
        let (second_tx, second_rx) = std::sync::mpsc::channel();
        queue_verify(&jobs, job(second_tx));
        let reply = second_rx.try_recv().expect("the refusal is immediate");
        assert!(reply.is_ok(), "a busy reply, not a transport error");
    }

    // A node that has fallen behind only ever sees sync traffic if it is exempt from the
    // height gate. Gating it would park the reply for a height the node cannot reach.
    #[test]
    fn sync_messages_are_never_height_gated() {
        assert_eq!(
            message_height(&Message::GetBlocks { from: 1, to: 64 }),
            None
        );
        assert_eq!(message_height(&Message::Blocks(Vec::new())), None);
    }

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
        for _ in 0..(MAX_BUFFERED_FRAMES * 4) {
            buffer.push(0, vec![7u8; 32]);
            within_ceilings(&buffer);
        }
        assert_eq!(buffer.len(), MAX_BUFFERED_FRAMES);
    }

    #[test]
    fn a_flood_of_large_ahead_frames_stays_within_the_byte_ceiling() {
        let mut buffer = FrameBuffer::default();
        let frame = vec![3u8; 1024 * 1024];
        for _ in 0..((MAX_BUFFERED_BYTES / frame.len()) * 4) {
            buffer.push(0, frame.clone());
            within_ceilings(&buffer);
        }
        assert!(buffer.len() < MAX_BUFFERED_FRAMES);
        assert!(buffer.byte_len() + frame.len() > MAX_BUFFERED_BYTES);
    }

    #[test]
    fn mixed_frame_sizes_cannot_bypass_either_ceiling() {
        let mut buffer = FrameBuffer::default();
        for round in 0..5000 {
            buffer.push(0, vec![1u8; 16]);
            within_ceilings(&buffer);
            buffer.push(0, vec![2u8; 200 * 1024]);
            within_ceilings(&buffer);
            if round % 1000 == 0 {
                buffer.push(0, vec![9u8; 900 * 1024]);
                within_ceilings(&buffer);
            }
        }
    }

    #[test]
    fn the_count_ceiling_holds_exactly_at_and_over_the_boundary() {
        let mut buffer = FrameBuffer::default();
        for _ in 0..MAX_BUFFERED_FRAMES {
            buffer.push(0, vec![0u8; 8]);
        }
        assert_eq!(
            buffer.len(),
            MAX_BUFFERED_FRAMES,
            "the buffer fills to the ceiling"
        );
        buffer.push(0, vec![0u8; 8]);
        assert_eq!(
            buffer.len(),
            MAX_BUFFERED_FRAMES,
            "the ceiling holds one frame over"
        );
        within_ceilings(&buffer);
    }

    #[test]
    fn an_oversized_single_frame_is_refused_and_leaves_the_buffer_intact() {
        let mut buffer = FrameBuffer::default();
        buffer.push(0, vec![5u8; 4096]);
        let before_frames = buffer.len();
        let before_bytes = buffer.byte_len();
        buffer.push(0, vec![6u8; MAX_BUFFERED_BYTES + 1]);
        assert_eq!(
            buffer.len(),
            before_frames,
            "the oversized frame was not stored"
        );
        assert_eq!(
            buffer.byte_len(),
            before_bytes,
            "no bytes were charged for it"
        );
        within_ceilings(&buffer);
    }

    #[test]
    fn eviction_keeps_the_freshest_frames() {
        let mut buffer = FrameBuffer::default();
        let total = MAX_BUFFERED_FRAMES + 100;
        for tag in 0..total as u64 {
            let mut frame = tag.to_le_bytes().to_vec();
            frame.resize(64, 0);
            buffer.push(0, frame);
        }
        let held = buffer.take();
        assert_eq!(held.len(), MAX_BUFFERED_FRAMES);
        let first_tag = u64::from_le_bytes(held.front().unwrap().1[..8].try_into().unwrap());
        let last_tag = u64::from_le_bytes(held.back().unwrap().1[..8].try_into().unwrap());
        assert_eq!(first_tag, (total - MAX_BUFFERED_FRAMES) as u64);
        assert_eq!(last_tag, (total - 1) as u64);
    }

    #[test]
    fn a_front_loaded_flood_does_not_collapse_a_buffered_proposal_onto_a_shared_source() {
        let mut buffer = FrameBuffer::default();
        let attacker: u64 = 1;
        let leader: u64 = 2;
        for i in 0..16u8 {
            buffer.push(attacker, vec![i; 8]);
        }
        buffer.push(leader, vec![0x9f; 64]);
        let held = buffer.take();
        assert!(
            held.iter().filter(|(s, _)| *s == attacker).count() >= 8,
            "the attacker frames keep the attacker source"
        );
        let genuine = held
            .iter()
            .find(|(_, frame)| frame.len() == 64)
            .expect("the genuine buffered frame survives the front loaded flood");
        assert_eq!(
            genuine.0, leader,
            "the genuine frame replays under the leader source not a shared bucket"
        );
        assert_ne!(
            genuine.0,
            u64::MAX,
            "the genuine frame is not collapsed onto the global source"
        );
    }

    #[test]
    fn take_empties_the_buffer_and_resets_the_byte_count() {
        let mut buffer = FrameBuffer::default();
        for _ in 0..64 {
            buffer.push(0, vec![4u8; 1000]);
        }
        assert!(buffer.byte_len() > 0);
        let held = buffer.take();
        assert_eq!(held.len(), 64);
        assert_eq!(buffer.len(), 0, "the buffer is empty after a drain");
        assert_eq!(buffer.byte_len(), 0, "the byte count resets on a drain");
    }
}

#[cfg(test)]
mod ingress_fairness_tests {
    use super::{FrameBuffer, MAX_BUFFERED_FRAMES};

    #[test]
    fn a_flooding_peer_cannot_evict_every_other_peers_frames() {
        let mut buf = FrameBuffer::default();
        for _ in 0..16 {
            buf.push(1, vec![0u8; 64]);
        }
        for _ in 0..(MAX_BUFFERED_FRAMES * 2) {
            buf.push(99, vec![0u8; 64]);
        }
        let honest = buf.frames.iter().filter(|(s, _)| *s == 1).count();
        assert!(
            honest > 0,
            "a peer flooding the ingress must not be able to evict every frame an honest peer buffered"
        );
    }

    #[test]
    fn the_buffer_stays_within_its_frame_bound() {
        let mut buf = FrameBuffer::default();
        for i in 0..(MAX_BUFFERED_FRAMES + 500) {
            buf.push((i % 7) as u64, vec![0u8; 32]);
        }
        assert!(buf.frames.len() <= MAX_BUFFERED_FRAMES);
    }
}
