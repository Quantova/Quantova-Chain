//! The continuous production round driver.
//!
//! This is the devnet node's round, driven the way a live chain drives it rather
//! than the way the measurement harness does. The harness runs a fixed number of
//! heights, splits each into an untimed fill and a timed consensus region, times
//! every phase, and treats a stall as the end of the run. None of that belongs in a
//! daemon. The daemon runs heights forever, admits transactions continuously as they
//! gossip in, proposes on a wall clock cadence rather than waiting for a full
//! mempool, and treats a slow or dropped leader as a view change to recover from
//! rather than a stop. The one node core, DevNode, is unchanged and unforked; only
//! the loop over it is production shaped.
//!
//! The round primitives are the same ones the harness calls, so the finalised chain
//! is the same chain the devnet finalises. Entering a view offers or re-offers the
//! leader's proposal and attests any staged block, a proposal drives verification and
//! attestation, an attestation aggregates toward the certificate, a view change
//! record routes around a leader that did not propose in time, and a height finalises
//! once every online committee member has attested the staged block. A committee of
//! one is its own online set and its own supermajority, so a single validator
//! proposes, attests, and finalises alone, which is what makes one quantovad a live
//! chain rather than a process waiting for a second box.

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

/// The pacing tick, the wall clock a loop iteration blocks on a peer record before it
/// checks the clock again. Short enough that the block cadence and the view timeout
/// are honoured to within a tick, long enough not to spin.
const TICK: Duration = Duration::from_millis(20);

/// The per node production round driver: the one validator, the outbound sealed
/// channels to each peer, the inbound record queue the reader threads feed, the
/// erasure coded proposal reassembly, and the buffer of records that arrived ahead of
/// the height the node is on.
pub struct Driver {
    node: DevNode,
    idx: usize,
    n: usize,
    send: Vec<Option<Channel<TcpStream>>>,
    inbound: Receiver<(usize, Vec<u8>)>,
    up: Vec<bool>,
    assembler: ProposalAssembler,
    buffered: Vec<Vec<u8>>,
    /// The one time sortition slot budget from the genesis. A height at or past this
    /// count has no committed slot, and the sampler asserts rather than returns none, so
    /// the driver stops one height short of the budget and halts cleanly rather than let
    /// that assert panic the node. u64::MAX means no budget was set.
    budget: u64,
    /// The RPC seam, present when the daemon was configured with a gateway. The static
    /// context node info reports, and the queue of client requests the gateway threads
    /// feed. The round loop drains this between round steps and answers each against the
    /// node, so the gateway never touches the node's state itself.
    rpc_context: Option<NodeContext>,
    rpc_requests: Option<Receiver<GatewayCall>>,
}

impl Driver {
    /// Build the driver over an opened node and its standing mesh.
    pub fn new(node: DevNode, idx: usize, mesh: Mesh) -> Driver {
        Driver {
            node,
            idx,
            n: mesh.up.len(),
            send: mesh.send,
            inbound: mesh.inbound,
            up: mesh.up,
            assembler: ProposalAssembler::new(),
            buffered: Vec::new(),
            budget: u64::MAX,
            rpc_context: None,
            rpc_requests: None,
        }
    }

    /// Set the one time slot budget the genesis committed, the number of heights the
    /// sortition can serve before its keys are spent. The driver halts cleanly one height
    /// short of this rather than let the sampler assert past its committed count.
    pub fn set_budget(&mut self, budget: u64) {
        self.budget = budget;
    }

    /// Attach the RPC seam, the node info context and the queue of client requests the
    /// gateway feeds. Once attached, the round loop serves these between round steps.
    pub fn attach_rpc(&mut self, context: NodeContext, requests: Receiver<GatewayCall>) {
        self.rpc_context = Some(context);
        self.rpc_requests = Some(requests);
    }

    /// Drain and answer every gateway request waiting in the queue, each against the
    /// node. This is called at each tick of the round loop, so a client request is
    /// answered within a tick, and it never blocks, so an idle queue costs nothing.
    fn serve_rpc(&mut self) {
        let Some(requests) = self.rpc_requests.as_ref() else {
            return;
        };
        let calls: Vec<GatewayCall> = std::iter::from_fn(|| requests.try_recv().ok()).collect();
        let Some(context) = self.rpc_context.as_ref() else {
            return;
        };
        for call in calls {
            let result = qtv_gateway::handle(context, &mut self.node, call.request);
            let _ = call.reply.send(result);
        }
    }

    /// Run the round until the stop flag is set or the slot budget is reached. Each
    /// iteration drives one height to finality; the loop then advances to the next. The
    /// budget is reached one height short of the committed slot count, so the sampler is
    /// never asked for a slot it does not serve, and the daemon halts cleanly with a
    /// message rather than panicking on the assert past the count.
    pub fn run(
        &mut self,
        block_interval: Duration,
        view_timeout: Duration,
        stopped: &AtomicBool,
    ) -> Result<(), String> {
        while !stopped.load(Ordering::SeqCst) {
            if self.node.height() >= self.budget {
                log(&format!(
                    "reached the one time slot budget at height {}, halting cleanly. The \
                     sortition keys are spent; a larger budget in the genesis, or the epoch \
                     and key rotation mechanism, is needed to run further",
                    self.budget.saturating_sub(1)
                ));
                return Ok(());
            }
            self.drive_one_height(block_interval, view_timeout, stopped)?;
        }
        Ok(())
    }

    /// Drive one height to finality or until the stop flag is set. A leader proposes
    /// once the block interval has elapsed, carrying whatever the mempool holds; a non
    /// leader enters at once and waits for the proposal. A view that runs out of wall
    /// clock without finalising announces a view change and rotates the leader.
    fn drive_one_height(
        &mut self,
        block_interval: Duration,
        view_timeout: Duration,
        stopped: &AtomicBool,
    ) -> Result<(), String> {
        let start_height = self.node.height();
        let selection = self.node.select().map_err(|e| {
            format!(
                "cannot select a committee at height {start_height}: {e:?}. the one time \
                 sortition slot budget is spent, so no further height can finalise. running \
                 past the budget needs an epoch or key rotation mechanism in the consensus, \
                 which is a named open item and not something the daemon papers over"
            )
        })?;

        let height_start = Instant::now();
        let mut entered_view: Option<u64> = None;
        let mut view_deadline = Instant::now() + view_timeout;

        // Replay any record that arrived while the node was on an earlier height and
        // named this one, so a peer racing a height ahead over the sockets is not lost.
        self.replay_buffered(start_height, &selection);

        loop {
            if stopped.load(Ordering::SeqCst) {
                return Ok(());
            }
            // Answer any client requests waiting at the gateway before the round step, so
            // a read or a submission is served within a tick of arriving.
            self.serve_rpc();
            if self.node.height() > start_height {
                self.log_finalized();
                return Ok(());
            }

            let view = self.node.view();
            let leads = leader_for(&selection, view) == self.node.id();
            // A view zero leader waits for the block cadence before it proposes, so an
            // idle chain still advances with empty blocks and a busy one carries what
            // the mempool holds. A non leader and any later view enter at once, since
            // the block arrives on the proposal or the justification.
            let interval_elapsed = height_start.elapsed() >= block_interval;
            let ready =
                entered_view != Some(view) && (!(view == 0 && leads) || interval_elapsed);
            if ready {
                self.enter_current_view(&selection, view);
                entered_view = Some(view);
                view_deadline = Instant::now() + view_timeout;
            }

            // The view ran out of wall clock without finalising. Announce the move to
            // the next view and rotate the leader, the recovery a live chain does
            // rather than the stall the harness reports.
            if entered_view == Some(view) && Instant::now() >= view_deadline {
                self.on_view_timeout(&selection);
                view_deadline = Instant::now() + view_timeout;
            }

            match self.inbound.recv_timeout(TICK) {
                Ok((_, bytes)) => self.handle_incoming(bytes, start_height, &selection),
                Err(RecvTimeoutError::Timeout) => {}
                // No peer reader is live, which is the single node case where the mesh
                // has no peers at all. This is not a stall: pace on the timer so the
                // sole leader still proposes on its cadence and finalises alone.
                Err(RecvTimeoutError::Disconnected) => thread::sleep(TICK),
            }
        }
    }

    /// Enter the current view. An online leader offers or re-offers its proposal and
    /// every node with a staged block re-offers its attestation. Past view zero the
    /// node announces its move with a view change record before the leader's justified
    /// proposal can form.
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

    /// The view timeout fired. Announce the move to the next view with a view change
    /// record and advance only once a blocking set of such records shows the network
    /// genuinely moved on, never on this local timer alone, the standard Byzantine
    /// view synchronisation. So a stray timer on a merely late proposal emits one
    /// harmless record, while a genuinely dropped leader draws the whole committee
    /// together.
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

    /// Let the leader of a later view offer its justified proposal once it holds a
    /// quorum of view change records, staging and attesting the block it selects.
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
            if let Some(attestation) = self.node.attest_staged() {
                self.emit(Message::Attest(Box::new(attestation)));
            }
        }
    }

    /// Dispatch one decoded record for the current height into the node, then settle.
    /// A gossiped transaction is admitted, a coded proposal shard feeds the reassembler
    /// and drives the proposal path once enough shards rebuild the block, and an
    /// attestation and a view change record drive their handlers. Every path
    /// re-broadcasts only what the node itself produces.
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
            Message::Peers(_)
            | Message::Status(_)
            | Message::GetBlocks { .. }
            | Message::Blocks(_) => {}
        }
        self.settle(selection);
    }

    /// Try to finalise the staged block once every online committee member has attested
    /// it. The online set is the committee members whose host this node holds up, so a
    /// committee of one is its own online set and finalises on its own attestation.
    fn settle(&mut self, selection: &Selection) {
        let online = self.online(selection);
        if !self.node.has_attestations_from(&online) {
            return;
        }
        let _ = self.node.try_finalize(selection);
    }

    /// Sort an inbound record by the height it names. A record for a later height is
    /// buffered until the node reaches it, a stale record is dropped, and a record for
    /// this height or a heightless transaction is dispatched at once.
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

    /// Replay the records buffered for this height, keeping any that name a still later
    /// height for when the node reaches it.
    fn replay_buffered(&mut self, start_height: u64, selection: &Selection) {
        let buffered = std::mem::take(&mut self.buffered);
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

    /// The online committee members from this node's view, the members whose host it
    /// holds up. The certificate aggregates over exactly this set, so the up hosts
    /// finalise the byte identical block.
    fn online(&self, selection: &Selection) -> Vec<u64> {
        selection
            .members
            .iter()
            .copied()
            .filter(|&id| self.up.get((id - 1) as usize).copied().unwrap_or(false))
            .collect()
    }

    /// Emit a record the node produced onto the mesh. A proposal disseminates as its
    /// erasure coded shards, each a sealed record within the transport bound; every
    /// other record goes whole.
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

    /// Send one sealed record to every up peer but this node. A single node network
    /// has no peers, so this is a no op and the node still finalises alone.
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

    /// Log the height that just finalised, its transaction count, its committed state
    /// root, and its block id, so an operator watching the process sees the chain
    /// advance and can compare the state root across a restart.
    fn log_finalized(&self) {
        let height = self.node.height().saturating_sub(1);
        let root = hex(&self.node.ledger().state_root());
        let (txs, id) = self
            .node
            .chain()
            .last()
            .map(|block| (block.block.body().len(), block.id()))
            .unwrap_or((0, String::new()));
        log(&format!(
            "finalised height {height} txs {txs} state_root {root} block {id}"
        ));
    }
}

/// The height a wire record names, or None for a transaction and the peer records
/// that belong to no single height. The driver uses this to buffer a record that
/// arrived ahead of the height the node is on rather than dropping it.
fn message_height(message: &Message) -> Option<u64> {
    match message {
        Message::Proposal(p) => Some(p.header.height()),
        Message::CodedProposal(c) => Some(c.header.height()),
        Message::Attest(a) => Some(a.height),
        Message::ViewChange(v) => Some(v.height),
        Message::Tx(_)
        | Message::Peers(_)
        | Message::Status(_)
        | Message::GetBlocks { .. }
        | Message::Blocks(_) => None,
    }
}
