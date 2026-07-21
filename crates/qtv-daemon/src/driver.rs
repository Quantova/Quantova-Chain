
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

pub struct Driver {
    node: DevNode,
    idx: usize,
    n: usize,
    send: Vec<Option<Channel<TcpStream>>>,
    inbound: Receiver<(usize, Vec<u8>)>,
    up: Vec<bool>,
    assembler: ProposalAssembler,
    buffered: Vec<Vec<u8>>,
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
            buffered: Vec::new(),
            budget: u64::MAX,
            rpc_context: None,
            rpc_requests: None,
        }
    }

    pub fn set_budget(&mut self, budget: u64) {
        self.budget = budget;
    }

    pub fn attach_rpc(&mut self, context: NodeContext, requests: Receiver<GatewayCall>) {
        self.rpc_context = Some(context);
        self.rpc_requests = Some(requests);
    }

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

        self.replay_buffered(start_height, &selection);

        loop {
            if stopped.load(Ordering::SeqCst) {
                return Ok(());
            }
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
            if let Some(attestation) = self.node.attest_staged() {
                self.emit(Message::Attest(Box::new(attestation)));
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
