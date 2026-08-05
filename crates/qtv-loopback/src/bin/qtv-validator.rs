// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::io::{BufRead, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use qtv_devnet::coded::{code_proposal, ProposalAssembler};
use qtv_devnet::node::{node_identity, node_peer_id};
use qtv_devnet::wire::Message;
use qtv_devnet::{leader_for, DevNode};
use qtv_net::{Channel, Identity};

use qtv_loopback::{
    accounts, build_batch, chain_digest, devnet_config, hex, message_height, recipients,
    transfer_fee,
};

const STALL_SECS: u64 = 30;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
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

struct Runtime {
    idx: usize,
    n: usize,
    node: DevNode,
    send: Vec<Option<Channel<TcpStream>>>,
    inbound: Receiver<(usize, Vec<u8>)>,
    assembler: ProposalAssembler,
    buffered: Vec<(usize, Vec<u8>)>,
    senders_n: usize,
}

enum HeightOutcome {
    Final { elapsed: Duration, txs: usize },
    Stalled,
}

impl Runtime {
    fn broadcast(&mut self, bytes: &[u8], exclude: Option<usize>) {
        for q in 0..self.n {
            if q == self.idx || Some(q) == exclude {
                continue;
            }
            if let Some(channel) = self.send[q].as_mut() {
                let _ = channel.send(bytes);
            }
        }
    }

    fn emit(&mut self, message: Message) {
        match message {
            Message::Proposal(proposal) => match code_proposal(&proposal) {
                Ok(shards) => {
                    for shard in shards {
                        let bytes = Message::CodedProposal(Box::new(shard)).encode();
                        self.broadcast(&bytes, None);
                    }
                }
                Err(_) => {}
            },
            other => {
                let bytes = other.encode();
                self.broadcast(&bytes, None);
            }
        }
    }

    fn dispatch(
        &mut self,
        from: usize,
        message: Message,
        selection: &qtv_node::consensus::Selection,
        online: &[u64],
    ) {
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
                for message in self.node.on_prevote(selection, *prevote) {
                    self.emit(message);
                }
            }
            Message::Attest(attestation) => self.node.on_attestation(*attestation),
            Message::ViewChange(record) => self.node.collect_view_change(selection, *record),
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
        let _ = self.settle(selection, online);
        let _ = from;
    }

    fn settle(
        &mut self,
        selection: &qtv_node::consensus::Selection,
        online: &[u64],
    ) -> Result<bool, String> {
        if !self.node.has_attestations_from(online) {
            return Ok(false);
        }
        self.node
            .try_finalize(selection)
            .map_err(|e| format!("finalize failed: {e:?}"))
    }

    /// At an epoch boundary publish this node's signed re registration of its rotated one
    /// time root, gather the peers' re registrations, and re form the committee. A no op in
    /// the genesis epoch.
    fn disseminate_registrations(&mut self) {
        if self.node.epoch() == 0 {
            return;
        }
        if let Some(note) = self.node.own_registration_note() {
            let bytes = Message::Register(Box::new(note)).encode();
            self.broadcast(&bytes, None);
        }
        let expected: Vec<u64> = (1..=self.n as u64).filter(|&id| id != self.node.id()).collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let have = self.node.collected_registration_ids();
            if expected.iter().all(|id| have.contains(id)) {
                break;
            }
            match self.inbound.recv_timeout(Duration::from_millis(10)) {
                Ok((from, bytes)) => {
                    if let Ok(Message::Register(note)) = Message::decode(&bytes) {
                        self.node.collect_registration(*note);
                    } else {
                        buffer_bounded(&mut self.buffered, from, bytes);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self.node.apply_registrations();
    }

    /// Publish this node's own reveal for the height and gather the peers' reveals.
    fn disseminate_reveals(&mut self) {
        if let Some(note) = self.node.own_reveal_note() {
            let bytes = Message::Reveal(Box::new(note)).encode();
            self.broadcast(&bytes, None);
        }
        let expected: Vec<u64> = (1..=self.n as u64).collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let have = self.node.collected_reveal_ids();
            if expected.iter().all(|id| have.contains(id)) {
                break;
            }
            match self.inbound.recv_timeout(Duration::from_millis(10)) {
                Ok((from, bytes)) => {
                    if let Ok(Message::Reveal(note)) = Message::decode(&bytes) {
                        self.node.collect_reveal(*note);
                    } else {
                        buffer_bounded(&mut self.buffered, from, bytes);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn drive_height(&mut self, batch: Option<Vec<qtv_tx::Wrapper>>) -> Result<HeightOutcome, String> {
        let start_height = self.node.height();
        self.disseminate_registrations();
        self.disseminate_reveals();
        let selection = self.node.select().map_err(|e| format!("select: {e:?}"))?;
        let online: Vec<u64> = selection.members.clone();
        let i_lead = leader_for(&selection, self.node.view()) == self.node.id();

        let start = Instant::now();

        let ready: Vec<(usize, Vec<u8>)> = std::mem::take(&mut self.buffered)
            .into_iter()
            .filter(|(_, bytes)| match Message::decode(bytes) {
                Ok(m) => message_height(&m) == Some(start_height),
                Err(_) => false,
            })
            .collect();
        for (from, bytes) in ready {
            if let Ok(message) = Message::decode(&bytes) {
                self.dispatch(from, message, &selection, &online);
            }
        }

        if let Some(batch) = batch {
            for transaction in batch {
                let _ = self.node.submit(transaction.clone());
                let bytes = Message::Tx(transaction).encode();
                self.broadcast(&bytes, None);
            }
        }

        let mut entered = false;
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
                });
            }
            if !entered && (!i_lead || self.node.mempool_len() >= self.senders_n) {
                let messages = self.node.enter_round(&selection, true);
                for message in messages {
                    self.emit(message);
                }
                let _ = self.settle(&selection, &online)?;
                entered = true;
            }

            let remaining = STALL_SECS
                .checked_sub(start.elapsed().as_secs())
                .unwrap_or(0);
            if remaining == 0 {
                return Ok(HeightOutcome::Stalled);
            }
            match self.inbound.recv_timeout(Duration::from_millis(200)) {
                Ok((from, bytes)) => {
                    let message = match Message::decode(&bytes) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    match message_height(&message) {
                        Some(h) if h > start_height => buffer_bounded(&mut self.buffered, from, bytes),
                        Some(h) if h < start_height => {}
                        _ => self.dispatch(from, message, &selection, &online),
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("a peer process closed its socket".to_string())
                }
            }
        }
    }
}

fn build_mesh(
    listener: TcpListener,
    ports: &[u16],
    idx: usize,
    n: usize,
    identity: &Identity,
) -> (Vec<Option<Channel<TcpStream>>>, Receiver<(usize, Vec<u8>)>) {
    let (inbound_tx, inbound_rx) = mpsc::channel::<(usize, Vec<u8>)>();
    let (accepted_tx, accepted_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();

    let identity_acc = identity.clone();
    let acceptor = thread::spawn(move || {
        for _ in 0..(n - 1) {
            let (stream, _) = listener.accept().expect("accept an inbound peer connection");
            let channel = Channel::accept(stream, &identity_acc).expect("responder handshake");
            let peer = channel.peer_id().clone();
            let from = (0..n)
                .find(|&q| q != idx && node_peer_id(q as u64 + 1) == peer)
                .expect("the inbound peer is a known validator");
            accepted_tx
                .send((from, channel))
                .expect("hand the accepted channel to the main thread");
        }
    });

    let mut send: Vec<Option<Channel<TcpStream>>> = (0..n).map(|_| None).collect();
    for q in 0..n {
        if q == idx {
            continue;
        }
        let addr = format!("127.0.0.1:{}", ports[q]);
        let stream = loop {
            match TcpStream::connect(&addr) {
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

    for _ in 0..(n - 1) {
        let (from, mut channel) = accepted_rx.recv().expect("an accepted inbound channel");
        let out = inbound_tx.clone();
        thread::spawn(move || loop {
            match channel.recv() {
                Ok(bytes) => {
                    if out.send((from, bytes)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        });
    }
    drop(inbound_tx);
    (send, inbound_rx)
}

fn main() {
    let idx: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .expect("the validator index is the first argument");
    let n = env_usize("QTV_MP_VALIDATORS", 4).max(1);
    let senders_n = env_usize("QTV_MP_ACCOUNTS", 250).max(2);
    let run_secs = env_usize("QTV_MP_SECS", 60).max(1) as f64;
    let warmup = env_usize("QTV_MP_WARMUP", 2);
    let height_cap = env_usize("QTV_MP_HEIGHTCAP", (qtv_loopback::HARNESS_SLOTS as usize) - 64);
    let base = std::env::var("QTV_MP_BASE").expect("the store base directory");
    let base = std::path::PathBuf::from(base);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
    let port = listener.local_addr().expect("listener address").port();
    println!("PORT {port}");
    std::io::stdout().flush().expect("flush the port line");

    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .expect("read the peer port line");
    let ports: Vec<u16> = line
        .trim()
        .strip_prefix("PEERS ")
        .expect("the peer line is PEERS <csv>")
        .split(',')
        .map(|p| p.parse().expect("a peer port"))
        .collect();
    assert_eq!(ports.len(), n, "one port per validator");

    let identity = node_identity(idx as u64 + 1);
    let senders = accounts(senders_n);
    let recipient_addrs = recipients(&senders);
    let config = devnet_config(&base, n, &senders);
    let node = DevNode::open(&config.nodes[idx], &config).expect("open the validator");

    eprintln!("[validator {idx}] standing up the qtv-net TCP mesh over {n} processes ...");
    let (send, inbound) = build_mesh(listener, &ports, idx, n, &identity);
    eprintln!("[validator {idx}] mesh up, driving the round ...");

    let mut rt = Runtime {
        idx,
        n,
        node,
        send,
        inbound,
        assembler: ProposalAssembler::new(),
        buffered: Vec::new(),
        senders_n,
    };

    let fee = transfer_fee();
    let mut nonces = vec![0u64; senders_n];

    for _ in 0..warmup {
        let batch = if idx == 0 {
            Some(build_batch(&senders, &recipient_addrs, &mut nonces, fee).0)
        } else {
            None
        };
        match rt.drive_height(batch).expect("a warmup height drives") {
            HeightOutcome::Final { .. } => {}
            HeightOutcome::Stalled => {
                println!(
                    "RESULT idx={idx} heights=0 finalized_tx=0 consensus_ms=0 sign_ms=0 \
                     committee=0 chainhash= stall=1 perblock="
                );
                return;
            }
        }
    }

    let committee = rt
        .node
        .chain()
        .last()
        .map(|b| b.attesters.len())
        .unwrap_or(0);

    let mut per_block_ms: Vec<f64> = Vec::new();
    let mut finalized_tx: u64 = 0;
    let mut consensus_wall = Duration::ZERO;
    let mut sign_wall = Duration::ZERO;
    let mut heights: u64 = 0;
    let mut stalled = false;

    while consensus_wall.as_secs_f64() < run_secs && (heights as usize) < height_cap {
        let (batch, sign_dt) = if idx == 0 {
            let (batch, dt) = build_batch(&senders, &recipient_addrs, &mut nonces, fee);
            (Some(batch), dt)
        } else {
            (None, Duration::ZERO)
        };
        match rt.drive_height(batch) {
            Ok(HeightOutcome::Final { elapsed, txs }) if txs > 0 => {
                sign_wall += sign_dt;
                consensus_wall += elapsed;
                per_block_ms.push(elapsed.as_secs_f64() * 1000.0);
                finalized_tx += txs as u64;
                heights += 1;
            }
            _ => {
                stalled = true;
                break;
            }
        }
    }

    let encoded: Vec<Vec<u8>> = rt.node.chain().iter().map(|b| b.encoded()).collect();
    let digest = chain_digest(&encoded);
    let blockhashes = encoded
        .iter()
        .map(|b| hex(&qtv_devnet::wire::gossip_id(b)))
        .collect::<Vec<_>>()
        .join(",");
    let perblock = per_block_ms
        .iter()
        .map(|ms| format!("{ms:.3}"))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "RESULT idx={idx} heights={heights} finalized_tx={finalized_tx} \
         consensus_ms={:.3} sign_ms={:.3} committee={committee} chainhash={} stall={} \
         perblock={perblock} blockhashes={blockhashes}",
        consensus_wall.as_secs_f64() * 1000.0,
        sign_wall.as_secs_f64() * 1000.0,
        hex(&digest),
        stalled as u8,
    );
    std::io::stdout().flush().expect("flush the result line");
}
