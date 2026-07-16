//! One validator of the loopback multi process run, in its own operating system
//! process.
//!
//! This process holds exactly one real validator: its own module lattice key, its
//! own state and store, and its own share of the round. It does NOT hold the other
//! validators and it does NOT step them; each of the others runs in its own process
//! on this same host. The processes talk to one another over REAL localhost TCP
//! sockets through the REAL qtv-net post quantum channel, an ML-KEM and ML-DSA
//! handshake with a ChaCha20-Poly1305 record layer, one sealed record stream per
//! direction per pair. So the committee's compute runs in parallel across processes
//! rather than serially in one, which is the single variable this run isolates
//! against the in process serial baseline.
//!
//! WHAT IS REAL HERE. The validator is a real qtv-devnet DevNode, reusing the exact
//! chain and consensus crates the in process baseline uses, not a reimplementation.
//! The committee is the real qtv-sampler one time key sortition of consensus v0.5.0
//! with the stake floor on. Blocks are built by the real leader, executed through the
//! real virtual machine to a real state root, attested with real module lattice
//! signatures over the real one time membership credential, and finalised by a real
//! aggregated certificate every process verifies. The proposal is disseminated as its
//! real erasure coded shards under a SHA3 commitment and rebuilt from any k. Every
//! transaction carries a real 3309 byte module lattice signature and is verified on
//! ingress. Every gossip byte crosses a real qtv-net socket sealed and opened, not an
//! in memory duplex.
//!
//! WHAT THE SOCKETS ARE, STATED PLAINLY. The sockets are localhost TCP. The qtv-net
//! channel is the real post quantum secure channel, but it is NOT the full QUIC
//! transport: qtv-net runs its ordered record stream over a reliable byte stream, and
//! its own notes name the UDP datagram layer, multiplexed streams, congestion
//! control, and loss recovery as not yet built. So this is the real post quantum
//! channel over a real localhost TCP socket, with near zero propagation. It measures
//! parallel per process compute plus the loopback socket cost; it does not measure
//! geographic propagation and is not a network throughput or a real global finality.
//!
//! THE ASYNCHRONY THE PROCESSES ADD. The in process baseline drives one logical clock
//! and owns both ends of every channel, so it never sees a peer race a height ahead.
//! Here each process runs its own wall clock round loop and blocks on real socket
//! reads, so a faster process can finalise a height and start the next before a slower
//! one has caught up. A message that names a height ahead of the one this process is
//! on is buffered and replayed when this process reaches that height, rather than
//! dropped, so the real socket asynchrony does not stall the round. Finality itself is
//! unchanged: a node finalises only once every online committee member has attested
//! its staged block, and the certificate sorts its attestations by signer, so every
//! process aggregates the byte identical certificate and the finalised chains are byte
//! identical across processes and against the in process baseline.

use std::io::{BufRead, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use qtv_devnet::coded::{code_proposal, ProposalAssembler};
use qtv_devnet::node::net_identity;
use qtv_devnet::wire::Message;
use qtv_devnet::{leader_for, DevNode};
use qtv_net::{Channel, Identity};

use qtv_loopback::{
    accounts, build_batch, chain_digest, devnet_config, hex, message_height, recipients,
    transfer_fee,
};

/// The wall clock a single height is given to finalise before the run calls it a
/// stall. On the loopback happy path a height finalises in well under a second, so a
/// height that runs past this bound has not finalised for a real reason, and the run
/// reports the stall rather than hanging. This is a run guard, not a consensus
/// timeout; the consensus view timeout is a separate mechanism inside the DevNode.
const STALL_SECS: u64 = 30;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The per process runtime: the one validator, the outbound sealed channels to each
/// peer, the inbound record queue the reader threads feed, the erasure coded proposal
/// reassembly buffer, and the buffer of messages that arrived ahead of this process's
/// height.
struct Runtime {
    idx: usize,
    n: usize,
    node: DevNode,
    /// The outbound sealed channel to each peer, `None` for this process's own slot.
    /// Only the main thread sends, so the channel is not shared.
    send: Vec<Option<Channel<TcpStream>>>,
    /// Inbound sealed records, `(from index, plaintext)`, fed by one reader thread per
    /// peer that blocks on its channel's real socket read.
    inbound: Receiver<(usize, Vec<u8>)>,
    assembler: ProposalAssembler,
    /// Messages that named a height ahead of this process's current height, kept to
    /// replay when this process reaches that height rather than dropped.
    buffered: Vec<(usize, Vec<u8>)>,
    senders_n: usize,
}

/// A single driven height's outcome for the ingress process's measurement.
enum HeightOutcome {
    /// The height finalised: the wall clock it took and how many transactions the
    /// finalised block actually carried.
    Final { elapsed: Duration, txs: usize },
    /// The height did not finalise within the stall guard.
    Stalled,
}

impl Runtime {
    /// Send one sealed record to every peer but this process, and one named peer to
    /// exclude. In the full mesh every peer receives the originator's record directly,
    /// so there is no separate relay hop; this is the full fanout the in process
    /// baseline runs, where a relay would only re deliver a record every peer already
    /// holds.
    fn broadcast(&mut self, bytes: &[u8], exclude: Option<usize>) {
        for q in 0..self.n {
            if q == self.idx || Some(q) == exclude {
                continue;
            }
            if let Some(channel) = self.send[q].as_mut() {
                // A send failure means a peer process died; the run guard catches the
                // resulting stall, so drop the byte and let the height time out rather
                // than crash mid measurement.
                let _ = channel.send(bytes);
            }
        }
    }

    /// Emit a message the DevNode produced onto the overlay. A proposal disseminates
    /// as its real erasure coded shards, each its own sealed record within the
    /// transport bound; every other message goes whole.
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

    /// Dispatch one decoded message for the current height into the consensus layer,
    /// then try to settle. A coded proposal shard feeds the reassembler and, once k
    /// verified shards rebuild the block and it checks against the header, drives the
    /// DevNode's proposal path and gossips the attestation it returns; an attestation
    /// and a view change record drive their handlers. Every path re-broadcasts nothing
    /// beyond what the DevNode itself produces, and settles by the same rule the
    /// baseline uses.
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
            Message::Attest(attestation) => self.node.on_attestation(*attestation),
            Message::ViewChange(record) => self.node.collect_view_change(selection, *record),
            Message::Peers(_)
            | Message::Status(_)
            | Message::GetBlocks { .. }
            | Message::Blocks(_) => {}
        }
        let _ = self.settle(selection, online);
        let _ = from;
    }

    /// Try to finalise the staged block once every online committee member has
    /// attested it, exactly the baseline's settle rule. The certificate sorts its
    /// attestations by signer, so aggregating the same complete set yields the byte
    /// identical certificate on every process.
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

    /// Drive one height to finality. The ingress process (index zero) first floods the
    /// pre signed batch over the real sockets, so a transaction is admitted on the
    /// ingress path and gossiped to every peer exactly as the baseline floods it, and
    /// the timed region starts before that flood so it covers the same work the
    /// baseline's submit and step cover. A message that arrived ahead of this height is
    /// replayed first. The leader waits until it holds the whole batch before it
    /// proposes; a non leader attests the block the proposal carries without needing
    /// its own mempool.
    fn drive_height(&mut self, batch: Option<Vec<qtv_tx::Wrapper>>) -> Result<HeightOutcome, String> {
        let start_height = self.node.height();
        let selection = self.node.select().map_err(|e| format!("select: {e:?}"))?;
        let online: Vec<u64> = selection.members.clone();
        let i_lead = leader_for(&selection, self.node.view()) == self.node.id();

        let start = Instant::now();

        // Replay any messages that arrived while this process was on an earlier height
        // and named this one, so the real socket asynchrony does not lose them.
        let ready: Vec<(usize, Vec<u8>)> = std::mem::take(&mut self.buffered)
            .into_iter()
            .filter(|(_, bytes)| match Message::decode(bytes) {
                Ok(m) => message_height(&m) == Some(start_height),
                Err(_) => false,
            })
            .collect();
        // Keep the ones still ahead of this height for a later replay.
        for (from, bytes) in ready {
            if let Ok(message) = Message::decode(&bytes) {
                self.dispatch(from, message, &selection, &online);
            }
        }

        // The ingress process floods the batch, admitting it and gossiping it over the
        // real sockets, before anyone proposes.
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
            // Enter the round once ready: a non leader can enter at once, since it
            // attests the block the proposal carries; the leader waits until it holds
            // the whole batch so its block carries every transaction.
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
                        Some(h) if h > start_height => self.buffered.push((from, bytes)),
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

/// Establish the real qtv-net TCP mesh. Each pair holds two connections, one sealed
/// record stream per direction: this process initiates an outbound connection to each
/// peer that it sends on, and accepts an inbound connection from each peer that a
/// reader thread reads. Both connections run the real ML-KEM and ML-DSA pinned
/// handshake, so a peer that cannot prove its identity is refused, and the outbound
/// and inbound directions never share a channel so the reader thread and the main
/// thread never contend.
fn build_mesh(
    listener: TcpListener,
    ports: &[u16],
    idx: usize,
    n: usize,
    identity: &Identity,
) -> (Vec<Option<Channel<TcpStream>>>, Receiver<(usize, Vec<u8>)>) {
    let (inbound_tx, inbound_rx) = mpsc::channel::<(usize, Vec<u8>)>();
    let (accepted_tx, accepted_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();

    // Accept the inbound connection from each peer on its own thread, so accepting and
    // connecting proceed together and neither side deadlocks waiting on the other.
    let identity_acc = identity.clone();
    let acceptor = thread::spawn(move || {
        for _ in 0..(n - 1) {
            let (stream, _) = listener.accept().expect("accept an inbound peer connection");
            let channel = Channel::accept(stream, &identity_acc).expect("responder handshake");
            let peer = channel.peer_id().clone();
            let from = (0..n)
                .find(|&q| q != idx && net_identity(q as u64 + 1).peer_id() == peer)
                .expect("the inbound peer is a known validator");
            accepted_tx
                .send((from, channel))
                .expect("hand the accepted channel to the main thread");
        }
    });

    // Connect an outbound channel to each peer. The peer's listener was bound before it
    // printed its port, so the connection lands in its backlog even if its acceptor has
    // not run yet; a short retry covers the process still coming up.
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
        let peer = net_identity(q as u64 + 1).peer_id();
        let channel =
            Channel::connect_pinned(stream, identity, &peer).expect("initiator handshake");
        send[q] = Some(channel);
    }

    acceptor.join().expect("the acceptor thread joins");

    // Spawn one reader thread per inbound channel; each blocks on its real socket read
    // and feeds the plaintext into the single inbound queue tagged by the peer.
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
    // The process index is the one argument; everything else is read from the
    // environment the driver sets, identical to the baseline's parameters.
    let idx: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .expect("the validator index is the first argument");
    let n = env_usize("QTV_MP_VALIDATORS", 4).max(1);
    let senders_n = env_usize("QTV_MP_ACCOUNTS", 250).max(2);
    let run_secs = env_usize("QTV_MP_SECS", 60).max(1) as f64;
    let warmup = env_usize("QTV_MP_WARMUP", 2);
    // The harness sizes each validator tree to HARNESS_SLOTS, well above the consensus
    // default, so the cap no longer pins the run below the default. The default leaves
    // headroom below the harness slot count for the warmup heights, and the driver
    // passes the same value it uses so both stay in step.
    let height_cap = env_usize("QTV_MP_HEIGHTCAP", (qtv_loopback::HARNESS_SLOTS as usize) - 64);
    let base = std::env::var("QTV_MP_BASE").expect("the store base directory");
    let base = std::path::PathBuf::from(base);

    // Bind the listener and announce the port before reading the peer set, so every
    // peer's listener is up before anyone connects.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
    let port = listener.local_addr().expect("listener address").port();
    println!("PORT {port}");
    std::io::stdout().flush().expect("flush the port line");

    // The driver replies with every process's port in index order.
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

    let identity = net_identity(idx as u64 + 1);
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

    // Warmup heights advance the chain but are not measured. Only the ingress process
    // signs and floods the batch; the others receive it over the sockets.
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

    // The measured sustained run: drive heights until the consensus wall clock reaches
    // the target or the height cap is hit. The cap keeps the whole run, warmup plus
    // measured, under the one time sortition tree's committed slot count. The harness
    // sizes that tree to HARNESS_SLOTS through the with_slots path, well above the
    // consensus default, so the run is no longer bounded near the default height count.
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
        match rt.drive_height(batch).expect("a measured height drives") {
            HeightOutcome::Final { elapsed, txs } if txs > 0 => {
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
    // The per block digest list lets the driver prove byte identity over the common
    // prefix even when two runs finalise a different number of heights.
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
