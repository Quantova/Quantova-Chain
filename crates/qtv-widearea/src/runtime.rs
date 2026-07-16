//! The per validator round loop, driven over real qtv-net sockets to real peer
//! addresses.
//!
//! This is the loopback validator's round loop with two changes and nothing else.
//! First, the mesh connects to the peers' real addresses read from configuration
//! rather than to localhost, so the same loop runs across the wide area. Second, the
//! loop finalises on the real consensus supermajority and routes around a silent or
//! dropped leader with the real view change, so the run degrades honestly under a slow
//! or dropped host instead of hanging or reporting a number that is not real. The
//! finality rule is the same one the in process devnet uses: a node finalises only
//! once every online committee member has attested its staged block, where the online
//! set is the members whose host is up this run, so the aggregated certificate is byte
//! identical across the up hosts and the beacon stays consistent between them.

use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use qtv_devnet::coded::{code_proposal, ProposalAssembler};
use qtv_devnet::node::net_identity;
use qtv_devnet::wire::Message;
use qtv_devnet::{leader_for, DevNode};
use qtv_net::{Channel, Identity};
use qtv_node::consensus::Selection;

use qtv_loopback::message_height;

/// The outbound sealed channel to each peer and the single inbound record queue a built
/// mesh yields to the round loop.
type MeshChannels = (Vec<Option<Channel<TcpStream>>>, Receiver<(usize, Vec<u8>)>);

/// A single driven height's outcome for a host's measurement.
pub enum HeightOutcome {
    /// The height finalised: the wall clock it took, how many transactions the
    /// finalised block carried, and whether it rotated through a view change to get
    /// there, which a healthy height never does and a dropped leader forces.
    Final {
        elapsed: Duration,
        txs: usize,
        rotated: bool,
    },
    /// The height did not finalise within the stall guard, which happens when the
    /// online set is below the supermajority so no quorum can form.
    Stalled,
}

/// The per process runtime: the one validator, the outbound sealed channels to each up
/// peer, the inbound record queue the reader threads feed, the erasure coded proposal
/// reassembly buffer, the buffer of messages that arrived ahead of this height, and the
/// fault and timing knobs a wide area run and its fault injection test set.
pub struct Runtime {
    pub idx: usize,
    pub n: usize,
    pub node: DevNode,
    /// The outbound sealed channel to each peer, `None` for this process's own slot
    /// and for a peer that is down this run. Only the main thread sends.
    pub send: Vec<Option<Channel<TcpStream>>>,
    /// Inbound sealed records, `(from index, plaintext)`, fed by one reader thread per
    /// up peer that blocks on its channel's real socket read.
    pub inbound: Receiver<(usize, Vec<u8>)>,
    pub assembler: ProposalAssembler,
    /// Messages that named a height ahead of this process's current height, kept to
    /// replay when this process reaches that height rather than dropped.
    pub buffered: Vec<(usize, Vec<u8>)>,
    pub senders_n: usize,
    /// Whether each validator index is up this run. A dropped host is `false` and is
    /// not started; the online set for finality is the up members.
    pub up: Vec<bool>,
    /// The per message send delay injected on this host, the slow host fault. Zero is a
    /// healthy host; a positive delay slows every message this host originates, so a
    /// present but slow host widens the finality distribution it is waited for in.
    pub slow: Duration,
    /// The wall clock a view is given before this node rotates the leader.
    pub view_timeout: Duration,
    /// The wall clock a single height is given before the run calls it a stall.
    pub stall: Duration,
}

impl Runtime {
    /// Whether this validator is up this run. A down validator is never started, so
    /// this is always true in practice, but the check keeps the round loop honest.
    fn i_am_up(&self) -> bool {
        self.up.get(self.idx).copied().unwrap_or(false)
    }

    /// The online committee members this run, the members whose host is up. The
    /// certificate is aggregated over exactly this set on every up host, so the up
    /// hosts finalise the byte identical block and advance the beacon alike.
    fn online(&self, selection: &Selection) -> Vec<u64> {
        selection
            .members
            .iter()
            .copied()
            .filter(|&id| self.up.get((id - 1) as usize).copied().unwrap_or(false))
            .collect()
    }

    /// Send one sealed record to every up peer but this one. A slow host sleeps first,
    /// so the delay lands on every message it originates. A send failure means a peer
    /// process died; the run guard catches the resulting stall, so the byte is dropped
    /// and the height is left to time out rather than crash mid measurement.
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

    /// Emit a message the DevNode produced onto the mesh. A proposal disseminates as
    /// its real erasure coded shards, each its own sealed record within the transport
    /// bound; every other message goes whole. This is the loopback emit unchanged.
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

    /// Enter the current view. At view zero the leader offers a fresh proposal and
    /// every node attests the block a proposal carries; past view zero a node announces
    /// its move as a view change record and the leader of the view offers its justified
    /// proposal once it holds a quorum of those records. This mirrors the in process
    /// devnet's enter_round exactly, over real sockets.
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

    /// The view timeout fired without this height finalising. A node does NOT advance
    /// its own view on a local timer, since a lone node that walks ahead while its peers
    /// stay locked would strand the all online finality rule on a view no one else is
    /// on. Instead it announces that it wants to move on by signing a view change record
    /// for the next view, and it advances only once a blocking set of such records shows
    /// the network genuinely moved on, the standard Byzantine view synchronisation. So a
    /// stray timer on a healthy height, where the proposal is merely a little late, emits
    /// one harmless record and the node still stages and attests the block when it
    /// arrives; a genuinely dropped leader draws a record from every up member and the
    /// whole committee jumps together.
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

    /// Let the leader of a later view offer its justified proposal once it holds a
    /// quorum of view change records for that view, staging and attesting the block it
    /// selects, then gossiping both. This is the devnet's try_justified_proposal.
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

    /// Dispatch one decoded message for the current height into the consensus layer,
    /// then try to settle. A coded proposal shard feeds the reassembler and drives the
    /// proposal path once k verified shards rebuild the block; an attestation and a
    /// view change record drive their handlers; a view change record may also carry
    /// this node into a later view once a blocking set has reached it. Every path
    /// re-broadcasts only what the DevNode itself produces.
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
                        // A blocking set has reached a later view: join it, keeping any
                        // lock. The main loop notices the view moved and re-enters.
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
        let _ = self.settle(selection);
    }

    /// Try to finalise the staged block once every online committee member has attested
    /// it, the same settle rule the in process devnet uses with the online set filtered
    /// to the up hosts. Below a supermajority of up members the aggregation forms no
    /// certificate, so no height finalises and the run stalls honestly.
    fn settle(&mut self, selection: &Selection) -> bool {
        let online = self.online(selection);
        if !self.node.has_attestations_from(&online) {
            return false;
        }
        self.node.try_finalize(selection).unwrap_or(false)
    }

    /// Drive one height to finality or a stall. The ingress process floods the pre
    /// signed batch over the real sockets before anyone proposes, and the timed region
    /// starts before that flood so it covers the same work the loopback run times. A
    /// message that arrived ahead of this height is replayed first. The leader waits
    /// until it holds the whole batch before it proposes at view zero; a view whose
    /// leader does not propose in time rotates to the next leader, and the height
    /// finalises once the online members have attested the block the surviving leader
    /// carried.
    pub fn drive_height(
        &mut self,
        batch: Option<Vec<qtv_tx::Wrapper>>,
    ) -> Result<HeightOutcome, String> {
        let start_height = self.node.height();
        let selection = self.node.select().map_err(|e| format!("select: {e:?}"))?;

        let start = Instant::now();

        // Replay any messages that arrived while this process was on an earlier height
        // and named this one, so the real socket asynchrony does not lose them.
        let ready: Vec<(usize, Vec<u8>)> = std::mem::take(&mut self.buffered)
            .into_iter()
            .filter(|(_, bytes)| {
                Message::decode(bytes)
                    .map(|m| message_height(&m) == Some(start_height))
                    .unwrap_or(false)
            })
            .collect();
        for (_, bytes) in ready {
            if let Ok(message) = Message::decode(&bytes) {
                self.dispatch(message, &selection);
            }
        }

        // The ingress process floods the batch, admitting it and gossiping it over the
        // real sockets, before anyone proposes.
        if let Some(batch) = batch {
            for transaction in batch {
                let _ = self.node.submit(transaction.clone());
                let bytes = Message::Tx(transaction).encode();
                self.broadcast(&bytes);
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
            // Enter the view once ready. At view zero the leader waits until it holds
            // the whole batch so its block carries every transaction; a non leader and a
            // later view enter at once, since the block arrives on the proposal.
            let ready_to_enter = entered_view != Some(view)
                && (!(view == 0 && leads) || self.node.mempool_len() >= self.senders_n);
            if self.i_am_up() && ready_to_enter {
                self.enter_current_view(&selection, view);
                entered_view = Some(view);
                view_deadline = Instant::now() + self.view_timeout;
            }

            // The view ran out of wall clock without finalising. Announce the move to
            // the next view with a view change record and advance only on a blocking set
            // of records, never on this local timer alone.
            if self.i_am_up() && entered_view == Some(view) && Instant::now() >= view_deadline {
                self.on_view_timeout(&selection);
                view_deadline = Instant::now() + self.view_timeout;
            }

            match self.inbound.recv_timeout(Duration::from_millis(20)) {
                Ok((_, bytes)) => {
                    let message = match Message::decode(&bytes) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    match message_height(&message) {
                        Some(h) if h > start_height => self.buffered.push((0, bytes)),
                        Some(h) if h < start_height => {}
                        _ => self.dispatch(message, &selection),
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    // Every up peer's reader thread has ended, so no further record can
                    // arrive. Nothing more will finalise, so let the run guard report
                    // the stall rather than spin.
                    return Ok(HeightOutcome::Stalled);
                }
            }
        }
    }
}

/// Establish the real qtv-net TCP mesh to the up peers. Each up pair holds two
/// connections, one sealed record stream per direction: this process initiates an
/// outbound connection to each up peer that it sends on, and accepts an inbound
/// connection from each up peer that a reader thread reads. Both connections run the
/// real ML-KEM and ML-DSA pinned handshake, so a peer that cannot prove its identity is
/// refused, and the outbound and inbound directions never share a channel. A down peer
/// is neither dialled nor awaited, so a dropped host does not stall the mesh.
///
/// This is the loopback build_mesh with the localhost port list replaced by the peers'
/// real socket addresses and with the down peers skipped.
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

    // Accept the inbound connection from each up peer on its own thread, so accepting
    // and connecting proceed together and neither side deadlocks waiting on the other.
    let identity_acc = identity.clone();
    let up_ids: Vec<bool> = up.to_vec();
    let acceptor = thread::spawn(move || {
        for _ in 0..up_peers {
            let (stream, _) = listener.accept().expect("accept an inbound peer connection");
            let channel = Channel::accept(stream, &identity_acc).expect("responder handshake");
            let peer = channel.peer_id().clone();
            let from = (0..n)
                .find(|&q| {
                    q != idx
                        && up_ids.get(q).copied().unwrap_or(false)
                        && net_identity(q as u64 + 1).peer_id() == peer
                })
                .expect("the inbound peer is a known up validator");
            accepted_tx
                .send((from, channel))
                .expect("hand the accepted channel to the main thread");
        }
    });

    // Connect an outbound channel to each up peer at its real address. A peer still
    // coming up refuses the connection, so a short retry covers the process start
    // ordering across hosts.
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
        let peer = net_identity(q as u64 + 1).peer_id();
        let channel =
            Channel::connect_pinned(stream, identity, &peer).expect("initiator handshake");
        send[q] = Some(channel);
    }

    acceptor.join().expect("the acceptor thread joins");

    // Spawn one reader thread per inbound channel; each blocks on its real socket read
    // and feeds the plaintext into the single inbound queue tagged by the peer.
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
