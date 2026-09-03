// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use qtv_net::{Channel, Identity, PeerId};

use crate::util::{hex, log};

const HELLO_TAG: &[u8; 8] = b"QTVGEN01";

const HELLO_LEN: usize = 8 + 32;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_HANDSHAKE_INFLIGHT: usize = 64;

const KNOWN_HANDSHAKE_RESERVE: usize = 64;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const BOOTSTRAP_DEADLINE: Duration = Duration::from_secs(60);
/// How often a lost link is retried, and how many times before it is left to the
/// next failure to re-arm. A node is never permanently written off.
const RECONNECT_MIN: Duration = Duration::from_millis(250);
const RECONNECT_MAX: Duration = Duration::from_secs(10);
const REJOIN_QUEUE: usize = 64;
/// Concurrent handshakes allowed from one source address, so a single host cannot
/// hold every slot and lock a returning validator out.
const LATE_PER_IP: usize = 2;
const LATE_PER_IP_KNOWN: usize = 4;

struct InflightGuard(Arc<AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn known_peer_ips(peer_addrs: &[Option<String>]) -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    for addr in peer_addrs.iter().flatten() {
        if let Ok(resolved) = addr.to_socket_addrs() {
            for socket in resolved {
                ips.insert(socket.ip());
            }
        }
    }
    ips
}

fn connect_peer(
    addr: &str,
    identity: &Identity,
    peer: &PeerId,
    hello: &[u8],
    label: usize,
) -> Option<Channel<TcpStream>> {
    let deadline = Instant::now() + BOOTSTRAP_DEADLINE;
    let stream = loop {
        if Instant::now() >= deadline {
            log(&format!(
                "could not reach peer {} within the bootstrap window, dropping it",
                label + 1
            ));
            return None;
        }
        let resolved = addr.to_socket_addrs().ok().and_then(|mut it| it.next());
        match resolved {
            Some(socket) => match TcpStream::connect_timeout(&socket, CONNECT_TIMEOUT) {
                Ok(stream) => break stream,
                Err(_) => thread::sleep(Duration::from_millis(200)),
            },
            None => thread::sleep(Duration::from_millis(200)),
        }
    };
    let mut channel =
        match Channel::connect_pinned_with_timeout(stream, identity, peer, HANDSHAKE_TIMEOUT) {
            Ok(channel) => channel,
            Err(_) => {
                log(&format!(
                    "could not handshake peer {}, dropping it",
                    label + 1
                ));
                return None;
            }
        };
    if channel.send(hello).is_err() {
        log(&format!("could not greet peer {}, dropping it", label + 1));
        return None;
    }
    Some(channel)
}

const INBOUND_CAP: usize = 4096;

const PEER_MSG_PER_SEC: f64 = 5_000.0;

const PEER_MSG_BURST: f64 = 10_000.0;

pub struct Mesh {
    pub send: Vec<Option<Channel<TcpStream>>>,
    pub inbound: Receiver<(usize, Vec<u8>)>,
    pub up: Vec<bool>,
    /// Links re-established after bootstrap. A validator that restarts dials its
    /// peers again, and without this the peers never answer, so the returning node
    /// runs on alone against a set that has moved past it.
    pub rejoined: Receiver<(usize, Channel<TcpStream>)>,
    /// The driver reports a peer whose link has failed so it is dialled again.
    pub down: SyncSender<usize>,
}

pub fn build_mesh(
    listener: TcpListener,
    peer_addrs: &[Option<String>],
    peer_ids: &[Option<PeerId>],
    idx: usize,
    n: usize,
    identity: &Identity,
    genesis_hash: [u8; 32],
) -> Mesh {
    let mut up = vec![false; n];
    up[idx] = true;
    for (q, addr) in peer_addrs.iter().enumerate() {
        if q != idx && addr.is_some() {
            up[q] = true;
        }
    }
    let up_peers = up
        .iter()
        .enumerate()
        .filter(|&(q, &u)| q != idx && u)
        .count();

    let (inbound_tx, inbound_rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
    let (accepted_tx, accepted_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();

    let identity_acc = identity.clone();
    let up_acc = up.clone();
    let peer_ids_acc: Vec<Option<PeerId>> = peer_ids.to_vec();
    let known_ips = known_peer_ips(peer_addrs);
    let (worker_tx, worker_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();
    let late_listener = listener.try_clone().expect("the listener clones");
    let acceptor = thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        let mut seen = vec![false; n];
        let mut registered = 0usize;
        let inflight = Arc::new(AtomicUsize::new(0));
        let deadline = Instant::now() + BOOTSTRAP_DEADLINE;
        while registered < up_peers && Instant::now() < deadline {
            while let Ok((from, channel)) = worker_rx.try_recv() {
                if from < n && !seen[from] {
                    seen[from] = true;
                    registered += 1;
                    let _ = accepted_tx.send((from, channel));
                }
            }
            if registered >= up_peers {
                break;
            }
            let (stream, addr) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
            };
            let known = known_ips.contains(&addr.ip());
            let cap = if known {
                MAX_HANDSHAKE_INFLIGHT + KNOWN_HANDSHAKE_RESERVE
            } else {
                MAX_HANDSHAKE_INFLIGHT
            };
            if inflight.load(Ordering::Relaxed) >= cap {
                continue;
            }
            inflight.fetch_add(1, Ordering::Relaxed);
            let identity_w = identity_acc.clone();
            let up_w = up_acc.clone();
            let peer_ids_w = peer_ids_acc.clone();
            let worker_tx_w = worker_tx.clone();
            let inflight_w = Arc::clone(&inflight);
            thread::spawn(move || {
                let _guard = InflightGuard(inflight_w);
                let _ = stream.set_nonblocking(false);
                if let Ok(channel) =
                    Channel::accept_with_timeout(stream, &identity_w, HANDSHAKE_TIMEOUT)
                {
                    let peer = channel.peer_id().clone();
                    let from = (0..n).find(|&q| {
                        q != idx
                            && up_w.get(q).copied().unwrap_or(false)
                            && peer_ids_w.get(q).and_then(|p| p.as_ref()) == Some(&peer)
                    });
                    if let Some(from) = from {
                        let _ = worker_tx_w.send((from, channel));
                    }
                }
            });
        }
        while let Ok((from, channel)) = worker_rx.try_recv() {
            if from < n && !seen[from] {
                seen[from] = true;
                let _ = accepted_tx.send((from, channel));
            }
        }
    });

    let hello = hello_frame(&genesis_hash);
    let mut dialers = Vec::new();
    for (q, addr) in peer_addrs.iter().enumerate() {
        let (addr, peer) = match (addr, peer_ids.get(q).and_then(|p| p.clone())) {
            (Some(addr), Some(peer)) if q != idx => (addr.clone(), peer),
            (Some(_), None) if q != idx => {
                log(&format!(
                    "no published peer id for peer {}, dropping it",
                    q + 1
                ));
                continue;
            }
            _ => continue,
        };
        let identity_dial = identity.clone();
        let hello_dial = hello.clone();
        dialers.push((
            q,
            thread::spawn(move || connect_peer(&addr, &identity_dial, &peer, &hello_dial, q)),
        ));
    }
    let mut send: Vec<Option<Channel<TcpStream>>> = (0..n).map(|_| None).collect();
    for (q, dialer) in dialers {
        if let Ok(Some(channel)) = dialer.join() {
            send[q] = Some(channel);
        }
    }

    acceptor.join().expect("the acceptor thread joins");

    spawn_readers(&accepted_rx, up_peers, inbound_tx.clone(), genesis_hash);

    // The listener stays open for the life of the node. Bootstrap only decides when
    // the round may start, it is not the end of the node's willingness to be reached.
    let (rejoined_tx, rejoined_rx) =
        mpsc::sync_channel::<(usize, Channel<TcpStream>)>(REJOIN_QUEUE);
    let (down_tx, down_rx) = mpsc::sync_channel::<usize>(REJOIN_QUEUE);
    spawn_late_acceptor(
        late_listener,
        idx,
        n,
        identity.clone(),
        peer_ids.to_vec(),
        peer_addrs.to_vec(),
        up.clone(),
        genesis_hash,
        inbound_tx,
    );
    spawn_redialer(
        peer_addrs.to_vec(),
        peer_ids.to_vec(),
        identity.clone(),
        genesis_hash,
        down_rx,
        rejoined_tx,
    );

    // A peer that never answered at bootstrap has no live link, and a down report is
    // only ever produced when a link that WAS alive fails to write. Without this the
    // redialer never hears about it and a validator that happened to be restarting
    // during bootstrap is written off for the life of the process, which is exactly
    // what the unbounded redial was added to prevent.
    for (q, addr) in peer_addrs.iter().enumerate() {
        if q != idx && addr.is_some() && send[q].is_none() {
            let _ = down_tx.try_send(q);
        }
    }

    Mesh {
        send,
        inbound: inbound_rx,
        up,
        rejoined: rejoined_rx,
        down: down_tx,
    }
}

/// Accept peers for as long as the node runs, so a returning validator is answered.
///
/// Bootstrap decides when the round may start, it is not the end of the node's
/// willingness to be reached. Everything the bootstrap acceptor does to stay safe is
/// done here too, because this listener is exposed for the life of the process rather
/// than for one minute.
fn spawn_late_acceptor(
    listener: TcpListener,
    idx: usize,
    n: usize,
    identity: Identity,
    peer_ids: Vec<Option<PeerId>>,
    peer_addrs: Vec<Option<String>>,
    up: Vec<bool>,
    genesis_hash: [u8; 32],
    inbound_tx: SyncSender<(usize, Vec<u8>)>,
) {
    thread::spawn(move || {
        let _ = listener.set_nonblocking(false);
        let known = known_peer_ips(&peer_addrs);
        let inflight = Arc::new(AtomicUsize::new(0));
        // Concurrent handshakes already running per source address. Without this one
        // host can hold every handshake slot and no validator can ever reconnect.
        let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        // Generation per peer. A newer link supersedes an older one, so a peer that
        // opens many connections cannot multiply its share of the inbound queue.
        let live: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(vec![0; n]));
        loop {
            let Ok((stream, addr)) = listener.accept() else {
                thread::sleep(Duration::from_millis(50));
                continue;
            };
            let ip = addr.ip();
            let is_known = known.contains(&ip);
            let cap = if is_known {
                MAX_HANDSHAKE_INFLIGHT + KNOWN_HANDSHAKE_RESERVE
            } else {
                MAX_HANDSHAKE_INFLIGHT
            };
            if inflight.load(Ordering::Relaxed) >= cap {
                continue;
            }
            {
                let mut map = per_ip.lock().expect("the per ip map is not poisoned");
                let slot = map.entry(ip).or_insert(0);
                let ip_cap = if is_known {
                    LATE_PER_IP_KNOWN
                } else {
                    LATE_PER_IP
                };
                if *slot >= ip_cap {
                    continue;
                }
                *slot += 1;
            }
            inflight.fetch_add(1, Ordering::Relaxed);
            let identity_w = identity.clone();
            let peer_ids_w = peer_ids.clone();
            let up_w = up.clone();
            let out = inbound_tx.clone();
            let inflight_w = Arc::clone(&inflight);
            let per_ip_w = Arc::clone(&per_ip);
            let live_w = Arc::clone(&live);
            thread::spawn(move || {
                let handshake = {
                    // Both slots cover the handshake only. Holding either for the life
                    // of the link would make the cap a permanent ceiling on how many
                    // peers may ever return: two unclean disconnects from one address
                    // leave two threads parked in read, and the third attempt from that
                    // address is refused for as long as the process runs. What the caps
                    // are for is bounding concurrent handshake cost. Once a link is up
                    // the authenticated one live link per peer rule governs it.
                    let _ip_guard = IpGuard(per_ip_w, ip);
                    let _guard = InflightGuard(inflight_w);
                    let _ = stream.set_nonblocking(false);
                    Channel::accept_with_timeout(stream, &identity_w, HANDSHAKE_TIMEOUT)
                };
                let Ok(channel) = handshake else {
                    return;
                };
                let peer = channel.peer_id().clone();
                // Same predicate the bootstrap acceptor applies, so a peer this node
                // was never configured to talk to cannot be adopted late.
                let Some(from) = (0..n).find(|&q| {
                    q != idx
                        && up_w.get(q).copied().unwrap_or(false)
                        && peer_ids_w.get(q).and_then(|p| p.as_ref()) == Some(&peer)
                }) else {
                    return;
                };
                let generation = {
                    let mut g = live_w.lock().expect("the generation table is not poisoned");
                    g[from] = g[from].saturating_add(1);
                    g[from]
                };
                log(&format!(
                    "peer {} reconnected, reading from it again",
                    from + 1
                ));
                read_peer_until_superseded(from, channel, out, genesis_hash, live_w, generation);
            });
        }
    });
}

/// Release a per address handshake slot however the thread leaves.
struct IpGuard(Arc<Mutex<HashMap<IpAddr, usize>>>, IpAddr);

impl Drop for IpGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.0.lock() {
            if let Some(slot) = map.get_mut(&self.1) {
                *slot = slot.saturating_sub(1);
                if *slot == 0 {
                    map.remove(&self.1);
                }
            }
        }
    }
}

/// Read a peer until a newer link from the same peer supersedes this one, so a peer
/// that opens many connections does not get many shares of the inbound queue.
fn read_peer_until_superseded(
    from: usize,
    channel: Channel<TcpStream>,
    out: SyncSender<(usize, Vec<u8>)>,
    genesis_hash: [u8; 32],
    live: Arc<Mutex<Vec<u64>>>,
    generation: u64,
) {
    let current = Arc::clone(&live);
    let stop = move || {
        current
            .lock()
            .map(|g| g[from] != generation)
            .unwrap_or(true)
    };
    read_peer_with_stop(from, channel, out, genesis_hash, &stop);
}

/// Dial a peer the driver has reported as down until it answers again.
///
/// A validator is never permanently written off. The delay grows to a ceiling and then
/// stays there, so a machine that is away for hours still rejoins when it returns.
fn spawn_redialer(
    peer_addrs: Vec<Option<String>>,
    peer_ids: Vec<Option<PeerId>>,
    identity: Identity,
    genesis_hash: [u8; 32],
    down_rx: Receiver<usize>,
    rejoined_tx: SyncSender<(usize, Channel<TcpStream>)>,
) {
    thread::spawn(move || {
        let hello = hello_frame(&genesis_hash);
        let dialling: Arc<Mutex<HashSet<usize>>> = Arc::new(Mutex::new(HashSet::new()));
        while let Ok(q) = down_rx.recv() {
            let (Some(addr), Some(peer)) = (
                peer_addrs.get(q).and_then(|a| a.clone()),
                peer_ids.get(q).and_then(|p| p.clone()),
            ) else {
                continue;
            };
            // One dialler per peer. Repeated down reports must not stack threads.
            if !dialling.lock().map(|mut d| d.insert(q)).unwrap_or(false) {
                continue;
            }
            let identity = identity.clone();
            let hello = hello.clone();
            let tx = rejoined_tx.clone();
            let dialling_w = Arc::clone(&dialling);
            thread::spawn(move || {
                let mut wait = RECONNECT_MIN;
                loop {
                    // Try immediately, a link lost to one write timeout is usually back
                    // straight away and should not cost a full backoff.
                    if let Some(channel) = connect_peer(&addr, &identity, &peer, &hello, q) {
                        log(&format!("re-established the link to peer {}", q + 1));
                        let _ = tx.send((q, channel));
                        break;
                    }
                    thread::sleep(wait);
                    wait = (wait * 2).min(RECONNECT_MAX);
                }
                if let Ok(mut d) = dialling_w.lock() {
                    d.remove(&q);
                }
            });
        }
    });
}

fn hello_frame(genesis_hash: &[u8; 32]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HELLO_LEN);
    frame.extend_from_slice(HELLO_TAG);
    frame.extend_from_slice(genesis_hash);
    frame
}

fn hello_ok(frame: &[u8], genesis_hash: &[u8; 32]) -> bool {
    frame.len() == HELLO_LEN && &frame[..8] == HELLO_TAG && &frame[8..] == genesis_hash
}

fn forward_frame(out: &SyncSender<(usize, Vec<u8>)>, from: usize, bytes: Vec<u8>) -> bool {
    match out.try_send((from, bytes)) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => true,
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn read_peer_with_stop(
    from: usize,
    mut channel: Channel<TcpStream>,
    out: SyncSender<(usize, Vec<u8>)>,
    genesis_hash: [u8; 32],
    stop: &dyn Fn() -> bool,
) {
    match channel.recv() {
        Ok(frame) if hello_ok(&frame, &genesis_hash) => {}
        Ok(frame) => {
            log(&format!(
                "refusing peer {}: its genesis hash {} is not ours, wrong chain",
                from + 1,
                hex(frame.get(8..).unwrap_or(&[]))
            ));
            return;
        }
        Err(_) => return,
    }
    let mut tokens = PEER_MSG_BURST;
    let mut last = Instant::now();
    let mut last_log: Option<Instant> = None;
    while let Ok(bytes) = channel.recv() {
        if stop() {
            return;
        }
        let now = Instant::now();
        tokens = (tokens + now.saturating_duration_since(last).as_secs_f64() * PEER_MSG_PER_SEC)
            .min(PEER_MSG_BURST);
        last = now;
        if tokens < 1.0 {
            if last_log.map_or(true, |t| {
                now.saturating_duration_since(t) > Duration::from_secs(10)
            }) {
                log(&format!(
                    "peer {} is over its message rate, dropping its frames",
                    from + 1
                ));
                last_log = Some(now);
            }
            continue;
        }
        tokens -= 1.0;
        if !forward_frame(&out, from, bytes) {
            break;
        }
    }
}

fn read_peer(
    from: usize,
    channel: Channel<TcpStream>,
    out: SyncSender<(usize, Vec<u8>)>,
    genesis_hash: [u8; 32],
) {
    read_peer_with_stop(from, channel, out, genesis_hash, &|| false);
}

fn spawn_readers(
    accepted_rx: &Receiver<(usize, Channel<TcpStream>)>,
    up_peers: usize,
    inbound_tx: SyncSender<(usize, Vec<u8>)>,
    genesis_hash: [u8; 32],
) {
    for _ in 0..up_peers {
        let Ok((from, channel)) = accepted_rx.recv() else {
            break;
        };
        let out = inbound_tx.clone();
        thread::spawn(move || read_peer(from, channel, out, genesis_hash));
    }
}

#[cfg(test)]
mod tests {
    use super::{forward_frame, INBOUND_CAP, PEER_MSG_BURST, PEER_MSG_PER_SEC};
    use std::sync::mpsc;

    #[test]
    fn the_inbound_channel_is_bounded_and_drops_the_overflow() {
        let (tx, rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
        let flood = INBOUND_CAP * 4;
        for _ in 0..flood {
            assert!(
                forward_frame(&tx, 1, vec![0u8; 64]),
                "a full inbound channel must drop the frame, not stop the reader"
            );
        }
        let mut drained = 0usize;
        while rx.try_recv().is_ok() {
            drained += 1;
        }
        assert!(
            drained <= INBOUND_CAP,
            "the queue grew past its cap, it held {drained}"
        );
        assert_eq!(
            drained, INBOUND_CAP,
            "the bounded channel fills exactly to its cap"
        );
    }

    #[test]
    fn a_drained_channel_keeps_accepting_after_a_full_burst() {
        let (tx, rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
        for _ in 0..INBOUND_CAP {
            assert!(forward_frame(&tx, 0, vec![1u8; 8]));
        }
        for _ in 0..INBOUND_CAP {
            assert!(rx.try_recv().is_ok());
        }
        assert!(
            forward_frame(&tx, 0, vec![2u8; 8]),
            "a drained channel accepts fresh frames again"
        );
    }

    #[test]
    fn a_gone_receiver_stops_the_reader() {
        let (tx, rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
        drop(rx);
        assert!(
            !forward_frame(&tx, 0, vec![9u8; 8]),
            "a disconnected receiver must stop the reader loop"
        );
    }

    #[test]
    fn the_rate_ceiling_is_bounded_and_below_the_earlier_flood_ceiling() {
        assert!(INBOUND_CAP > 0);
        assert!(PEER_MSG_PER_SEC <= 5_000.0, "the per peer rate was lowered");
        assert!(
            PEER_MSG_BURST >= PEER_MSG_PER_SEC,
            "the burst covers the sustained rate"
        );
    }
}
