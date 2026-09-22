// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, TcpListener, TcpStream, ToSocketAddrs};
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

fn bootstrap_deadline() -> Duration {
    match std::env::var("QTV_BOOTSTRAP_DEADLINE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        Some(ms) => Duration::from_millis(ms),
        None => BOOTSTRAP_DEADLINE,
    }
}
const RECONNECT_MIN: Duration = Duration::from_millis(250);
const RECONNECT_MAX: Duration = Duration::from_secs(10);

const RECONNECT_FLOOR: Duration = Duration::from_secs(2);
const REJOIN_QUEUE: usize = 64;
const LATE_PER_IP: usize = 2;
const LATE_PER_IP_KNOWN: usize = 4;
const FAILED_HANDSHAKE_BAR: Duration = Duration::from_secs(30);
const MAX_BARRED: usize = 65_536;

fn address_bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[derive(Default)]
struct Bars {
    by_ip: HashMap<IpAddr, Instant>,
    by_time: std::collections::BTreeSet<(Instant, IpAddr)>,
}

impl Bars {
    fn expire(&mut self, now: Instant) {
        while let Some(&(until, ip)) = self.by_time.first() {
            if until > now {
                break;
            }
            self.by_time.remove(&(until, ip));
            self.by_ip.remove(&ip);
        }
    }

    fn remove(&mut self, ip: IpAddr) {
        if let Some(until) = self.by_ip.remove(&ip) {
            self.by_time.remove(&(until, ip));
        }
    }
}

#[derive(Clone, Default)]
struct HandshakeBar(Arc<Mutex<Bars>>);

impl HandshakeBar {
    fn barred(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let key = address_bucket(ip);
        let mut bars = self.0.lock().unwrap_or_else(|e| e.into_inner());
        bars.expire(now);
        bars.by_ip.contains_key(&key)
    }

    fn bar(&self, ip: IpAddr, window: Duration) {
        let now = Instant::now();
        let key = address_bucket(ip);
        let mut bars = self.0.lock().unwrap_or_else(|e| e.into_inner());
        bars.expire(now);
        bars.remove(key);
        while bars.by_ip.len() >= MAX_BARRED {
            let Some(&(_, oldest)) = bars.by_time.first() else {
                break;
            };
            bars.remove(oldest);
        }
        let until = now + window;
        bars.by_ip.insert(key, until);
        bars.by_time.insert((until, key));
    }
}

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
                ips.insert(canonical_ip(socket.ip()));
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
    let deadline = Instant::now() + bootstrap_deadline();
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

const INBOUND_BYTES_CAP: usize = 64 * 1024 * 1024;
const MIN_PEER_FRAMES: usize = 64;

pub struct InboundBudget {
    total: AtomicUsize,
    peer_bytes: Vec<AtomicUsize>,
    peer_frames: Vec<AtomicUsize>,
    peer_bytes_cap: usize,
    peer_frames_cap: usize,
}

impl InboundBudget {
    pub fn new(n: usize) -> InboundBudget {
        let peers = n.saturating_sub(1).max(1);
        InboundBudget {
            total: AtomicUsize::new(0),
            peer_bytes: (0..n.max(1)).map(|_| AtomicUsize::new(0)).collect(),
            peer_frames: (0..n.max(1)).map(|_| AtomicUsize::new(0)).collect(),
            peer_bytes_cap: (INBOUND_BYTES_CAP / peers).max(qtv_net::MAX_MESSAGE),
            peer_frames_cap: (INBOUND_CAP / peers).max(MIN_PEER_FRAMES),
        }
    }

    fn reserve(&self, from: usize, len: usize) -> bool {
        let (Some(bytes), Some(frames)) = (self.peer_bytes.get(from), self.peer_frames.get(from))
        else {
            return false;
        };
        if self.total.load(Ordering::Relaxed).saturating_add(len) > INBOUND_BYTES_CAP
            || bytes.load(Ordering::Relaxed).saturating_add(len) > self.peer_bytes_cap
            || frames.load(Ordering::Relaxed) >= self.peer_frames_cap
        {
            return false;
        }
        self.total.fetch_add(len, Ordering::Relaxed);
        bytes.fetch_add(len, Ordering::Relaxed);
        frames.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn release(&self, from: usize, len: usize) {
        let (Some(bytes), Some(frames)) = (self.peer_bytes.get(from), self.peer_frames.get(from))
        else {
            return;
        };
        self.total.fetch_sub(len, Ordering::Relaxed);
        bytes.fetch_sub(len, Ordering::Relaxed);
        frames.fetch_sub(1, Ordering::Relaxed);
    }
}

const PEER_MSG_PER_SEC: f64 = 5_000.0;

const HELLO_DEADLINE: Duration = Duration::from_secs(30);

const PEER_MSG_BURST: f64 = 10_000.0;

pub struct Mesh {
    pub send: Vec<Option<Channel<TcpStream>>>,
    pub inbound: Receiver<(usize, Vec<u8>)>,
    pub queued_bytes: Arc<InboundBudget>,
    pub up: Vec<bool>,
    pub rejoined: Receiver<(usize, Channel<TcpStream>)>,
    pub down: SyncSender<usize>,
    pub redialing: Vec<usize>,
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
    let queued_bytes = Arc::new(InboundBudget::new(n));
    let (accepted_tx, accepted_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();

    let identity_acc = identity.clone();
    let up_acc = up.clone();
    let peer_ids_acc: Vec<Option<PeerId>> = peer_ids.to_vec();
    let known_ips = known_peer_ips(peer_addrs);
    let bar = HandshakeBar::default();
    let late_bar = bar.clone();
    let (worker_tx, worker_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();
    let late_listener = listener.try_clone().expect("the listener clones");
    let acceptor = thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        let mut seen = vec![false; n];
        let mut registered = 0usize;
        let inflight = Arc::new(AtomicUsize::new(0));
        let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let deadline = Instant::now() + bootstrap_deadline();
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
            let known = known_ips.contains(&canonical_ip(addr.ip()));
            if !known && bar.barred(addr.ip()) {
                continue;
            }
            let cap = if known {
                MAX_HANDSHAKE_INFLIGHT + KNOWN_HANDSHAKE_RESERVE
            } else {
                MAX_HANDSHAKE_INFLIGHT
            };
            if inflight.load(Ordering::Relaxed) >= cap {
                continue;
            }
            let slot_key = if known {
                addr.ip()
            } else {
                address_bucket(addr.ip())
            };
            {
                let mut map = per_ip.lock().unwrap_or_else(|e| e.into_inner());
                let slot = map.entry(slot_key).or_insert(0);
                let ip_cap = if known {
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
            let identity_w = identity_acc.clone();
            let up_w = up_acc.clone();
            let peer_ids_w = peer_ids_acc.clone();
            let known_peers: Vec<PeerId> = peer_ids_acc.iter().flatten().cloned().collect();
            let worker_tx_w = worker_tx.clone();
            let inflight_w = Arc::clone(&inflight);
            let bar_w = bar.clone();
            let ip = addr.ip();
            let per_ip_w = Arc::clone(&per_ip);
            thread::spawn(move || {
                let _guard = InflightGuard(inflight_w);
                let _ip_guard = IpGuard(per_ip_w, slot_key);
                let _ = stream.set_nonblocking(false);
                let handshake = Channel::accept_known_with_timeout(
                    stream,
                    &identity_w,
                    HANDSHAKE_TIMEOUT,
                    &known_peers,
                );
                if handshake.is_err() && !known {
                    bar_w.bar(ip, FAILED_HANDSHAKE_BAR);
                }
                if let Ok(channel) = handshake {
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

    spawn_readers(
        &accepted_rx,
        up_peers,
        inbound_tx.clone(),
        Arc::clone(&queued_bytes),
        genesis_hash,
    );

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
        Arc::clone(&queued_bytes),
        late_bar,
    );
    spawn_redialer(
        peer_addrs.to_vec(),
        peer_ids.to_vec(),
        identity.clone(),
        genesis_hash,
        down_rx,
        rejoined_tx,
    );

    let redialing = bootstrap_misses(peer_addrs, &send, idx);
    for &q in &redialing {
        let _ = down_tx.try_send(q);
    }

    Mesh {
        queued_bytes,
        send,
        inbound: inbound_rx,
        up,
        rejoined: rejoined_rx,
        down: down_tx,
        redialing,
    }
}

fn bootstrap_misses<T>(
    peer_addrs: &[Option<String>],
    send: &[Option<T>],
    idx: usize,
) -> Vec<usize> {
    peer_addrs
        .iter()
        .enumerate()
        .filter(|&(q, addr)| {
            q != idx && addr.is_some() && send.get(q).map(Option::is_none).unwrap_or(true)
        })
        .map(|(q, _)| q)
        .collect()
}

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
    queued: Arc<InboundBudget>,
    bar: HandshakeBar,
) {
    thread::spawn(move || {
        let _ = listener.set_nonblocking(false);
        let known = known_peer_ips(&peer_addrs);
        let inflight = Arc::new(AtomicUsize::new(0));
        let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let live: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(vec![0; n]));
        loop {
            let Ok((stream, addr)) = listener.accept() else {
                thread::sleep(Duration::from_millis(50));
                continue;
            };
            let ip = canonical_ip(addr.ip());
            let is_known = known.contains(&ip);
            if !is_known && bar.barred(ip) {
                continue;
            }
            let slot_key = if is_known { ip } else { address_bucket(ip) };
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
                let slot = map.entry(slot_key).or_insert(0);
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
            let known_peers_w: Vec<PeerId> = peer_ids.iter().flatten().cloned().collect();
            let up_w = up.clone();
            let out = inbound_tx.clone();
            let inflight_w = Arc::clone(&inflight);
            let per_ip_w = Arc::clone(&per_ip);
            let live_w = Arc::clone(&live);
            let queued_w = Arc::clone(&queued);
            let bar_w = bar.clone();
            thread::spawn(move || {
                let handshake = {
                    let _ip_guard = IpGuard(per_ip_w, slot_key);
                    let _guard = InflightGuard(inflight_w);
                    let _ = stream.set_nonblocking(false);
                    Channel::accept_known_with_timeout(
                        stream,
                        &identity_w,
                        HANDSHAKE_TIMEOUT,
                        &known_peers_w,
                    )
                };
                let Ok(channel) = handshake else {
                    if !is_known {
                        bar_w.bar(ip, FAILED_HANDSHAKE_BAR);
                    }
                    return;
                };
                let peer = channel.peer_id().clone();
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
                read_peer_until_superseded(
                    from,
                    channel,
                    out,
                    queued_w,
                    genesis_hash,
                    live_w,
                    generation,
                );
            });
        }
    });
}

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

fn read_peer_until_superseded(
    from: usize,
    channel: Channel<TcpStream>,
    out: SyncSender<(usize, Vec<u8>)>,
    queued: Arc<InboundBudget>,
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
    read_peer_with_stop(from, channel, out, queued, genesis_hash, &stop);
}

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
        let last_connect: Arc<Mutex<HashMap<usize, Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));
        while let Ok(q) = down_rx.recv() {
            let (Some(addr), Some(peer)) = (
                peer_addrs.get(q).and_then(|a| a.clone()),
                peer_ids.get(q).and_then(|p| p.clone()),
            ) else {
                continue;
            };
            if !dialling.lock().map(|mut d| d.insert(q)).unwrap_or(false) {
                continue;
            }
            let identity = identity.clone();
            let hello = hello.clone();
            let tx = rejoined_tx.clone();
            let dialling_w = Arc::clone(&dialling);
            let last_connect_w = Arc::clone(&last_connect);
            thread::spawn(move || {
                if let Ok(seen) = last_connect_w.lock() {
                    if let Some(at) = seen.get(&q) {
                        let since = at.elapsed();
                        if since < RECONNECT_FLOOR {
                            thread::sleep(RECONNECT_FLOOR - since);
                        }
                    }
                }
                let mut wait = RECONNECT_MIN;
                loop {
                    if let Some(channel) = connect_peer(&addr, &identity, &peer, &hello, q) {
                        log(&format!("re-established the link to peer {}", q + 1));
                        if let Ok(mut seen) = last_connect_w.lock() {
                            seen.insert(q, Instant::now());
                        }
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

fn forward_frame(
    out: &SyncSender<(usize, Vec<u8>)>,
    queued: &InboundBudget,
    from: usize,
    bytes: Vec<u8>,
) -> bool {
    let len = bytes.len();
    if !queued.reserve(from, len) {
        return true;
    }
    match out.try_send((from, bytes)) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            queued.release(from, len);
            true
        }
        Err(TrySendError::Disconnected(_)) => {
            queued.release(from, len);
            false
        }
    }
}

fn read_peer_with_stop(
    from: usize,
    mut channel: Channel<TcpStream>,
    out: SyncSender<(usize, Vec<u8>)>,
    queued: Arc<InboundBudget>,
    genesis_hash: [u8; 32],
    stop: &dyn Fn() -> bool,
) {
    let hello_deadline = Instant::now() + HELLO_DEADLINE;
    loop {
        if Instant::now() >= hello_deadline {
            return;
        }
        match channel.recv() {
            Ok(frame) if hello_ok(&frame, &genesis_hash) => break,
            Ok(frame) => {
                log(&format!(
                    "refusing peer {}: its genesis hash {} is not ours, wrong chain",
                    from + 1,
                    hex(frame.get(8..HELLO_LEN).unwrap_or(&[]))
                ));
                return;
            }
            Err(err) if err.is_timeout() => {
                if stop() {
                    return;
                }
                continue;
            }
            Err(_) => return,
        }
    }
    let mut tokens = PEER_MSG_BURST;
    let mut last = Instant::now();
    let mut last_log: Option<Instant> = None;
    loop {
        let bytes = match channel.recv() {
            Ok(bytes) => bytes,
            Err(err) if err.is_timeout() => {
                if stop() {
                    return;
                }
                continue;
            }
            Err(_) => break,
        };
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
        if !forward_frame(&out, &queued, from, bytes) {
            break;
        }
    }
}

fn read_peer(
    from: usize,
    channel: Channel<TcpStream>,
    out: SyncSender<(usize, Vec<u8>)>,
    queued: Arc<InboundBudget>,
    genesis_hash: [u8; 32],
) {
    read_peer_with_stop(from, channel, out, queued, genesis_hash, &|| false);
}

fn spawn_readers(
    accepted_rx: &Receiver<(usize, Channel<TcpStream>)>,
    up_peers: usize,
    inbound_tx: SyncSender<(usize, Vec<u8>)>,
    queued: Arc<InboundBudget>,
    genesis_hash: [u8; 32],
) {
    for _ in 0..up_peers {
        let Ok((from, channel)) = accepted_rx.recv() else {
            break;
        };
        let out = inbound_tx.clone();
        let queued = Arc::clone(&queued);
        thread::spawn(move || read_peer(from, channel, out, queued, genesis_hash));
    }
}

#[cfg(test)]
mod tests {
    use super::{forward_frame, InboundBudget, INBOUND_CAP, PEER_MSG_BURST, PEER_MSG_PER_SEC};

    #[test]
    fn the_inbound_queue_is_bounded_by_bytes_not_only_by_frame_count() {
        let (tx, _rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
        let queued = InboundBudget::new(2);
        let big = super::INBOUND_BYTES_CAP / 4;

        for _ in 0..4 {
            assert!(
                forward_frame(&tx, &queued, 0, vec![7u8; big]),
                "a frame inside the budget is accepted"
            );
        }
        let at_cap = queued.total.load(super::Ordering::Relaxed);
        assert!(
            at_cap <= super::INBOUND_BYTES_CAP,
            "the queue must never hold more than its byte budget, held {at_cap}"
        );
        assert!(
            forward_frame(&tx, &queued, 0, vec![7u8; big]),
            "past the budget the reader keeps running"
        );
        assert_eq!(
            queued.total.load(super::Ordering::Relaxed),
            at_cap,
            "but the frame past the budget is dropped rather than parked"
        );
    }
    use std::sync::mpsc;

    #[test]
    fn the_inbound_channel_is_bounded_and_drops_the_overflow() {
        let (tx, rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
        let flood = INBOUND_CAP * 4;
        for _ in 0..flood {
            assert!(
                forward_frame(&tx, &InboundBudget::new(2), 1, vec![0u8; 64]),
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
    fn one_peer_cannot_take_another_peers_share_of_the_inbound_queue() {
        let (tx, rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
        let budget = InboundBudget::new(5);
        for _ in 0..INBOUND_CAP {
            assert!(forward_frame(&tx, &budget, 1, vec![0u8; 64]));
        }
        assert!(forward_frame(&tx, &budget, 2, vec![0u8; 64]));
        let mut from_flooder = 0usize;
        let mut from_honest = 0usize;
        while let Ok((from, bytes)) = rx.try_recv() {
            budget.release(from, bytes.len());
            match from {
                1 => from_flooder += 1,
                2 => from_honest += 1,
                _ => {}
            }
        }
        assert_eq!(
            from_flooder,
            INBOUND_CAP / 4,
            "the flooder is held to its share"
        );
        assert_eq!(from_honest, 1, "the honest peer's frame still gets in");
        assert_eq!(budget.total.load(super::Ordering::Relaxed), 0);
    }

    #[test]
    fn a_drained_channel_keeps_accepting_after_a_full_burst() {
        let (tx, rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
        for _ in 0..INBOUND_CAP {
            assert!(forward_frame(&tx, &InboundBudget::new(2), 0, vec![1u8; 8]));
        }
        for _ in 0..INBOUND_CAP {
            assert!(rx.try_recv().is_ok());
        }
        assert!(
            forward_frame(&tx, &InboundBudget::new(2), 0, vec![2u8; 8]),
            "a drained channel accepts fresh frames again"
        );
    }

    #[test]
    fn a_gone_receiver_stops_the_reader() {
        let (tx, rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
        drop(rx);
        assert!(
            !forward_frame(&tx, &InboundBudget::new(2), 0, vec![9u8; 8]),
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

#[cfg(test)]
mod bootstrap_report {
    use super::bootstrap_misses;

    fn addrs(v: &[Option<&str>]) -> Vec<Option<String>> {
        v.iter().map(|a| a.map(str::to_string)).collect()
    }

    #[test]
    fn a_configured_peer_with_no_link_is_reported_down() {
        let peers = addrs(&[Some("a:1"), Some("b:2"), Some("c:3"), Some("d:4")]);
        let send: Vec<Option<()>> = vec![None, None, Some(()), None];
        assert_eq!(bootstrap_misses(&peers, &send, 0), vec![1, 3]);
    }

    #[test]
    fn this_node_is_never_reported_against_itself() {
        let peers = addrs(&[Some("a:1"), Some("b:2")]);
        let send: Vec<Option<()>> = vec![None, None];
        assert_eq!(bootstrap_misses(&peers, &send, 0), vec![1]);
    }

    #[test]
    fn a_peer_with_no_configured_address_is_not_reported() {
        let peers = addrs(&[Some("a:1"), None, Some("c:3")]);
        let send: Vec<Option<()>> = vec![None, None, None];
        assert_eq!(bootstrap_misses(&peers, &send, 0), vec![2]);
    }

    #[test]
    fn a_peer_that_answered_is_not_reported() {
        let peers = addrs(&[Some("a:1"), Some("b:2")]);
        let send: Vec<Option<()>> = vec![None, Some(())];
        assert!(bootstrap_misses(&peers, &send, 0).is_empty());
    }
}

#[cfg(test)]
mod per_ip_slots {
    use super::{IpGuard, LATE_PER_IP};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    fn admit(map: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr, cap: usize) -> Option<IpGuard> {
        let mut m = map.lock().unwrap();
        let slot = m.entry(ip).or_insert(0);
        if *slot >= cap {
            return None;
        }
        *slot += 1;
        drop(m);
        Some(IpGuard(Arc::clone(map), ip))
    }

    #[test]
    fn a_finished_handshake_gives_its_slot_back() {
        let map: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        for round in 0..50 {
            let mut held = Vec::new();
            for _ in 0..LATE_PER_IP {
                held.push(
                    admit(&map, ip, LATE_PER_IP)
                        .unwrap_or_else(|| panic!("round {round} was refused a slot")),
                );
            }
            assert!(
                admit(&map, ip, LATE_PER_IP).is_none(),
                "the cap must still bound concurrent handshakes"
            );
            drop(held);
            assert!(
                map.lock().unwrap().get(&ip).is_none(),
                "every slot must be released once the handshakes finish"
            );
        }
    }

    #[test]
    fn the_cap_still_bounds_concurrent_handshakes_from_one_address() {
        let map: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
        let _a = admit(&map, ip, LATE_PER_IP).expect("first");
        let _b = admit(&map, ip, LATE_PER_IP).expect("second");
        assert!(admit(&map, ip, LATE_PER_IP).is_none(), "a third is refused");
    }

    #[test]
    fn one_address_cannot_starve_another() {
        let map: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let noisy = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let quiet = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        let _a = admit(&map, noisy, LATE_PER_IP).expect("first");
        let _b = admit(&map, noisy, LATE_PER_IP).expect("second");
        assert!(admit(&map, noisy, LATE_PER_IP).is_none());
        assert!(
            admit(&map, quiet, LATE_PER_IP).is_some(),
            "a different address keeps its own budget"
        );
    }
}

#[cfg(test)]
mod bootstrap_wiring {
    use super::build_mesh;
    use qtv_net::Identity;
    use std::net::TcpListener;

    #[test]
    fn a_peer_that_never_answered_is_handed_to_the_redialer() {
        std::env::set_var("QTV_BOOTSTRAP_DEADLINE_MS", "300");
        let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
        let dead = TcpListener::bind("127.0.0.1:0").expect("a port to close");
        let dead_addr = dead.local_addr().expect("addr").to_string();
        drop(dead);

        let peers = vec![None, Some(dead_addr), None];
        let ids = vec![None, None, None];
        let identity = Identity::from_seed(&[42u8; 32]);
        let mesh = build_mesh(listener, &peers, &ids, 0, 3, &identity, [0u8; 32]);

        std::env::remove_var("QTV_BOOTSTRAP_DEADLINE_MS");
        assert_eq!(
            mesh.redialing,
            vec![1],
            "a configured peer that never answered must be handed to the redialer"
        );
    }

    #[test]
    fn a_node_with_no_configured_peers_reports_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
        let peers = vec![None, None];
        let ids = vec![None, None];
        let identity = Identity::from_seed(&[43u8; 32]);
        let mesh = build_mesh(listener, &peers, &ids, 0, 2, &identity, [0u8; 32]);
        assert!(
            mesh.redialing.is_empty(),
            "there is nothing to redial, so the redialer must not be woken"
        );
    }
}

#[cfg(test)]
mod handshake_bar {
    use super::{
        canonical_ip, spawn_late_acceptor, HandshakeBar, FAILED_HANDSHAKE_BAR, MAX_BARRED,
    };
    use qtv_net::Identity;
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::{Duration, Instant};

    fn claim(addr: std::net::SocketAddr, claimed: &Identity) -> Option<TcpStream> {
        let mut stream = TcpStream::connect(addr).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream.write_all(claimed.public()).ok()?;
        stream.write_all(&[0u8; 32]).ok()?;
        let mut first = [0u8; 1];
        match stream.read(&mut first) {
            Ok(1) => Some(stream),
            _ => None,
        }
    }

    #[test]
    fn a_stranger_claiming_a_validator_key_gets_one_handshake_then_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let validator = Identity::from_seed(&[61u8; 32]);
        let (inbound_tx, _inbound_rx) = mpsc::sync_channel(16);
        let bar = HandshakeBar::default();
        spawn_late_acceptor(
            listener,
            0,
            2,
            Identity::from_seed(&[60u8; 32]),
            vec![None, Some(validator.peer_id())],
            vec![None, Some("127.0.0.2:9".to_string())],
            vec![true, true],
            [0u8; 32],
            inbound_tx,
            Arc::new(super::InboundBudget::new(2)),
            bar.clone(),
        );
        let mut first = claim(addr, &validator).expect("the claimed key is answered once");
        let _ = first.write_all(&[0u8; 8192]);
        drop(first);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !bar.barred("127.0.0.1".parse().unwrap()) {
            assert!(
                Instant::now() < deadline,
                "the failed handshake bars its address"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            claim(addr, &validator).is_none(),
            "a barred address gets no keygen and no signature"
        );
    }

    #[test]
    fn a_failed_handshake_bars_its_address_and_the_bar_lapses() {
        let bar = HandshakeBar::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(!bar.barred(ip));
        bar.bar(ip, Duration::from_millis(50));
        assert!(bar.barred(ip));
        assert!(!bar.barred(other), "one address does not bar its neighbour");
        thread::sleep(Duration::from_millis(80));
        assert!(!bar.barred(ip), "the bar lapses");
    }

    #[test]
    fn a_v6_bar_covers_the_whole_64_and_a_mapped_v4_is_its_v4() {
        let bar = HandshakeBar::default();
        bar.bar("2001:db8:1:2::5".parse().unwrap(), FAILED_HANDSHAKE_BAR);
        assert!(bar.barred("2001:db8:1:2:ffff::9".parse().unwrap()));
        assert!(!bar.barred("2001:db8:1:3::5".parse().unwrap()));
        bar.bar("198.51.100.4".parse().unwrap(), FAILED_HANDSHAKE_BAR);
        assert!(bar.barred("::ffff:198.51.100.4".parse().unwrap()));
    }

    #[test]
    fn a_full_bar_table_evicts_the_soonest_to_lapse_and_refuses_no_stranger() {
        let bar = HandshakeBar::default();
        let first: IpAddr = IpAddr::V4(std::net::Ipv4Addr::from(0u32));
        bar.bar(first, Duration::from_secs(1));
        for i in 1..MAX_BARRED as u32 {
            bar.bar(
                IpAddr::V4(std::net::Ipv4Addr::from(i)),
                FAILED_HANDSHAKE_BAR,
            );
        }
        assert!(bar.barred(first));
        assert!(!bar.barred("192.0.2.200".parse().unwrap()));
        bar.bar("192.0.2.201".parse().unwrap(), FAILED_HANDSHAKE_BAR);
        assert!(bar.barred("192.0.2.201".parse().unwrap()));
        assert!(!bar.barred(first), "the entry closest to lapsing made room");
    }

    #[test]
    fn a_known_peer_is_recognised_through_a_mapped_address() {
        let mapped: IpAddr = "::ffff:198.51.100.4".parse().unwrap();
        let plain: IpAddr = "198.51.100.4".parse().unwrap();
        assert_eq!(canonical_ip(mapped), plain);
        let known = super::known_peer_ips(&[Some("198.51.100.4:9".to_string())]);
        assert!(known.contains(&canonical_ip(mapped)));
    }
}
