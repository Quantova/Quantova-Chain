// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::HashSet;
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
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
                log(&format!("could not handshake peer {}, dropping it", label + 1));
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
    let up_peers = up.iter().enumerate().filter(|&(q, &u)| q != idx && u).count();

    let (inbound_tx, inbound_rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_CAP);
    let (accepted_tx, accepted_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();

    let identity_acc = identity.clone();
    let up_acc = up.clone();
    let peer_ids_acc: Vec<Option<PeerId>> = peer_ids.to_vec();
    let known_ips = known_peer_ips(peer_addrs);
    let (worker_tx, worker_rx) = mpsc::channel::<(usize, Channel<TcpStream>)>();
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
                log(&format!("no published peer id for peer {}, dropping it", q + 1));
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

    spawn_readers(&accepted_rx, up_peers, inbound_tx, genesis_hash);

    Mesh {
        send,
        inbound: inbound_rx,
        up,
    }
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

fn spawn_readers(
    accepted_rx: &Receiver<(usize, Channel<TcpStream>)>,
    up_peers: usize,
    inbound_tx: SyncSender<(usize, Vec<u8>)>,
    genesis_hash: [u8; 32],
) {
    for _ in 0..up_peers {
        let Ok((from, mut channel)) = accepted_rx.recv() else {
            break;
        };
        let out = inbound_tx.clone();
        thread::spawn(move || {
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
                let now = Instant::now();
                tokens = (tokens + now.saturating_duration_since(last).as_secs_f64() * PEER_MSG_PER_SEC)
                    .min(PEER_MSG_BURST);
                last = now;
                if tokens < 1.0 {
                    if last_log.map_or(true, |t| now.saturating_duration_since(t) > Duration::from_secs(10)) {
                        log(&format!("peer {} is over its message rate, dropping its frames", from + 1));
                        last_log = Some(now);
                    }
                    continue;
                }
                tokens -= 1.0;
                if !forward_frame(&out, from, bytes) {
                    break;
                }
            }
        });
    }
    drop(inbound_tx);
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
        assert_eq!(drained, INBOUND_CAP, "the bounded channel fills exactly to its cap");
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
        assert!(PEER_MSG_BURST >= PEER_MSG_PER_SEC, "the burst covers the sustained rate");
    }
}
