// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use qtv_net::{Channel, Identity, PeerId};

use crate::util::{hex, log};

const HELLO_TAG: &[u8; 8] = b"QTVGEN01";

const HELLO_LEN: usize = 8 + 32;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    let acceptor = thread::spawn(move || {
        let mut seen = vec![false; n];
        let mut registered = 0usize;
        while registered < up_peers {
            let (stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
            };
            let channel = match Channel::accept_with_timeout(stream, &identity_acc, HANDSHAKE_TIMEOUT)
            {
                Ok(channel) => channel,
                Err(_) => continue,
            };
            let peer = channel.peer_id().clone();
            let from = (0..n).find(|&q| {
                q != idx
                    && up_acc.get(q).copied().unwrap_or(false)
                    && peer_ids_acc.get(q).and_then(|p| p.as_ref()) == Some(&peer)
            });
            if let Some(from) = from {
                if !seen[from] {
                    seen[from] = true;
                    registered += 1;
                    let _ = accepted_tx.send((from, channel));
                }
            }
        }
    });

    let hello = hello_frame(&genesis_hash);
    let mut send: Vec<Option<Channel<TcpStream>>> = (0..n).map(|_| None).collect();
    for (q, addr) in peer_addrs.iter().enumerate() {
        let (q, addr) = match addr {
            Some(addr) if q != idx => (q, addr),
            _ => continue,
        };
        let Some(peer) = peer_ids.get(q).and_then(|p| p.clone()) else {
            log(&format!("no published peer id for peer {}, dropping it", q + 1));
            continue;
        };
        let stream = loop {
            match TcpStream::connect(addr) {
                Ok(stream) => break stream,
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        };
        let mut channel = match Channel::connect_pinned_with_timeout(
            stream,
            identity,
            &peer,
            HANDSHAKE_TIMEOUT,
        ) {
            Ok(channel) => channel,
            Err(_) => {
                log(&format!("could not handshake peer {}, dropping it", q + 1));
                continue;
            }
        };
        if channel.send(&hello).is_err() {
            log(&format!("could not greet peer {}, dropping it", q + 1));
            continue;
        }
        send[q] = Some(channel);
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
