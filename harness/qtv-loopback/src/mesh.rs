// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use qtv_devnet::node::node_peer_id;
use qtv_net::{Channel, Identity};

pub type MeshChannels = (Vec<Option<Channel<TcpStream>>>, Receiver<(usize, Vec<u8>)>);

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const INBOUND_FRAME_CAP: usize = 1024;

pub fn build_mesh(
    listener: TcpListener,
    addrs: &[String],
    idx: usize,
    up: &[bool],
    identity: &Identity,
    join_timeout: Duration,
) -> Result<MeshChannels, String> {
    let n = addrs.len();
    let is_up = |q: usize| up.get(q).copied().unwrap_or(false);
    let expected: Vec<usize> = (0..n).filter(|&q| q != idx && is_up(q)).collect();
    let deadline = Instant::now() + join_timeout;

    listener
        .set_nonblocking(true)
        .map_err(|e| format!("the listener cannot poll: {e}"))?;
    let identity_acc = identity.clone();
    let wanted = expected.clone();
    let acceptor = thread::spawn(move || {
        let mut accepted: BTreeMap<usize, Channel<TcpStream>> = BTreeMap::new();
        while accepted.len() < wanted.len() && Instant::now() < deadline {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            if stream.set_nonblocking(false).is_err() {
                continue;
            }
            let Ok(channel) =
                Channel::accept_with_timeout(stream, &identity_acc, HANDSHAKE_TIMEOUT)
            else {
                continue;
            };
            let peer = channel.peer_id().clone();
            if let Some(&from) = wanted.iter().find(|&&q| node_peer_id(q as u64 + 1) == peer) {
                accepted.insert(from, channel);
            }
        }
        accepted
    });

    let mut send: Vec<Option<Channel<TcpStream>>> = (0..n).map(|_| None).collect();
    for &q in &expected {
        let peer = node_peer_id(q as u64 + 1);
        let channel = loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "peer {q} never came up within the mesh join window"
                ));
            }
            let Ok(stream) = TcpStream::connect(&addrs[q]) else {
                thread::sleep(Duration::from_millis(20));
                continue;
            };
            match Channel::connect_pinned_with_timeout(stream, identity, &peer, HANDSHAKE_TIMEOUT) {
                Ok(channel) => break channel,
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        };
        send[q] = Some(channel);
    }

    let accepted = acceptor
        .join()
        .map_err(|_| "the acceptor thread failed".to_string())?;
    if accepted.len() < expected.len() {
        let missing: Vec<usize> = expected
            .iter()
            .copied()
            .filter(|q| !accepted.contains_key(q))
            .collect();
        return Err(format!(
            "peers {missing:?} never connected within the mesh join window"
        ));
    }

    let (inbound_tx, inbound_rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(INBOUND_FRAME_CAP);
    for (from, mut channel) in accepted {
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
    Ok((send, inbound_rx))
}
