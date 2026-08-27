// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::Write;
use std::net::TcpListener;
use std::time::Duration;

use qtv_devnet::node::node_identity;
use qtv_devnet::DevNode;

use qtv_loopback::{
    accounts, build_batch, chain_digest, devnet_config, hex, recipients, transfer_fee,
};
use qtv_widearea::env as wenv;
use qtv_widearea::runtime::{build_mesh, HeightOutcome, PhaseTimers, Runtime};
use qtv_widearea::{env_usize, format_result, RunReport};

fn port_of(addr: &str) -> u16 {
    addr.rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .expect("the address is host:port with a numeric port")
}

fn parse_up(n: usize) -> Vec<bool> {
    match std::env::var(wenv::UP) {
        Ok(list) if !list.trim().is_empty() => {
            let mut up = vec![false; n];
            for field in list.split(',') {
                if let Ok(i) = field.trim().parse::<usize>() {
                    if i < n {
                        up[i] = true;
                    }
                }
            }
            up
        }
        _ => vec![true; n],
    }
}

fn main() {
    let idx: usize = std::env::var(wenv::INDEX)
        .ok()
        .or_else(|| std::env::args().nth(1))
        .and_then(|a| a.parse().ok())
        .expect("the validator index is QTV_WA_INDEX or the first argument");

    let addrs: Vec<String> = std::env::var(wenv::ADDRS)
        .expect("the peer addresses are QTV_WA_ADDRS, one host:port per validator")
        .split(',')
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect();
    let n = addrs.len();
    assert!(idx < n, "the index sits inside the validator set");

    let up = parse_up(n);
    assert!(up[idx], "a started validator is up this run");

    let senders_n = env_usize(wenv::ACCOUNTS, 250).max(2);
    let target_heights = env_usize(wenv::HEIGHTS, 60).max(1);
    let warmup = env_usize(wenv::WARMUP, 2);
    let height_cap = env_usize(wenv::HEIGHTCAP, (qtv_loopback::HARNESS_SLOTS as usize) - 64);
    let view_ms = env_usize(wenv::VIEWMS, 800).max(1) as u64;
    let stall_secs = env_usize(wenv::STALLSECS, 30).max(1) as u64;
    let slow_ms = env_usize(wenv::SLOWMS, 0) as u64;
    let base = std::path::PathBuf::from(
        std::env::var(wenv::BASE).expect("the store base directory is QTV_WA_BASE"),
    );

    let port = port_of(&addrs[idx]);
    let listener =
        TcpListener::bind(("0.0.0.0", port)).expect("bind the transport port on every interface");

    let identity = node_identity(idx as u64 + 1);
    let senders = accounts(senders_n);
    let recipient_addrs = recipients(&senders);
    let config = devnet_config(&base, n, &senders);
    let node = DevNode::open(&config.nodes[idx], &config).expect("open the validator");

    let up_count = up.iter().filter(|&&u| u).count();
    eprintln!(
        "[validator {idx}] standing up the qtv-net mesh over {up_count} of {n} hosts on port {port} ..."
    );
    let (send, inbound) = build_mesh(listener, &addrs, idx, n, &up, &identity);
    eprintln!("[validator {idx}] mesh up, driving the round ...");

    let mut rt = Runtime {
        idx,
        n,
        node,
        send,
        inbound,
        assembler: qtv_devnet::coded::ProposalAssembler::new(),
        buffered: Vec::new(),
        senders_n,
        up,
        slow: Duration::from_millis(slow_ms),
        view_timeout: Duration::from_millis(view_ms),
        stall: Duration::from_secs(stall_secs),
        phase: PhaseTimers::default(),
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
                let report = RunReport {
                    idx,
                    stalled: true,
                    ..Default::default()
                };
                println!("{}", format_result(&report));
                std::io::stdout().flush().ok();
                return;
            }
        }
    }

    let committee = rt.node.select().map(|s| s.members.len()).unwrap_or(0);

    let mut per_block_ms: Vec<f64> = Vec::new();
    let mut finalized_tx: u64 = 0;
    let mut consensus_ms = 0.0f64;
    let mut sign_ms = 0.0f64;
    let mut fill_ms = 0.0f64;
    let mut heights: u64 = 0;
    let mut rotations: u64 = 0;
    let mut stalled = false;
    let mut phase_wait_ms = 0.0f64;
    let mut phase_build_ms = 0.0f64;
    let mut phase_verify_ms = 0.0f64;
    let mut phase_aggregate_ms = 0.0f64;
    let mut phase_finalise_ms = 0.0f64;
    let mut phase_flood_ms = 0.0f64;

    while (heights as usize) < target_heights && (rt.node.chain().len()) < height_cap {
        let (batch, sign_dt) = if idx == 0 {
            let (batch, dt) = build_batch(&senders, &recipient_addrs, &mut nonces, fee);
            (Some(batch), dt)
        } else {
            (None, Duration::ZERO)
        };
        match rt.drive_height(batch).expect("a measured height drives") {
            HeightOutcome::Final {
                elapsed,
                txs,
                rotated,
                phases,
                fill,
            } => {
                if txs > 0 {
                    sign_ms += sign_dt.as_secs_f64() * 1000.0;
                    consensus_ms += elapsed.as_secs_f64() * 1000.0;
                    fill_ms += fill.as_secs_f64() * 1000.0;
                    per_block_ms.push(elapsed.as_secs_f64() * 1000.0);
                    finalized_tx += txs as u64;
                    heights += 1;
                    phase_wait_ms += phases.wait.as_secs_f64() * 1000.0;
                    phase_build_ms += phases.build.as_secs_f64() * 1000.0;
                    phase_verify_ms += phases.verify.as_secs_f64() * 1000.0;
                    phase_aggregate_ms += phases.aggregate.as_secs_f64() * 1000.0;
                    phase_finalise_ms += phases.finalise.as_secs_f64() * 1000.0;
                    phase_flood_ms += phases.flood.as_secs_f64() * 1000.0;
                    if rotated {
                        rotations += 1;
                    }
                }
            }
            HeightOutcome::Stalled => {
                stalled = true;
                break;
            }
        }
    }

    let header_hashes: Vec<[u8; 32]> = rt.node.chain().iter().map(|b| b.header_hash()).collect();
    let chainhash = hex(&chain_digest(
        &header_hashes.iter().map(|h| h.to_vec()).collect::<Vec<_>>(),
    ));
    let block_hashes = header_hashes.iter().map(|h| hex(h)).collect::<Vec<_>>();

    let report = RunReport {
        idx,
        per_block_ms,
        finalized_tx,
        consensus_ms,
        sign_ms,
        fill_ms,
        committee,
        heights,
        rotations,
        chainhash,
        block_hashes,
        stalled,
        phase_wait_ms,
        phase_build_ms,
        phase_verify_ms,
        phase_aggregate_ms,
        phase_finalise_ms,
        phase_flood_ms,
    };
    println!("{}", format_result(&report));
    std::io::stdout().flush().expect("flush the result line");
}
