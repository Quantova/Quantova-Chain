//! One validator of the wide area run, in its own operating system process on its own
//! host.
//!
//! This is the loopback validator with the localhost peer addresses replaced by real
//! addresses read from configuration. The process holds exactly one real validator: its
//! own module lattice key, its own state and store, and its own share of the round. It
//! reads its own listen address and its peers' real addresses from the environment the
//! deploy script sets, binds the single fixed transport port, and connects to the other
//! hosts over the real qtv-net post quantum channel, an ML-KEM and ML-DSA handshake with
//! a ChaCha20-Poly1305 record layer. Run across regions, the compute runs in parallel
//! across hosts exactly as the loopback run runs it across processes, and the sealed
//! records now cross real wide area links, so the run measures real propagation on top
//! of the parallelism the loopback run already measured.
//!
//! WHAT IS REAL HERE. The validator is a real qtv-devnet DevNode over the exact chain
//! and consensus crates the loopback and in process runs use, not a reimplementation.
//! The committee is the real qtv-sampler one time key sortition of consensus v0.5.0 with
//! the stake floor on. Blocks are built by the real leader, executed through the real
//! virtual machine to a real state root, attested with real module lattice signatures
//! over the real one time membership credential, and finalised by a real aggregated
//! certificate every host verifies. The proposal is disseminated as its real erasure
//! coded shards under a SHA3 commitment and rebuilt from any k. Every transaction carries
//! a real module lattice signature and is verified on ingress. Every mesh byte crosses a
//! real qtv-net socket sealed and opened, not an in memory duplex.
//!
//! WHAT THE SOCKETS ARE, STATED PLAINLY. The sockets are real TCP over whatever the
//! configuration addresses point at. Deployed across regions they carry real inter host
//! propagation. Validated on one host over localhost, as the harness is validated before
//! any host is provisioned, they carry near zero propagation, so a local figure is a
//! loopback multi process figure over real sockets with near zero propagation and is not
//! a network number. The qtv-net channel is the real post quantum secure channel over a
//! reliable byte stream; it is not the full QUIC transport, and qtv-net's own notes name
//! the UDP datagram layer, multiplexed streams, congestion control, and loss recovery as
//! not yet built, so a wide area run measures the transport that exists.

use std::io::Write;
use std::net::TcpListener;
use std::time::Duration;

use qtv_devnet::node::net_identity;
use qtv_devnet::DevNode;

use qtv_loopback::{
    accounts, build_batch, chain_digest, devnet_config, hex, recipients, transfer_fee,
};
use qtv_widearea::env as wenv;
use qtv_widearea::runtime::{build_mesh, HeightOutcome, PhaseTimers, Runtime};
use qtv_widearea::{env_usize, format_result, RunReport};

/// The port of a `host:port` address, the one this process binds. The host part names
/// how peers reach this host, not how this host binds, so only the port is taken and
/// the listener binds every interface.
fn port_of(addr: &str) -> u16 {
    addr.rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .expect("the address is host:port with a numeric port")
}

/// The up set as a boolean per index, from a comma separated index list, or every
/// index up when the list is absent.
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

    // Bind the single fixed transport port on every interface, so a peer reaches this
    // host on the one open port whatever interface the connection lands on.
    let port = port_of(&addrs[idx]);
    let listener =
        TcpListener::bind(("0.0.0.0", port)).expect("bind the transport port on every interface");

    let identity = net_identity(idx as u64 + 1);
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
                // A stall in warmup is the online set below the supermajority, reported
                // as a stall with no figure rather than a fabricated number.
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

    // The measured sustained run: drive a shared number of measured heights, the same
    // count on every host, so the up hosts stop together in lockstep and no host is
    // stranded mid height when a peer that finished first closes its sockets. A stall
    // breaks the run and is reported as a stall with the partial finalised count, never
    // as a throughput number.
    let mut per_block_ms: Vec<f64> = Vec::new();
    let mut finalized_tx: u64 = 0;
    let mut consensus_ms = 0.0f64;
    let mut sign_ms = 0.0f64;
    let mut heights: u64 = 0;
    let mut rotations: u64 = 0;
    let mut stalled = false;
    // The per phase wall clock, accumulated over exactly the measured heights that feed
    // consensus_ms, so the five phases plus the derived remainder sum to it.
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
            } => {
                // A finalised height advanced the chain. A height that carried the full
                // batch is a measured sample; a rare empty height, which a spurious
                // rotation can build before the batch lands, still advanced the chain but
                // carries no transactions, so it is skipped in the accounting rather than
                // counted or mistaken for a stall. Only a genuine stall, no quorum, ends
                // the run.
                if txs > 0 {
                    sign_ms += sign_dt.as_secs_f64() * 1000.0;
                    consensus_ms += elapsed.as_secs_f64() * 1000.0;
                    per_block_ms.push(elapsed.as_secs_f64() * 1000.0);
                    finalized_tx += txs as u64;
                    heights += 1;
                    // Accumulate the phase split alongside consensus_ms, on the same
                    // measured heights, so the totals cover the whole timed run.
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

    let encoded: Vec<Vec<u8>> = rt.node.chain().iter().map(|b| b.encoded()).collect();
    let chainhash = hex(&chain_digest(&encoded));
    let block_hashes = encoded
        .iter()
        .map(|b| hex(&qtv_devnet::wire::gossip_id(b)))
        .collect::<Vec<_>>();

    let report = RunReport {
        idx,
        per_block_ms,
        finalized_tx,
        consensus_ms,
        sign_ms,
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
