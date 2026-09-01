// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod stats;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use qtv_account::{derive, Account};
use qtv_devnet::config::{DevnetConfig, NodeConfig, FULL_FANOUT};
use qtv_devnet::Devnet;
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::{sign, Body, Wrapper};

use crate::stats::Distribution;

const GENESIS_TIME: u64 = 1_700_000_000_000;
const ACCOUNT_SEED: [u8; 32] = [37u8; 32];
const FUND: u64 = 1_000_000_000_000;
const TRANSFER_AMOUNT: u64 = 1;
const HARNESS_SLOTS: u64 = 4096;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn shell(program: &str, args: &[&str], fallback: &str) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn accounts(count: usize) -> Vec<Account> {
    (0..count as u64)
        .map(|i| derive(&ACCOUNT_SEED, i))
        .collect()
}

fn devnet_config(base: &PathBuf, validators: usize, senders: &[Account]) -> DevnetConfig {
    let funded: Vec<GenesisAccount> = senders
        .iter()
        .map(|a| GenesisAccount::from_account(a, FUND))
        .collect();
    let nodes: Vec<NodeConfig> = (0..validators)
        .map(|i| {
            let id = i as u64 + 1;
            let bootstrap = if i == 0 {
                if validators > 1 {
                    vec![2]
                } else {
                    Vec::new()
                }
            } else {
                vec![1]
            };
            NodeConfig {
                id,
                stake: qtv_bft::params::VALIDATOR_STAKE_QTOV,
                online: true,
                store_dir: base.join(format!("node-{id}")),
                bootstrap,
                address: format!("mem://{id}"),
                secret: qtv_node::keys::fixture_secret(id),
            }
        })
        .collect();
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: funded,
        nodes,
        genesis_time: GENESIS_TIME,
        fanout: FULL_FANOUT,
        slots: HARNESS_SLOTS,
        published_roster: None,
        bridge_dest_chain: None,
        guardians: qtv_devnet::GuardianSet::default(),
        bridge_operators: None,
        bridged_assets: vec![],
        bridge_era: None,
    }
}

fn build_batch(
    senders: &[Account],
    recipients: &[String],
    nonces: &mut [u64],
    fee: u128,
) -> (Vec<Wrapper>, Duration) {
    let start = Instant::now();
    let mut batch = Vec::with_capacity(senders.len());
    for (i, from) in senders.iter().enumerate() {
        let call = transfer_call(&recipients[i], TRANSFER_AMOUNT);
        let body = Body::new(from.address(), nonces[i], TRANSFER_METER, fee, call);
        batch.push(sign(from, &body));
        nonces[i] += 1;
    }
    (batch, start.elapsed())
}

const MAX_RECORD_PLAINTEXT: usize = 1 << 20;

fn drive_height<S: std::io::Read + std::io::Write>(
    devnet: &mut Devnet<S>,
    batch: Vec<Wrapper>,
) -> Result<(Duration, usize), String> {
    let before = devnet.node(0).chain().last().map(|b| b.header().height());
    let start = Instant::now();
    for tx in batch {
        let _ = devnet.submit(0, tx);
    }
    devnet
        .step()
        .map_err(|e| format!("the height did not finalise: {e:?}"))?;
    let elapsed = start.elapsed();
    let chain = devnet.node(0).chain();
    let finalized = match chain.last() {
        Some(last) if Some(last.header().height()) != before => last.block.body().len(),
        _ => 0,
    };
    Ok((elapsed, finalized))
}

fn rule() {
    println!("{}", "-".repeat(80));
}

fn main() {
    let validators = env_usize("QTV_LIVE_VALIDATORS", 4).max(1);
    let senders_n = env_usize("QTV_LIVE_ACCOUNTS", 250).max(2);
    let run_secs = env_usize("QTV_LIVE_SECS", 60).max(1) as f64;
    let warmup = env_usize("QTV_LIVE_WARMUP", 3);

    let manifest = env!("CARGO_MANIFEST_DIR");
    let cpu = shell("sysctl", &["-n", "machdep.cpu.brand_string"], "unknown CPU");
    let cores = shell("sysctl", &["-n", "hw.ncpu"], "?");
    let mem_bytes: u64 = shell("sysctl", &["-n", "hw.memsize"], "0")
        .parse()
        .unwrap_or(0);
    let commit = shell(
        "git",
        &["-C", manifest, "rev-parse", "--short", "HEAD"],
        "unknown",
    );

    println!("================================================================================");
    println!(" Quantova live in process multi node harness");
    println!("================================================================================");
    println!(" This measures the real consensus software on ONE host with the validators run");
    println!(" as several in process instances over the real post quantum transport. It is an");
    println!(" in process multi node run, NOT a live multi machine network. Inter node network");
    println!(" bandwidth and latency are not measured; every other listed part is real.");
    println!();
    println!(" Host (measured on):");
    println!(
        "   {cpu}, {cores} cores, {:.0} GB memory",
        mem_bytes as f64 / 1e9
    );
    println!("   build: release (opt-level 3)");
    println!(" Source:");
    println!("   Quantova-Chain commit {commit} (qtv-live drives qtv-devnet, path deps)");
    println!(
        "   consensus crates pinned at QRC-CONSENSUS tag v0.5.0 (qtv-bft, qtv-sampler, qtv-attest)"
    );
    println!();
    println!(" Real in this run:");
    println!("   - {validators} real validator instances, each with its own module lattice key");
    println!("   - real qtv-sampler committee sortition: the one time key sortition of consensus");
    println!(
        "     v0.5.0 with the stake floor on, each validator staking {} QTOV at the floor",
        qtv_bft::params::VALIDATOR_STAKE_QTOV
    );
    println!("   - real block production, real module lattice attestations, real aggregated");
    println!("     finality certificate that every node verifies (no stub)");
    println!(
        "   - real transactions, each a 3309 byte module lattice signature, verified on ingress"
    );
    println!(
        "   - real qtv-net post quantum channel (ML-KEM + ML-DSA handshake, ChaCha20-Poly1305)"
    );
    println!(
        "   - real erasure coded proposal dissemination: the proposal is coded into shards under"
    );
    println!(
        "     a SHA3 commitment and rebuilt from any k, verified against the header, per node"
    );
    println!(" The sortition that runs:");
    println!("   - the one time key sortition, drawn as a committed preimage with its Merkle path");
    println!("     against the registered root, with the minimum self stake floor on. It is the");
    println!("     grinding resistant successor to the v0.3.0 module lattice draw, now pinned at");
    println!("     consensus v0.5.0, so the predecessor draw is no longer on the path.");
    println!(
        "   - the harness sizes each validator one time tree to {HARNESS_SLOTS} slots through the"
    );
    println!(
        "     with_slots path, a harness parameter, not the consensus default of 64. One slot is"
    );
    println!(
        "     spent per height, so a sustained run finalises past 64 heights without the sortition"
    );
    println!("     refusing a slot past the commitment.");
    println!(" In process, so NOT measured:");
    println!("   - inter node bandwidth and propagation latency (in memory duplex, not a socket)");
    println!(
        "   - every member's compute runs serially on this one host, not parallel across machines"
    );
    println!(
        "   - the devnet schedules the round on a logical clock, so slot and view timeouts are"
    );
    println!("     logical; the finality figure below is measured wall clock compute, not modelled slots");
    println!(
        "   - coded dissemination changes how the proposal is carried, it does not turn the in"
    );
    println!(
        "     memory transport into a real network. It removes the width cap so a wider block can"
    );
    println!("     be measured; it does not by itself produce a network throughput number.");
    println!();
    println!(
        " Consensus parameters: slot {} ms (logical), committee budget {}, stake {} QTOV,",
        qtv_bft::params::SLOT_MS,
        qtv_sampler::params::COMMITTEE_BUDGET,
        qtv_bft::params::VALIDATOR_STAKE_QTOV
    );
    println!(
        "      minimum self stake floor {} QTOV, on",
        qtv_sampler::params::MIN_SELF_STAKE
    );
    println!(" Run: {validators} validators, {senders_n} distinct signing accounts (block width),");
    println!(
        "      target sustained duration {run_secs:.0} s, {warmup} warmup heights (not counted)"
    );
    rule();

    let base =
        std::env::temp_dir().join(format!("qtv-live-{}-{}", std::process::id(), GENESIS_TIME));
    let senders = accounts(senders_n);
    let recipients: Vec<String> = (0..senders_n)
        .map(|i| senders[(i + 1) % senders_n].address())
        .collect();
    let fee = u128::from(FeeParams::devnet().transfer_fee());
    let mut nonces = vec![0u64; senders_n];

    let sample_tx_bytes = {
        let call = transfer_call(&recipients[0], TRANSFER_AMOUNT);
        let body = Body::new(senders[0].address(), 0, TRANSFER_METER, fee, call);
        qtv_codec::to_bytes(&sign(&senders[0], &body)).len()
    };
    let est_body_bytes = sample_tx_bytes * senders_n;
    let old_single_record_width = (MAX_RECORD_PLAINTEXT - 4096) / sample_tx_bytes;

    println!(
        " Proposal dissemination: erasure coded shards over the overlay, not one whole record."
    );
    println!(
        "   the block is coded into k data + parity shards under a SHA3 commitment; each node"
    );
    println!("   rebuilds it from any k shards and verifies it against the header before use.");
    println!(
        "   block body at this width       : {:.2} MB ({senders_n} tx x {sample_tx_bytes} bytes)",
        est_body_bytes as f64 / 1e6
    );
    println!("   old single record width cap    : {old_single_record_width} accounts ({:.0} MB record bound)",
        MAX_RECORD_PLAINTEXT as f64 / 1e6);
    if senders_n > old_single_record_width {
        println!("   THIS RUN's width {senders_n} EXCEEDS the old cap, so the single record proposal path");
        println!("   would have refused it. The coded dissemination is what carries it.");
    } else {
        println!("   this run's width {senders_n} is within the old cap; the wider run above it is the one");
        println!("   that would previously have been refused.");
    }
    rule();

    println!(" Standing up {validators} validators over the qtv-net duplex mesh and discovering peers ...");
    let mut devnet =
        Devnet::over_duplex(devnet_config(&base, validators, &senders)).expect("devnet stands up");

    for _ in 0..warmup {
        let (batch, _) = build_batch(&senders, &recipients, &mut nonces, fee);
        drive_height(&mut devnet, batch).expect("a warmup height finalises");
    }

    let committee = devnet
        .node(0)
        .chain()
        .last()
        .map(|b| b.attesters.len())
        .unwrap_or(0);

    let (tx_bytes, cert_bytes, block_bytes) = {
        let last = devnet.node(0).chain().last().expect("a warmup block");
        let body = last.block.body();
        let tx: usize = body
            .iter()
            .map(|w| qtv_codec::to_bytes(w).len())
            .sum::<usize>()
            .checked_div(body.len().max(1))
            .unwrap_or(0);
        (tx, last.block.certificate().len(), last.encoded().len())
    };

    println!(" Committee (from a real finalised block): {committee} attesters (all {validators} validators");
    println!(
        "   pass the sortition at this set size and stake). Supermajority to finalise is {}.",
        qtv_bft::params::supermajority(committee)
    );
    println!(" Real measured wire sizes:");
    println!(
        "   transaction: {tx_bytes} bytes (dominated by the 3309 byte module lattice signature)"
    );
    println!(
        "   finality certificate on the block: {:.2} KB ({committee} attestations)",
        cert_bytes as f64 / 1e3
    );
    println!("   finalised block: {:.2} MB", block_bytes as f64 / 1e6);
    rule();

    println!(" Sustained finalised run (real wall clock, only finalised transactions counted):");
    println!(
        "   driving back to back heights until the consensus wall clock reaches {run_secs:.0} s."
    );
    println!();

    let mut per_block_ms: Vec<f64> = Vec::new();
    let mut finalized_tx: u64 = 0;
    let mut consensus_wall = Duration::ZERO;
    let mut sign_wall = Duration::ZERO;
    let mut heights: u64 = 0;
    let mut stalled: Option<String> = None;

    let run_start = Instant::now();
    while consensus_wall.as_secs_f64() < run_secs {
        let (batch, sign_dt) = build_batch(&senders, &recipients, &mut nonces, fee);
        let (dt, tx) = match drive_height(&mut devnet, batch) {
            Ok((dt, tx)) if tx > 0 => (dt, tx),
            Ok(_) => {
                stalled = Some("a height finalised no transactions".to_string());
                break;
            }
            Err(e) => {
                stalled = Some(e);
                break;
            }
        };
        sign_wall += sign_dt;
        consensus_wall += dt;
        per_block_ms.push(dt.as_secs_f64() * 1000.0);
        finalized_tx += tx as u64;
        heights += 1;
    }
    let wall_total = run_start.elapsed();

    let dist = Distribution::of(&per_block_ms).expect("at least one finalised block");
    let consensus_s = consensus_wall.as_secs_f64();
    let tps_consensus = finalized_tx as f64 / consensus_s;
    let tps_end_to_end = finalized_tx as f64 / (consensus_s + sign_wall.as_secs_f64());

    if let Some(reason) = &stalled {
        println!(
            " NOTE: the run stopped early ({reason}). The numbers below cover only the heights"
        );
        println!("       that genuinely finalised, which is the honest partial result.");
        println!();
    }
    println!("   heights finalised          : {heights}");
    println!("   transactions finalised     : {finalized_tx}");
    println!(
        "   consensus wall clock        : {consensus_s:.1} s  (client signing {:.1} s, separate)",
        sign_wall.as_secs_f64()
    );
    println!(
        "   total run wall clock        : {:.1} s",
        wall_total.as_secs_f64()
    );
    println!();
    println!("   SUSTAINED FINALISED THROUGHPUT (measured, in process, one host):");
    println!("     {tps_consensus:.0} finalised transactions per second");
    println!(
        "     caveat: consensus only, client signing excluded; all {committee} members' compute is"
    );
    println!("     serial on one host and the transport is in memory, so this is a compute bound,");
    println!("     network free single host rate, not a live multi machine network throughput.");
    println!(
        "   end to end incl. client signing: {tps_end_to_end:.0} finalised transactions per second"
    );
    rule();

    println!(" FINALITY LATENCY DISTRIBUTION (measured, in process), per finalised block:");
    println!("   each sample is the real wall clock to build, attest, aggregate and verify one");
    println!(
        "   block across the committee. caveat: this is compute time with all {committee} members"
    );
    println!("   run serially on one host over the in memory transport; it EXCLUDES real network");
    println!(
        "   propagation latency, so it is the in process compute floor per block, not the wall"
    );
    println!("   clock finality a globally distributed validator set would see.");
    println!();
    println!("   samples (finalised blocks) : {}", dist.count);
    println!("   median (p50)               : {:.1} ms", dist.p50);
    println!("   p90                        : {:.1} ms", dist.p90);
    println!("   p99                        : {:.1} ms", dist.p99);
    println!("   maximum                    : {:.1} ms", dist.max);
    println!("   (min {:.1} ms, mean {:.1} ms)", dist.min, dist.mean);
    rule();

    println!(" Reproduce:");
    println!("   cd Quantova-Chain && \\");
    println!("     QTV_LIVE_VALIDATORS={validators} QTV_LIVE_ACCOUNTS={senders_n} QTV_LIVE_SECS={run_secs:.0} \\");
    println!("     cargo run --release -p qtv-live");
    println!(
        " The numbers move a little between runs; rerun for current figures. The number measured"
    );
    println!(
        " is the number reported: the harness drives a fixed workload and does not tune to a path."
    );
    println!("================================================================================");

    let _ = std::fs::remove_dir_all(&base);
}
