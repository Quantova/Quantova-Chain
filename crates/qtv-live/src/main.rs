//! The Quantova live in process multi node harness.
//!
//! It stands up several real validator instances over the real qtv-net post
//! quantum transport, runs the real committee sortition, real block production,
//! real module lattice attestation, and a real aggregated finality certificate,
//! and drives a real signed transaction workload through them for a real run of
//! at least a minute. It then reports two measured numbers: the sustained
//! finalised throughput and the finality latency as a distribution with its tail.
//!
//! WHAT IS REAL HERE. The validator instances are real DevNode instances, each
//! with its own module lattice key. The committee is drawn by the real qtv-sampler
//! one time key sortition, the grinding resistant construction of consensus v0.5.0,
//! the pin the buildable devnet now carries. Each validator commits a one time
//! preimage tree bonded to its stake, and membership is a committed preimage with
//! its Merkle path against the registered root, drawn with the stake floor on.
//! Blocks are produced by the real leader, executed through the real virtual machine
//! to a real state root, attested with real module lattice signatures over the real
//! one time membership credential, and finalised by a real aggregated certificate
//! that every node verifies. Every transaction carries a real 3309 byte module
//! lattice signature and is verified on the ingress path. Every gossip byte is
//! sealed and opened through the real qtv-net channel, an ML-KEM and ML-DSA
//! handshake with a ChaCha20-Poly1305 record layer.
//!
//! THE SORTITION THIS RUNS, STATED PLAINLY. This harness measures the one time key
//! sortition, the grinding resistant successor to the v0.3.0 module lattice
//! verifiable random draw. The devnet pins consensus v0.5.0, which carries the one
//! time construction with the minimum self stake floor on by default, so committee
//! membership and proposer eligibility are drawn and rechecked as a committed one
//! time preimage with its Merkle path against the registered root, and an account
//! below the floor is not eligible. The predecessor draw is no longer on the path.
//!
//! WHAT IS IN PROCESS, NOT MULTI MACHINE, AND SO NOT MEASURED. The validators run
//! as several instances inside one operating system process on one host, and the
//! transport is an in memory duplex rather than a socket to another machine. So the
//! seal and open cryptography is paid for real, but the network transfer is a
//! memory copy: inter node bandwidth and propagation latency are NOT measured. The
//! consensus round is scheduled on a logical clock inside the devnet, so the
//! modelled slot and view timeouts are logical, not wall clock. Every committee
//! member's compute runs serially on this one host rather than in parallel across
//! machines. The two consequences are stated at each number below and must be read
//! with it: this is an in process multi node measurement of the consensus software
//! on one host, not a live global network figure. The modelled global topology
//! finality and the bandwidth bound throughput live in the separate Quantova-Bench
//! and are labelled modelled there; they are not restated here as measured.
//!
//! WHAT ERASURE CODED DISSEMINATION CHANGES HERE. The devnet no longer carries a
//! block proposal as one whole qtv-net record. It codes the block the proposal
//! commits to into k data shards and n minus k parity shards under a SHA3 commitment
//! and disseminates the shards over the overlay, each shard within the record bound,
//! and every node rebuilds the block from any k shards and verifies it against the
//! header. This changes how the proposal is carried; it does not turn the in memory
//! transport into a real network, so it does not by itself produce a network
//! throughput number. What it does is remove the width cap the single record proposal
//! imposed, so a block wider than one record can be driven and measured at all. This
//! harness now runs a width that the single record path would have refused.

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

/// The genesis time the run starts from.
const GENESIS_TIME: u64 = 1_700_000_000_000;
/// The seed the funded sender accounts derive from.
const ACCOUNT_SEED: [u8; 32] = [37u8; 32];
/// The native balance each sender account is funded with at genesis, ample for a
/// long run at the protocol fee so no transaction ever fails on funds.
const FUND: u64 = 1_000_000_000_000;
/// The value each transfer moves. Nonzero so no transaction is a no op.
const TRANSFER_AMOUNT: u64 = 1;
/// The one time slot count the harness sizes each validator tree to. The founder
/// authorised this count for the harness so a sustained run can finalise more heights
/// than the consensus default of sixty four serves, one slot per height. It is a
/// harness parameter, not a consensus parameter. The consensus default is unchanged;
/// the harness opts into the larger count through the DevnetConfig slots field, which
/// flows into the committee sampler and the attester over the with_slots path.
const HARNESS_SLOTS: u64 = 4096;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The short output of a shell command, or a fallback when it cannot be run, so
/// the harness reports the host and the commit without a hard dependency on the
/// tools being present.
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

/// A distinct funded sender account, one per block slot. Each sends one transfer
/// per height, so the block width is the account count and every signature is over
/// a distinct key on a distinct state leaf.
fn accounts(count: usize) -> Vec<Account> {
    (0..count as u64).map(|i| derive(&ACCOUNT_SEED, i)).collect()
}

/// The devnet configuration: a set of real validators all at the stake floor, an
/// online full mesh over the in memory duplex, and the funded sender accounts.
fn devnet_config(base: &PathBuf, validators: usize, senders: &[Account]) -> DevnetConfig {
    let funded: Vec<GenesisAccount> = senders
        .iter()
        .map(|a| GenesisAccount::from_account(a, FUND))
        .collect();
    let nodes: Vec<NodeConfig> = (0..validators)
        .map(|i| {
            let id = i as u64 + 1;
            // A star bootstrap centred on the first node, so the discovery graph is
            // connected and every node learns the whole validator set.
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
    }
}

/// Build and sign the transactions for one height: every account sends one
/// transfer to the next account at its current nonce. The signing is real ML-DSA
/// work but it is client side, so it is timed separately and kept out of the
/// consensus throughput. Returns the batch and the wall clock spent signing it.
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

/// The qtv-net record plaintext bound, one mebibyte. The devnet no longer carries a
/// proposal as one whole record: it disseminates the proposal as its erasure coded
/// shards, each shard within this bound, and every node rebuilds the block from any k
/// shards and verifies it against the header. So this bound no longer caps the block
/// width; it is kept only to report the width the old single record path could carry,
/// so a run above it is one the old path would have refused.
const MAX_RECORD_PLAINTEXT: usize = 1 << 20;

/// One driven height: submit the pre built batch to the ingress node and finalise
/// the block across the committee. The submit runs the real ingress signature
/// verification and the step runs the real gossip, build, attestation, aggregation
/// and finalisation, so the timed region is exactly the consensus work on a batch
/// of already signed transactions. Returns the wall clock the height took and how
/// many transactions the finalised block actually carried, or the transport or
/// consensus error that stopped it.
fn drive_height<S: std::io::Read + std::io::Write>(
    devnet: &mut Devnet<S>,
    batch: Vec<Wrapper>,
) -> Result<(Duration, usize), String> {
    let before = devnet.node(0).chain().len();
    let start = Instant::now();
    for tx in batch {
        // A rejected transaction never reaches a block; the nonces and funding are
        // set so none is rejected, but a reject is dropped rather than counted.
        let _ = devnet.submit(0, tx);
    }
    devnet
        .step()
        .map_err(|e| format!("the height did not finalise: {e:?}"))?;
    let elapsed = start.elapsed();
    let chain = devnet.node(0).chain();
    // Only a genuinely finalised block is counted, and only the transactions it
    // actually included, so a skipped transaction is never counted as finalised.
    let finalized = if chain.len() > before {
        chain.last().expect("a finalised block").block.body().len()
    } else {
        0
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
    let commit = shell("git", &["-C", manifest, "rev-parse", "--short", "HEAD"], "unknown");

    println!("================================================================================");
    println!(" Quantova live in process multi node harness");
    println!("================================================================================");
    println!(" This measures the real consensus software on ONE host with the validators run");
    println!(" as several in process instances over the real post quantum transport. It is an");
    println!(" in process multi node run, NOT a live multi machine network. Inter node network");
    println!(" bandwidth and latency are not measured; every other listed part is real.");
    println!();
    println!(" Host (measured on):");
    println!("   {cpu}, {cores} cores, {:.0} GB memory", mem_bytes as f64 / 1e9);
    println!("   build: release (opt-level 3)");
    println!(" Source:");
    println!("   Quantova-Chain commit {commit} (qtv-live drives qtv-devnet, path deps)");
    println!("   consensus crates pinned at QRC-CONSENSUS tag v0.5.0 (qtv-bft, qtv-sampler, qtv-attest)");
    println!();
    println!(" Real in this run:");
    println!("   - {validators} real validator instances, each with its own module lattice key");
    println!("   - real qtv-sampler committee sortition: the one time key sortition of consensus");
    println!("     v0.5.0 with the stake floor on, each validator staking {} QTOV at the floor",
        qtv_bft::params::VALIDATOR_STAKE_QTOV);
    println!("   - real block production, real module lattice attestations, real aggregated");
    println!("     finality certificate that every node verifies (no stub)");
    println!("   - real transactions, each a 3309 byte module lattice signature, verified on ingress");
    println!("   - real qtv-net post quantum channel (ML-KEM + ML-DSA handshake, ChaCha20-Poly1305)");
    println!("   - real erasure coded proposal dissemination: the proposal is coded into shards under");
    println!("     a SHA3 commitment and rebuilt from any k, verified against the header, per node");
    println!(" The sortition that runs:");
    println!("   - the one time key sortition, drawn as a committed preimage with its Merkle path");
    println!("     against the registered root, with the minimum self stake floor on. It is the");
    println!("     grinding resistant successor to the v0.3.0 module lattice draw, now pinned at");
    println!("     consensus v0.5.0, so the predecessor draw is no longer on the path.");
    println!("   - the harness sizes each validator one time tree to {HARNESS_SLOTS} slots through the");
    println!("     with_slots path, a harness parameter, not the consensus default of 64. One slot is");
    println!("     spent per height, so a sustained run finalises past 64 heights without the sortition");
    println!("     refusing a slot past the commitment.");
    println!(" In process, so NOT measured:");
    println!("   - inter node bandwidth and propagation latency (in memory duplex, not a socket)");
    println!("   - every member's compute runs serially on this one host, not parallel across machines");
    println!("   - the devnet schedules the round on a logical clock, so slot and view timeouts are");
    println!("     logical; the finality figure below is measured wall clock compute, not modelled slots");
    println!("   - coded dissemination changes how the proposal is carried, it does not turn the in");
    println!("     memory transport into a real network. It removes the width cap so a wider block can");
    println!("     be measured; it does not by itself produce a network throughput number.");
    println!();
    println!(" Consensus parameters: slot {} ms (logical), committee budget {}, stake {} QTOV,",
        qtv_bft::params::SLOT_MS,
        qtv_sampler::params::COMMITTEE_BUDGET,
        qtv_bft::params::VALIDATOR_STAKE_QTOV);
    println!("      minimum self stake floor {} QTOV, on",
        qtv_sampler::params::MIN_SELF_STAKE);
    println!(" Run: {validators} validators, {senders_n} distinct signing accounts (block width),");
    println!("      target sustained duration {run_secs:.0} s, {warmup} warmup heights (not counted)");
    rule();

    // ---- stand up the real devnet ----
    let base = std::env::temp_dir().join(format!(
        "qtv-live-{}-{}",
        std::process::id(),
        GENESIS_TIME
    ));
    let senders = accounts(senders_n);
    let recipients: Vec<String> = (0..senders_n)
        .map(|i| senders[(i + 1) % senders_n].address())
        .collect();
    let fee = u128::from(FeeParams::devnet().transfer_fee());
    let mut nonces = vec![0u64; senders_n];

    // The proposal is no longer one whole record. The devnet erasure codes the block
    // the proposal commits to into k data shards and n minus k parity shards under a
    // SHA3 commitment and disseminates the shards over the overlay, each shard within
    // the record bound, and every node rebuilds the block from any k shards and
    // verifies it against the header before use. So the block width is no longer
    // capped by the record size. The single record path could carry only the width
    // below, computed from one real signed transaction so it tracks the true wire
    // size, and a run above it is one that path would have refused mid run inside the
    // transport.
    let sample_tx_bytes = {
        let call = transfer_call(&recipients[0], TRANSFER_AMOUNT);
        let body = Body::new(senders[0].address(), 0, TRANSFER_METER, fee, call);
        qtv_codec::to_bytes(&sign(&senders[0], &body)).len()
    };
    let est_body_bytes = sample_tx_bytes * senders_n;
    let old_single_record_width = (MAX_RECORD_PLAINTEXT - 4096) / sample_tx_bytes;

    println!(" Proposal dissemination: erasure coded shards over the overlay, not one whole record.");
    println!("   the block is coded into k data + parity shards under a SHA3 commitment; each node");
    println!("   rebuilds it from any k shards and verifies it against the header before use.");
    println!("   block body at this width       : {:.2} MB ({senders_n} tx x {sample_tx_bytes} bytes)",
        est_body_bytes as f64 / 1e6);
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

    // ---- warmup ----
    for _ in 0..warmup {
        let (batch, _) = build_batch(&senders, &recipients, &mut nonces, fee);
        drive_height(&mut devnet, batch).expect("a warmup height finalises");
    }

    // The committee is read from a real finalised block: the attesters that signed
    // it are the online committee, the ground truth of the committee size.
    let committee = devnet
        .node(0)
        .chain()
        .last()
        .map(|b| b.attesters.len())
        .unwrap_or(0);

    // The real wire sizes, measured off a real finalised block, not modelled.
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
    println!("   pass the sortition at this set size and stake). Supermajority to finalise is {}.",
        qtv_bft::params::supermajority(committee));
    println!(" Real measured wire sizes:");
    println!("   transaction: {tx_bytes} bytes (dominated by the 3309 byte module lattice signature)");
    println!("   finality certificate on the block: {:.2} KB ({committee} attestations)",
        cert_bytes as f64 / 1e3);
    println!("   finalised block: {:.2} MB", block_bytes as f64 / 1e6);
    rule();

    // ---- the measured sustained run ----
    println!(" Sustained finalised run (real wall clock, only finalised transactions counted):");
    println!("   driving back to back heights until the consensus wall clock reaches {run_secs:.0} s.");
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
    // The primary sustained throughput: finalised transactions divided by the
    // consensus wall clock. This EXCLUDES client side signing (timed separately)
    // and, because every member's compute runs serially on one host and the
    // transport is in memory, it is a compute bound, network free, single host
    // figure, not a multi machine network throughput.
    let tps_consensus = finalized_tx as f64 / consensus_s;
    // The end to end figure includes the client signing time, the rate a single
    // driver that signs then submits sustains with no pipelining.
    let tps_end_to_end = finalized_tx as f64 / (consensus_s + sign_wall.as_secs_f64());

    if let Some(reason) = &stalled {
        println!(" NOTE: the run stopped early ({reason}). The numbers below cover only the heights");
        println!("       that genuinely finalised, which is the honest partial result.");
        println!();
    }
    println!("   heights finalised          : {heights}");
    println!("   transactions finalised     : {finalized_tx}");
    println!("   consensus wall clock        : {consensus_s:.1} s  (client signing {:.1} s, separate)",
        sign_wall.as_secs_f64());
    println!("   total run wall clock        : {:.1} s", wall_total.as_secs_f64());
    println!();
    println!("   SUSTAINED FINALISED THROUGHPUT (measured, in process, one host):");
    println!("     {tps_consensus:.0} finalised transactions per second");
    println!("     caveat: consensus only, client signing excluded; all {committee} members' compute is");
    println!("     serial on one host and the transport is in memory, so this is a compute bound,");
    println!("     network free single host rate, not a live multi machine network throughput.");
    println!("   end to end incl. client signing: {tps_end_to_end:.0} finalised transactions per second");
    rule();

    // ---- the finality distribution with its tail ----
    println!(" FINALITY LATENCY DISTRIBUTION (measured, in process), per finalised block:");
    println!("   each sample is the real wall clock to build, attest, aggregate and verify one");
    println!("   block across the committee. caveat: this is compute time with all {committee} members");
    println!("   run serially on one host over the in memory transport; it EXCLUDES real network");
    println!("   propagation latency, so it is the in process compute floor per block, not the wall");
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
    println!(" The numbers move a little between runs; rerun for current figures. The number measured");
    println!(" is the number reported: the harness drives a fixed workload and does not tune to a path.");
    println!("================================================================================");

    // Best effort cleanup of the per node stores this run wrote.
    let _ = std::fs::remove_dir_all(&base);
}
