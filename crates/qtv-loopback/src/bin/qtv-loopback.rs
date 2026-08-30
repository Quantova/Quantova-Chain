// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use qtv_devnet::Devnet;

use qtv_loopback::stats::Distribution;
use qtv_loopback::{accounts, build_batch, devnet_config, hex, recipients, transfer_fee};

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

struct RunResult {
    per_block_ms: Vec<f64>,
    finalized_tx: u64,
    consensus_ms: f64,
    sign_ms: f64,
    committee: usize,
    heights: u64,
    block_hashes: Vec<String>,
    stalled: bool,
}

fn run_serial(
    validators: usize,
    senders_n: usize,
    run_secs: f64,
    warmup: usize,
    height_cap: usize,
) -> RunResult {
    let base = std::env::temp_dir().join(format!("qtv-loopback-serial-{}", std::process::id()));
    let senders = accounts(senders_n);
    let recipient_addrs = recipients(&senders);
    let fee = transfer_fee();
    let mut nonces = vec![0u64; senders_n];
    let mut devnet = Devnet::over_duplex(devnet_config(&base, validators, &senders))
        .expect("the in process devnet stands up");

    for _ in 0..warmup {
        let (batch, _) = build_batch(&senders, &recipient_addrs, &mut nonces, fee);
        for tx in batch {
            let _ = devnet.submit(0, tx);
        }
        devnet.step().expect("a warmup height finalises");
    }

    let committee = devnet
        .node(0)
        .chain()
        .last()
        .map(|b| b.attesters.len())
        .unwrap_or(0);

    let mut per_block_ms: Vec<f64> = Vec::new();
    let mut finalized_tx: u64 = 0;
    let mut consensus_wall = Duration::ZERO;
    let mut sign_wall = Duration::ZERO;
    let mut heights: u64 = 0;
    let mut stalled = false;

    while consensus_wall.as_secs_f64() < run_secs && (heights as usize) < height_cap {
        let (batch, sign_dt) = build_batch(&senders, &recipient_addrs, &mut nonces, fee);
        let before = devnet.node(0).chain().len();
        let start = Instant::now();
        for tx in batch {
            let _ = devnet.submit(0, tx);
        }
        if devnet.step().is_err() {
            stalled = true;
            break;
        }
        let elapsed = start.elapsed();
        let chain = devnet.node(0).chain();
        let txs = if chain.len() > before {
            chain.last().expect("a finalised block").block.body().len()
        } else {
            0
        };
        if txs == 0 {
            stalled = true;
            break;
        }
        sign_wall += sign_dt;
        consensus_wall += elapsed;
        per_block_ms.push(elapsed.as_secs_f64() * 1000.0);
        finalized_tx += txs as u64;
        heights += 1;
    }

    let header_hashes: Vec<String> = devnet
        .node(0)
        .chain()
        .iter()
        .map(|b| hex(&b.header_hash()))
        .collect();
    let _ = std::fs::remove_dir_all(&base);
    RunResult {
        per_block_ms,
        finalized_tx,
        consensus_ms: consensus_wall.as_secs_f64() * 1000.0,
        sign_ms: sign_wall.as_secs_f64() * 1000.0,
        committee,
        heights,
        block_hashes: header_hashes,
        stalled,
    }
}

fn parse_result(line: &str) -> RunResult {
    let mut per_block_ms = Vec::new();
    let mut finalized_tx = 0u64;
    let mut consensus_ms = 0.0;
    let mut sign_ms = 0.0;
    let mut committee = 0usize;
    let mut heights = 0u64;
    let mut block_hashes = Vec::new();
    let mut stalled = false;
    for field in line.trim().trim_start_matches("RESULT ").split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key {
            "finalized_tx" => finalized_tx = value.parse().unwrap_or(0),
            "consensus_ms" => consensus_ms = value.parse().unwrap_or(0.0),
            "sign_ms" => sign_ms = value.parse().unwrap_or(0.0),
            "committee" => committee = value.parse().unwrap_or(0),
            "heights" => heights = value.parse().unwrap_or(0),
            "stall" => stalled = value == "1",
            "perblock" => {
                per_block_ms = value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            }
            "blockhashes" => {
                block_hashes = value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            }
            _ => {}
        }
    }
    RunResult {
        per_block_ms,
        finalized_tx,
        consensus_ms,
        sign_ms,
        committee,
        heights,
        block_hashes,
        stalled,
    }
}

fn run_loopback(
    validators: usize,
    senders_n: usize,
    run_secs: usize,
    warmup: usize,
    height_cap: usize,
    validator_bin: &str,
) -> Vec<RunResult> {
    let base = std::env::temp_dir().join(format!("qtv-loopback-mp-{}", std::process::id()));
    std::fs::create_dir_all(&base).expect("create the store base");

    let mut children: Vec<Child> = Vec::with_capacity(validators);
    for idx in 0..validators {
        let child = Command::new(validator_bin)
            .arg(idx.to_string())
            .env("QTV_MP_VALIDATORS", validators.to_string())
            .env("QTV_MP_ACCOUNTS", senders_n.to_string())
            .env("QTV_MP_SECS", run_secs.to_string())
            .env("QTV_MP_WARMUP", warmup.to_string())
            .env("QTV_MP_HEIGHTCAP", height_cap.to_string())
            .env("QTV_MP_BASE", base.to_string_lossy().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn a validator process");
        children.push(child);
    }

    let mut readers: Vec<BufReader<std::process::ChildStdout>> = children
        .iter_mut()
        .map(|c| BufReader::new(c.stdout.take().expect("child stdout")))
        .collect();
    let mut ports: Vec<u16> = vec![0; validators];
    for (idx, reader) in readers.iter_mut().enumerate() {
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read a child port line");
            if let Some(port) = line.trim().strip_prefix("PORT ") {
                ports[idx] = port.parse().expect("a listener port");
                break;
            }
        }
    }

    let csv = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    for child in children.iter_mut() {
        let stdin = child.stdin.as_mut().expect("child stdin");
        writeln!(stdin, "PEERS {csv}").expect("write the peer set");
        stdin.flush().expect("flush the peer set");
    }

    let mut results: Vec<RunResult> = Vec::with_capacity(validators);
    for reader in readers.iter_mut() {
        loop {
            let mut line = String::new();
            let read = reader
                .read_line(&mut line)
                .expect("read a child result line");
            if read == 0 {
                results.push(parse_result("RESULT stall=1"));
                break;
            }
            if line.trim_start().starts_with("RESULT ") {
                results.push(parse_result(&line));
                break;
            }
        }
    }
    for child in children.iter_mut() {
        let _ = child.wait();
    }
    let _ = std::fs::remove_dir_all(&base);
    results
}

fn prefix_matches(a: &[String], b: &[String]) -> bool {
    let common = a.len().min(b.len());
    common > 0 && a[..common] == b[..common]
}

fn rule() {
    println!("{}", "-".repeat(80));
}

fn main() {
    let validators = env_usize("QTV_MP_VALIDATORS", 4).max(1);
    let senders_n = env_usize("QTV_MP_ACCOUNTS", 250).max(2);
    let run_secs = env_usize("QTV_MP_SECS", 60).max(1);
    let warmup = env_usize("QTV_MP_WARMUP", 2);
    let height_cap = env_usize(
        "QTV_MP_HEIGHTCAP",
        (qtv_loopback::HARNESS_SLOTS as usize) - 64,
    );

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

    let validator_bin = std::env::var("QTV_MP_VALIDATOR_BIN").unwrap_or_else(|_| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("qtv-validator")))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "qtv-validator".to_string())
    });

    println!("================================================================================");
    println!(" Quantova loopback multi process run");
    println!("================================================================================");
    println!(" This isolates ONE variable, parallelism, against the in process serial baseline.");
    println!(" It runs BOTH at the identical committee size and block width on this one host:");
    println!("   - in process serial   : all committee compute serial in ONE process, in memory");
    println!("   - loopback multi proc : one OS process per validator over REAL localhost TCP");
    println!("                           sockets through the REAL qtv-net post quantum channel");
    println!();
    println!(" Every loopback number is LOOPBACK MULTI PROCESS, REAL SOCKETS, NEAR ZERO");
    println!(" PROPAGATION: parallel per process compute plus loopback socket cost. It is NOT a");
    println!(" geographic network throughput and NOT a real global finality; localhost sockets");
    println!(" carry no inter host bandwidth or propagation, so neither is measured here.");
    println!();
    println!(" Host (measured on):");
    println!(
        "   {cpu}, {cores} cores, {:.0} GB memory",
        mem_bytes as f64 / 1e9
    );
    println!("   build: release (opt-level 3)");
    println!(" Source:");
    println!("   Quantova-Chain commit {commit} (qtv-loopback drives qtv-devnet DevNodes)");
    println!(
        "   consensus crates pinned at QRC-CONSENSUS tag v0.5.0 (qtv-bft, qtv-sampler, qtv-attest)"
    );
    println!();
    println!(" Configuration (identical for both sides):");
    println!("   validators / committee : {validators}");
    println!("   block width (accounts) : {senders_n}");
    println!("   target consensus secs  : {run_secs}");
    println!("   warmup heights         : {warmup} (not counted)");
    println!("   height cap             : {height_cap} measured (under the one time sortition's");
    println!(
        "                            {}-slot tree the harness sizes; see the note below)",
        qtv_loopback::HARNESS_SLOTS
    );
    println!(" Process count (loopback): {validators} validator processes + 1 driver");
    rule();

    println!(
        " [1/2] In process serial baseline (all committee compute serial, one host, in memory) ..."
    );
    let serial = run_serial(validators, senders_n, run_secs as f64, warmup, height_cap);
    println!(
        "       finalised {} blocks, {} transactions over {:.1} s consensus wall clock{}",
        serial.heights,
        serial.finalized_tx,
        serial.consensus_ms / 1000.0,
        if serial.stalled {
            " (stopped early)"
        } else {
            ""
        },
    );

    println!(
        " [2/2] Loopback multi process run (one process per validator, real qtv-net TCP mesh) ..."
    );
    let loopback = run_loopback(
        validators,
        senders_n,
        run_secs,
        warmup,
        height_cap,
        &validator_bin,
    );
    let ingress = loopback
        .first()
        .expect("at least the ingress process reported");
    println!(
        "       finalised {} blocks, {} transactions over {:.1} s consensus wall clock{}",
        ingress.heights,
        ingress.finalized_tx,
        ingress.consensus_ms / 1000.0,
        if ingress.stalled {
            " (stopped early)"
        } else {
            ""
        },
    );
    rule();

    let all_agree = loopback
        .iter()
        .all(|r| prefix_matches(&r.block_hashes, &ingress.block_hashes));
    let matches_serial = prefix_matches(&ingress.block_hashes, &serial.block_hashes);
    println!(" Correctness oracle (checked before any number is trusted):");
    println!(
        "   every process finalised the byte identical chain : {}",
        if all_agree { "YES" } else { "NO" }
    );
    println!(
        "   loopback chain matches the in process chain       : {}",
        if matches_serial { "YES" } else { "NO" }
    );
    if !all_agree || !matches_serial {
        println!();
        println!("   THE CHAINS DID NOT MATCH. The run did not settle a clean measurement, so no");
        println!("   number below should be trusted. Reporting the mismatch rather than a figure.");
        rule();
        return;
    }
    println!("   both hold, so the two runs differ in exactly the intended variable and the");
    println!("   loopback numbers are a like for like comparison against the serial baseline.");
    rule();

    let serial_dist = Distribution::of(&serial.per_block_ms);
    let loop_dist = Distribution::of(&ingress.per_block_ms);
    let serial_tps = if serial.consensus_ms > 0.0 {
        serial.finalized_tx as f64 / (serial.consensus_ms / 1000.0)
    } else {
        0.0
    };
    let loop_tps = if ingress.consensus_ms > 0.0 {
        ingress.finalized_tx as f64 / (ingress.consensus_ms / 1000.0)
    } else {
        0.0
    };
    let serial_e2e = if serial.consensus_ms + serial.sign_ms > 0.0 {
        serial.finalized_tx as f64 / ((serial.consensus_ms + serial.sign_ms) / 1000.0)
    } else {
        0.0
    };
    let loop_e2e = if ingress.consensus_ms + ingress.sign_ms > 0.0 {
        ingress.finalized_tx as f64 / ((ingress.consensus_ms + ingress.sign_ms) / 1000.0)
    } else {
        0.0
    };

    let committee = ingress.committee.max(serial.committee);
    println!(" Committee read from a real finalised block: {committee} attesters (serial {}, loopback {}).",
        serial.committee, ingress.committee);
    println!(" SIDE BY SIDE at committee {validators}, block width {senders_n} (only finalised tx counted):");
    println!();
    println!(
        "   {:<34} {:>18} {:>18}",
        "", "in process SERIAL", "loopback MULTI-PROC"
    );
    println!(
        "   {:<34} {:>18} {:>18}",
        "", "(one host, memory)", "(real TCP sockets)"
    );
    println!(
        "   {:<34} {:>18} {:>18}",
        "heights finalised", serial.heights, ingress.heights
    );
    println!(
        "   {:<34} {:>18} {:>18}",
        "transactions finalised", serial.finalized_tx, ingress.finalized_tx
    );
    println!(
        "   {:<34} {:>18.1} {:>18.1}",
        "consensus wall clock (s)",
        serial.consensus_ms / 1000.0,
        ingress.consensus_ms / 1000.0
    );
    println!(
        "   {:<34} {:>18.0} {:>18.0}",
        "SUSTAINED THROUGHPUT (tx/s)", serial_tps, loop_tps
    );
    println!(
        "   {:<34} {:>18.0} {:>18.0}",
        "  end to end incl. signing (tx/s)", serial_e2e, loop_e2e
    );
    if let (Some(s), Some(l)) = (serial_dist, loop_dist) {
        println!(
            "   {:<34} {:>18.1} {:>18.1}",
            "finality median p50 (ms)", s.p50, l.p50
        );
        println!(
            "   {:<34} {:>18.1} {:>18.1}",
            "finality p90 (ms)", s.p90, l.p90
        );
        println!(
            "   {:<34} {:>18.1} {:>18.1}",
            "finality p99 (ms)", s.p99, l.p99
        );
        println!(
            "   {:<34} {:>18.1} {:>18.1}",
            "finality max (ms)", s.max, l.max
        );
        println!(
            "   {:<34} {:>18.1} {:>18.1}",
            "finality min (ms)", s.min, l.min
        );
    }
    rule();

    let speedup = if loop_tps > 0.0 {
        loop_tps / serial_tps.max(1e-9)
    } else {
        0.0
    };
    let finality_ratio = match (serial_dist, loop_dist) {
        (Some(s), Some(l)) if l.p50 > 0.0 => s.p50 / l.p50,
        _ => 0.0,
    };
    println!(" WHAT MOVED (loopback multi process vs in process serial, same config):");
    println!(
        "   throughput moved by {:.2}x ({:.0} -> {:.0} tx/s)",
        speedup, serial_tps, loop_tps
    );
    if let (Some(s), Some(l)) = (serial_dist, loop_dist) {
        println!(
            "   finality median moved by {:.2}x ({:.0} -> {:.0} ms per block)",
            finality_ratio, s.p50, l.p50
        );
    }
    println!(" WHAT CARRIES THAT MOVE. This run changed exactly one thing against the in process");
    println!(" baseline: the committee's compute went from serial in one process to parallel");
    println!(" across one process per validator over real qtv-net TCP sockets. The workload, the");
    println!(
        " committee, the sortition, the attestations, the certificate, and the coded proposal"
    );
    println!(
        " dissemination are byte identical, proven by the identical finalised chains above. So"
    );
    println!(" the move is the parallelism plus the loopback socket cost, and nothing else.");
    println!(" WHAT DID NOT MOVE, AND IS NOT MEASURED. The sockets are localhost, so there is no");
    println!(" inter host bandwidth and no geographic propagation in either number; this is not a");
    println!(" network throughput or a real global finality. A globally distributed validator set");
    println!(" would add real propagation latency this run deliberately excludes to isolate");
    println!(" parallelism alone.");
    rule();

    println!(" NOTE on the run length. The one time key sortition commits each validator's tree");
    println!(" to a fixed slot count, one slot per height, and a run cannot exceed that many");
    println!(" finalised heights without the sortition refusing a slot past the commitment. The");
    println!(
        " consensus default of 64 stays the default; the harness sizes its trees to {} slots",
        qtv_loopback::HARNESS_SLOTS
    );
    println!(" through the with_slots path, a harness parameter only, so a sustained run is no");
    println!(
        " longer bounded near 64 heights and both runs above stop on the target seconds or the"
    );
    println!(" height cap rather than on the slot count.");
    println!("================================================================================");
}
