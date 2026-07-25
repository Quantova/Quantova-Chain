// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_widearea::local::{run_scenario, Scenario};
use qtv_widearea::{env_usize, prefix_matches, RunReport, TRANSPORT_PORT};

use qtv_loopback::stats::Distribution;

fn validator_bin() -> String {
    std::env::var("QTV_WA_VALIDATOR_BIN").unwrap_or_else(|_| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("qtv-validator-wide")))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "qtv-validator-wide".to_string())
    })
}

fn rule() {
    println!("{}", "-".repeat(80));
}

fn index_list(name: &str) -> Vec<usize> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

fn main() {
    if let Ok(dir) = std::env::var("QTV_WA_COLLECT") {
        collect_and_report(&dir);
        return;
    }

    let validators = env_usize("QTV_WA_VALIDATORS", 4).max(1);
    let senders_n = env_usize("QTV_WA_ACCOUNTS", 64).max(2);
    let heights = env_usize("QTV_WA_HEIGHTS", 40).max(1);
    let warmup = env_usize("QTV_WA_WARMUP", 2);
    let view_ms = env_usize("QTV_WA_VIEWMS", 800).max(1);
    let stall_secs = env_usize("QTV_WA_STALLSECS", 30).max(1);
    let height_cap = env_usize("QTV_WA_HEIGHTCAP", (qtv_loopback::HARNESS_SLOTS as usize) - 64);

    let mut up = vec![true; validators];
    for i in index_list("QTV_WA_DOWN") {
        if i < validators {
            up[i] = false;
        }
    }
    let mut slow_ms = vec![0u64; validators];
    if let Ok(list) = std::env::var("QTV_WA_SLOW") {
        for pair in list.split(',').filter(|s| !s.is_empty()) {
            if let Some((idx, ms)) = pair.split_once(':') {
                if let (Ok(i), Ok(ms)) = (idx.trim().parse::<usize>(), ms.trim().parse::<u64>()) {
                    if i < validators {
                        slow_ms[i] = ms;
                    }
                }
            }
        }
    }

    let scenario = Scenario {
        validators,
        senders_n,
        heights,
        warmup,
        height_cap,
        view_ms,
        stall_secs,
        up,
        slow_ms,
        validator_bin: validator_bin(),
    };

    println!("================================================================================");
    println!(" Quantova wide area harness, local stand up validation");
    println!("================================================================================");
    println!(" This runs the wide area validator binary on THIS ONE host over localhost sockets,");
    println!(" to prove the harness rendezvous, finalises, and agrees before any host is");
    println!(" provisioned. It is the loopback multi process substrate with the peer addresses");
    println!(" read from configuration, so the round, the workload, and the finality are the");
    println!(" same and only the peer addresses differ.");
    println!();
    println!(" EVERY FIGURE BELOW IS LOOPBACK MULTI PROCESS, REAL SOCKETS, NEAR ZERO PROPAGATION.");
    println!(" The sockets are localhost, so there is no inter host propagation and this is not a");
    println!(" network throughput or a real global finality. The propagation number this harness");
    println!(" exists to produce comes only from a real run across regions, driven by the deploy");
    println!(" script, and is not produced here.");
    println!();
    println!(" Fixed transport port for a real deployment: {TRANSPORT_PORT} (one open port per host).");
    println!(" Local run binds a distinct localhost port per process, since one host cannot share");
    println!(" one port across several processes.");
    println!();
    println!(" Configuration:");
    println!("   validators / committee : {validators}");
    println!("   block width (accounts) : {senders_n}");
    println!("   measured heights       : {heights}");
    println!("   warmup heights         : {warmup} (not counted)");
    println!("   view timeout (ms)      : {view_ms}");
    println!("   stall guard (s)        : {stall_secs}");
    let down: Vec<usize> = (0..validators).filter(|&i| !scenario.up[i]).collect();
    let slow: Vec<String> = (0..validators)
        .filter(|&i| scenario.slow_ms[i] > 0)
        .map(|i| format!("{i} by {} ms", scenario.slow_ms[i]))
        .collect();
    println!(
        "   up hosts               : {} of {validators} ({} the supermajority)",
        scenario.up_count(),
        if scenario.up_count() >= (2 * validators / 3 + 1) {
            "at or above"
        } else {
            "below"
        }
    );
    if !down.is_empty() {
        println!("   dropped hosts          : {down:?}");
    }
    if !slow.is_empty() {
        println!("   slow hosts             : {}", slow.join(", "));
    }
    rule();

    println!(" Standing up {validators} validator processes over the real qtv-net mesh ...");
    let reports = run_scenario(&scenario);
    report_run(
        &reports,
        "LOOPBACK MULTI PROCESS, REAL SOCKETS, NEAR ZERO PROPAGATION",
    );
    println!(" The harness stood up over real qtv-net sockets, finalised, and every up host agreed");
    println!(" on the byte identical chain. This is the local stand up proof. A network propagation");
    println!(" figure is produced only by the deploy script across real hosts and is committed in a");
    println!(" results file in the q-prover form, never reported without it.");
    println!("================================================================================");
}

fn report_run(reports: &[RunReport], label: &str) {
    let up = reports.len();
    let ingress = match reports.iter().find(|r| r.idx == 0) {
        Some(r) => r,
        None => {
            println!(" No ingress host reported, so no run to report.");
            return;
        }
    };

    if ingress.stalled || ingress.heights == 0 {
        println!(" The run STALLED. No height finalised, so no figure is reported, only the stall.");
        println!(" finalised transactions before the stall: {}", ingress.finalized_tx);
        rule();
        return;
    }

    let all_agree = reports
        .iter()
        .filter(|r| !r.stalled)
        .all(|r| prefix_matches(&r.block_hashes, &ingress.block_hashes));
    println!(
        "       {up} host(s) reported, committee {} read from a finalised block",
        ingress.committee
    );
    println!(
        "       every up host finalised the byte identical chain : {}",
        if all_agree { "YES" } else { "NO" }
    );
    if !all_agree {
        println!();
        println!("   THE CHAINS DID NOT MATCH, so no figure below should be trusted. Reporting the");
        println!("   mismatch rather than a number.");
        rule();
        return;
    }
    rule();

    let dist = Distribution::of(&ingress.per_block_ms);
    println!(" Ingress host measurement ({label}):");
    println!("   heights finalised            : {}", ingress.heights);
    println!("   transactions finalised       : {}", ingress.finalized_tx);
    println!("   heights via a view change    : {}", ingress.rotations);
    println!(
        "   consensus wall clock (s)     : {:.1}",
        ingress.consensus_ms / 1000.0
    );
    println!(
        "   fill wall clock, untimed (s) : {:.1}  (admission, not counted as consensus)",
        ingress.fill_ms / 1000.0
    );
    println!(
        "   sustained throughput (tx/s)  : {:.0}",
        ingress.throughput()
    );
    if let Some(d) = dist {
        println!("   finality p50 (ms)            : {:.1}", d.p50);
        println!("   finality p90 (ms)            : {:.1}", d.p90);
        println!("   finality p99 (ms)            : {:.1}", d.p99);
        println!("   finality max (ms)            : {:.1}", d.max);
    }
    println!("   phase wait (ms)              : {:.1}", ingress.phase_wait_ms);
    println!("   phase build (ms)             : {:.1}", ingress.phase_build_ms);
    println!("   phase verify (ms)            : {:.1}", ingress.phase_verify_ms);
    println!("   phase aggregate (ms)         : {:.1}", ingress.phase_aggregate_ms);
    println!("   phase finalise (ms)          : {:.1}", ingress.phase_finalise_ms);
    println!("   phase flood (ms)             : {:.1}", ingress.phase_flood_ms);
    println!("   phase other (ms)             : {:.1}", ingress.phase_other_ms());
    rule();
}

fn collect_and_report(dir: &str) {
    let mut reports: Vec<RunReport> = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            println!("could not read the result directory {dir}: {error}");
            return;
        }
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("result-"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    for path in paths {
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if line.trim_start().starts_with("RESULT ") {
                    reports.push(qtv_widearea::parse_result(line));
                }
            }
        }
    }

    println!("================================================================================");
    println!(" Quantova wide area run, collected host results");
    println!("================================================================================");
    println!(" {} host result(s) gathered from {dir}.", reports.len());
    println!(" Fixed transport port for the run: {TRANSPORT_PORT}.");
    println!(" This figure carries the real propagation of wherever the hosts ran. It is a network");
    println!(" number only if the hosts were geographically spread, and it must be committed to a");
    println!(" results file in the q-prover form with the host regions and the measured inter host");
    println!(" round trips before it is reported as one. Compare it to the loopback finality at the");
    println!(" same committee and width; the delta is the propagation cost.");
    rule();
    report_run(&reports, "WIDE AREA HOSTS, REAL PROPAGATION OF WHEREVER THEY RAN");
}
