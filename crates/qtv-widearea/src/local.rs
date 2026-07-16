//! Stand the wide area validators up on one host over localhost sockets, for the
//! validation that proves the harness before any host is provisioned and for the fault
//! injection test.
//!
//! This is the local coordinator. It is not the deploy flow. The deploy flow starts one
//! validator on each real host over the single fixed transport port and collects each
//! host's measurement over its own transport; see the deploy script and its notes. Here
//! every validator runs on this one host, so each process is handed a distinct localhost
//! port instead of the one fixed port several hosts could each bind, and the rest of the
//! run, the mesh, the workload, the finality, and the honest degradation, is identical.
//!
//! Every figure a local run produces is a LOOPBACK MULTI PROCESS figure over REAL
//! SOCKETS with NEAR ZERO PROPAGATION, exactly as the loopback run was labelled. It is
//! not a network number, because localhost sockets carry no inter host propagation.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};

use crate::env as wenv;
use crate::{parse_result, RunReport};

/// One local scenario: the committee size, the workload, the timing, which validators
/// are up, and the per validator slow host delay. The fault injection test sets the up
/// set and the slow delays; the driver runs the healthy all up scenario.
#[derive(Clone)]
pub struct Scenario {
    pub validators: usize,
    pub senders_n: usize,
    /// The measured heights the run finalises, the shared run length.
    pub heights: usize,
    pub warmup: usize,
    pub height_cap: usize,
    pub view_ms: usize,
    pub stall_secs: usize,
    /// Whether each validator index is up this run. A down validator is not started.
    pub up: Vec<bool>,
    /// The per validator slow host delay in milliseconds, zero for a healthy host.
    pub slow_ms: Vec<u64>,
    /// The validator binary to spawn, found by the driver beside itself and by the test
    /// from its cargo bin path.
    pub validator_bin: String,
}

impl Scenario {
    /// A healthy all up scenario of a given committee size and workload.
    pub fn healthy(validators: usize, validator_bin: String) -> Self {
        Scenario {
            validators,
            senders_n: 64,
            heights: 40,
            warmup: 2,
            height_cap: (qtv_loopback_slots() as usize) - 64,
            view_ms: 800,
            stall_secs: 30,
            up: vec![true; validators],
            slow_ms: vec![0; validators],
            validator_bin,
        }
    }

    /// The number of up validators this scenario starts.
    pub fn up_count(&self) -> usize {
        self.up.iter().filter(|&&u| u).count()
    }
}

/// The harness slot count, read from the loopback lib so both harnesses size the one
/// time tree alike.
fn qtv_loopback_slots() -> u64 {
    qtv_loopback::HARNESS_SLOTS
}

/// Pick a free localhost TCP port by binding an ephemeral port and releasing it. Used
/// to hand each local validator a distinct port, since several processes on one host
/// cannot share the one fixed transport port a real deployment gives each host.
fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind an ephemeral port");
    listener.local_addr().expect("ephemeral address").port()
}

/// Run one scenario to completion and collect each up validator's measured report. The
/// down validators are not started and do not report. The store base is a fresh
/// temporary directory removed when the run ends.
pub fn run_scenario(scenario: &Scenario) -> Vec<RunReport> {
    let base = std::env::temp_dir().join(format!(
        "qtv-widearea-{}-{}",
        std::process::id(),
        fastrand_suffix()
    ));
    std::fs::create_dir_all(&base).expect("create the store base");

    // Assign every validator a distinct localhost port and build the ordered address
    // list every process reads its peers from.
    let ports: Vec<u16> = (0..scenario.validators).map(|_| free_port()).collect();
    let addrs = ports
        .iter()
        .map(|p| format!("127.0.0.1:{p}"))
        .collect::<Vec<_>>()
        .join(",");
    let up_list = (0..scenario.validators)
        .filter(|&i| scenario.up[i])
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let mut children: Vec<(usize, Child)> = Vec::new();
    for idx in 0..scenario.validators {
        if !scenario.up[idx] {
            continue;
        }
        let child = Command::new(&scenario.validator_bin)
            .env(wenv::INDEX, idx.to_string())
            .env(wenv::ADDRS, &addrs)
            .env(wenv::UP, &up_list)
            .env(wenv::ACCOUNTS, scenario.senders_n.to_string())
            .env(wenv::HEIGHTS, scenario.heights.to_string())
            .env(wenv::WARMUP, scenario.warmup.to_string())
            .env(wenv::HEIGHTCAP, scenario.height_cap.to_string())
            .env(wenv::VIEWMS, scenario.view_ms.to_string())
            .env(wenv::STALLSECS, scenario.stall_secs.to_string())
            .env(wenv::SLOWMS, scenario.slow_ms[idx].to_string())
            .env(wenv::BASE, base.to_string_lossy().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn a validator process");
        children.push((idx, child));
    }

    // Read each up child's RESULT line. A child that closes its stdout without a RESULT
    // line died, so it is counted as a stall rather than dropped from the run.
    let mut reports: Vec<RunReport> = Vec::new();
    for (idx, child) in children.iter_mut() {
        let stdout = child.stdout.take().expect("child stdout");
        let mut reader = BufReader::new(stdout);
        let mut report = RunReport {
            idx: *idx,
            stalled: true,
            ..Default::default()
        };
        loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line).unwrap_or(0);
            if read == 0 {
                break;
            }
            if line.trim_start().starts_with("RESULT ") {
                report = parse_result(&line);
                break;
            }
        }
        reports.push(report);
    }
    for (_, child) in children.iter_mut() {
        let _ = child.wait();
    }
    let _ = std::fs::remove_dir_all(&base);
    reports
}

/// A short unique suffix so two scenarios in one process do not share a store base. It
/// is drawn from the wall clock nanoseconds, which is enough to separate sequential
/// runs; it is not a cryptographic value.
fn fastrand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
