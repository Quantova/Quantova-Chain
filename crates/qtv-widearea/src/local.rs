// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};

use crate::env as wenv;
use crate::{parse_result, RunReport};

#[derive(Clone)]
pub struct Scenario {
    pub validators: usize,
    pub senders_n: usize,
    pub heights: usize,
    pub warmup: usize,
    pub height_cap: usize,
    pub view_ms: usize,
    pub stall_secs: usize,
    pub up: Vec<bool>,
    pub slow_ms: Vec<u64>,
    pub validator_bin: String,
}

impl Scenario {
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

    pub fn up_count(&self) -> usize {
        self.up.iter().filter(|&&u| u).count()
    }
}

fn qtv_loopback_slots() -> u64 {
    qtv_loopback::HARNESS_SLOTS
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind an ephemeral port");
    listener.local_addr().expect("ephemeral address").port()
}

pub fn run_scenario(scenario: &Scenario) -> Vec<RunReport> {
    let base = std::env::temp_dir().join(format!(
        "qtv-widearea-{}-{}",
        std::process::id(),
        fastrand_suffix()
    ));
    std::fs::create_dir_all(&base).expect("create the store base");

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

fn fastrand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
