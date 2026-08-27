// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_widearea::local::{run_scenario, Scenario};
use qtv_widearea::RunReport;

fn validator_bin() -> String {
    env!("CARGO_BIN_EXE_qtv-validator-wide").to_string()
}

fn base_scenario() -> Scenario {
    Scenario {
        validators: 4,
        senders_n: 12,
        heights: 16,
        warmup: 2,
        height_cap: (qtv_loopback::HARNESS_SLOTS as usize) - 64,
        view_ms: 400,
        stall_secs: 5,
        up: vec![true; 4],
        slow_ms: vec![0; 4],
        validator_bin: validator_bin(),
    }
}

fn ingress(reports: &[RunReport]) -> RunReport {
    reports
        .iter()
        .find(|r| r.idx == 0)
        .cloned()
        .expect("the ingress host reported")
}

#[test]
fn faults_degrade_honestly_over_real_sockets() {
    let healthy = base_scenario();
    let healthy_reports = run_scenario(&healthy);
    let base = ingress(&healthy_reports);
    assert!(!base.stalled, "the healthy baseline must not stall");
    assert_eq!(
        base.heights as usize, healthy.heights,
        "the healthy baseline finalises the whole run"
    );
    base.finality().expect("the baseline has a finality distribution");
    for report in &healthy_reports {
        assert_eq!(
            report.block_hashes, base.block_hashes,
            "every up host finalises the byte identical chain on the healthy run"
        );
    }

    let mut drop_one = base_scenario();
    drop_one.up[3] = false;
    let drop_one_reports = run_scenario(&drop_one);
    let drop_one_ingress = ingress(&drop_one_reports);
    assert!(
        !drop_one_ingress.stalled,
        "three publishers meet the threshold, so one host dropping does not stall the run"
    );
    assert_eq!(
        drop_one_ingress.heights as usize, drop_one.heights,
        "the degraded run still finalises the whole height count on the remaining hosts"
    );
    for report in &drop_one_reports {
        assert_eq!(
            report.block_hashes, drop_one_ingress.block_hashes,
            "every up host finalises the byte identical chain when one host drops"
        );
    }

    let mut drop_two = base_scenario();
    drop_two.up[2] = false;
    drop_two.up[3] = false;
    let drop_two_reports = run_scenario(&drop_two);
    let drop_two_ingress = ingress(&drop_two_reports);
    assert!(
        drop_two_ingress.stalled,
        "two publishers are below the absolute threshold, which must be reported as a stall"
    );
    assert_eq!(
        drop_two_ingress.heights, 0,
        "a minority of publishers finalises no measured height, so it reports a stall"
    );
    assert!(
        drop_two_ingress.finality().is_none(),
        "a stalled run has no finality distribution to report"
    );
}

#[test]
#[ignore = "needs the proposer to declare the committee for its height; required before multi validator"]
fn a_slow_host_beyond_the_threshold_stays_robust() {
    let mut slow = base_scenario();
    slow.slow_ms[3] = 120;
    let slow_reports = run_scenario(&slow);
    let slow_ingress = ingress(&slow_reports);
    assert!(
        !slow_ingress.stalled,
        "a single slow host beyond the threshold does not stall the run"
    );
    assert_eq!(
        slow_ingress.heights as usize, slow.heights,
        "finality tolerates a slow host beyond the threshold and finalises the whole run"
    );
}
