//! Fault injection over the real wide area validator processes.
//!
//! This is the test that proves the wide area number will be honest before any host is
//! provisioned. It stands the real validator binary up on this one host over real
//! localhost sockets, the same substrate a real run uses with only the peer addresses
//! changed, and it injects the three faults a wide area run will meet: a slow host, one
//! host dropping, and two hosts dropping. It asserts the harness degrades honestly under
//! each and never turns a broken run into a clean looking number.
//!
//! Finality reaches an absolute threshold derived from the registered committee, not a
//! fraction of whoever published. A slow host is still a present committee member, so the
//! round waits for it and the tail of the slow run is wider than the healthy tail. One
//! host dropping leaves three publishers, which still meets the threshold, so the run
//! finalises the whole run at zero margin over the three that remain. Two hosts dropping
//! leaves two publishers, a minority below the threshold, so no height finalises however
//! the two rotate the view, and the run reports the stall, never a number.
//!
//! Every figure here is a loopback multi process figure over real sockets with near zero
//! propagation, exactly as the loopback run was labelled. It is not a network number.

use qtv_widearea::local::{run_scenario, Scenario};
use qtv_widearea::RunReport;

/// The validator binary cargo built for this test, so the test drives the exact binary a
/// real host runs.
fn validator_bin() -> String {
    env!("CARGO_BIN_EXE_qtv-validator-wide").to_string()
}

/// A small fast scenario shared by the faults, so the whole test runs in seconds. The
/// registered committee is four and the absolute threshold three, the block width small so
/// a healthy height finalises in tens of milliseconds well under the view timeout, and the
/// run is a short fixed height count so every up host stops together.
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

/// The ingress host's report, index zero, the host that drives the workload and whose
/// measurement the run reports.
fn ingress(reports: &[RunReport]) -> RunReport {
    reports
        .iter()
        .find(|r| r.idx == 0)
        .cloned()
        .expect("the ingress host reported")
}

#[test]
fn faults_degrade_honestly_over_real_sockets() {
    // The healthy baseline. Four up hosts, no fault, the committee is the whole
    // registered set and finality reaches the absolute threshold with a margin.
    let healthy = base_scenario();
    let healthy_reports = run_scenario(&healthy);
    let base = ingress(&healthy_reports);
    assert!(!base.stalled, "the healthy baseline must not stall");
    assert_eq!(
        base.heights as usize, healthy.heights,
        "the healthy baseline finalises the whole run"
    );
    let base_dist = base.finality().expect("the baseline has a finality distribution");
    let base_tail = base_dist.p99;
    for report in &healthy_reports {
        assert_eq!(
            report.block_hashes, base.block_hashes,
            "every up host finalises the byte identical chain on the healthy run"
        );
    }

    // Fault one, a slow host. Host three is present and attesting but slow to send every
    // message, so the round, which waits for every online member, waits for it and the
    // finality tail widens. Assert the slow tail is clearly wider than the healthy tail.
    let mut slow = base_scenario();
    slow.slow_ms[3] = 120;
    let slow_reports = run_scenario(&slow);
    let slow_ingress = ingress(&slow_reports);
    assert!(
        !slow_ingress.stalled,
        "a single slow host does not stall the run, it only slows it"
    );
    let slow_dist = slow_ingress
        .finality()
        .expect("the slow run still finalises and has a distribution");
    assert!(
        slow_dist.p99 > base_tail * 1.5,
        "the slow host must widen the finality tail: slow p99 {:.1} ms was not clearly above \
         the healthy p99 {:.1} ms",
        slow_dist.p99,
        base_tail
    );

    // Fault two, one host dropping. Host three is down, so three of four publish. Three
    // meets the absolute threshold, so the run still finalises the whole height count over
    // the three that remain, now at zero margin. The committee is the three publishers.
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

    // Fault three, two hosts dropping. Hosts two and three are down, so two of four
    // publish. Two is below the absolute threshold, so no height reaches it however the two
    // rotate the view, and the run reports the stall rather than finalising on a minority.
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
