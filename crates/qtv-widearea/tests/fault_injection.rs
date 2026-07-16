//! Fault injection over the real wide area validator processes.
//!
//! This is the test that proves the wide area number will be honest before any host is
//! provisioned. It stands the real validator binary up on this one host over real
//! localhost sockets, the same substrate a real run uses with only the peer addresses
//! changed, and it injects the three faults a wide area run will meet: a slow host, one
//! host dropping, and two hosts dropping. It asserts the harness degrades honestly under
//! each and never turns a broken run into a clean looking number.
//!
//! A slow host is still a present committee member, so the round waits for it and its
//! cost lands in the finality distribution: the tail of the slow run is wider than the
//! healthy tail. One host dropping leaves a supermajority, so the run continues, but the
//! dropped host's heights rotate through a view change, so the finalised throughput
//! falls, the finalised count per unit wall clock dropping because only finalised
//! transactions are counted. Two hosts dropping leaves the online set below the
//! supermajority, so no height finalises and the run reports the stall, never a number.
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
/// committee is four, the supermajority three, the block width small so a healthy height
/// finalises in tens of milliseconds well under the view timeout, and the run is a short
/// fixed height count so every up host stops together.
fn base_scenario() -> Scenario {
    Scenario {
        validators: 4,
        senders_n: 12,
        // A long enough run that the dropped host is elected leader several times, so
        // the view change that routes around it is exercised without depending on a
        // single lucky election.
        heights: 30,
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
    // The healthy baseline: four up hosts, no fault. It finalises the full run and every
    // up host agrees on a byte identical chain, the reference the faults move against.
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
    let base_throughput = base.throughput();
    // Every up host finalised the byte identical chain over the healthy run.
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

    // Fault two, one host dropping. Host three is down. Three of four remain, still the
    // supermajority, so the run continues and finalises the whole height count, but the
    // dropped host's heights rotate through a view change, so the finalised throughput
    // falls. Assert the run continued and the throughput fell.
    let mut drop_one = base_scenario();
    drop_one.up[3] = false;
    let drop_one_reports = run_scenario(&drop_one);
    let drop_one_ingress = ingress(&drop_one_reports);
    assert!(
        !drop_one_ingress.stalled,
        "one host dropping leaves a supermajority, so the run continues"
    );
    assert_eq!(
        drop_one_ingress.heights as usize, drop_one.heights,
        "the degraded run still finalises the whole height count on the remaining hosts"
    );
    assert!(
        drop_one_ingress.rotations > 0,
        "the dropped host's heights must rotate through a view change, none were seen"
    );
    assert!(
        drop_one_ingress.throughput() < base_throughput,
        "the finalised throughput must fall when a host drops: degraded {:.0} tx/s was not \
         below the healthy {:.0} tx/s",
        drop_one_ingress.throughput(),
        base_throughput
    );

    // Fault three, two hosts dropping. Hosts two and three are down. Two of four remain,
    // below the supermajority, so no height can finalise. Assert the run reports the
    // stall with no finalised heights, never a fabricated number.
    let mut drop_two = base_scenario();
    drop_two.up[2] = false;
    drop_two.up[3] = false;
    let drop_two_reports = run_scenario(&drop_two);
    let drop_two_ingress = ingress(&drop_two_reports);
    assert!(
        drop_two_ingress.stalled,
        "two hosts dropping leaves the online set below the supermajority, which must be \
         reported as a stall"
    );
    assert_eq!(
        drop_two_ingress.heights, 0,
        "a stalled run finalises no measured height, so it reports a stall and not a number"
    );
    assert!(
        drop_two_ingress.finality().is_none(),
        "a stalled run has no finality distribution to report"
    );
}
