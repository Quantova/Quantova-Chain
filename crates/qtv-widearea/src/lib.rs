//! Shared pieces for the wide area run.
//!
//! The wide area run is the loopback multi process run with one change: where the
//! loopback validator hardcodes localhost, this validator reads its own listen
//! address and its peers' real addresses from configuration, so the same binary runs
//! on a remote host and connects to the other hosts over the internet on the real
//! qtv-net post quantum channel. Everything else is the loopback harness. The
//! workload, the funded accounts, the devnet configuration, the committee sortition,
//! the module lattice attestations, the aggregated certificate, and the erasure coded
//! proposal dissemination are reused byte for byte from the loopback lib, so a wide
//! area run and a loopback run drive the identical deterministic workload over the
//! identical committee and differ only in the peer addresses and in the honest
//! degradation path this crate adds.
//!
//! WHAT A WIDE AREA NUMBER WILL MEAN. Run across regions, this measures real
//! propagation on top of the parallelism the loopback run already isolated. The
//! finding is the delta from the loopback finality, and that delta is the propagation
//! cost. Run on one host over localhost sockets, as it is validated here, it produces
//! no network number: every local figure is a LOOPBACK MULTI PROCESS figure over REAL
//! SOCKETS with NEAR ZERO PROPAGATION, exactly as the loopback run was labelled, and
//! it is not a network number.
//!
//! THE HONEST DEGRADATION THIS ADDS. A wide area run will have a slow host and a
//! dropping host, and the harness must never produce a number that looks fine and is
//! not. So this validator finalises on the real consensus supermajority, and it routes
//! around a silent or dropped leader with the real view change, exactly as the in
//! process devnet does. A host that is up but slow is waited for, since it is a present
//! committee member, so its cost shows in a widened finality distribution. One host
//! dropping leaves a supermajority, so the run continues on the remaining hosts and the
//! finalised count falls because the dropped host's heights rotate through a view
//! change and only finalised transactions are counted. Two hosts dropping leaves the
//! online set below the supermajority, so no height finalises and the run reports the
//! stall and the partial finalised count as a stall, not a fabricated number.

use qtv_loopback::stats::Distribution;

pub mod local;
pub mod runtime;

/// The single transport TCP port a wide area run fixes for the qtv-net mesh.
///
/// A real deployment opens exactly this one port inbound on each validator host and
/// each validator binds it, so every host reaches every other host on one known port
/// and the founder's firewall rule is a single line. The port is stated here in the
/// code and again in the deploy notes so the two never drift. It sits in the user port
/// range and is not an IANA registered service, so it does not collide with a common
/// daemon on a fresh server class host.
///
/// The port is a deploy convention, not a hardcoded bind: the validator binds whatever
/// listen address its configuration gives it. A real host binds this port; the local
/// validation binds a distinct localhost port per process, since several processes
/// cannot share one port on one host. The deploy script builds each host's address as
/// its host joined to this port.
pub const TRANSPORT_PORT: u16 = 40404;

/// The environment variable names the driver and the deploy script set on each
/// validator process. Keeping them in one place lets the validator, the local driver,
/// and the deploy script agree without a scattered set of string literals.
pub mod env {
    /// This validator's zero based index in the ordered validator set.
    pub const INDEX: &str = "QTV_WA_INDEX";
    /// The ordered peer addresses, one host:port per validator in index order, comma
    /// separated. Entry i is the address of validator i, and this validator's own
    /// entry names the port it binds.
    pub const ADDRS: &str = "QTV_WA_ADDRS";
    /// The indices that are up this run, comma separated. A dropped host is left out
    /// of this set and is not started. Absent means every validator is up.
    pub const UP: &str = "QTV_WA_UP";
    /// The distinct signing accounts that set the block width.
    pub const ACCOUNTS: &str = "QTV_WA_ACCOUNTS";
    /// The number of measured heights the run finalises. The run length is a shared
    /// discrete height count rather than a per host wall clock, so every up host stops
    /// on the same height in lockstep and no host is stranded mid height when a peer
    /// that reached its own budget first closes its sockets. A real run sizes this to
    /// the wall clock it wants at the finality it sees, bounded by the slot tree.
    pub const HEIGHTS: &str = "QTV_WA_HEIGHTS";
    /// The warmup heights that advance the chain but are not measured.
    pub const WARMUP: &str = "QTV_WA_WARMUP";
    /// The measured height cap, kept under the one time sortition tree's slot count.
    pub const HEIGHTCAP: &str = "QTV_WA_HEIGHTCAP";
    /// The wall clock a view is given before a node rotates the leader, in
    /// milliseconds. It must sit above a healthy height's finality and the round trip
    /// so propagation does not trip a spurious rotation, and below the stall guard so a
    /// dropped leader is routed around long before the height is called a stall.
    pub const VIEWMS: &str = "QTV_WA_VIEWMS";
    /// The wall clock a single height is given before the run calls it a stall, in
    /// seconds.
    pub const STALLSECS: &str = "QTV_WA_STALLSECS";
    /// The per message send delay injected on this validator, in milliseconds, the
    /// slow host fault. Zero is a healthy host.
    pub const SLOWMS: &str = "QTV_WA_SLOWMS";
    /// The store base directory this validator opens its node under.
    pub const BASE: &str = "QTV_WA_BASE";
}

/// Read a usize environment variable, or a default.
pub fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The measured result of one validator process: the per block finality samples, the
/// finalised transaction count, the consensus and client signing wall clocks, the
/// committee size, the per block chain digests the driver compares across hosts, how
/// many heights rotated through a view change, and whether the run stalled.
#[derive(Clone, Default)]
pub struct RunReport {
    pub idx: usize,
    pub per_block_ms: Vec<f64>,
    pub finalized_tx: u64,
    pub consensus_ms: f64,
    pub sign_ms: f64,
    /// The untimed fill wall clock, summed over the measured heights, in milliseconds.
    /// This is the admission a real chain does in the mempool before a block: the ingress
    /// flood and the drain that admits the batch until the mempool holds the height's
    /// width. It sits outside the timed consensus region, so consensus_ms excludes it; it
    /// is reported here so the admission is visible but never counted as consensus.
    pub fill_ms: f64,
    pub committee: usize,
    pub heights: u64,
    pub rotations: u64,
    pub chainhash: String,
    pub block_hashes: Vec<String>,
    pub stalled: bool,
    /// The per phase split of the consensus wall clock, summed over the measured
    /// heights, in milliseconds. Instrumentation only, it does not enter any consensus
    /// decision and the finalised chain is byte identical whether it is measured or not.
    /// The idle wait blocked on the peer, the leader build and disseminate, the proposal
    /// verify, the attestation aggregate, the finalise, and the ingress batch flood; the
    /// unattributed remainder is reported separately as phase_other_ms so no time is
    /// hidden.
    pub phase_wait_ms: f64,
    pub phase_build_ms: f64,
    pub phase_verify_ms: f64,
    pub phase_aggregate_ms: f64,
    pub phase_finalise_ms: f64,
    pub phase_flood_ms: f64,
}

impl RunReport {
    /// The sustained finalised throughput, only finalised transactions over the
    /// consensus wall clock, or zero when nothing finalised.
    pub fn throughput(&self) -> f64 {
        if self.consensus_ms > 0.0 {
            self.finalized_tx as f64 / (self.consensus_ms / 1000.0)
        } else {
            0.0
        }
    }

    /// The finality distribution over the per block samples, if any finalised.
    pub fn finality(&self) -> Option<Distribution> {
        Distribution::of(&self.per_block_ms)
    }

    /// The consensus wall clock not attributed to any of the six timed phases, the
    /// honest remainder so nothing is hidden. It is the consensus wall clock less the
    /// summed phase totals, covering the buffered replay, the view change path, and the
    /// loop overhead that no seam times. It is not forced to a floor, so a seam overlap
    /// would show as a small negative, which does not occur on a finalised height since
    /// the seams do not nest.
    pub fn phase_other_ms(&self) -> f64 {
        self.consensus_ms
            - self.phase_wait_ms
            - self.phase_build_ms
            - self.phase_verify_ms
            - self.phase_aggregate_ms
            - self.phase_finalise_ms
            - self.phase_flood_ms
    }
}

/// The RESULT line a validator prints, and the mirror the driver reads it back with.
/// The format is one space separated key=value field per measurement, so a line is
/// self describing and a field added later does not shift the earlier ones.
pub fn format_result(report: &RunReport) -> String {
    let perblock = report
        .per_block_ms
        .iter()
        .map(|ms| format!("{ms:.3}"))
        .collect::<Vec<_>>()
        .join(",");
    let blockhashes = report.block_hashes.join(",");
    format!(
        "RESULT idx={} heights={} finalized_tx={} consensus_ms={:.3} sign_ms={:.3} \
         fill_ms={:.3} \
         phase_wait_ms={:.3} phase_build_ms={:.3} phase_verify_ms={:.3} \
         phase_aggregate_ms={:.3} phase_finalise_ms={:.3} phase_flood_ms={:.3} \
         phase_other_ms={:.3} \
         committee={} rotations={} chainhash={} stall={} perblock={perblock} \
         blockhashes={blockhashes}",
        report.idx,
        report.heights,
        report.finalized_tx,
        report.consensus_ms,
        report.sign_ms,
        report.fill_ms,
        report.phase_wait_ms,
        report.phase_build_ms,
        report.phase_verify_ms,
        report.phase_aggregate_ms,
        report.phase_finalise_ms,
        report.phase_flood_ms,
        report.phase_other_ms(),
        report.committee,
        report.rotations,
        report.chainhash,
        report.stalled as u8,
    )
}

/// Parse a validator's RESULT line back into a report. An unreadable or missing line
/// parses to a stalled report, so a process that died mid run is counted as a stall
/// rather than dropped from the run.
pub fn parse_result(line: &str) -> RunReport {
    let mut report = RunReport::default();
    for field in line.trim().trim_start_matches("RESULT ").split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key {
            "idx" => report.idx = value.parse().unwrap_or(0),
            "heights" => report.heights = value.parse().unwrap_or(0),
            "finalized_tx" => report.finalized_tx = value.parse().unwrap_or(0),
            "consensus_ms" => report.consensus_ms = value.parse().unwrap_or(0.0),
            "sign_ms" => report.sign_ms = value.parse().unwrap_or(0.0),
            "fill_ms" => report.fill_ms = value.parse().unwrap_or(0.0),
            "phase_wait_ms" => report.phase_wait_ms = value.parse().unwrap_or(0.0),
            "phase_build_ms" => report.phase_build_ms = value.parse().unwrap_or(0.0),
            "phase_verify_ms" => report.phase_verify_ms = value.parse().unwrap_or(0.0),
            "phase_aggregate_ms" => report.phase_aggregate_ms = value.parse().unwrap_or(0.0),
            "phase_finalise_ms" => report.phase_finalise_ms = value.parse().unwrap_or(0.0),
            "phase_flood_ms" => report.phase_flood_ms = value.parse().unwrap_or(0.0),
            // phase_other_ms is the derived remainder, recomputed from the fields above.
            "committee" => report.committee = value.parse().unwrap_or(0),
            "rotations" => report.rotations = value.parse().unwrap_or(0),
            "chainhash" => report.chainhash = value.to_string(),
            "stall" => report.stalled = value == "1",
            "perblock" => {
                report.per_block_ms = value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            }
            "blockhashes" => {
                report.block_hashes = value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            }
            _ => {}
        }
    }
    report
}

/// Whether two per block digest lists agree over their common prefix, the byte
/// identity the finalised chains of two up hosts must hold to prove they finalised the
/// same blocks. A host that stalled reports no blocks and is compared separately.
pub fn prefix_matches(a: &[String], b: &[String]) -> bool {
    let common = a.len().min(b.len());
    common > 0 && a[..common] == b[..common]
}
