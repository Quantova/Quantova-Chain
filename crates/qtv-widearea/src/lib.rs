
use qtv_loopback::stats::Distribution;

pub mod local;
pub mod runtime;

pub const TRANSPORT_PORT: u16 = 40404;

pub mod env {
    pub const INDEX: &str = "QTV_WA_INDEX";
    pub const ADDRS: &str = "QTV_WA_ADDRS";
    pub const UP: &str = "QTV_WA_UP";
    pub const ACCOUNTS: &str = "QTV_WA_ACCOUNTS";
    pub const HEIGHTS: &str = "QTV_WA_HEIGHTS";
    pub const WARMUP: &str = "QTV_WA_WARMUP";
    pub const HEIGHTCAP: &str = "QTV_WA_HEIGHTCAP";
    pub const VIEWMS: &str = "QTV_WA_VIEWMS";
    pub const STALLSECS: &str = "QTV_WA_STALLSECS";
    pub const SLOWMS: &str = "QTV_WA_SLOWMS";
    pub const BASE: &str = "QTV_WA_BASE";
}

pub fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[derive(Clone, Default)]
pub struct RunReport {
    pub idx: usize,
    pub per_block_ms: Vec<f64>,
    pub finalized_tx: u64,
    pub consensus_ms: f64,
    pub sign_ms: f64,
    pub fill_ms: f64,
    pub committee: usize,
    pub heights: u64,
    pub rotations: u64,
    pub chainhash: String,
    pub block_hashes: Vec<String>,
    pub stalled: bool,
    pub phase_wait_ms: f64,
    pub phase_build_ms: f64,
    pub phase_verify_ms: f64,
    pub phase_aggregate_ms: f64,
    pub phase_finalise_ms: f64,
    pub phase_flood_ms: f64,
}

impl RunReport {
    pub fn throughput(&self) -> f64 {
        if self.consensus_ms > 0.0 {
            self.finalized_tx as f64 / (self.consensus_ms / 1000.0)
        } else {
            0.0
        }
    }

    pub fn finality(&self) -> Option<Distribution> {
        Distribution::of(&self.per_block_ms)
    }

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

pub fn prefix_matches(a: &[String], b: &[String]) -> bool {
    let common = a.len().min(b.len());
    common > 0 && a[..common] == b[..common]
}
