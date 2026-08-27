// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Clone, Copy, Debug)]
pub struct Distribution {
    pub count: usize,
    pub min: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub max: f64,
    pub mean: f64,
}

impl Distribution {
    pub fn of(samples: &[f64]) -> Option<Distribution> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).expect("the samples are finite"));
        let sum: f64 = sorted.iter().sum();
        Some(Distribution {
            count: sorted.len(),
            min: sorted[0],
            p50: percentile(&sorted, 50.0),
            p90: percentile(&sorted, 90.0),
            p99: percentile(&sorted, 99.0),
            max: sorted[sorted.len() - 1],
            mean: sum / sorted.len() as f64,
        })
    }
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let rank = pct / 100.0 * (n - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        return sorted[lo];
    }
    let frac = rank - lo as f64;
    sorted[lo] + (sorted[hi] - sorted[lo]) * frac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_sample_is_its_own_summary() {
        let d = Distribution::of(&[7.0]).expect("one sample");
        assert_eq!(d.count, 1);
        assert_eq!(d.p50, 7.0);
        assert_eq!(d.p99, 7.0);
        assert_eq!(d.max, 7.0);
    }

    #[test]
    fn the_median_and_tail_track_a_known_set() {
        let samples: Vec<f64> = (1..=100).map(|v| v as f64).collect();
        let d = Distribution::of(&samples).expect("many samples");
        assert!((d.p50 - 50.5).abs() < 1e-9);
        assert!((d.p90 - 90.1).abs() < 1e-9);
        assert!((d.p99 - 99.01).abs() < 1e-9);
    }

    #[test]
    fn an_empty_set_has_no_distribution() {
        assert!(Distribution::of(&[]).is_none());
    }
}
