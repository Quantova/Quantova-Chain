// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::params::NetworkParams;
use crate::work::U256;

pub fn clamp_timespan(actual: u32, params: &NetworkParams) -> u32 {
    let min = params.target_timespan / 4;
    let max = params.target_timespan.saturating_mul(4);
    actual.clamp(min, max)
}

pub fn compute_retarget(old_bits: u32, actual_timespan: u32, params: &NetworkParams) -> u32 {
    let span = clamp_timespan(actual_timespan, params);
    let old = U256::from_compact(old_bits);
    let mut next = old
        .mul_u64(span as u64)
        .div_u64(params.target_timespan as u64);
    let limit = U256::from_compact(params.pow_limit_bits);
    if next > limit {
        next = limit;
    }
    next.to_compact()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{BITCOIN, BITCOIN_CASH};

    const PERIOD_FIRST_TIME: u32 = 1_261_130_161;
    const PERIOD_LAST_TIME: u32 = 1_262_152_739;

    #[test]
    fn the_first_bitcoin_difficulty_change_matches_the_real_chain() {
        let actual = PERIOD_LAST_TIME - PERIOD_FIRST_TIME;
        assert_eq!(compute_retarget(0x1d00ffff, actual, &BITCOIN), 0x1d00d86a);
    }

    #[test]
    fn a_fast_period_clamps_to_a_quarter_of_the_target_timespan() {
        let quarter = BITCOIN.target_timespan / 4;
        assert_eq!(
            compute_retarget(0x1d00ffff, 0, &BITCOIN),
            compute_retarget(0x1d00ffff, quarter, &BITCOIN)
        );
    }

    #[test]
    fn a_slow_period_clamps_to_four_target_timespans() {
        let four = BITCOIN.target_timespan.saturating_mul(4);
        assert_eq!(
            compute_retarget(0x1d00d86a, u32::MAX, &BITCOIN),
            compute_retarget(0x1d00d86a, four, &BITCOIN)
        );
    }

    #[test]
    fn a_retarget_never_drops_below_the_pow_limit() {
        assert_eq!(compute_retarget(0x1d00ffff, u32::MAX, &BITCOIN), 0x1d00ffff);
    }

    #[test]
    fn bitcoin_cash_uses_the_same_legacy_retarget() {
        let actual = PERIOD_LAST_TIME - PERIOD_FIRST_TIME;
        assert_eq!(
            compute_retarget(0x1d00ffff, actual, &BITCOIN_CASH),
            0x1d00d86a
        );
    }
}
