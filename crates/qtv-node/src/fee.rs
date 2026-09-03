// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// The frozen fee band, in millionths of a dollar.
///
/// FLOOR is half a tenth of a cent and CEILING is one tenth of a cent: every fee the
/// chain charges is clamped into this band by `native_fee`, whatever a caller asks
/// for and whatever the price feed says. These two numbers are economics, not
/// tuning. They are pinned by the founder, they are consensus visible through the
/// fee every block charges, and `the_fee_band_is_frozen` below exists to make a
/// change to either one impossible to land by accident.
pub const MICRO_USD_FLOOR: u128 = 500;

pub const MICRO_USD_CEILING: u128 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeParams {
    pub transfer_micro_usd: u128,
    pub rate_micro_usd_per_qtov: u128,
    pub native_unit: u128,
    pub max_fee_native: u64,
    pub chain_id: u64,
}

impl FeeParams {
    pub fn devnet() -> Self {
        FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 1_000_000,
            native_unit: 1_000_000,
            max_fee_native: 1_000,
            chain_id: qtv_tx::LOCAL_CHAIN_ID,
        }
    }

    pub fn native_fee(&self, micro_usd: u128) -> u64 {
        let banded = micro_usd.clamp(MICRO_USD_FLOOR, MICRO_USD_CEILING);
        let native = banded
            .saturating_mul(self.native_unit)
            .checked_div(self.rate_micro_usd_per_qtov)
            .unwrap_or(0);
        let native = u64::try_from(native).unwrap_or(u64::MAX);
        native.min(self.max_fee_native)
    }

    pub fn transfer_fee(&self) -> u64 {
        self.native_fee(self.transfer_micro_usd)
    }

    pub fn ceiling_fee(&self) -> u64 {
        self.native_fee(MICRO_USD_CEILING)
    }

    pub fn floor_native_uncapped(&self) -> u64 {
        let native = MICRO_USD_FLOOR
            .saturating_mul(self.native_unit)
            .checked_div(self.rate_micro_usd_per_qtov)
            .unwrap_or(0);
        u64::try_from(native).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fee_band_is_frozen() {
        // Pinned economics. 500 micro USD is 0.05 of a cent and 1000 is 0.10 of a
        // cent, so the band is 0.05c to 0.10c per transaction. Changing either number
        // repices every transaction on the chain and every quote the explorer, the
        // SDKs and the wallet publish, so it does not get to happen as a side effect
        // of some other edit. If this test is failing, the band was changed: put it
        // back, or change it deliberately with the founder's word on the new figures.
        assert_eq!(
            MICRO_USD_FLOOR, 500,
            "the fee floor is frozen at 0.05 of a cent"
        );
        assert_eq!(
            MICRO_USD_CEILING, 1000,
            "the fee ceiling is frozen at 0.10 of a cent"
        );
        assert!(
            MICRO_USD_FLOOR < MICRO_USD_CEILING,
            "the band must be a band"
        );

        // And the band has to actually bind, not merely be declared.
        let p = FeeParams::devnet();
        for asked in [0, 1, MICRO_USD_FLOOR - 1, MICRO_USD_CEILING + 1, u128::MAX] {
            let charged = p.native_fee(asked);
            assert!(
                charged >= p.native_fee(MICRO_USD_FLOOR)
                    && charged <= p.native_fee(MICRO_USD_CEILING),
                "asking for {asked} micro USD charged {charged}, outside the frozen band"
            );
        }
    }

    #[test]
    fn a_transfer_fee_is_nonzero_and_within_the_band() {
        let p = FeeParams::devnet();
        let floor = p.native_fee(MICRO_USD_FLOOR);
        let ceiling = p.native_fee(MICRO_USD_CEILING);
        assert!(floor > 0);
        assert_eq!(p.transfer_fee(), floor);
        assert_eq!(p.ceiling_fee(), ceiling);
        assert!(p.transfer_fee() <= ceiling);
    }

    #[test]
    fn the_ceiling_binds_above_the_band() {
        let p = FeeParams::devnet();
        assert_eq!(
            p.native_fee(MICRO_USD_CEILING * 10),
            p.native_fee(MICRO_USD_CEILING)
        );
    }

    #[test]
    fn a_rising_native_price_lowers_the_native_fee() {
        let cheap = FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 1_000_000,
            native_unit: 1_000_000,
            max_fee_native: 1_000,
            chain_id: qtv_tx::LOCAL_CHAIN_ID,
        };
        let dear = FeeParams {
            rate_micro_usd_per_qtov: 2_000_000,
            ..cheap
        };
        assert!(dear.transfer_fee() < cheap.transfer_fee());
    }

    #[test]
    fn the_native_ceiling_holds_when_the_rate_goes_stale_low() {
        let fresh = FeeParams {
            transfer_micro_usd: MICRO_USD_CEILING,
            rate_micro_usd_per_qtov: 1_000_000,
            native_unit: 1_000_000,
            max_fee_native: 1_000,
            chain_id: qtv_tx::LOCAL_CHAIN_ID,
        };
        assert_eq!(fresh.native_fee(MICRO_USD_CEILING), 1_000);
        let stale_low = FeeParams {
            rate_micro_usd_per_qtov: 100_000,
            ..fresh
        };
        assert_eq!(stale_low.native_fee(MICRO_USD_CEILING), 1_000);
    }

    #[test]
    fn a_tiny_rate_saturates_rather_than_panics() {
        let p = FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 1,
            native_unit: u128::from(u64::MAX),
            max_fee_native: u64::MAX,
            chain_id: qtv_tx::LOCAL_CHAIN_ID,
        };
        assert_eq!(p.transfer_fee(), u64::MAX);
    }

    #[test]
    fn a_zero_rate_does_not_divide_by_zero() {
        let p = FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 0,
            native_unit: 1_000_000,
            max_fee_native: 1_000,
            chain_id: qtv_tx::LOCAL_CHAIN_ID,
        };
        assert_eq!(p.transfer_fee(), 0);
    }
}
