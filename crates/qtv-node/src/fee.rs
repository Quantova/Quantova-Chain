
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
