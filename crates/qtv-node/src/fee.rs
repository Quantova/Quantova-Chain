//! Protocol fee parameters, following SPEC-economics.md.
//!
//! The fee schedule is stated in dollar micro units, one millionth of a United
//! States dollar, and never in a raw native amount. Every fee falls within the
//! band from one hundredth of a cent to one tenth of a cent, which is USD 0.0001
//! to USD 0.0010. At charge time the dollar figure is converted to the native
//! asset by a governance rate, the price of one whole QTOV in dollar micro units.
//! The one tenth of a cent ceiling is a runtime invariant, so the charged figure
//! is clamped into the band before conversion and can never exceed the ceiling.

/// One hundredth of a cent, USD 0.0001, in dollar micro units. The band floor
/// and the fee of a simple transfer, which sits at the low end of the band.
pub const MICRO_USD_FLOOR: u128 = 100;

/// One tenth of a cent, USD 0.0010, in dollar micro units. The band ceiling and
/// the hard runtime invariant a charged fee can never exceed.
pub const MICRO_USD_CEILING: u128 = 1000;

/// The protocol fee parameters. Every value is a genesis setting changed only
/// through the monetary track of governance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeParams {
    /// The scheduled fee for a simple transfer in dollar micro units.
    pub transfer_micro_usd: u128,
    /// The price of one whole QTOV in dollar micro units, the conversion rate.
    pub rate_micro_usd_per_qtov: u128,
    /// The number of native base units in one whole QTOV.
    pub native_unit: u128,
}

impl FeeParams {
    /// The devnet parameters. One QTOV is worth one dollar and holds one million
    /// base units, so a transfer at the band floor costs one hundred base units,
    /// a nonzero charge that never rounds away.
    pub fn devnet() -> Self {
        FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 1_000_000,
            native_unit: 1_000_000,
        }
    }

    /// The native charge for a scheduled dollar micro fee. The figure is clamped
    /// into the band before conversion, so the ceiling binds however the rate
    /// moves, and the floor keeps the charge nonzero. The result is the dollar
    /// figure divided by the rate, expressed in native base units.
    pub fn native_fee(&self, micro_usd: u128) -> u64 {
        let banded = micro_usd.clamp(MICRO_USD_FLOOR, MICRO_USD_CEILING);
        let native = banded * self.native_unit / self.rate_micro_usd_per_qtov;
        u64::try_from(native).expect("a banded fee stays within the native word")
    }

    /// The native charge for a simple transfer, taken from the schedule.
    pub fn transfer_fee(&self) -> u64 {
        self.native_fee(self.transfer_micro_usd)
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
        assert!(p.transfer_fee() <= ceiling);
    }

    #[test]
    fn the_ceiling_binds_above_the_band() {
        let p = FeeParams::devnet();
        // A schedule that asks for more than a tenth of a cent is clamped down.
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
        };
        let dear = FeeParams {
            rate_micro_usd_per_qtov: 2_000_000,
            ..cheap
        };
        assert!(dear.transfer_fee() < cheap.transfer_fee());
    }
}
