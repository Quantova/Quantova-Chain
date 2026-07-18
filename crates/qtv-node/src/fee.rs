//! Protocol fee parameters, following SPEC-economics.md.
//!
//! The fee schedule is stated in dollar micro units, one millionth of a United
//! States dollar, and never in a raw native amount. Every fee falls within the
//! band from five hundredths of a cent to one tenth of a cent, which is USD 0.0005
//! to USD 0.0010: a transfer sits at the floor when traffic is light and rises
//! toward the ceiling under contention, and never above the ceiling at any load.
//! At charge time the dollar figure is converted to the native asset by a
//! governance rate, the price of one whole QTOV in dollar micro units.
//!
//! WHAT THE CEILING BINDS, AND WHAT IT DOES NOT. The dollar figure is clamped into
//! the band before conversion, so the charge measured at the governance rate can
//! never exceed the ceiling. That is the invariant this module enforces, and the
//! conversion saturates rather than panics so no rate can overflow the native word
//! on the path every transaction takes. The invariant does not extend to the
//! charge measured against the true market price of QTOV, because the chain
//! observes no price other than the governance rate. If the rate lags a real move
//! the realized cost drifts with the market. Binding that needs either a price
//! oracle or a hard native ceiling, a monetary decision that belongs in
//! SPEC-economics and governance, not a silent default here. See RECORD-fee-cap.md.

/// Five hundredths of a cent, USD 0.0005, in dollar micro units. The band floor
/// and the fee of a simple transfer when traffic is light, a nonzero charge that
/// never rounds away.
pub const MICRO_USD_FLOOR: u128 = 500;

/// One tenth of a cent, USD 0.0010, in dollar micro units. The band ceiling and
/// the hard invariant a charged fee can never exceed when measured at the
/// governance rate.
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
    /// base units, so a transfer at the band floor costs five hundred base units,
    /// a nonzero charge that never rounds away.
    pub fn devnet() -> Self {
        FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 1_000_000,
            native_unit: 1_000_000,
        }
    }

    /// The native charge for a scheduled dollar micro fee. The figure is clamped
    /// into the band before conversion, so the charge at the governance rate never
    /// exceeds the ceiling and the floor keeps it nonzero. The result is the dollar
    /// figure divided by the rate, expressed in native base units.
    ///
    /// The arithmetic cannot panic. The multiply saturates and the divide is
    /// checked, so a rate small enough to overflow the native word yields the
    /// largest representable charge rather than aborting the block, and a rate the
    /// genesis loader should have rejected as zero yields zero rather than dividing
    /// by it. The genesis loader is the real guard on both, this is the belt.
    pub fn native_fee(&self, micro_usd: u128) -> u64 {
        let banded = micro_usd.clamp(MICRO_USD_FLOOR, MICRO_USD_CEILING);
        let native = banded
            .saturating_mul(self.native_unit)
            .checked_div(self.rate_micro_usd_per_qtov)
            .unwrap_or(0);
        u64::try_from(native).unwrap_or(u64::MAX)
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
    fn a_tiny_rate_saturates_rather_than_panics() {
        // A rate of one dollar micro unit per whole QTOV would overflow the native
        // word under the old multiply. The charge saturates to the native maximum
        // instead of aborting the block, so a misconfigured or extreme rate cannot
        // take the fee path, which every transaction crosses, down with it.
        let p = FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 1,
            native_unit: u128::from(u64::MAX),
        };
        assert_eq!(p.transfer_fee(), u64::MAX);
    }

    #[test]
    fn a_zero_rate_does_not_divide_by_zero() {
        // The genesis loader rejects a zero rate, but the charge path still refuses
        // to divide by it, yielding zero rather than panicking.
        let p = FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 0,
            native_unit: 1_000_000,
        };
        assert_eq!(p.transfer_fee(), 0);
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
