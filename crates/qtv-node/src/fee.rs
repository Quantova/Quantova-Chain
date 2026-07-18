//! Protocol fee parameters, following SPEC-economics.md.
//!
//! The fee schedule is stated in dollar micro units, one millionth of a United
//! States dollar, and never in a raw native amount. Every fee targets a band from
//! five hundredths of a cent to one tenth of a cent, which is USD 0.0005 to USD
//! 0.0010: a transfer sits at the floor when traffic is light and rises toward the
//! ceiling under contention. At charge time the dollar figure is converted to the
//! native asset by a governance rate, the price of one whole QTOV in dollar micro
//! units.
//!
//! CAPPED IN QTOV, TARGETED IN USD. The chain has no price feed. It knows only the
//! governance rate, so it cannot bind the charge measured against the true market
//! price of QTOV, only against that rate. The enforced cap is therefore a hard
//! native ceiling, a maximum number of base units a fee can ever be, set in genesis
//! and independent of the rate. No rate however stale can drive a charge past it.
//! The dollar band is the target the governance rate is kept honest against. So the
//! true claim is that a fee is capped in QTOV and targeted in USD, and it is not
//! capped at a tenth of a cent, because that sentence would require a price oracle
//! the chain deliberately refuses. If QTOV rises faster than governance re-pegs the
//! rate, the realized dollar cost drifts above the target. That residual is inherent
//! without an oracle and is chosen deliberately. See RECORD-fee-cap.md.

/// Five hundredths of a cent, USD 0.0005, in dollar micro units. The band floor
/// and the fee of a simple transfer when traffic is light, a nonzero charge that
/// never rounds away.
pub const MICRO_USD_FLOOR: u128 = 500;

/// One tenth of a cent, USD 0.0010, in dollar micro units. The band ceiling, the
/// dollar target a charge rises to under contention and never past.
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
    /// The hard ceiling on any native charge, in base units, independent of the
    /// rate. The band is a dollar target converted at the governance rate; this
    /// bounds the charge in the unit the sender actually pays, so no rate however
    /// stale drives a fee past it. It caps the charge in QTOV, not in dollars. See
    /// the module note and RECORD-fee-cap.md.
    pub max_fee_native: u64,
}

impl FeeParams {
    /// The devnet parameters. One QTOV is worth one dollar and holds one million
    /// base units, so a transfer at the band floor costs five hundred base units and
    /// the band ceiling is one thousand, which is also the native ceiling at this
    /// rate, so the ceiling does not bite the band until the rate goes stale.
    pub fn devnet() -> Self {
        FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 1_000_000,
            native_unit: 1_000_000,
            max_fee_native: 1_000,
        }
    }

    /// The native charge for a scheduled dollar micro fee. The figure is clamped
    /// into the band before conversion, then the native ceiling bounds the result in
    /// base units, so the charge at the governance rate stays within the band and no
    /// rate drives it past the ceiling in the unit the sender pays.
    ///
    /// The arithmetic cannot panic. The multiply saturates and the divide is checked,
    /// so a rate small enough to overflow the native word yields the largest
    /// representable charge, which the native ceiling then bounds, and a rate the
    /// genesis loader should have rejected as zero yields zero rather than dividing
    /// by it.
    pub fn native_fee(&self, micro_usd: u128) -> u64 {
        let banded = micro_usd.clamp(MICRO_USD_FLOOR, MICRO_USD_CEILING);
        let native = banded
            .saturating_mul(self.native_unit)
            .checked_div(self.rate_micro_usd_per_qtov)
            .unwrap_or(0);
        let native = u64::try_from(native).unwrap_or(u64::MAX);
        native.min(self.max_fee_native)
    }

    /// The native charge for a simple transfer at the band floor, the least a
    /// transfer is charged and the floor a declared fee is rejected below.
    pub fn transfer_fee(&self) -> u64 {
        self.native_fee(self.transfer_micro_usd)
    }

    /// The native charge at the band ceiling, the most a transfer is charged under
    /// contention. Pay what you bid clamps a declared fee to this.
    pub fn ceiling_fee(&self) -> u64 {
        self.native_fee(MICRO_USD_CEILING)
    }

    /// The band floor converted to native at the current rate, before the native
    /// ceiling is applied. The genesis loader holds the ceiling at or above this, so
    /// the ceiling never clamps the floor fee below the band the chain advertises.
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
            max_fee_native: 1_000,
        };
        let dear = FeeParams {
            rate_micro_usd_per_qtov: 2_000_000,
            ..cheap
        };
        assert!(dear.transfer_fee() < cheap.transfer_fee());
    }

    #[test]
    fn the_native_ceiling_holds_when_the_rate_goes_stale_low() {
        // At the genesis rate the band sits within the ceiling. If the rate falls to
        // a tenth without governance re-pegging, the uncapped charge would be ten
        // times larger, but the native ceiling holds it at the ceiling in base units,
        // so a stale rate drives the charge to the ceiling and never past it.
        let fresh = FeeParams {
            transfer_micro_usd: MICRO_USD_CEILING,
            rate_micro_usd_per_qtov: 1_000_000,
            native_unit: 1_000_000,
            max_fee_native: 1_000,
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
        // A rate of one dollar micro unit per whole QTOV would overflow the native
        // word under the old multiply. The charge saturates and the native ceiling
        // bounds it, so an extreme rate cannot take the fee path, which every
        // transaction crosses, down with it.
        let p = FeeParams {
            transfer_micro_usd: MICRO_USD_FLOOR,
            rate_micro_usd_per_qtov: 1,
            native_unit: u128::from(u64::MAX),
            max_fee_native: u64::MAX,
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
            max_fee_native: 1_000,
        };
        assert_eq!(p.transfer_fee(), 0);
    }
}
