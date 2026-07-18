pub const NATIVE_UNIT: u128 = 1_000_000;
pub const MIN_STAKE: u64 = 2_000 * NATIVE_UNIT as u64;

pub const HIGH_SESSION_TX: u64 = 50_000_000_000;

pub const LOW_SESSION_BPS: u128 = 100;
pub const HIGH_SESSION_BPS: u128 = 175;
pub const BPS_DENOM: u128 = 10_000;

pub const REWARD_CAP_MICRO_USD_PER_SESSION: u128 = 4_000 * NATIVE_UNIT;

pub const MAINNET_BLACKOUT_DAYS: u64 = 365;
pub const BOND_LOCK_DAYS: u64 = 90;
pub const UNBONDING_DAYS: u64 = 21;
pub const EARLIEST_EXIT_DAYS: u64 = BOND_LOCK_DAYS + UNBONDING_DAYS;

pub const VEST_CLIFF_DAYS: u64 = 365;
pub const VEST_TRANCHE_DAYS: u64 = 120;
pub const VEST_TRANCHES: u64 = 4;

pub const SLASH_ATTRIBUTABLE_BPS: u128 = 10_000;
pub const SLASH_LIVENESS_MINOR_BPS: u128 = 100;
pub const SLASH_LIVENESS_MAJOR_BPS: u128 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    Low,
    High,
}

impl Session {
    pub fn classify(transactions: u64) -> Session {
        if transactions >= HIGH_SESSION_TX {
            Session::High
        } else {
            Session::Low
        }
    }

    pub fn bps(self) -> u128 {
        match self {
            Session::Low => LOW_SESSION_BPS,
            Session::High => HIGH_SESSION_BPS,
        }
    }
}

pub fn eligible(stake: u64) -> bool {
    stake >= MIN_STAKE
}

pub fn session_reward(stake: u64, session: Session, rate_micro_usd_per_qtov: u128) -> u64 {
    let by_rate = (stake as u128).saturating_mul(session.bps()) / BPS_DENOM;
    let bounded = if rate_micro_usd_per_qtov == 0 {
        by_rate
    } else {
        let cap = REWARD_CAP_MICRO_USD_PER_SESSION.saturating_mul(NATIVE_UNIT)
            / rate_micro_usd_per_qtov;
        by_rate.min(cap)
    };
    bounded.min(u64::MAX as u128) as u64
}

pub fn in_blackout(now_day: u64, mainnet_start_day: u64) -> bool {
    now_day.saturating_sub(mainnet_start_day) < MAINNET_BLACKOUT_DAYS
}

pub fn released(earned: u64, age_days: u64) -> u64 {
    let unlocked = if age_days < VEST_CLIFF_DAYS {
        0
    } else {
        (1 + (age_days - VEST_CLIFF_DAYS) / VEST_TRANCHE_DAYS).min(VEST_TRANCHES)
    };
    ((earned as u128) * (unlocked as u128) / (VEST_TRANCHES as u128)) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Attributable,
    LivenessMinor,
    LivenessMajor,
}

pub fn slash(bond: u64, fault: Fault) -> u64 {
    let bps = match fault {
        Fault::Attributable => SLASH_ATTRIBUTABLE_BPS,
        Fault::LivenessMinor => SLASH_LIVENESS_MINOR_BPS,
        Fault::LivenessMajor => SLASH_LIVENESS_MAJOR_BPS,
    };
    ((bond as u128) * bps / SLASH_ATTRIBUTABLE_BPS) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bond {
    pub amount: u64,
    pub bonded_at_day: u64,
}

impl Bond {
    pub fn new(amount: u64, bonded_at_day: u64) -> Option<Bond> {
        if eligible(amount) {
            Some(Bond {
                amount,
                bonded_at_day,
            })
        } else {
            None
        }
    }

    pub fn can_request_exit(&self, now_day: u64) -> bool {
        now_day.saturating_sub(self.bonded_at_day) >= BOND_LOCK_DAYS
    }

    pub fn earliest_exit_day(&self) -> u64 {
        self.bonded_at_day + EARLIEST_EXIT_DAYS
    }

    pub fn slashable_until(&self, exit_requested_day: u64) -> u64 {
        exit_requested_day + UNBONDING_DAYS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QTOV: u64 = NATIVE_UNIT as u64;
    const PRICE_70: u128 = 70 * NATIVE_UNIT;
    const PRICE_2000: u128 = 2_000 * NATIVE_UNIT;

    #[test]
    fn eligibility_is_a_hard_floor() {
        assert!(!eligible(MIN_STAKE - 1));
        assert!(eligible(MIN_STAKE));
        assert!(eligible(MIN_STAKE * 10));
        assert!(Bond::new(1_999 * QTOV, 0).is_none());
        assert!(Bond::new(2_000 * QTOV, 0).is_some());
    }

    #[test]
    fn session_switches_at_fifty_billion() {
        assert_eq!(Session::classify(HIGH_SESSION_TX - 1), Session::Low);
        assert_eq!(Session::classify(HIGH_SESSION_TX), Session::High);
        assert_eq!(Session::classify(HIGH_SESSION_TX + 1), Session::High);
        assert_eq!(Session::classify(0), Session::Low);
    }

    #[test]
    fn reward_is_two_and_three_point_five_percent_a_year() {
        let stake = 2_000 * QTOV;
        assert_eq!(session_reward(stake, Session::Low, PRICE_70), 20 * QTOV);
        assert_eq!(session_reward(stake, Session::High, PRICE_70), 35 * QTOV);
    }

    #[test]
    fn reward_scales_with_stake_until_the_ceiling() {
        assert_eq!(session_reward(3_000 * QTOV, Session::High, PRICE_70), 52_500_000);
        let cap = (REWARD_CAP_MICRO_USD_PER_SESSION * NATIVE_UNIT / PRICE_70) as u64;
        assert_eq!(session_reward(20_000 * QTOV, Session::High, PRICE_70), cap);
        assert!(session_reward(20_000 * QTOV, Session::High, PRICE_70) < 350 * QTOV);
    }

    #[test]
    fn the_dollar_ceiling_bites_when_price_climbs() {
        let stake = 2_000 * QTOV;
        let high = session_reward(stake, Session::High, PRICE_2000);
        assert_eq!(high, 2 * QTOV);
        let per_year = session_reward(stake, Session::High, PRICE_2000) * 2;
        assert_eq!(per_year, 4 * QTOV);
        assert_eq!((per_year as u128) * PRICE_2000 / NATIVE_UNIT, 8_000 * NATIVE_UNIT);
    }

    #[test]
    fn no_rate_means_no_ceiling() {
        let stake = 2_000 * QTOV;
        assert_eq!(session_reward(stake, Session::High, 0), 35 * QTOV);
    }

    #[test]
    fn nothing_pays_in_the_first_year() {
        assert!(in_blackout(0, 0));
        assert!(in_blackout(364, 0));
        assert!(!in_blackout(365, 0));
        assert!(in_blackout(400, 100));
    }

    #[test]
    fn vesting_releases_a_quarter_every_four_months_after_a_year() {
        let earned = 100 * QTOV;
        assert_eq!(released(earned, 0), 0);
        assert_eq!(released(earned, 364), 0);
        assert_eq!(released(earned, 365), 25 * QTOV);
        assert_eq!(released(earned, 485), 50 * QTOV);
        assert_eq!(released(earned, 605), 75 * QTOV);
        assert_eq!(released(earned, 725), 100 * QTOV);
        assert_eq!(released(earned, 5_000), 100 * QTOV);
    }

    #[test]
    fn attributable_faults_take_the_whole_bond() {
        let bond = 2_000 * QTOV;
        assert_eq!(slash(bond, Fault::Attributable), bond);
        assert_eq!(slash(bond, Fault::LivenessMinor), 20 * QTOV);
        assert_eq!(slash(bond, Fault::LivenessMajor), 200 * QTOV);
    }

    #[test]
    fn the_lock_holds_for_ninety_days_then_exit_after_a_hundred_and_eleven() {
        let bond = Bond::new(2_000 * QTOV, 10).unwrap();
        assert!(!bond.can_request_exit(10 + 89));
        assert!(bond.can_request_exit(10 + 90));
        assert_eq!(bond.earliest_exit_day(), 10 + 111);
        assert_eq!(bond.slashable_until(10 + 90), 10 + 90 + 21);
    }
}
