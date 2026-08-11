// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use qtv_codec::{Decode, Decoder, Encode, Encoder, Error};
use std::collections::{BTreeMap, BTreeSet};

pub const NATIVE_UNIT: u128 = 1_000_000;
pub const MIN_STAKE: u64 = 2_000 * NATIVE_UNIT as u64;
pub const STAKING_POOL: u64 = 685_714 * NATIVE_UNIT as u64;

// The staking reward emission per session. The pool above is distributed pro rata by stake at the
// founder preference rate of about 57,143 QTOV a year, roughly two sessions a year, so about 28,571 QTOV
pub const SESSION_EMISSION: u64 = 28_571 * NATIVE_UNIT as u64;

// A staking reward becomes fully transferable twelve months after the epoch it was earned, a rolling
// schedule that is the sell pressure control.
pub const REWARD_VEST_DAYS: u64 = 365;

pub const HIGH_SESSION_TX: u64 = 50_000_000_000;
pub const SESSION_DAYS: u64 = 182;

pub const MAINNET_BLACKOUT_DAYS: u64 = 365;
pub const BOND_LOCK_DAYS: u64 = 90;
pub const UNBONDING_DAYS: u64 = 21;
pub const EARLIEST_EXIT_DAYS: u64 = BOND_LOCK_DAYS + UNBONDING_DAYS;

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
}

pub fn eligible(stake: u64) -> bool {
    stake >= MIN_STAKE
}

// The emergent staking reward. A fixed per session emission is distributed pro rata by stake, so the
// yield finds its own level, high when little is staked to draw validators in and settling as the set
// grows, with no cap. The earlier fixed bps curve and the USD rate cap are retired.
pub fn session_reward(stake: u64, total_staked: u64) -> u64 {
    if total_staked == 0 {
        return 0;
    }
    ((SESSION_EMISSION as u128) * (stake as u128) / (total_staked as u128)) as u64
}

pub fn in_blackout(now_day: u64, mainnet_start_day: u64) -> bool {
    now_day.saturating_sub(mainnet_start_day) < MAINNET_BLACKOUT_DAYS
}

// A staking reward tranche is locked until twelve months after the epoch it was earned, then becomes
// fully transferable, a rolling twelve month schedule. This replaces the earlier multi tranche vest.
pub fn released(earned: u64, age_days: u64) -> u64 {
    if age_days < REWARD_VEST_DAYS {
        0
    } else {
        earned
    }
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
    pub exit_requested_at: Option<u64>,
}

impl Bond {
    pub fn new(amount: u64, bonded_at_day: u64) -> Option<Bond> {
        if eligible(amount) {
            Some(Bond {
                amount,
                bonded_at_day,
                exit_requested_at: None,
            })
        } else {
            None
        }
    }

    pub fn request_exit(&mut self, now_day: u64) -> bool {
        if self.exit_requested_at.is_none() && self.can_request_exit(now_day) {
            self.exit_requested_at = Some(now_day);
            true
        } else {
            false
        }
    }

    pub fn can_withdraw(&self, now_day: u64) -> bool {
        match self.exit_requested_at {
            Some(day) => now_day >= day + UNBONDING_DAYS,
            None => false,
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

impl Encode for Bond {
    fn encode(&self, encoder: &mut Encoder) {
        self.amount.encode(encoder);
        self.bonded_at_day.encode(encoder);
        self.exit_requested_at.encode(encoder);
    }
}

impl Decode for Bond {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Bond {
            amount: u64::decode(decoder)?,
            bonded_at_day: u64::decode(decoder)?,
            exit_requested_at: Option::<u64>::decode(decoder)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardTranche {
    pub earned_day: u64,
    pub amount: u64,
    pub claimed: u64,
}

impl Encode for RewardTranche {
    fn encode(&self, encoder: &mut Encoder) {
        self.earned_day.encode(encoder);
        self.amount.encode(encoder);
        self.claimed.encode(encoder);
    }
}

impl Decode for RewardTranche {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(RewardTranche {
            earned_day: u64::decode(decoder)?,
            amount: u64::decode(decoder)?,
            claimed: u64::decode(decoder)?,
        })
    }
}

pub struct StakeLedger {
    bonds: BTreeMap<[u8; 32], Bond>,
    banned: BTreeSet<[u8; 32]>,
    rewards: BTreeMap<[u8; 32], Vec<RewardTranche>>,
    pool: u64,
    treasury: u64,
}

impl StakeLedger {
    pub fn new(pool: u64) -> StakeLedger {
        StakeLedger {
            bonds: BTreeMap::new(),
            banned: BTreeSet::new(),
            rewards: BTreeMap::new(),
            pool,
            treasury: 0,
        }
    }

    pub fn pool(&self) -> u64 {
        self.pool
    }

    pub fn treasury(&self) -> u64 {
        self.treasury
    }

    pub fn bond_of(&self, id: &[u8; 32]) -> Option<&Bond> {
        self.bonds.get(id)
    }

    pub fn is_banned(&self, id: &[u8; 32]) -> bool {
        self.banned.contains(id)
    }

    pub fn total_staked(&self) -> u64 {
        self.bonds.values().map(|b| b.amount).sum()
    }

    pub fn bond(&mut self, id: [u8; 32], amount: u64, day: u64) -> bool {
        if self.banned.contains(&id) {
            return false;
        }
        if let Some(existing) = self.bonds.get_mut(&id) {
            return match existing.amount.checked_add(amount) {
                Some(total) => {
                    existing.amount = total;
                    true
                }
                None => false,
            };
        }
        match Bond::new(amount, day) {
            Some(bond) => {
                self.bonds.insert(id, bond);
                true
            }
            None => false,
        }
    }

    pub fn accrue(&mut self, id: &[u8; 32], now_day: u64, mainnet_start_day: u64) -> u64 {
        if in_blackout(now_day, mainnet_start_day) {
            return 0;
        }
        let total = self.total_staked();
        let stake = match self.bonds.get(id) {
            Some(bond) => bond.amount,
            None => return 0,
        };
        let paid = session_reward(stake, total).min(self.pool);
        self.pool -= paid;
        if paid > 0 {
            self.rewards.entry(*id).or_default().push(RewardTranche {
                earned_day: now_day,
                amount: paid,
                claimed: 0,
            });
        }
        paid
    }

    pub fn claimable(&self, id: &[u8; 32], now_day: u64) -> u64 {
        self.rewards.get(id).map_or(0, |tranches| {
            tranches
                .iter()
                .map(|t| {
                    released(t.amount, now_day.saturating_sub(t.earned_day))
                        .saturating_sub(t.claimed)
                })
                .sum()
        })
    }

    pub fn claim(&mut self, id: &[u8; 32], now_day: u64) -> u64 {
        let mut total = 0;
        if let Some(tranches) = self.rewards.get_mut(id) {
            for t in tranches.iter_mut() {
                let unlocked = released(t.amount, now_day.saturating_sub(t.earned_day));
                total += unlocked.saturating_sub(t.claimed);
                t.claimed = unlocked;
            }
        }
        total
    }

    pub fn slash(&mut self, id: &[u8; 32], fault: Fault) -> u64 {
        let taken = match self.bonds.get_mut(id) {
            Some(bond) => {
                let amount = slash(bond.amount, fault);
                bond.amount -= amount;
                amount
            }
            None => return 0,
        };
        self.treasury += taken;
        if let Fault::Attributable = fault {
            self.bonds.remove(id);
            self.banned.insert(*id);
        }
        taken
    }

    pub fn bond_from_balance(
        &mut self,
        id: [u8; 32],
        balance: u64,
        amount: u64,
        day: u64,
    ) -> Option<u64> {
        if amount > balance {
            return None;
        }
        if self.bond(id, amount, day) {
            Some(balance - amount)
        } else {
            None
        }
    }

    pub fn request_exit(&mut self, id: &[u8; 32], now_day: u64) -> bool {
        match self.bonds.get_mut(id) {
            Some(bond) => bond.request_exit(now_day),
            None => false,
        }
    }

    pub fn withdraw_to_balance(&mut self, id: &[u8; 32], balance: u64, now_day: u64) -> Option<u64> {
        let amount = match self.bonds.get(id) {
            Some(bond) if bond.can_withdraw(now_day) => bond.amount,
            _ => return None,
        };
        self.bonds.remove(id);
        Some(balance + amount)
    }
}

pub struct SessionMeter {
    window_start_day: u64,
    count: u64,
}

impl SessionMeter {
    pub fn new(start_day: u64) -> SessionMeter {
        SessionMeter {
            window_start_day: start_day,
            count: 0,
        }
    }

    pub fn record(&mut self, transactions: u64) {
        self.count = self.count.saturating_add(transactions);
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn window_closed(&self, now_day: u64) -> bool {
        now_day.saturating_sub(self.window_start_day) >= SESSION_DAYS
    }

    pub fn close(&mut self, now_day: u64) -> Option<Session> {
        if self.window_closed(now_day) {
            let session = Session::classify(self.count);
            self.window_start_day = now_day;
            self.count = 0;
            Some(session)
        } else {
            None
        }
    }
}

impl Encode for SessionMeter {
    fn encode(&self, encoder: &mut Encoder) {
        self.window_start_day.encode(encoder);
        self.count.encode(encoder);
    }
}

impl Decode for SessionMeter {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(SessionMeter {
            window_start_day: u64::decode(decoder)?,
            count: u64::decode(decoder)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QTOV: u64 = NATIVE_UNIT as u64;

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
    fn the_reward_is_emergent_and_pro_rata_by_stake() {
        // A sole staker earns the whole session emission, two equal stakers split it, and a larger share
        // of the same total earns proportionally more. There is no cap.
        let stake = 2_000 * QTOV;
        assert_eq!(session_reward(stake, stake), SESSION_EMISSION);
        assert_eq!(session_reward(stake, 2 * stake), SESSION_EMISSION / 2);
        assert_eq!(session_reward(3 * stake, 4 * stake), SESSION_EMISSION * 3 / 4);
        assert_eq!(session_reward(stake, 0), 0);
    }

    #[test]
    fn the_yield_is_higher_when_little_is_staked_and_falls_as_the_set_grows() {
        let stake = 2_000 * QTOV;
        let thin = session_reward(stake, 10_000 * QTOV);
        let deep = session_reward(stake, 1_000_000 * QTOV);
        assert!(thin > deep, "the same stake earns more when less is staked");
    }

    #[test]
    fn nothing_pays_in_the_first_year() {
        assert!(in_blackout(0, 0));
        assert!(in_blackout(364, 0));
        assert!(!in_blackout(365, 0));
        assert!(in_blackout(400, 100));
    }

    #[test]
    fn a_reward_is_locked_for_a_year_then_fully_transferable() {
        let earned = 100 * QTOV;
        assert_eq!(released(earned, 0), 0);
        assert_eq!(released(earned, 364), 0);
        assert_eq!(released(earned, 365), 100 * QTOV);
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

    fn id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn ledger_bonds_only_eligible_and_never_the_banned() {
        let mut l = StakeLedger::new(100_000 * QTOV);
        assert!(!l.bond(id(1), 1_999 * QTOV, 0));
        assert!(l.bond(id(1), 2_000 * QTOV, 0));
        assert_eq!(l.total_staked(), 2_000 * QTOV);
        l.slash(&id(1), Fault::Attributable);
        assert!(l.is_banned(&id(1)));
        assert!(!l.bond(id(1), 2_000 * QTOV, 0));
    }

    #[test]
    fn rewards_come_from_the_pool_and_never_overdraw() {
        // A small pool caps the emergent reward and the pool never goes negative.
        let mut l = StakeLedger::new(50 * QTOV);
        l.bond(id(1), 2_000 * QTOV, 0);
        assert_eq!(l.accrue(&id(1), 400, 0), 50 * QTOV);
        assert_eq!(l.pool(), 0);
        assert_eq!(l.accrue(&id(1), 400, 0), 0);
    }

    #[test]
    fn a_sole_staker_earns_the_whole_session_emission() {
        let mut l = StakeLedger::new(100_000 * QTOV);
        l.bond(id(1), 2_000 * QTOV, 0);
        assert_eq!(l.accrue(&id(1), 400, 0), SESSION_EMISSION);
        assert_eq!(l.pool(), 100_000 * QTOV - SESSION_EMISSION);
    }

    #[test]
    fn the_blackout_pays_nothing_in_the_first_year() {
        let mut l = StakeLedger::new(100_000 * QTOV);
        l.bond(id(1), 2_000 * QTOV, 0);
        assert_eq!(l.accrue(&id(1), 364, 0), 0);
        assert_eq!(l.pool(), 100_000 * QTOV);
        assert_eq!(l.accrue(&id(1), 365, 0), SESSION_EMISSION);
    }

    #[test]
    fn slashing_moves_stake_to_the_treasury() {
        let mut l = StakeLedger::new(0);
        l.bond(id(1), 2_000 * QTOV, 0);
        assert_eq!(l.slash(&id(1), Fault::LivenessMinor), 20 * QTOV);
        assert_eq!(l.treasury(), 20 * QTOV);
        assert_eq!(l.bond_of(&id(1)).unwrap().amount, 1_980 * QTOV);
        l.slash(&id(1), Fault::Attributable);
        assert_eq!(l.treasury(), 2_000 * QTOV);
        assert!(l.bond_of(&id(1)).is_none());
    }

    #[test]
    fn bonding_moves_coins_out_of_the_spendable_balance() {
        let mut l = StakeLedger::new(0);
        assert_eq!(
            l.bond_from_balance(id(1), 5_000 * QTOV, 2_000 * QTOV, 0),
            Some(3_000 * QTOV)
        );
        assert_eq!(l.total_staked(), 2_000 * QTOV);
        assert_eq!(l.bond_from_balance(id(2), 1_000 * QTOV, 2_000 * QTOV, 0), None);
        assert_eq!(l.bond_from_balance(id(2), 5_000 * QTOV, 1_999 * QTOV, 0), None);
        l.slash(&id(1), Fault::Attributable);
        assert_eq!(l.bond_from_balance(id(1), 5_000 * QTOV, 2_000 * QTOV, 0), None);
    }

    #[test]
    fn exit_runs_the_lock_then_the_unbonding_then_returns_the_stake() {
        let mut l = StakeLedger::new(0);
        l.bond_from_balance(id(1), 5_000 * QTOV, 2_000 * QTOV, 0);
        assert!(!l.request_exit(&id(1), 89));
        assert!(l.request_exit(&id(1), 90));
        assert!(!l.request_exit(&id(1), 90));
        assert_eq!(l.withdraw_to_balance(&id(1), 3_000 * QTOV, 90 + 20), None);
        assert_eq!(
            l.withdraw_to_balance(&id(1), 3_000 * QTOV, 90 + 21),
            Some(5_000 * QTOV)
        );
        assert!(l.bond_of(&id(1)).is_none());
    }

    #[test]
    fn a_bond_stays_slashable_through_the_unbonding() {
        let mut l = StakeLedger::new(0);
        l.bond_from_balance(id(1), 5_000 * QTOV, 2_000 * QTOV, 0);
        l.request_exit(&id(1), 90);
        assert_eq!(l.slash(&id(1), Fault::Attributable), 2_000 * QTOV);
        assert_eq!(l.treasury(), 2_000 * QTOV);
        assert!(l.bond_of(&id(1)).is_none());
    }

    #[test]
    fn the_session_meter_counts_a_window_then_classifies_and_resets() {
        let mut m = SessionMeter::new(0);
        m.record(30_000_000_000);
        m.record(15_000_000_000);
        assert_eq!(m.count(), 45_000_000_000);
        assert!(!m.window_closed(181));
        assert_eq!(m.close(181), None);
        assert_eq!(m.close(182), Some(Session::Low));
        assert_eq!(m.count(), 0);
        m.record(50_000_000_000);
        assert_eq!(m.close(182 + 182), Some(Session::High));
    }

    #[test]
    fn a_reward_is_claimable_in_full_a_year_after_it_is_earned() {
        let mut l = StakeLedger::new(100_000 * QTOV);
        l.bond(id(1), 2_000 * QTOV, 0);
        let earned = l.accrue(&id(1), 400, 0);
        assert_eq!(earned, SESSION_EMISSION);
        assert_eq!(l.claimable(&id(1), 400 + 364), 0);
        assert_eq!(l.claimable(&id(1), 400 + 365), earned);
        assert_eq!(l.claim(&id(1), 400 + 365), earned);
        assert_eq!(l.claimable(&id(1), 400 + 365), 0);
        assert_eq!(l.claim(&id(1), 400 + 5_000), 0);
    }

    #[test]
    fn a_bond_round_trips_through_the_codec() {
        let bond = Bond::new(2_000 * QTOV, 42).unwrap();
        let bytes = qtv_codec::to_bytes(&bond);
        assert_eq!(qtv_codec::from_bytes::<Bond>(&bytes).unwrap(), bond);
    }
}
