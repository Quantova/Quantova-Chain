use qtv_codec::{Decode, Decoder, Encode, Encoder, Error};

pub const NATIVE_UNIT: u64 = 1_000_000;
pub const BPS_DENOM: u128 = 10_000;

pub const DAY_SECONDS: u64 = 86_400;
pub const HOUR_SECONDS: u64 = 3_600;
pub const MONTH_SECONDS: u64 = 30 * DAY_SECONDS;
pub const YEAR_SECONDS: u64 = 365 * DAY_SECONDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    ChainUpgrade,
    Mint,
    BridgeMigration,
    FreezeRecovery,
    BlacklistKill,
    AddAsset,
    Parameter,
}

impl Track {
    pub fn all() -> [Track; 7] {
        [
            Track::ChainUpgrade,
            Track::Mint,
            Track::BridgeMigration,
            Track::FreezeRecovery,
            Track::BlacklistKill,
            Track::AddAsset,
            Track::Parameter,
        ]
    }

    pub fn deposit(self) -> u64 {
        let whole = match self {
            Track::ChainUpgrade => 600_000,
            Track::Mint => 250_000,
            Track::BridgeMigration => 200_000,
            Track::FreezeRecovery => 150_000,
            Track::BlacklistKill => 200_000,
            Track::AddAsset => 30_000,
            Track::Parameter => 15_000,
        };
        whole * NATIVE_UNIT
    }

    pub fn approval_bps(self) -> u128 {
        match self {
            Track::ChainUpgrade => 8_000,
            Track::Mint => 8_000,
            Track::BridgeMigration => 8_000,
            Track::FreezeRecovery => 7_500,
            Track::BlacklistKill => 7_500,
            Track::AddAsset => 6_000,
            Track::Parameter => 5_000,
        }
    }

    pub fn support_bps(self) -> u128 {
        match self {
            Track::ChainUpgrade => 4_000,
            Track::Mint => 3_500,
            Track::BridgeMigration => 4_000,
            Track::FreezeRecovery => 3_000,
            Track::BlacklistKill => 3_000,
            Track::AddAsset => 1_000,
            Track::Parameter => 400,
        }
    }

    pub fn period_seconds(self) -> u64 {
        match self {
            Track::ChainUpgrade => 14 * DAY_SECONDS,
            Track::Mint => 3 * DAY_SECONDS,
            Track::BridgeMigration => 5 * DAY_SECONDS,
            Track::FreezeRecovery => 6 * HOUR_SECONDS,
            Track::BlacklistKill => 2 * DAY_SECONDS,
            Track::AddAsset => 7 * DAY_SECONDS,
            Track::Parameter => 7 * DAY_SECONDS,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Track::ChainUpgrade => 1,
            Track::Mint => 2,
            Track::BridgeMigration => 3,
            Track::FreezeRecovery => 4,
            Track::BlacklistKill => 5,
            Track::AddAsset => 6,
            Track::Parameter => 7,
        }
    }

    pub fn from_code(code: u8) -> Option<Track> {
        Track::all().into_iter().find(|track| track.code() == code)
    }
}

impl Encode for Track {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u8(self.code());
    }
}

impl Decode for Track {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let code = decoder.get_u8()?;
        Track::from_code(code).ok_or(Error::UnknownTag { tag: code })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conviction {
    Liquid,
    Year,
    TwoYear,
}

impl Conviction {
    pub fn factor_x10(self) -> u128 {
        match self {
            Conviction::Liquid => 10,
            Conviction::Year => 15,
            Conviction::TwoYear => 25,
        }
    }

    pub fn lock_seconds(self) -> u64 {
        match self {
            Conviction::Liquid => MONTH_SECONDS,
            Conviction::Year => YEAR_SECONDS,
            Conviction::TwoYear => 2 * YEAR_SECONDS,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Conviction::Liquid => 0,
            Conviction::Year => 1,
            Conviction::TwoYear => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<Conviction> {
        match code {
            0 => Some(Conviction::Liquid),
            1 => Some(Conviction::Year),
            2 => Some(Conviction::TwoYear),
            _ => None,
        }
    }

    pub fn weight(self, stake: u64) -> u128 {
        (stake as u128) * self.factor_x10() / 10
    }
}

impl Encode for Conviction {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u8(self.code());
    }
}

impl Decode for Conviction {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let code = decoder.get_u8()?;
        Conviction::from_code(code).ok_or(Error::UnknownTag { tag: code })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ballot {
    pub aye: bool,
    pub conviction: Conviction,
    pub stake: u64,
}

impl Ballot {
    pub fn weight(&self) -> u128 {
        self.conviction.weight(self.stake)
    }
}

impl Encode for Ballot {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u8(self.aye as u8);
        self.conviction.encode(encoder);
        encoder.put_u64(self.stake);
    }
}

impl Decode for Ballot {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let aye = decoder.get_u8()? != 0;
        let conviction = Conviction::decode(decoder)?;
        let stake = decoder.get_u64()?;
        Ok(Ballot {
            aye,
            conviction,
            stake,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    pub amount: u64,
    pub until: u64,
}

impl Lock {
    pub fn withdrawable(&self, now: u64) -> bool {
        now >= self.until
    }
}

impl Encode for Lock {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u64(self.amount);
        encoder.put_u64(self.until);
    }
}

impl Decode for Lock {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Lock {
            amount: decoder.get_u64()?,
            until: decoder.get_u64()?,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub aye_weight: u128,
    pub nay_weight: u128,
    pub turnout_stake: u128,
}

impl Tally {
    pub fn record(&mut self, aye: bool, conviction: Conviction, stake: u64) {
        let weight = conviction.weight(stake);
        if aye {
            self.aye_weight += weight;
        } else {
            self.nay_weight += weight;
        }
        self.turnout_stake += stake as u128;
    }

    pub fn reached_support(&self, track: Track, electorate_stake: u128) -> bool {
        electorate_stake > 0
            && self.turnout_stake * BPS_DENOM >= electorate_stake * track.support_bps()
    }

    pub fn reached_approval(&self, track: Track) -> bool {
        let cast = self.aye_weight + self.nay_weight;
        cast > 0 && self.aye_weight * BPS_DENOM >= cast * track.approval_bps()
    }

    pub fn approved(&self, track: Track, electorate_stake: u128) -> bool {
        self.reached_approval(track) && self.reached_support(track, electorate_stake)
    }
}

impl Encode for Tally {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u128(self.aye_weight);
        encoder.put_u128(self.nay_weight);
        encoder.put_u128(self.turnout_stake);
    }
}

impl Decode for Tally {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Tally {
            aye_weight: decoder.get_u128()?,
            nay_weight: decoder.get_u128()?,
            turnout_stake: decoder.get_u128()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seizure {
    pub from: Vec<u8>,
    pub amount: u64,
}

impl Encode for Seizure {
    fn encode(&self, encoder: &mut Encoder) {
        self.from.encode(encoder);
        encoder.put_u64(self.amount);
    }
}

impl Decode for Seizure {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Seizure {
            from: Vec::<u8>::decode(decoder)?,
            amount: decoder.get_u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Upgrade { blob: Vec<u8> },
    Mint { to: Vec<u8>, amount: u64 },
    BridgeMigration { vault: Vec<u8> },
    FreezeRecovery {
        scope: [u8; 32],
        victim: Vec<u8>,
        seizures: Vec<Seizure>,
    },
    Freeze { targets: Vec<Vec<u8>> },
    Blacklist { target: Vec<u8> },
    AddAsset { asset: Vec<u8> },
    Parameter { key: Vec<u8>, value: Vec<u8> },
}

impl Action {
    pub fn track(&self) -> Track {
        match self {
            Action::Upgrade { .. } => Track::ChainUpgrade,
            Action::Mint { .. } => Track::Mint,
            Action::BridgeMigration { .. } => Track::BridgeMigration,
            Action::FreezeRecovery { .. } => Track::FreezeRecovery,
            Action::Blacklist { .. } => Track::BlacklistKill,
            Action::Freeze { .. } => Track::BlacklistKill,
            Action::AddAsset { .. } => Track::AddAsset,
            Action::Parameter { .. } => Track::Parameter,
        }
    }

    pub fn recovery_scope_preimage(victim: &[u8], seizures: &[Seizure]) -> Vec<u8> {
        let mut encoder = Encoder::new();
        victim.to_vec().encode(&mut encoder);
        (seizures.len() as u64).encode(&mut encoder);
        for seizure in seizures {
            seizure.encode(&mut encoder);
        }
        encoder.into_bytes()
    }
}

impl Encode for Action {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Action::Upgrade { blob } => {
                encoder.put_u8(1);
                blob.encode(encoder);
            }
            Action::Mint { to, amount } => {
                encoder.put_u8(2);
                to.encode(encoder);
                encoder.put_u64(*amount);
            }
            Action::BridgeMigration { vault } => {
                encoder.put_u8(3);
                vault.encode(encoder);
            }
            Action::FreezeRecovery {
                scope,
                victim,
                seizures,
            } => {
                encoder.put_u8(4);
                encoder.put_bytes(scope);
                victim.encode(encoder);
                (seizures.len() as u64).encode(encoder);
                for seizure in seizures {
                    seizure.encode(encoder);
                }
            }
            Action::Freeze { targets } => {
                encoder.put_u8(5);
                (targets.len() as u64).encode(encoder);
                for target in targets {
                    target.encode(encoder);
                }
            }
            Action::Blacklist { target } => {
                encoder.put_u8(6);
                target.encode(encoder);
            }
            Action::AddAsset { asset } => {
                encoder.put_u8(7);
                asset.encode(encoder);
            }
            Action::Parameter { key, value } => {
                encoder.put_u8(8);
                key.encode(encoder);
                value.encode(encoder);
            }
        }
    }
}

impl Decode for Action {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let tag = decoder.get_u8()?;
        match tag {
            1 => Ok(Action::Upgrade {
                blob: Vec::<u8>::decode(decoder)?,
            }),
            2 => Ok(Action::Mint {
                to: Vec::<u8>::decode(decoder)?,
                amount: decoder.get_u64()?,
            }),
            3 => Ok(Action::BridgeMigration {
                vault: Vec::<u8>::decode(decoder)?,
            }),
            4 => {
                let scope_bytes = decoder.get_bytes()?;
                let scope: [u8; 32] = scope_bytes.try_into().map_err(|_| Error::UnknownTag { tag })?;
                let victim = Vec::<u8>::decode(decoder)?;
                let count = u64::decode(decoder)?;
                let mut seizures = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    seizures.push(Seizure::decode(decoder)?);
                }
                Ok(Action::FreezeRecovery {
                    scope,
                    victim,
                    seizures,
                })
            }
            5 => {
                let count = u64::decode(decoder)?;
                let mut targets = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    targets.push(Vec::<u8>::decode(decoder)?);
                }
                Ok(Action::Freeze { targets })
            }
            6 => Ok(Action::Blacklist {
                target: Vec::<u8>::decode(decoder)?,
            }),
            7 => Ok(Action::AddAsset {
                asset: Vec::<u8>::decode(decoder)?,
            }),
            8 => Ok(Action::Parameter {
                key: Vec::<u8>::decode(decoder)?,
                value: Vec::<u8>::decode(decoder)?,
            }),
            other => Err(Error::UnknownTag { tag: other }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    WrongTrack,
    RecoveryOutOfScope,
    RecoveryTouchesProtected,
    FreezeTouchesProtected,
    BlacklistTouchesProtected,
}

pub fn check_enactment<F>(track: Track, action: &Action, scope_ok: bool, is_protected: F) -> Result<(), Violation>
where
    F: Fn(&[u8]) -> bool,
{
    if action.track() != track {
        return Err(Violation::WrongTrack);
    }
    match action {
        Action::FreezeRecovery { seizures, .. } => {
            if !scope_ok {
                return Err(Violation::RecoveryOutOfScope);
            }
            if seizures.iter().any(|seizure| is_protected(&seizure.from)) {
                return Err(Violation::RecoveryTouchesProtected);
            }
            Ok(())
        }
        Action::Freeze { targets } => {
            if targets.iter().any(|target| is_protected(target)) {
                return Err(Violation::FreezeTouchesProtected);
            }
            Ok(())
        }
        Action::Blacklist { target } => {
            if is_protected(target) {
                return Err(Violation::BlacklistTouchesProtected);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Deciding,
    Approved,
    Rejected,
}

impl Status {
    pub fn code(self) -> u8 {
        match self {
            Status::Deciding => 0,
            Status::Approved => 1,
            Status::Rejected => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<Status> {
        match code {
            0 => Some(Status::Deciding),
            1 => Some(Status::Approved),
            2 => Some(Status::Rejected),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referendum {
    pub id: u64,
    pub track: Track,
    pub proposer: Vec<u8>,
    pub deposit: u64,
    pub submitted_at: u64,
    pub tally: Tally,
    pub status: Status,
    pub killed: bool,
}

impl Referendum {
    pub fn open(id: u64, track: Track, proposer: Vec<u8>, submitted_at: u64) -> Referendum {
        Referendum {
            id,
            track,
            proposer,
            deposit: track.deposit(),
            submitted_at,
            tally: Tally::default(),
            status: Status::Deciding,
            killed: false,
        }
    }

    pub fn decides_at(&self) -> u64 {
        self.submitted_at.saturating_add(self.track.period_seconds())
    }

    pub fn ready(&self, now: u64) -> bool {
        now >= self.decides_at()
    }

    pub fn resolve(&mut self, now: u64, electorate_stake: u128) -> Status {
        if self.status != Status::Deciding {
            return self.status;
        }
        if self.killed {
            self.status = Status::Rejected;
            return self.status;
        }
        if !self.ready(now) {
            return Status::Deciding;
        }
        self.status = if self.tally.approved(self.track, electorate_stake) {
            Status::Approved
        } else {
            Status::Rejected
        };
        self.status
    }

    pub fn deposit_refunded(&self, electorate_stake: u128) -> bool {
        !self.killed && self.tally.reached_support(self.track, electorate_stake)
    }
}

impl Encode for Referendum {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u64(self.id);
        self.track.encode(encoder);
        self.proposer.encode(encoder);
        encoder.put_u64(self.deposit);
        encoder.put_u64(self.submitted_at);
        self.tally.encode(encoder);
        encoder.put_u8(self.status.code());
        encoder.put_u8(self.killed as u8);
    }
}

impl Decode for Referendum {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let id = decoder.get_u64()?;
        let track = Track::decode(decoder)?;
        let proposer = Vec::<u8>::decode(decoder)?;
        let deposit = decoder.get_u64()?;
        let submitted_at = decoder.get_u64()?;
        let tally = Tally::decode(decoder)?;
        let status_code = decoder.get_u8()?;
        let status = Status::from_code(status_code).ok_or(Error::UnknownTag { tag: status_code })?;
        let killed = decoder.get_u8()? != 0;
        Ok(Referendum {
            id,
            track,
            proposer,
            deposit,
            submitted_at,
            tally,
            status,
            killed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_codec::{from_bytes, to_bytes};

    #[test]
    fn the_seven_tracks_carry_the_canonical_parameters() {
        assert_eq!(Track::all().len(), 7);
        assert_eq!(Track::ChainUpgrade.deposit(), 600_000 * NATIVE_UNIT);
        assert_eq!(Track::ChainUpgrade.approval_bps(), 8_000);
        assert_eq!(Track::ChainUpgrade.support_bps(), 4_000);
        assert_eq!(Track::ChainUpgrade.period_seconds(), 14 * DAY_SECONDS);

        assert_eq!(Track::Mint.deposit(), 250_000 * NATIVE_UNIT);
        assert_eq!(Track::Mint.support_bps(), 3_500);
        assert_eq!(Track::Mint.period_seconds(), 3 * DAY_SECONDS);

        assert_eq!(Track::FreezeRecovery.deposit(), 150_000 * NATIVE_UNIT);
        assert_eq!(Track::FreezeRecovery.approval_bps(), 7_500);
        assert_eq!(Track::FreezeRecovery.support_bps(), 3_000);
        assert_eq!(Track::FreezeRecovery.period_seconds(), 6 * HOUR_SECONDS);

        assert_eq!(Track::AddAsset.deposit(), 30_000 * NATIVE_UNIT);
        assert_eq!(Track::AddAsset.approval_bps(), 6_000);
        assert_eq!(Track::AddAsset.support_bps(), 1_000);

        assert_eq!(Track::Parameter.deposit(), 15_000 * NATIVE_UNIT);
        assert_eq!(Track::Parameter.approval_bps(), 5_000);
        assert_eq!(Track::Parameter.support_bps(), 400);
        assert_eq!(Track::Parameter.period_seconds(), 7 * DAY_SECONDS);
    }

    #[test]
    fn conviction_tops_out_at_two_and_a_half() {
        assert_eq!(Conviction::Liquid.factor_x10(), 10);
        assert_eq!(Conviction::Year.factor_x10(), 15);
        assert_eq!(Conviction::TwoYear.factor_x10(), 25);
        for conviction in [Conviction::Liquid, Conviction::Year, Conviction::TwoYear] {
            assert!(conviction.factor_x10() <= 25);
        }
        assert_eq!(Conviction::Liquid.weight(1_000), 1_000);
        assert_eq!(Conviction::Year.weight(1_000), 1_500);
        assert_eq!(Conviction::TwoYear.weight(1_000), 2_500);
        assert_eq!(Conviction::TwoYear.lock_seconds(), 2 * YEAR_SECONDS);
    }

    #[test]
    fn a_tally_must_clear_both_the_approval_and_the_support_bar() {
        let mut t = Tally::default();
        t.record(true, Conviction::Liquid, 3_000);
        t.record(false, Conviction::Liquid, 2_000);
        // Sixty percent approval and five percent support clear the QIP bars.
        assert!(t.reached_approval(Track::Parameter));
        assert!(t.reached_support(Track::Parameter, 100_000));
        assert!(t.approved(Track::Parameter, 100_000));
        // The same tally clears neither of the chain upgrade bars (needs 80% / 40%).
        assert!(!t.reached_approval(Track::ChainUpgrade));
        assert!(!t.reached_support(Track::ChainUpgrade, 100_000));
        assert!(!t.approved(Track::ChainUpgrade, 100_000));
    }

    #[test]
    fn approval_is_conviction_weighted_but_support_is_raw_stake() {
        let mut t = Tally::default();
        t.record(true, Conviction::TwoYear, 2_000);
        t.record(false, Conviction::Liquid, 2_000);
        assert_eq!(t.aye_weight, 5_000);
        assert_eq!(t.nay_weight, 2_000);
        assert_eq!(t.turnout_stake, 4_000);
    }

    #[test]
    fn a_deposit_returns_on_support_and_is_forfeit_on_spam_or_a_kill() {
        let mut passed = Referendum::open(1, Track::Parameter, vec![1; 32], 0);
        passed.tally.record(true, Conviction::Liquid, 5_000);
        assert!(passed.deposit_refunded(100_000));

        let mut spam = Referendum::open(2, Track::Parameter, vec![2; 32], 0);
        spam.tally.record(true, Conviction::Liquid, 100);
        assert!(!spam.deposit_refunded(100_000));

        let mut killed = Referendum::open(3, Track::Parameter, vec![3; 32], 0);
        killed.tally.record(true, Conviction::Liquid, 5_000);
        killed.killed = true;
        assert!(!killed.deposit_refunded(100_000));
    }

    #[test]
    fn a_referendum_decides_only_when_its_window_closes() {
        let mut r = Referendum::open(1, Track::Mint, vec![1; 32], 1_000);
        r.tally.record(true, Conviction::Liquid, 40_000);
        assert_eq!(
            r.resolve(1_000 + 3 * DAY_SECONDS - 1, 100_000),
            Status::Deciding
        );
        assert_eq!(r.resolve(1_000 + 3 * DAY_SECONDS, 100_000), Status::Approved);
        // Resolving again does not move an already decided referendum.
        assert_eq!(r.resolve(1_000 + 30 * DAY_SECONDS, 100_000), Status::Approved);

        let mut thin = Referendum::open(2, Track::Mint, vec![2; 32], 0);
        thin.tally.record(true, Conviction::Liquid, 10_000);
        assert_eq!(thin.resolve(3 * DAY_SECONDS, 100_000), Status::Rejected);
    }

    #[test]
    fn a_killed_referendum_is_rejected_the_moment_it_resolves() {
        let mut r = Referendum::open(1, Track::Mint, vec![1; 32], 0);
        r.tally.record(true, Conviction::Liquid, 90_000);
        r.killed = true;
        assert_eq!(r.resolve(0, 100_000), Status::Rejected);
    }

    #[test]
    fn the_constitution_gate_lets_an_uncapped_mint_through_on_its_track() {
        let mint = Action::Mint {
            to: vec![9; 32],
            amount: u64::MAX,
        };
        assert_eq!(check_enactment(Track::Mint, &mint, true, |_| false), Ok(()));
        assert_eq!(
            check_enactment(Track::Parameter, &mint, true, |_| false),
            Err(Violation::WrongTrack)
        );
    }

    #[test]
    fn the_constitution_gate_binds_recovery_to_scope_and_shields_protected_accounts() {
        let seizures = vec![Seizure {
            from: vec![1; 32],
            amount: 100,
        }];
        let rec = Action::FreezeRecovery {
            scope: [7u8; 32],
            victim: vec![2; 32],
            seizures: seizures.clone(),
        };
        // A recovery whose committed scope no longer matches is unenactable.
        assert_eq!(
            check_enactment(Track::FreezeRecovery, &rec, false, |_| false),
            Err(Violation::RecoveryOutOfScope)
        );
        // In scope but reaching a protected account (stake, gov lock, treasury) is unenactable.
        assert_eq!(
            check_enactment(Track::FreezeRecovery, &rec, true, |addr| addr == [1u8; 32]),
            Err(Violation::RecoveryTouchesProtected)
        );
        // In scope and touching no protected account, the recovery stands.
        assert_eq!(
            check_enactment(Track::FreezeRecovery, &rec, true, |_| false),
            Ok(())
        );
    }

    #[test]
    fn the_constitution_gate_shields_protected_accounts_from_freeze_and_blacklist() {
        let freeze = Action::Freeze {
            targets: vec![vec![1; 32]],
        };
        assert_eq!(
            check_enactment(Track::BlacklistKill, &freeze, true, |addr| addr == [1u8; 32]),
            Err(Violation::FreezeTouchesProtected)
        );
        assert_eq!(
            check_enactment(Track::BlacklistKill, &freeze, true, |_| false),
            Ok(())
        );

        let blacklist = Action::Blacklist { target: vec![5; 32] };
        assert_eq!(
            check_enactment(Track::BlacklistKill, &blacklist, true, |addr| addr == [5u8; 32]),
            Err(Violation::BlacklistTouchesProtected)
        );
        assert_eq!(
            check_enactment(Track::BlacklistKill, &blacklist, true, |_| false),
            Ok(())
        );
    }

    #[test]
    fn a_recovery_scope_preimage_is_stable_and_changes_with_the_set() {
        let seizures = vec![Seizure {
            from: vec![1; 32],
            amount: 100,
        }];
        let a = Action::recovery_scope_preimage(&[2; 32], &seizures);
        let b = Action::recovery_scope_preimage(&[2; 32], &seizures);
        assert_eq!(a, b);
        let widened = vec![
            Seizure {
                from: vec![1; 32],
                amount: 100,
            },
            Seizure {
                from: vec![3; 32],
                amount: 50,
            },
        ];
        assert_ne!(a, Action::recovery_scope_preimage(&[2; 32], &widened));
    }

    #[test]
    fn a_ballot_and_a_lock_round_trip_through_the_codec() {
        let ballot = Ballot {
            aye: true,
            conviction: Conviction::TwoYear,
            stake: 5_000,
        };
        assert_eq!(ballot.weight(), 12_500);
        let back: Ballot = from_bytes(&to_bytes(&ballot)).unwrap();
        assert_eq!(ballot, back);

        let lock = Lock {
            amount: 5_000,
            until: 63_072_000,
        };
        assert!(!lock.withdrawable(100));
        assert!(lock.withdrawable(63_072_000));
        let back: Lock = from_bytes(&to_bytes(&lock)).unwrap();
        assert_eq!(lock, back);
    }

    #[test]
    fn every_action_round_trips_through_the_codec() {
        let actions = [
            Action::Upgrade { blob: vec![1, 2, 3] },
            Action::Mint {
                to: vec![9; 32],
                amount: 12_345,
            },
            Action::BridgeMigration { vault: vec![4; 32] },
            Action::FreezeRecovery {
                scope: [7u8; 32],
                victim: vec![2; 32],
                seizures: vec![
                    Seizure {
                        from: vec![1; 32],
                        amount: 100,
                    },
                    Seizure {
                        from: vec![3; 32],
                        amount: 50,
                    },
                ],
            },
            Action::Freeze {
                targets: vec![vec![1; 32], vec![2; 32]],
            },
            Action::Blacklist { target: vec![5; 32] },
            Action::AddAsset { asset: vec![6; 32] },
            Action::Parameter {
                key: b"price".to_vec(),
                value: 70_000_000u128.to_le_bytes().to_vec(),
            },
        ];
        for action in actions {
            let back: Action = from_bytes(&to_bytes(&action)).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn a_referendum_round_trips_through_the_codec() {
        let mut r = Referendum::open(42, Track::FreezeRecovery, vec![9; 32], 123);
        r.tally.record(true, Conviction::TwoYear, 1_000);
        r.tally.record(false, Conviction::Year, 400);
        r.status = Status::Approved;
        let bytes = to_bytes(&r);
        let back: Referendum = from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
    }
}
