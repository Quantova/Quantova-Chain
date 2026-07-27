// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_codec::{Decode, Decoder, Encode, Encoder, Error};

const PREALLOC_LIMIT: usize = 4096;
const MIN_SEIZURE: usize = 16;
const MIN_BYTES_VEC: usize = 8;

fn bounded_capacity(remaining: usize, count: u64, min_element: usize) -> Result<usize, Error> {
    let ceiling = (remaining / min_element.max(1)) as u64;
    if count > ceiling {
        return Err(Error::LengthOverrun {
            length: count,
            found: remaining,
        });
    }
    Ok((count as usize).min(PREALLOC_LIMIT))
}

pub const NATIVE_UNIT: u64 = 1_000_000;
pub const BPS_DENOM: u128 = 10_000;
pub const THRESHOLD_BPS: u128 = 4_000;

pub const DAY_SECONDS: u64 = 86_400;
pub const HOUR_SECONDS: u64 = 3_600;
pub const MONTH_SECONDS: u64 = 30 * DAY_SECONDS;
pub const YEAR_SECONDS: u64 = 365 * DAY_SECONDS;

pub const BRIDGE_FREEZE_BOND: u64 = 390_000 * NATIVE_UNIT;
pub const BRIDGE_FREEZE_DURATION: u64 = 7 * DAY_SECONDS;
pub const BRIDGE_FREEZE_COOLDOWN: u64 = DAY_SECONDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    ChainUpgrade,
    Mint,
    BridgeMigration,
    FreezeRecovery,
    BlacklistKill,
}

impl Track {
    pub fn all() -> [Track; 5] {
        [
            Track::ChainUpgrade,
            Track::Mint,
            Track::BridgeMigration,
            Track::FreezeRecovery,
            Track::BlacklistKill,
        ]
    }

    pub fn deposit(self) -> u64 {
        let whole = match self {
            Track::ChainUpgrade => 2_250_000,
            Track::Mint => 4_000_000,
            Track::BridgeMigration => 1_500_000,
            Track::FreezeRecovery => 292_500,
            Track::BlacklistKill => 390_000,
        };
        whole * NATIVE_UNIT
    }

    pub fn period_seconds(self) -> u64 {
        match self {
            Track::ChainUpgrade => 14 * DAY_SECONDS,
            Track::Mint => 3 * DAY_SECONDS,
            Track::BridgeMigration => 5 * DAY_SECONDS,
            Track::FreezeRecovery => 6 * HOUR_SECONDS,
            Track::BlacklistKill => 2 * DAY_SECONDS,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Track::ChainUpgrade => 1,
            Track::Mint => 2,
            Track::BridgeMigration => 3,
            Track::FreezeRecovery => 4,
            Track::BlacklistKill => 5,
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
    pub aye_stake: u128,
    pub nay_stake: u128,
}

impl Tally {
    pub fn record(&mut self, aye: bool, stake: u64) {
        if aye {
            self.aye_stake += stake as u128;
        } else {
            self.nay_stake += stake as u128;
        }
    }

    pub fn turnout(&self) -> u128 {
        self.aye_stake + self.nay_stake
    }

    pub fn approved(&self, electorate_stake: u128) -> bool {
        electorate_stake > 0 && self.aye_stake * BPS_DENOM >= electorate_stake * THRESHOLD_BPS
    }
}

impl Encode for Tally {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u128(self.aye_stake);
        encoder.put_u128(self.nay_stake);
    }
}

impl Decode for Tally {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Tally {
            aye_stake: decoder.get_u128()?,
            nay_stake: decoder.get_u128()?,
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
pub struct OperatorClaim {
    pub operator_id: u32,
    pub public_key: Vec<u8>,
    pub pop: Vec<u8>,
}

impl Encode for OperatorClaim {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u32(self.operator_id);
        encoder.put_bytes(&self.public_key);
        encoder.put_bytes(&self.pop);
    }
}

impl Decode for OperatorClaim {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let operator_id = decoder.get_u32()?;
        let public_key = decoder.get_bytes()?.to_vec();
        let pop = decoder.get_bytes()?.to_vec();
        Ok(OperatorClaim {
            operator_id,
            public_key,
            pop,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommitteeRotation {
    pub operators: Vec<OperatorClaim>,
    pub threshold: u32,
}

impl Encode for CommitteeRotation {
    fn encode(&self, encoder: &mut Encoder) {
        (self.operators.len() as u64).encode(encoder);
        for operator in &self.operators {
            operator.encode(encoder);
        }
        encoder.put_u32(self.threshold);
    }
}

impl Decode for CommitteeRotation {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let count = u64::decode(decoder)?;
        let mut operators =
            Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_BYTES_VEC)?);
        for _ in 0..count {
            operators.push(OperatorClaim::decode(decoder)?);
        }
        let threshold = decoder.get_u32()?;
        Ok(CommitteeRotation {
            operators,
            threshold,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    // turn on a feature that shipped in the binary but stayed dormant, by version, so an upgrade rides a vote and never a fork
    Activate { feature: Vec<u8>, version: u64 },
    Mint { to: Vec<u8>, amount: u64 },
    BridgeMigration { vault: Vec<u8> },
    BridgeUnfreeze,
    GuardianRotate { set: GuardianSet },
    CommitteeRotate { rotation: CommitteeRotation },
    AssetRegister {
        asset_id: [u8; 16],
        cap: u128,
        epoch_cap: u128,
        requires_stark: bool,
    },
    EpochAdvance,
    OperatorRevoke { operator_id: u32 },
    FreezeRecovery {
        scope: [u8; 32],
        victim: Vec<u8>,
        seizures: Vec<Seizure>,
    },
    Freeze { targets: Vec<Vec<u8>> },
    Blacklist { target: Vec<u8> },
    Parameter { key: Vec<u8>, value: Vec<u8> },
    Spend { from: Vec<u8>, to: Vec<u8>, amount: u64 },
    Unfreeze { targets: Vec<Vec<u8>> },
}

impl Action {
    pub fn track(&self) -> Track {
        match self {
            Action::Activate { .. } => Track::ChainUpgrade,
            Action::Mint { .. } => Track::Mint,
            Action::BridgeMigration { .. } => Track::BridgeMigration,
            Action::BridgeUnfreeze => Track::BlacklistKill,
            Action::GuardianRotate { .. } => Track::ChainUpgrade,
            Action::CommitteeRotate { .. } => Track::BridgeMigration,
            Action::AssetRegister { .. } => Track::BridgeMigration,
            Action::EpochAdvance => Track::BridgeMigration,
            Action::OperatorRevoke { .. } => Track::BridgeMigration,
            Action::FreezeRecovery { .. } => Track::FreezeRecovery,
            Action::Blacklist { .. } => Track::BlacklistKill,
            Action::Freeze { .. } => Track::BlacklistKill,
            Action::Parameter { .. } => Track::ChainUpgrade,
            Action::Spend { .. } => Track::Mint,
            Action::Unfreeze { .. } => Track::BlacklistKill,
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
            Action::Activate { feature, version } => {
                encoder.put_u8(1);
                feature.encode(encoder);
                encoder.put_u64(*version);
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
            Action::BridgeUnfreeze => {
                encoder.put_u8(11);
            }
            Action::GuardianRotate { set } => {
                encoder.put_u8(12);
                set.encode(encoder);
            }
            Action::CommitteeRotate { rotation } => {
                encoder.put_u8(13);
                rotation.encode(encoder);
            }
            Action::AssetRegister {
                asset_id,
                cap,
                epoch_cap,
                requires_stark,
            } => {
                encoder.put_u8(14);
                encoder.put_bytes(asset_id);
                encoder.put_u128(*cap);
                encoder.put_u128(*epoch_cap);
                encoder.put_u8(*requires_stark as u8);
            }
            Action::EpochAdvance => {
                encoder.put_u8(15);
            }
            Action::OperatorRevoke { operator_id } => {
                encoder.put_u8(16);
                encoder.put_u32(*operator_id);
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
            Action::Parameter { key, value } => {
                encoder.put_u8(8);
                key.encode(encoder);
                value.encode(encoder);
            }
            Action::Spend { from, to, amount } => {
                encoder.put_u8(9);
                from.encode(encoder);
                to.encode(encoder);
                encoder.put_u64(*amount);
            }
            Action::Unfreeze { targets } => {
                encoder.put_u8(10);
                (targets.len() as u64).encode(encoder);
                for target in targets {
                    target.encode(encoder);
                }
            }
        }
    }
}

impl Decode for Action {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let tag = decoder.get_u8()?;
        match tag {
            1 => Ok(Action::Activate {
                feature: Vec::<u8>::decode(decoder)?,
                version: decoder.get_u64()?,
            }),
            2 => Ok(Action::Mint {
                to: Vec::<u8>::decode(decoder)?,
                amount: decoder.get_u64()?,
            }),
            3 => Ok(Action::BridgeMigration {
                vault: Vec::<u8>::decode(decoder)?,
            }),
            11 => Ok(Action::BridgeUnfreeze),
            12 => Ok(Action::GuardianRotate {
                set: GuardianSet::decode(decoder)?,
            }),
            13 => Ok(Action::CommitteeRotate {
                rotation: CommitteeRotation::decode(decoder)?,
            }),
            14 => {
                let asset_id: [u8; 16] = decoder
                    .get_bytes()?
                    .try_into()
                    .map_err(|_| Error::UnknownTag { tag })?;
                let cap = decoder.get_u128()?;
                let epoch_cap = decoder.get_u128()?;
                let requires_stark = decoder.get_u8()? != 0;
                Ok(Action::AssetRegister {
                    asset_id,
                    cap,
                    epoch_cap,
                    requires_stark,
                })
            }
            15 => Ok(Action::EpochAdvance),
            16 => Ok(Action::OperatorRevoke {
                operator_id: decoder.get_u32()?,
            }),
            4 => {
                let scope_bytes = decoder.get_bytes()?;
                let scope: [u8; 32] = scope_bytes.try_into().map_err(|_| Error::UnknownTag { tag })?;
                let victim = Vec::<u8>::decode(decoder)?;
                let count = u64::decode(decoder)?;
                let mut seizures =
                    Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_SEIZURE)?);
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
                let mut targets =
                    Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_BYTES_VEC)?);
                for _ in 0..count {
                    targets.push(Vec::<u8>::decode(decoder)?);
                }
                Ok(Action::Freeze { targets })
            }
            6 => Ok(Action::Blacklist {
                target: Vec::<u8>::decode(decoder)?,
            }),
            8 => Ok(Action::Parameter {
                key: Vec::<u8>::decode(decoder)?,
                value: Vec::<u8>::decode(decoder)?,
            }),
            9 => Ok(Action::Spend {
                from: Vec::<u8>::decode(decoder)?,
                to: Vec::<u8>::decode(decoder)?,
                amount: decoder.get_u64()?,
            }),
            10 => {
                let count = u64::decode(decoder)?;
                let mut targets =
                    Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_BYTES_VEC)?);
                for _ in 0..count {
                    targets.push(Vec::<u8>::decode(decoder)?);
                }
                Ok(Action::Unfreeze { targets })
            }
            other => Err(Error::UnknownTag { tag: other }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeFreeze {
    pub who: [u8; 32],
    pub bond: u64,
    pub until: u64,
}

impl Encode for BridgeFreeze {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_bytes(&self.who);
        encoder.put_u64(self.bond);
        encoder.put_u64(self.until);
    }
}

impl Decode for BridgeFreeze {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let who: [u8; 32] = decoder
            .get_bytes()?
            .try_into()
            .map_err(|_| Error::UnknownTag { tag: 0 })?;
        Ok(BridgeFreeze {
            who,
            bond: decoder.get_u64()?,
            until: decoder.get_u64()?,
        })
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GuardianSet {
    pub members: Vec<[u8; 32]>,
    pub threshold: u32,
}

impl GuardianSet {
    pub fn new(members: Vec<[u8; 32]>, threshold: u32) -> GuardianSet {
        GuardianSet { members, threshold }
    }

    pub fn well_formed(&self) -> bool {
        self.threshold >= 2 && (self.threshold as usize) <= self.members.len()
    }

    pub fn is_member(&self, id: &[u8; 32]) -> bool {
        self.members.contains(id)
    }

    pub fn authorizes(&self, approvers: &[[u8; 32]]) -> bool {
        if !self.well_formed() {
            return false;
        }
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for approver in approvers {
            if self.is_member(approver) && !seen.contains(approver) {
                seen.push(*approver);
            }
        }
        seen.len() as u32 >= self.threshold
    }
}

impl Encode for GuardianSet {
    fn encode(&self, encoder: &mut Encoder) {
        (self.members.len() as u64).encode(encoder);
        for member in &self.members {
            encoder.put_bytes(member);
        }
        encoder.put_u32(self.threshold);
    }
}

impl Decode for GuardianSet {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let count = u64::decode(decoder)?;
        let mut members =
            Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_SEIZURE)?);
        for _ in 0..count {
            let bytes = decoder.get_bytes()?;
            let member: [u8; 32] = bytes.try_into().map_err(|_| Error::UnknownTag { tag: 0 })?;
            members.push(member);
        }
        let threshold = decoder.get_u32()?;
        Ok(GuardianSet { members, threshold })
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
        self.status = if self.tally.approved(electorate_stake) {
            Status::Approved
        } else {
            Status::Rejected
        };
        self.status
    }

    pub fn deposit_refunded(&self, electorate_stake: u128) -> bool {
        !self.killed && self.tally.approved(electorate_stake)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnactmentReceipt {
    pub referendum: u64,
    pub proposal_hash: [u8; 32],
    pub scope: [u8; 32],
    pub tally: Tally,
    pub enacted_at: u64,
}

impl Encode for EnactmentReceipt {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u64(self.referendum);
        encoder.put_bytes(&self.proposal_hash);
        encoder.put_bytes(&self.scope);
        self.tally.encode(encoder);
        encoder.put_u64(self.enacted_at);
    }
}

impl Decode for EnactmentReceipt {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let referendum = decoder.get_u64()?;
        let proposal_hash: [u8; 32] = decoder
            .get_bytes()?
            .try_into()
            .map_err(|_| Error::UnknownTag { tag: 0 })?;
        let scope: [u8; 32] = decoder
            .get_bytes()?
            .try_into()
            .map_err(|_| Error::UnknownTag { tag: 0 })?;
        let tally = Tally::decode(decoder)?;
        let enacted_at = decoder.get_u64()?;
        Ok(EnactmentReceipt {
            referendum,
            proposal_hash,
            scope,
            tally,
            enacted_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_codec::{from_bytes, to_bytes};

    #[test]
    fn the_five_tracks_carry_the_canonical_parameters() {
        assert_eq!(Track::all().len(), 5);
        assert_eq!(Track::ChainUpgrade.deposit(), 2_250_000 * NATIVE_UNIT);
        assert_eq!(Track::ChainUpgrade.period_seconds(), 14 * DAY_SECONDS);

        assert_eq!(Track::Mint.deposit(), 4_000_000 * NATIVE_UNIT);
        assert_eq!(Track::Mint.period_seconds(), 3 * DAY_SECONDS);

        assert_eq!(Track::BridgeMigration.deposit(), 1_500_000 * NATIVE_UNIT);
        assert_eq!(Track::BridgeMigration.period_seconds(), 5 * DAY_SECONDS);

        assert_eq!(Track::FreezeRecovery.deposit(), 292_500 * NATIVE_UNIT);
        assert_eq!(Track::FreezeRecovery.period_seconds(), 6 * HOUR_SECONDS);

        assert_eq!(Track::BlacklistKill.deposit(), 390_000 * NATIVE_UNIT);
        assert_eq!(Track::BlacklistKill.period_seconds(), 2 * DAY_SECONDS);

        assert_eq!(THRESHOLD_BPS, 4_000);
        assert!(Track::from_code(6).is_none());
        assert!(Track::from_code(7).is_none());
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
    fn a_tally_passes_at_forty_percent_of_total_staked_and_fails_just_below() {
        let mut pass = Tally::default();
        pass.record(true, 400_000);
        assert!(pass.approved(1_000_000));

        let mut fail = Tally::default();
        fail.record(true, 399_999);
        assert!(!fail.approved(1_000_000));

        let mut none = Tally::default();
        none.record(true, 500_000);
        assert!(!none.approved(0));
    }

    #[test]
    fn a_tally_counts_raw_stake_on_each_side() {
        let mut t = Tally::default();
        t.record(true, 2_000);
        t.record(false, 2_000);
        assert_eq!(t.aye_stake, 2_000);
        assert_eq!(t.nay_stake, 2_000);
        assert_eq!(t.turnout(), 4_000);
    }

    #[test]
    fn a_deposit_returns_when_the_bar_is_met_and_is_forfeit_on_a_miss_or_a_kill() {
        let mut passed = Referendum::open(1, Track::ChainUpgrade, vec![1; 32], 0);
        passed.tally.record(true, 40_000);
        assert!(passed.deposit_refunded(100_000));

        let mut miss = Referendum::open(2, Track::ChainUpgrade, vec![2; 32], 0);
        miss.tally.record(true, 39_999);
        assert!(!miss.deposit_refunded(100_000));

        let mut killed = Referendum::open(3, Track::ChainUpgrade, vec![3; 32], 0);
        killed.tally.record(true, 40_000);
        killed.killed = true;
        assert!(!killed.deposit_refunded(100_000));
    }

    #[test]
    fn a_referendum_decides_only_when_its_window_closes() {
        let mut r = Referendum::open(1, Track::Mint, vec![1; 32], 1_000);
        r.tally.record(true, 40_000);
        assert_eq!(
            r.resolve(1_000 + 3 * DAY_SECONDS - 1, 100_000),
            Status::Deciding
        );
        assert_eq!(r.resolve(1_000 + 3 * DAY_SECONDS, 100_000), Status::Approved);
        assert_eq!(r.resolve(1_000 + 30 * DAY_SECONDS, 100_000), Status::Approved);

        let mut thin = Referendum::open(2, Track::Mint, vec![2; 32], 0);
        thin.tally.record(true, 39_999);
        assert_eq!(thin.resolve(3 * DAY_SECONDS, 100_000), Status::Rejected);
    }

    #[test]
    fn a_killed_referendum_is_rejected_the_moment_it_resolves() {
        let mut r = Referendum::open(1, Track::Mint, vec![1; 32], 0);
        r.tally.record(true, 90_000);
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
            check_enactment(Track::BlacklistKill, &mint, true, |_| false),
            Err(Violation::WrongTrack)
        );
    }

    #[test]
    fn a_parameter_change_rides_the_chain_upgrade_track_and_no_other() {
        let action = Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        assert_eq!(action.track(), Track::ChainUpgrade);
        assert_eq!(
            check_enactment(Track::ChainUpgrade, &action, true, |_| false),
            Ok(())
        );
        assert_eq!(
            check_enactment(Track::Mint, &action, true, |_| false),
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
        assert_eq!(
            check_enactment(Track::FreezeRecovery, &rec, false, |_| false),
            Err(Violation::RecoveryOutOfScope)
        );
        assert_eq!(
            check_enactment(Track::FreezeRecovery, &rec, true, |addr| addr == [1u8; 32]),
            Err(Violation::RecoveryTouchesProtected)
        );
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
    fn an_enactment_receipt_round_trips_through_the_codec() {
        let mut tally = Tally::default();
        tally.record(true, 3_000);
        let receipt = EnactmentReceipt {
            referendum: 7,
            proposal_hash: [9u8; 32],
            scope: [4u8; 32],
            tally,
            enacted_at: 123_456,
        };
        let back: EnactmentReceipt = from_bytes(&to_bytes(&receipt)).unwrap();
        assert_eq!(receipt, back);
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
            Action::Activate { feature: b"parallel_state".to_vec(), version: 2 },
            Action::Mint {
                to: vec![9; 32],
                amount: 12_345,
            },
            Action::BridgeMigration { vault: vec![4; 32] },
            Action::BridgeUnfreeze,
            Action::GuardianRotate {
                set: GuardianSet::new(vec![[7u8; 32], [8u8; 32], [9u8; 32]], 2),
            },
            Action::CommitteeRotate {
                rotation: CommitteeRotation {
                    operators: vec![
                        OperatorClaim {
                            operator_id: 0,
                            public_key: vec![1, 2, 3],
                            pop: vec![4, 5, 6],
                        },
                        OperatorClaim {
                            operator_id: 1,
                            public_key: vec![7, 8],
                            pop: vec![9],
                        },
                    ],
                    threshold: 2,
                },
            },
            Action::AssetRegister {
                asset_id: [3u8; 16],
                cap: 1_000_000,
                epoch_cap: 250_000,
                requires_stark: true,
            },
            Action::EpochAdvance,
            Action::OperatorRevoke { operator_id: 7 },
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
            Action::Parameter {
                key: b"price".to_vec(),
                value: 70_000_000u128.to_le_bytes().to_vec(),
            },
            Action::Spend {
                from: vec![7; 32],
                to: vec![8; 32],
                amount: 42_000_000,
            },
            Action::Unfreeze {
                targets: vec![vec![1; 32], vec![2; 32]],
            },
        ];
        for action in actions {
            let back: Action = from_bytes(&to_bytes(&action)).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn a_guardian_caucus_never_acts_on_a_single_key() {
        let members = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let caucus = GuardianSet::new(members.clone(), 2);
        assert!(caucus.well_formed());
        assert!(!caucus.authorizes(&[[1u8; 32]]), "one guardian is not a caucus");
        assert!(
            !caucus.authorizes(&[[1u8; 32], [1u8; 32]]),
            "one guardian named twice is still one key"
        );
        assert!(caucus.authorizes(&[[1u8; 32], [2u8; 32]]));
        assert!(!caucus.authorizes(&[[1u8; 32], [9u8; 32]]), "an outsider carries no weight");
        assert!(caucus.authorizes(&[[3u8; 32], [1u8; 32], [2u8; 32]]));

        let single = GuardianSet::new(members, 1);
        assert!(!single.well_formed(), "a threshold of one is never a well formed caucus");
        assert!(!single.authorizes(&[[1u8; 32]]));

        let short = GuardianSet::new(vec![[1u8; 32]], 2);
        assert!(!short.well_formed(), "a threshold above the membership is not well formed");
    }

    #[test]
    fn a_guardian_set_round_trips_through_the_codec() {
        let caucus = GuardianSet::new(vec![[4u8; 32], [5u8; 32], [6u8; 32]], 2);
        let back: GuardianSet = from_bytes(&to_bytes(&caucus)).unwrap();
        assert_eq!(caucus, back);
    }

    #[test]
    fn an_early_bridge_unfreeze_rides_the_blacklist_kill_track() {
        assert_eq!(Action::BridgeUnfreeze.track(), Track::BlacklistKill);
        assert_eq!(
            check_enactment(Track::BlacklistKill, &Action::BridgeUnfreeze, true, |_| false),
            Ok(())
        );
        assert_eq!(
            check_enactment(Track::BridgeMigration, &Action::BridgeUnfreeze, true, |_| false),
            Err(Violation::WrongTrack)
        );
    }

    #[test]
    fn the_bridge_freeze_bond_matches_the_account_freeze_deposit() {
        assert_eq!(BRIDGE_FREEZE_BOND, Track::BlacklistKill.deposit());
    }

    #[test]
    fn the_bridge_admin_actions_ride_the_bridge_migration_track() {
        let actions = [
            Action::CommitteeRotate {
                rotation: CommitteeRotation::default(),
            },
            Action::AssetRegister {
                asset_id: [1u8; 16],
                cap: 1,
                epoch_cap: 1,
                requires_stark: false,
            },
            Action::EpochAdvance,
            Action::OperatorRevoke { operator_id: 3 },
        ];
        for action in actions {
            assert_eq!(action.track(), Track::BridgeMigration);
            assert_eq!(
                check_enactment(Track::BridgeMigration, &action, true, |_| false),
                Ok(())
            );
            assert_eq!(
                check_enactment(Track::Mint, &action, true, |_| false),
                Err(Violation::WrongTrack)
            );
        }
    }

    #[test]
    fn a_guardian_rotation_rides_the_chain_upgrade_track() {
        let action = Action::GuardianRotate {
            set: GuardianSet::new(vec![[1u8; 32], [2u8; 32], [3u8; 32]], 2),
        };
        assert_eq!(action.track(), Track::ChainUpgrade);
        assert_eq!(
            check_enactment(Track::ChainUpgrade, &action, true, |_| false),
            Ok(())
        );
        assert_eq!(
            check_enactment(Track::BridgeMigration, &action, true, |_| false),
            Err(Violation::WrongTrack)
        );
    }

    #[test]
    fn a_treasury_spend_rides_the_mint_track() {
        let spend = Action::Spend {
            from: vec![1; 32],
            to: vec![2; 32],
            amount: 1_000,
        };
        assert_eq!(spend.track(), Track::Mint);
    }

    #[test]
    fn a_referendum_round_trips_through_the_codec() {
        let mut r = Referendum::open(42, Track::FreezeRecovery, vec![9; 32], 123);
        r.tally.record(true, 1_000);
        r.tally.record(false, 400);
        r.status = Status::Approved;
        let bytes = to_bytes(&r);
        let back: Referendum = from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn a_recovery_action_with_a_huge_seizure_count_and_a_tiny_body_is_rejected() {
        let mut encoder = Encoder::new();
        encoder.put_u8(4);
        encoder.put_bytes(&[0u8; 32]);
        vec![1u8, 2, 3, 4].encode(&mut encoder);
        u64::MAX.encode(&mut encoder);
        let bytes = encoder.into_bytes();
        let result: Result<Action, Error> = from_bytes(&bytes);
        assert!(matches!(result, Err(Error::LengthOverrun { .. })));
    }

    #[test]
    fn a_freeze_action_with_a_huge_target_count_and_a_tiny_body_is_rejected() {
        let mut encoder = Encoder::new();
        encoder.put_u8(5);
        u64::MAX.encode(&mut encoder);
        let bytes = encoder.into_bytes();
        let result: Result<Action, Error> = from_bytes(&bytes);
        assert!(matches!(result, Err(Error::LengthOverrun { .. })));
    }

    #[test]
    fn bounded_capacity_rejects_a_count_that_overruns_the_remaining_bytes() {
        assert!(matches!(
            bounded_capacity(0, u64::MAX, MIN_SEIZURE),
            Err(Error::LengthOverrun { .. })
        ));
        assert_eq!(bounded_capacity(1_000_000, 2, MIN_SEIZURE).unwrap(), 2);
    }

    #[test]
    fn a_bridge_freeze_record_round_trips_through_the_codec() {
        let record = BridgeFreeze {
            who: [0x2Au8; 32],
            bond: BRIDGE_FREEZE_BOND,
            until: 1_000 + BRIDGE_FREEZE_DURATION,
        };
        let back: BridgeFreeze = from_bytes(&to_bytes(&record)).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn the_bridge_freeze_bond_holds_for_longer_than_a_migration_runs() {
        assert_eq!(BRIDGE_FREEZE_BOND, 390_000 * NATIVE_UNIT);
        assert_eq!(BRIDGE_FREEZE_DURATION, 7 * DAY_SECONDS);
        assert_eq!(BRIDGE_FREEZE_COOLDOWN, DAY_SECONDS);
        assert!(BRIDGE_FREEZE_DURATION > Track::BridgeMigration.period_seconds());
        assert!(BRIDGE_FREEZE_COOLDOWN > 0);
    }
}
