//! Chain state held in the qtv-state sparse Merkle trie, following SPEC-state.md
//! and SPEC-accounts.md.
//!
//! Every address maps to an account record that holds the nonce that orders the
//! transactions of the sender, the native balance in base units, and the sender
//! signature scheme and public key. The public key is kept in state so a
//! signature can be verified without a side channel. The trie is keyed by the
//! thirty two byte address hash, which is the canonical address payload, so no
//! separate hashing step is introduced. The state root is the trie root over the
//! whole account set and is fixed by that set, independent of insertion order.

use qtv_codec::{from_bytes, to_bytes, Decode, Decoder, Encode, Encoder, Error};
use qtv_crypto::sha3;
use qtv_staking::{Bond, Session, SessionMeter};
use qtv_state::{Key, Trie, HASH_LEN, KEY_LEN};

/// An account record: the nonce, the native balance, the signature scheme, and
/// the public key the sender signs under. An absent account reads as the default,
/// a fresh account with a zero balance and no key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: u64,
    pub scheme: u8,
    pub public_key: Vec<u8>,
}

impl Account {
    /// A funded account with a known signing key, the shape a genesis account and
    /// a sender both take.
    pub fn funded(balance: u64, scheme: u8, public_key: Vec<u8>) -> Self {
        Account {
            nonce: 0,
            balance,
            scheme,
            public_key,
        }
    }

    /// Whether the account carries a public key, the precondition for verifying a
    /// signature from it. A receive only account has none until it first signs.
    pub fn has_key(&self) -> bool {
        !self.public_key.is_empty()
    }
}

impl Encode for Account {
    fn encode(&self, encoder: &mut Encoder) {
        self.nonce.encode(encoder);
        self.balance.encode(encoder);
        self.scheme.encode(encoder);
        self.public_key.encode(encoder);
    }
}

impl Decode for Account {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Account {
            nonce: u64::decode(decoder)?,
            balance: u64::decode(decoder)?,
            scheme: u8::decode(decoder)?,
            public_key: Vec::<u8>::decode(decoder)?,
        })
    }
}

/// The trie key for an address, the canonical address payload rendered back to
/// its raw bytes. A canonical address carries the full thirty two byte hash, so
/// the payload fills the key. A shorter payload is left padded space, and an
/// address that does not parse maps to the zero key, which the caller rules out
/// by validating the address before it reaches state.
fn state_key(address: &str) -> Key {
    let mut key = [0u8; KEY_LEN];
    if let Ok(payload) = qtv_idfmt::parse_address(address) {
        let n = payload.len().min(KEY_LEN);
        key[..n].copy_from_slice(&payload[..n]);
    }
    key
}

/// The trie key an address maps to, the handle a disk store persists an account
/// under. It is the same key the ledger writes under, so a persisted account
/// reloads into the identical trie position.
pub fn account_key(address: &str) -> Key {
    state_key(address)
}

const STAKE_BOND_TAG: &[u8] = b"qtv/stake/bond/";
const STAKE_REWARDS_TAG: &[u8] = b"qtv/stake/rewards/";
const STAKE_POOL_TAG: &[u8] = b"qtv/stake/pool";
const STAKE_TREASURY_TAG: &[u8] = b"qtv/stake/treasury";
const STAKE_PRICE_TAG: &[u8] = b"qtv/stake/price";
const STAKE_MAINNET_TAG: &[u8] = b"qtv/stake/mainnet";
const STAKE_METER_TAG: &[u8] = b"qtv/stake/meter";

fn stake_bond_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(STAKE_BOND_TAG.len() + id.len());
    input.extend_from_slice(STAKE_BOND_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

fn stake_rewards_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(STAKE_REWARDS_TAG.len() + id.len());
    input.extend_from_slice(STAKE_REWARDS_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

/// A validator's persisted reward record: the tranches accrued to it, each dated
/// by the session it was earned and carrying how much of it has been claimed. The
/// list is length prefixed so it round trips through one trie leaf, and it stays
/// short because a tranche is added at most once per session and a fully claimed,
/// fully vested tranche is pruned on claim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RewardBook {
    pub tranches: Vec<qtv_staking::RewardTranche>,
}

impl Encode for RewardBook {
    fn encode(&self, encoder: &mut Encoder) {
        (self.tranches.len() as u64).encode(encoder);
        for tranche in &self.tranches {
            tranche.encode(encoder);
        }
    }
}

impl Decode for RewardBook {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let count = u64::decode(decoder)?;
        let mut tranches = Vec::with_capacity(count as usize);
        for _ in 0..count {
            tranches.push(qtv_staking::RewardTranche::decode(decoder)?);
        }
        Ok(RewardBook { tranches })
    }
}

fn stake_singleton_key(tag: &[u8]) -> Key {
    sha3::sha3_256(tag)
}

const STAKE_BANNED_TAG: &[u8] = b"qtv/stake/banned/";

fn stake_banned_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(STAKE_BANNED_TAG.len() + id.len());
    input.extend_from_slice(STAKE_BANNED_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

fn address_id(address: &str) -> Option<[u8; 32]> {
    let payload = qtv_idfmt::parse_address(address).ok()?;
    if payload.len() != KEY_LEN {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&payload);
    Some(id)
}

pub fn stake_system_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/stake/system"))
        .expect("a full hash reaches the address floor")
}

impl Ledger {
    pub fn stake_bond(&self, id: &[u8; 32]) -> Option<Bond> {
        match self.trie.get(&stake_bond_key(id)) {
            Some(bytes) if !bytes.is_empty() => {
                Some(from_bytes(bytes).expect("state holds a canonical bond record"))
            }
            _ => None,
        }
    }

    pub fn set_stake_bond(&mut self, id: &[u8; 32], bond: &Bond) {
        self.trie.insert(stake_bond_key(id), to_bytes(bond));
    }

    pub fn clear_stake_bond(&mut self, id: &[u8; 32]) {
        self.trie.insert(stake_bond_key(id), Vec::new());
    }

    /// The committee weight of an address in whole native units, the unit the
    /// sortition sampler weighs a validator by. A banned account or one with no
    /// bond weighs zero. The base unit remainder below one whole unit is dropped,
    /// which can never cross the eligibility floor because the minimum bond is
    /// thousands of whole units, so the truncation only ever discards dust.
    pub fn staked_weight(&self, address: &str) -> u64 {
        let id = match address_id(address) {
            Some(id) => id,
            None => return 0,
        };
        if self.is_stake_banned(&id) {
            return 0;
        }
        self.stake_bond(&id)
            .map(|bond| bond.amount / qtv_staking::NATIVE_UNIT as u64)
            .unwrap_or(0)
    }

    /// Seed a genesis validator's bond directly, returning the state key and value
    /// so a persisting node can write it under the genesis root. The amount is in
    /// base units and the bond dates from day zero. This puts the stake the
    /// committee already assumed onto the ledger, so every later reweight reads the
    /// live bond rather than a genesis constant, and a slash or a top up moves the
    /// committee weight with it.
    pub fn seed_validator_bond(&mut self, address: &str, amount: u64) -> Option<(Key, Vec<u8>)> {
        let id = address_id(address)?;
        let bond = Bond {
            amount,
            bonded_at_day: 0,
            exit_requested_at: None,
        };
        self.set_stake_bond(&id, &bond);
        Some((stake_bond_key(&id), to_bytes(&bond)))
    }

    pub fn stake_pool(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(STAKE_POOL_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical pool balance"))
            .unwrap_or(0)
    }

    pub fn set_stake_pool(&mut self, amount: u64) {
        self.trie
            .insert(stake_singleton_key(STAKE_POOL_TAG), to_bytes(&amount));
    }

    pub fn seed_stake_pool(&mut self, amount: u64) -> (Key, Vec<u8>) {
        self.set_stake_pool(amount);
        (stake_singleton_key(STAKE_POOL_TAG), to_bytes(&amount))
    }

    pub fn stake_treasury(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(STAKE_TREASURY_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical treasury balance"))
            .unwrap_or(0)
    }

    pub fn set_stake_treasury(&mut self, amount: u64) {
        self.trie
            .insert(stake_singleton_key(STAKE_TREASURY_TAG), to_bytes(&amount));
    }

    pub fn is_stake_banned(&self, id: &[u8; 32]) -> bool {
        matches!(self.trie.get(&stake_banned_key(id)), Some(bytes) if !bytes.is_empty())
    }

    pub fn set_stake_banned(&mut self, id: &[u8; 32]) {
        self.trie.insert(stake_banned_key(id), vec![1]);
    }

    /// The native to dollar rate governance publishes, in base dollar units per
    /// whole native unit, the figure the session reward cap is measured against. It
    /// is zero until governance sets it, and a zero rate holds every accrual to
    /// nothing, so no reward is ever paid on an unpublished rate.
    pub fn stake_price(&self) -> u128 {
        self.trie
            .get(&stake_singleton_key(STAKE_PRICE_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical price"))
            .unwrap_or(0)
    }

    pub fn set_stake_price(&mut self, rate_micro_usd_per_qtov: u128) {
        self.trie.insert(
            stake_singleton_key(STAKE_PRICE_TAG),
            to_bytes(&rate_micro_usd_per_qtov),
        );
    }

    /// The day mainnet began, the anchor the reward blackout is measured from. It
    /// defaults to the maximum day, which holds the whole validator set in blackout
    /// so no reward accrues until governance sets the real mainnet start. This is
    /// what keeps a test network, which never sets it, from ever paying a reward.
    pub fn stake_mainnet_start(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(STAKE_MAINNET_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical mainnet start"))
            .unwrap_or(u64::MAX)
    }

    pub fn set_stake_mainnet_start(&mut self, day: u64) {
        self.trie
            .insert(stake_singleton_key(STAKE_MAINNET_TAG), to_bytes(&day));
    }

    /// The session meter, the running count of transactions in the open session
    /// window and the day the window opened. It defaults to a window that opened on
    /// day zero, so the first session runs from genesis.
    pub fn session_meter(&self) -> SessionMeter {
        self.trie
            .get(&stake_singleton_key(STAKE_METER_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical session meter"))
            .unwrap_or_else(|| SessionMeter::new(0))
    }

    pub fn set_session_meter(&mut self, meter: &SessionMeter) {
        self.trie
            .insert(stake_singleton_key(STAKE_METER_TAG), to_bytes(meter));
    }

    fn stake_rewards(&self, id: &[u8; 32]) -> RewardBook {
        self.trie
            .get(&stake_rewards_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical reward book"))
            .unwrap_or_default()
    }

    fn set_stake_rewards(&mut self, id: &[u8; 32], book: &RewardBook) {
        self.trie.insert(stake_rewards_key(id), to_bytes(book));
    }

    /// Accrue one session's reward to a validator from the pool. Nothing accrues
    /// during the mainnet blackout, on an unpublished rate, to an account with no
    /// bond, or beyond what the pool holds. The paid amount leaves the pool and
    /// lands as a tranche dated to the accrual day, from which it vests on the
    /// released schedule. Returns the amount paid, so a caller can total the round.
    pub fn accrue_reward(&mut self, address: &str, session: Session, now_day: u64) -> u64 {
        let id = match address_id(address) {
            Some(id) => id,
            None => return 0,
        };
        if qtv_staking::in_blackout(now_day, self.stake_mainnet_start()) {
            return 0;
        }
        let rate = self.stake_price();
        if rate == 0 {
            return 0;
        }
        let stake = match self.stake_bond(&id) {
            Some(bond) => bond.amount,
            None => return 0,
        };
        let paid = qtv_staking::session_reward(stake, session, rate).min(self.stake_pool());
        if paid == 0 {
            return 0;
        }
        self.set_stake_pool(self.stake_pool() - paid);
        let mut book = self.stake_rewards(&id);
        book.tranches.push(qtv_staking::RewardTranche {
            earned_day: now_day,
            amount: paid,
            claimed: 0,
        });
        self.set_stake_rewards(&id, &book);
        paid
    }

    /// The reward a validator could claim on a given day, the vested but unclaimed
    /// amount summed over its tranches. It is read only and moves no balance.
    pub fn claimable_reward(&self, address: &str, now_day: u64) -> u64 {
        let id = match address_id(address) {
            Some(id) => id,
            None => return 0,
        };
        self.stake_rewards(&id)
            .tranches
            .iter()
            .map(|tranche| {
                qtv_staking::released(tranche.amount, now_day.saturating_sub(tranche.earned_day))
                    .saturating_sub(tranche.claimed)
            })
            .sum()
    }

    /// Claim a validator's vested rewards into its balance on a given day. Each
    /// tranche releases the vested amount not yet claimed, the total credits the
    /// account, and a tranche that is fully vested and fully claimed is pruned so
    /// the book cannot grow without bound. Returns the amount credited.
    pub fn claim_reward(&mut self, address: &str, now_day: u64) -> u64 {
        let id = match address_id(address) {
            Some(id) => id,
            None => return 0,
        };
        let mut book = self.stake_rewards(&id);
        let mut credited = 0u64;
        for tranche in book.tranches.iter_mut() {
            let vested = qtv_staking::released(tranche.amount, now_day.saturating_sub(tranche.earned_day));
            credited += vested.saturating_sub(tranche.claimed);
            tranche.claimed = vested;
        }
        if credited == 0 {
            return 0;
        }
        book.tranches
            .retain(|tranche| tranche.claimed < tranche.amount);
        self.set_stake_rewards(&id, &book);
        let mut account = self.account(address);
        account.balance = account.balance.saturating_add(credited);
        self.set_account(address, &account);
        credited
    }

    /// Feed a block's transaction count into the session meter and, when the session
    /// window closes, classify it and reset the window. Returns the classification
    /// of the session that just closed, or None while the window is still open. The
    /// meter is persisted, so the count carries across blocks and reloads, and the
    /// classification is a pure function of committed state, so every node closes the
    /// same session on the same day with the same verdict.
    pub fn record_session(&mut self, transactions: u64, now_day: u64) -> Option<Session> {
        let mut meter = self.session_meter();
        meter.record(transactions);
        let closed = meter.close(now_day);
        self.set_session_meter(&meter);
        closed
    }

    pub fn bond(&mut self, address: &str, amount: u64, day: u64) -> bool {
        let id = match address_id(address) {
            Some(id) => id,
            None => return false,
        };
        if self.is_stake_banned(&id) {
            return false;
        }
        let mut account = self.account(address);
        if account.balance < amount {
            return false;
        }
        let existing = self.stake_bond(&id).map(|b| b.amount).unwrap_or(0);
        let total = existing + amount;
        if !qtv_staking::eligible(total) {
            return false;
        }
        account.balance -= amount;
        self.set_account(address, &account);
        self.set_stake_bond(
            &id,
            &Bond {
                amount: total,
                bonded_at_day: day,
                exit_requested_at: None,
            },
        );
        true
    }

    pub fn bond_with_fee(&mut self, address: &str, amount: u64, fee: u64, day: u64) -> bool {
        let id = match address_id(address) {
            Some(id) => id,
            None => return false,
        };
        if self.is_stake_banned(&id) {
            return false;
        }
        let debit = match amount.checked_add(fee) {
            Some(debit) => debit,
            None => return false,
        };
        let mut account = self.account(address);
        if account.balance < debit {
            return false;
        }
        let existing = self.stake_bond(&id).map(|b| b.amount).unwrap_or(0);
        let total = match existing.checked_add(amount) {
            Some(total) => total,
            None => return false,
        };
        if !qtv_staking::eligible(total) {
            return false;
        }
        account.balance -= debit;
        account.nonce += 1;
        self.set_account(address, &account);
        self.set_stake_bond(
            &id,
            &Bond {
                amount: total,
                bonded_at_day: day,
                exit_requested_at: None,
            },
        );
        true
    }

    pub fn slash_stake(&mut self, address: &str, fault: qtv_staking::Fault) -> u64 {
        let id = match address_id(address) {
            Some(id) => id,
            None => return 0,
        };
        let bond = match self.stake_bond(&id) {
            Some(bond) => bond,
            None => return 0,
        };
        let taken = qtv_staking::slash(bond.amount, fault);
        let treasury = self.stake_treasury() + taken;
        self.set_stake_treasury(treasury);
        if let qtv_staking::Fault::Attributable = fault {
            self.clear_stake_bond(&id);
            self.set_stake_banned(&id);
        } else {
            self.set_stake_bond(
                &id,
                &Bond {
                    amount: bond.amount - taken,
                    ..bond
                },
            );
        }
        taken
    }

    pub fn request_stake_exit(&mut self, address: &str, now_day: u64) -> bool {
        let id = match address_id(address) {
            Some(id) => id,
            None => return false,
        };
        let mut bond = match self.stake_bond(&id) {
            Some(bond) => bond,
            None => return false,
        };
        if bond.request_exit(now_day) {
            self.set_stake_bond(&id, &bond);
            true
        } else {
            false
        }
    }

    pub fn withdraw_stake(&mut self, address: &str, now_day: u64) -> bool {
        let id = match address_id(address) {
            Some(id) => id,
            None => return false,
        };
        let bond = match self.stake_bond(&id) {
            Some(bond) if bond.can_withdraw(now_day) => bond,
            _ => return false,
        };
        self.clear_stake_bond(&id);
        let mut account = self.account(address);
        account.balance += bond.amount;
        self.set_account(address, &account);
        true
    }
}

#[cfg(test)]
mod stake_state_tests {
    use super::*;

    #[test]
    fn staking_keys_are_namespaced_off_the_account_space() {
        let id = [7u8; 32];
        assert_ne!(stake_bond_key(&id), id);
        assert_ne!(stake_bond_key(&id), stake_singleton_key(STAKE_POOL_TAG));
        assert_ne!(
            stake_singleton_key(STAKE_POOL_TAG),
            stake_singleton_key(STAKE_TREASURY_TAG)
        );
        assert_ne!(stake_bond_key(&[1u8; 32]), stake_bond_key(&[2u8; 32]));
    }

    #[test]
    fn a_bond_and_the_pool_persist_and_reload_from_the_trie() {
        let mut l = Ledger::new();
        let id = [9u8; 32];
        assert!(l.stake_bond(&id).is_none());
        let bond = Bond::new(2_000 * 1_000_000, 5).unwrap();
        l.set_stake_bond(&id, &bond);
        assert_eq!(l.stake_bond(&id), Some(bond));
        l.set_stake_pool(685_714 * 1_000_000);
        assert_eq!(l.stake_pool(), 685_714 * 1_000_000);
        l.set_stake_treasury(1_000);
        assert_eq!(l.stake_treasury(), 1_000);
        l.clear_stake_bond(&id);
        assert!(l.stake_bond(&id).is_none());
    }

    #[test]
    fn rewards_accrue_vest_and_claim_only_after_the_blackout_and_a_set_rate() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[12u8; 32]).unwrap();
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);

        // In the default blackout nothing accrues, whatever the session classifies as.
        assert_eq!(l.accrue_reward(&addr, qtv_staking::Session::Low, 400), 0);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);

        // Past the blackout but with no published rate, still nothing accrues.
        l.set_stake_mainnet_start(0);
        assert_eq!(l.accrue_reward(&addr, qtv_staking::Session::Low, 400), 0);

        // With a rate published, a low session pays one percent of the bond, twenty
        // whole units on a two thousand unit bond, and it leaves the pool.
        l.set_stake_price(70 * 1_000_000);
        let paid = l.accrue_reward(&addr, qtv_staking::Session::Low, 400);
        assert_eq!(paid, 20 * 1_000_000);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000 - 20 * 1_000_000);

        // It is locked through the year long cliff: nothing is claimable inside it.
        assert_eq!(l.claimable_reward(&addr, 400 + 364), 0);
        // At the cliff a quarter releases, and a claim moves exactly that to balance.
        assert_eq!(l.claimable_reward(&addr, 400 + 365), 5 * 1_000_000);
        assert_eq!(l.claim_reward(&addr, 400 + 365), 5 * 1_000_000);
        assert_eq!(l.balance(&addr), 5 * 1_000_000);
        // A second claim on the same day moves nothing more.
        assert_eq!(l.claim_reward(&addr, 400 + 365), 0);
        // The whole amount releases after the last tranche day, and the book prunes.
        let full_day = 400 + 365 + 3 * 120;
        assert_eq!(l.claim_reward(&addr, full_day), 15 * 1_000_000);
        assert_eq!(l.balance(&addr), 20 * 1_000_000);
        assert_eq!(l.claimable_reward(&addr, full_day + 1_000), 0);
    }

    #[test]
    fn the_reward_cap_binds_when_the_price_climbs() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[13u8; 32]).unwrap();
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        l.set_stake_mainnet_start(0);
        // At a high price the four thousand dollar per session cap bites, so the
        // reward is the cap converted to native units, not one percent of the bond.
        l.set_stake_price(2_000 * 1_000_000);
        assert_eq!(
            l.accrue_reward(&addr, qtv_staking::Session::Low, 400),
            2 * 1_000_000
        );
    }

    #[test]
    fn the_session_meter_counts_across_blocks_and_closes_on_the_window() {
        let mut l = Ledger::new();
        // The window opens on day zero and transactions accumulate while it is open.
        assert_eq!(l.record_session(10, 100), None);
        assert_eq!(l.record_session(20, 150), None);
        assert_eq!(l.session_meter().count(), 30);
        // At the window length the session closes, classifies by the total count, and
        // the meter resets for the next window.
        assert_eq!(l.record_session(5, 182), Some(qtv_staking::Session::Low));
        assert_eq!(l.session_meter().count(), 0);
    }

    #[test]
    fn committee_weight_tracks_the_live_bond_in_whole_units() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[8u8; 32]).unwrap();
        let id = [8u8; 32];
        assert_eq!(l.staked_weight(&addr), 0);
        // A genesis style seed of 2,000 whole units reads back as a weight of 2,000,
        // the unit the sortition sampler weighs a validator by.
        l.seed_validator_bond(&addr, 2_000 * 1_000_000).unwrap();
        assert_eq!(l.staked_weight(&addr), 2_000);
        // Base unit dust below one whole unit is dropped and never lifts the weight.
        l.set_stake_bond(&id, &Bond::new(2_000 * 1_000_000 + 999_999, 0).unwrap());
        assert_eq!(l.staked_weight(&addr), 2_000);
        // An attributable slash clears the bond and bans the account, so its weight
        // falls to zero and it can never be drawn into a committee again.
        l.slash_stake(&addr, qtv_staking::Fault::Attributable);
        assert_eq!(l.staked_weight(&addr), 0);
        assert!(l.is_stake_banned(&id));
    }

    #[test]
    fn bonding_debits_the_account_and_persists_the_bond() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[3u8; 32]).unwrap();
        let id = [3u8; 32];
        l.set_account(&addr, &Account::funded(5_000 * 1_000_000, 1, vec![]));
        assert!(!l.bond(&addr, 1_999 * 1_000_000, 0));
        assert_eq!(l.balance(&addr), 5_000 * 1_000_000);
        assert!(l.bond(&addr, 2_000 * 1_000_000, 0));
        assert_eq!(l.balance(&addr), 3_000 * 1_000_000);
        assert_eq!(l.stake_bond(&id).unwrap().amount, 2_000 * 1_000_000);
        assert!(!l.bond(&addr, 4_000 * 1_000_000, 0));
        assert!(l.bond(&addr, 1_000 * 1_000_000, 30));
        let bond = l.stake_bond(&id).unwrap();
        assert_eq!(bond.amount, 3_000 * 1_000_000);
        assert_eq!(bond.bonded_at_day, 30);
        assert_eq!(l.balance(&addr), 2_000 * 1_000_000);
        l.set_stake_banned(&id);
        assert!(!l.bond(&addr, 100 * 1_000_000, 0));
    }

    #[test]
    fn the_bond_slash_exit_lifecycle_keeps_balance_and_stake_in_step() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[4u8; 32]).unwrap();
        let id = [4u8; 32];
        l.set_account(&addr, &Account::funded(5_000 * 1_000_000, 1, vec![]));
        l.bond(&addr, 2_000 * 1_000_000, 0);
        assert_eq!(
            l.slash_stake(&addr, qtv_staking::Fault::LivenessMinor),
            20 * 1_000_000
        );
        assert_eq!(l.stake_treasury(), 20 * 1_000_000);
        assert_eq!(l.stake_bond(&id).unwrap().amount, 1_980 * 1_000_000);
        assert!(!l.request_stake_exit(&addr, 89));
        assert!(l.request_stake_exit(&addr, 90));
        assert!(!l.withdraw_stake(&addr, 90 + 20));
        assert!(l.withdraw_stake(&addr, 90 + 21));
        assert_eq!(l.balance(&addr), 3_000 * 1_000_000 + 1_980 * 1_000_000);
        assert!(l.stake_bond(&id).is_none());
    }

    #[test]
    fn an_attributable_slash_empties_the_bond_and_bans() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[5u8; 32]).unwrap();
        let id = [5u8; 32];
        l.set_account(&addr, &Account::funded(3_000 * 1_000_000, 1, vec![]));
        l.bond(&addr, 2_000 * 1_000_000, 0);
        assert_eq!(
            l.slash_stake(&addr, qtv_staking::Fault::Attributable),
            2_000 * 1_000_000
        );
        assert_eq!(l.stake_treasury(), 2_000 * 1_000_000);
        assert!(l.stake_bond(&id).is_none());
        assert!(l.is_stake_banned(&id));
        assert!(!l.bond(&addr, 1_000 * 1_000_000, 0));
    }

    #[test]
    fn bond_with_fee_charges_the_fee_and_bonds_atomically() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[6u8; 32]).unwrap();
        let id = [6u8; 32];
        l.set_account(&addr, &Account::funded(3_000 * 1_000_000, 1, vec![]));
        assert!(!l.bond_with_fee(&addr, 2_999 * 1_000_000, 2 * 1_000_000, 0));
        assert_eq!(l.balance(&addr), 3_000 * 1_000_000);
        assert_eq!(l.account(&addr).nonce, 0);
        assert!(l.bond_with_fee(&addr, 2_000 * 1_000_000, 1_000_000, 7));
        assert_eq!(l.balance(&addr), 999 * 1_000_000);
        assert_eq!(l.stake_bond(&id).unwrap().amount, 2_000 * 1_000_000);
        assert_eq!(l.stake_bond(&id).unwrap().bonded_at_day, 7);
        assert_eq!(l.account(&addr).nonce, 1);
    }

    #[test]
    fn the_stake_system_address_is_fixed_and_reserved() {
        let a = stake_system_address();
        assert!(a.starts_with("Q1"));
        assert_eq!(stake_system_address(), a);
        assert!(qtv_idfmt::parse_address(&a).is_ok());
    }
}

/// The account state of the chain over the sparse Merkle trie.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    trie: Trie,
}

impl Ledger {
    /// An empty ledger with no accounts.
    pub fn new() -> Self {
        Ledger { trie: Trie::new() }
    }

    /// A ledger over a trie loaded from disk. The trie holds the account leaves a
    /// store reopened, so a node restarted from its store rebuilds the exact state
    /// it committed, with the same state root.
    pub fn from_trie(trie: Trie) -> Self {
        Ledger { trie }
    }

    /// The account an address holds, or the default fresh account when the
    /// address is absent.
    pub fn account(&self, address: &str) -> Account {
        match self.trie.get(&state_key(address)) {
            Some(bytes) => from_bytes(bytes).expect("state holds a canonical account record"),
            None => Account::default(),
        }
    }

    /// Bind an address to an account record, replacing any prior record.
    pub fn set_account(&mut self, address: &str, account: &Account) {
        self.trie.insert(state_key(address), to_bytes(account));
    }

    /// The balance an address holds.
    pub fn balance(&self, address: &str) -> u64 {
        self.account(address).balance
    }

    /// The next expected nonce of an address.
    pub fn nonce(&self, address: &str) -> u64 {
        self.account(address).nonce
    }

    /// The state root over the whole account set, fixed by the set and not by the
    /// order the accounts were written in.
    pub fn state_root(&self) -> [u8; HASH_LEN] {
        self.trie.root()
    }

    /// The state root rendered under the state family for display.
    pub fn state_root_id(&self) -> String {
        qtv_idfmt::render_state(&self.state_root())
            .expect("a state root is the fixed digest length")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(index: u64) -> String {
        let account = qtv_account::derive(&[7u8; 32], index);
        account.address()
    }

    #[test]
    fn an_absent_account_reads_as_the_default() {
        let ledger = Ledger::new();
        assert_eq!(ledger.account(&address(0)), Account::default());
        assert_eq!(ledger.balance(&address(0)), 0);
    }

    #[test]
    fn an_account_round_trips_through_state() {
        let mut ledger = Ledger::new();
        let addr = address(1);
        let account = Account::funded(5_000, qtv_account::SCHEME_LATTICE, vec![1, 2, 3]);
        ledger.set_account(&addr, &account);
        assert_eq!(ledger.account(&addr), account);
        assert_eq!(ledger.balance(&addr), 5_000);
    }

    #[test]
    fn the_root_moves_with_a_balance_change() {
        let mut ledger = Ledger::new();
        let addr = address(2);
        ledger.set_account(&addr, &Account::funded(1, 0, Vec::new()));
        let before = ledger.state_root();
        ledger.set_account(&addr, &Account::funded(2, 0, Vec::new()));
        assert_ne!(before, ledger.state_root());
    }

    #[test]
    fn the_root_is_independent_of_write_order() {
        let a = address(3);
        let b = address(4);
        let mut one = Ledger::new();
        one.set_account(&a, &Account::funded(10, 0, Vec::new()));
        one.set_account(&b, &Account::funded(20, 0, Vec::new()));
        let mut two = Ledger::new();
        two.set_account(&b, &Account::funded(20, 0, Vec::new()));
        two.set_account(&a, &Account::funded(10, 0, Vec::new()));
        assert_eq!(one.state_root(), two.state_root());
    }
}
