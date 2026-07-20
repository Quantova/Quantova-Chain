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
use qtv_governance::{
    check_enactment, Action, Ballot, Conviction, EnactmentReceipt, Lock, Referendum, Status, Track,
    Violation,
};
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
pub(crate) fn state_key(address: &str) -> Key {
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
const GRANTS_POOL_TAG: &[u8] = b"qtv/grants/pool";

/// The transaction fee split, in basis points of ten thousand. A portion is burned, credited to no
/// one so the total supply falls, and the rest funds the validators reward pool and the grants pool.
/// These are the genesis defaults; governance can change them (SPEC-economics).
const FEE_BURN_BPS: u64 = 2_000;
const FEE_VALIDATORS_BPS: u64 = 6_000;
const FEE_GRANTS_BPS: u64 = 2_000;
const _: () = assert!(FEE_BURN_BPS + FEE_VALIDATORS_BPS + FEE_GRANTS_BPS == 10_000);
const STAKE_PRICE_TAG: &[u8] = b"qtv/stake/price";
const STAKE_MAINNET_TAG: &[u8] = b"qtv/stake/mainnet";
const STAKE_METER_TAG: &[u8] = b"qtv/stake/meter";
const STAKE_VALIDATORS_TAG: &[u8] = b"qtv/stake/validators";

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

/// The reserved address a validator sends an empty transfer to in order to claim
/// its vested rewards into its balance. The amount is ignored; the transfer is the
/// claim intent.
pub fn stake_claim_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/stake/claim"))
        .expect("a full hash reaches the address floor")
}

const GOV_NEXT_TAG: &[u8] = b"qtv/gov/next";
const GOV_LOCKED_TAG: &[u8] = b"qtv/gov/locked";
const GOV_REF_TAG: &[u8] = b"qtv/gov/ref/";
const GOV_ACTION_TAG: &[u8] = b"qtv/gov/action/";
const GOV_BALLOT_TAG: &[u8] = b"qtv/gov/ballot/";
const GOV_LOCK_TAG: &[u8] = b"qtv/gov/lock/";
const GOV_BLACKLIST_TAG: &[u8] = b"qtv/gov/blacklist/";
const GOV_RECEIPT_TAG: &[u8] = b"qtv/gov/receipt/";

fn gov_blacklist_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(GOV_BLACKLIST_TAG.len() + id.len());
    input.extend_from_slice(GOV_BLACKLIST_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

fn gov_receipt_key(id: u64) -> Key {
    let mut input = Vec::with_capacity(GOV_RECEIPT_TAG.len() + 8);
    input.extend_from_slice(GOV_RECEIPT_TAG);
    input.extend_from_slice(&id.to_le_bytes());
    sha3::sha3_256(&input)
}

fn gov_referendum_key(id: u64) -> Key {
    let mut input = Vec::with_capacity(GOV_REF_TAG.len() + 8);
    input.extend_from_slice(GOV_REF_TAG);
    input.extend_from_slice(&id.to_le_bytes());
    sha3::sha3_256(&input)
}

fn gov_action_key(id: u64) -> Key {
    let mut input = Vec::with_capacity(GOV_ACTION_TAG.len() + 8);
    input.extend_from_slice(GOV_ACTION_TAG);
    input.extend_from_slice(&id.to_le_bytes());
    sha3::sha3_256(&input)
}

fn gov_ballot_key(referendum: u64, voter: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(GOV_BALLOT_TAG.len() + 8 + voter.len());
    input.extend_from_slice(GOV_BALLOT_TAG);
    input.extend_from_slice(&referendum.to_le_bytes());
    input.extend_from_slice(voter);
    sha3::sha3_256(&input)
}

fn gov_lock_key(voter: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(GOV_LOCK_TAG.len() + voter.len());
    input.extend_from_slice(GOV_LOCK_TAG);
    input.extend_from_slice(voter);
    sha3::sha3_256(&input)
}

pub fn gov_system_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/gov/system"))
        .expect("a full hash reaches the address floor")
}

const VM_CODE_TAG: &[u8] = b"qtv/vm/code/";
const VM_STORE_TAG: &[u8] = b"qtv/vm/store/";

/// The reserved address a deploy transaction targets. A transfer style call whose target is this
/// address, carrying a container in its arguments, deploys that container to a fresh contract address.
pub fn vm_deploy_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/vm/deploy"))
        .expect("a full hash reaches the address floor")
}

/// The address a deploy from a given account at a given nonce lands the contract at. It is a pure
/// function of the deployer and the nonce, so the deployer computes the same address the chain does
/// and can call the contract immediately, and two deploys from the same account never collide because
/// the nonce differs.
pub fn contract_address(deployer: &str, nonce: u64) -> Option<String> {
    let id = address_id(deployer)?;
    let mut input = Vec::with_capacity(16 + id.len() + 8);
    input.extend_from_slice(b"qtv/vm/contract/");
    input.extend_from_slice(&id);
    input.extend_from_slice(&nonce.to_le_bytes());
    qtv_idfmt::render_address(&sha3::sha3_256(&input)).ok()
}

fn contract_code_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(VM_CODE_TAG.len() + id.len());
    input.extend_from_slice(VM_CODE_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

fn contract_store_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(VM_STORE_TAG.len() + id.len());
    input.extend_from_slice(VM_STORE_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

/// The reduction of a full account address to the one machine word a contract sees it as. The virtual
/// machine works in sixty four bit words, so an address a contract stores as an owner or reads as its
/// caller is this word, not the whole thirty two byte payload. The word is the leading eight bytes of
/// the address payload read big endian, a pure function of the address, so the same address always
/// reduces to the same word for a storage key, a caller check, and an argument alike. It is lossy, so
/// it is an internal handle for a pure state contract and never a route back to a full address.
pub fn address_word(address: &str) -> Option<u64> {
    let id = address_id(address)?;
    Some(u64::from_be_bytes(id[..8].try_into().expect("eight bytes")))
}

/// Encode a contract's whole storage as one length prefixed run of slot and value words, so a
/// contract's state is one trie leaf that loads and stores in one read and one write regardless of how
/// its keyed maps scatter across the word space.
fn encode_storage(storage: &std::collections::BTreeMap<u64, u64>) -> Vec<u8> {
    let mut encoder = qtv_codec::Encoder::new();
    (storage.len() as u64).encode(&mut encoder);
    for (slot, value) in storage {
        slot.encode(&mut encoder);
        value.encode(&mut encoder);
    }
    encoder.into_bytes()
}

fn decode_storage(bytes: &[u8]) -> std::collections::BTreeMap<u64, u64> {
    let mut decoder = qtv_codec::Decoder::new(bytes);
    let mut storage = std::collections::BTreeMap::new();
    let count = u64::decode(&mut decoder).unwrap_or(0);
    for _ in 0..count {
        match (u64::decode(&mut decoder), u64::decode(&mut decoder)) {
            (Ok(slot), Ok(value)) => {
                storage.insert(slot, value);
            }
            _ => break,
        }
    }
    storage
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnactError {
    Unknown,
    NotApproved,
    Constitution(Violation),
    BadAddress,
    UnknownParameter,
    BadValue,
}

fn id_bytes_to_address(id: &[u8]) -> Option<String> {
    if id.len() != KEY_LEN {
        return None;
    }
    qtv_idfmt::render_address(id).ok()
}

fn id_from_slice(id: &[u8]) -> Option<[u8; 32]> {
    if id.len() != KEY_LEN {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(id);
    Some(out)
}

fn u64_from_le(bytes: &[u8]) -> Option<u64> {
    bytes.try_into().ok().map(u64::from_le_bytes)
}

fn u128_from_le(bytes: &[u8]) -> Option<u128> {
    bytes.try_into().ok().map(u128::from_le_bytes)
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
        if self.is_stake_banned(&id) || self.is_gov_blacklisted(&id) {
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

    pub fn grants_pool(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(GRANTS_POOL_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical grants balance"))
            .unwrap_or(0)
    }

    pub fn set_grants_pool(&mut self, amount: u64) {
        self.trie
            .insert(stake_singleton_key(GRANTS_POOL_TAG), to_bytes(&amount));
    }

    /// Split a charged transaction fee: a portion is burned, credited to no one so the total supply
    /// falls, and the rest funds the validators reward pool and the grants pool. The burned portion is
    /// the remainder after the two credited shares, so any rounding dust is burned rather than
    /// misallocated and no unit is ever created. The shares are the genesis defaults and governance
    /// can change them (SPEC-economics).
    pub fn collect_fee(&mut self, fee: u64) {
        if fee == 0 {
            return;
        }
        let validators = ((fee as u128) * (FEE_VALIDATORS_BPS as u128) / 10_000) as u64;
        let grants = ((fee as u128) * (FEE_GRANTS_BPS as u128) / 10_000) as u64;
        // The rest, the burn share plus any rounding dust, is credited nowhere, so it leaves the supply.
        let pool = self.stake_pool().saturating_add(validators);
        self.set_stake_pool(pool);
        let grants_pool = self.grants_pool().saturating_add(grants);
        self.set_grants_pool(grants_pool);
    }

    /// The portion of a fee that is burned under the current split, credited to no one. Used to check
    /// the supply drops by exactly the burned share.
    pub fn fee_burned(fee: u64) -> u64 {
        let validators = ((fee as u128) * (FEE_VALIDATORS_BPS as u128) / 10_000) as u64;
        let grants = ((fee as u128) * (FEE_GRANTS_BPS as u128) / 10_000) as u64;
        fee - validators - grants
    }

    /// The validators and grants shares of a single fee, split exactly as collect_fee splits it, but
    /// without touching the pools. A block executor accumulates these across its transactions and
    /// credits the pools once, which lands on the identical pool values as crediting per transaction,
    /// since addition is associative, while doing two pool writes for the whole block instead of two
    /// per transaction.
    pub fn fee_shares(fee: u64) -> (u64, u64) {
        if fee == 0 {
            return (0, 0);
        }
        let validators = ((fee as u128) * (FEE_VALIDATORS_BPS as u128) / 10_000) as u64;
        let grants = ((fee as u128) * (FEE_GRANTS_BPS as u128) / 10_000) as u64;
        (validators, grants)
    }

    /// Credit already split validators and grants shares to their pools in one pair of writes. Used by
    /// the block executor after it has summed the per transaction shares, so the pools are read and
    /// written once for the whole block rather than once per transaction.
    pub fn credit_pools(&mut self, validators: u64, grants: u64) {
        if validators == 0 && grants == 0 {
            return;
        }
        let pool = self.stake_pool().saturating_add(validators);
        self.set_stake_pool(pool);
        let grants_pool = self.grants_pool().saturating_add(grants);
        self.set_grants_pool(grants_pool);
    }

    /// The keys changed since the last call and their current values, so a persisting node writes back
    /// exactly what a block changed, accounts and protocol singletons alike, the treasury, the pool,
    /// bonds, and any other state. This replaces persisting a hand listed set of touched accounts,
    /// which silently dropped every singleton a block modified and diverged a node on reload.
    pub fn take_dirty_entries(&mut self) -> Vec<(Key, Vec<u8>)> {
        self.trie
            .take_persist_dirty()
            .into_iter()
            .map(|key| {
                let value = self.trie.get(&key).map(|v| v.to_vec()).unwrap_or_default();
                (key, value)
            })
            .collect()
    }

    /// Discard the pending persist set, for after genesis has written the whole state explicitly.
    pub fn clear_dirty(&mut self) {
        self.trie.clear_persist_dirty();
    }

    pub fn is_stake_banned(&self, id: &[u8; 32]) -> bool {
        matches!(self.trie.get(&stake_banned_key(id)), Some(bytes) if !bytes.is_empty())
    }

    pub fn set_stake_banned(&mut self, id: &[u8; 32]) {
        self.trie.insert(stake_banned_key(id), vec![1]);
    }

    fn is_gov_blacklisted(&self, id: &[u8; 32]) -> bool {
        matches!(self.trie.get(&gov_blacklist_key(id)), Some(bytes) if !bytes.is_empty())
    }

    fn set_gov_blacklisted(&mut self, id: &[u8; 32]) {
        self.trie.insert(gov_blacklist_key(id), vec![1]);
    }

    /// Whether an address has been retired by the blacklist and kill track. A
    /// blacklisted address is refused as the sender or the recipient of a transfer,
    /// as a governance caller, and as a staker, so a compromised or hostile address
    /// stops moving value the block after the referendum enacts. It is a pure read
    /// of committed state, so every node refuses the same address at the same height.
    pub fn is_blacklisted(&self, address: &str) -> bool {
        match address_id(address) {
            Some(id) => self.is_gov_blacklisted(&id),
            None => false,
        }
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
        match address_id(address) {
            Some(id) => self.accrue_reward_by_id(&id, session, now_day),
            None => 0,
        }
    }

    fn accrue_reward_by_id(&mut self, id: &[u8; 32], session: Session, now_day: u64) -> u64 {
        if qtv_staking::in_blackout(now_day, self.stake_mainnet_start()) {
            return 0;
        }
        let rate = self.stake_price();
        if rate == 0 {
            return 0;
        }
        let stake = match self.stake_bond(id) {
            Some(bond) => bond.amount,
            None => return 0,
        };
        let paid = qtv_staking::session_reward(stake, session, rate).min(self.stake_pool());
        if paid == 0 {
            return 0;
        }
        self.set_stake_pool(self.stake_pool() - paid);
        let mut book = self.stake_rewards(id);
        book.tranches.push(qtv_staking::RewardTranche {
            earned_day: now_day,
            amount: paid,
            claimed: 0,
        });
        self.set_stake_rewards(id, &book);
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

    /// Charge a claim transaction's fee, bump the nonce, and credit the vested
    /// rewards into the sender's balance. The fee applies whether or not anything
    /// was vested, so a claim with nothing to release is a fee paying no op rather
    /// than a free retry. Returns false only when the sender cannot cover the fee.
    pub fn claim_with_fee(&mut self, address: &str, fee: u64, now_day: u64) -> bool {
        let mut account = self.account(address);
        if account.balance < fee {
            return false;
        }
        account.balance -= fee;
        account.nonce += 1;
        self.set_account(address, &account);
        self.collect_fee(fee);
        self.claim_reward(address, now_day);
        true
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

    /// Whether an address holds a deployed contract, so a transaction to it is a call rather than a
    /// transfer. It is a pure read of committed state.
    pub fn is_contract(&self, address: &str) -> bool {
        match address_id(address) {
            Some(id) => self.contract_code(&id).is_some(),
            None => false,
        }
    }

    /// The container of the contract at an address, or None when the address holds no contract. This
    /// is the address facing form of contract_code, so a reader holding a q1 address need not reduce
    /// it to an id first. The gateway reads a container through this.
    pub fn contract_code_at(&self, address: &str) -> Option<Vec<u8>> {
        self.contract_code(&address_id(address)?)
    }

    /// The whole storage of the contract at an address, empty when the address holds no contract. The
    /// address facing form of contract_storage.
    pub fn contract_storage_at(&self, address: &str) -> std::collections::BTreeMap<u64, u64> {
        match address_id(address) {
            Some(id) => self.contract_storage(&id),
            None => std::collections::BTreeMap::new(),
        }
    }

    /// The deployed container of a contract, its compiled bytes, or None when the id holds no contract.
    pub fn contract_code(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.trie
            .get(&contract_code_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| bytes.to_vec())
    }

    /// Deploy a container at a contract id. The container is the compiled contract the virtual machine
    /// runs; it is written once and read on every call.
    pub fn set_contract_code(&mut self, id: &[u8; 32], code: &[u8]) {
        self.trie.insert(contract_code_key(id), code.to_vec());
    }

    /// Deploy a container from a deployer at a nonce, storing it at the derived contract address and
    /// returning that address so the caller records where the contract lives.
    pub fn deploy_contract(&mut self, deployer: &str, nonce: u64, code: &[u8]) -> Option<String> {
        let contract = contract_address(deployer, nonce)?;
        let id = address_id(&contract)?;
        self.set_contract_code(&id, code);
        Some(contract)
    }

    /// The whole storage of a contract, loaded as the slot to value map the virtual machine reads. An
    /// absent contract reads as empty, so a first call sees a clean slate.
    pub fn contract_storage(&self, id: &[u8; 32]) -> std::collections::BTreeMap<u64, u64> {
        match self.trie.get(&contract_store_key(id)) {
            Some(bytes) if !bytes.is_empty() => decode_storage(bytes),
            _ => std::collections::BTreeMap::new(),
        }
    }

    /// Write back a contract's whole storage after a call, as one trie leaf.
    pub fn set_contract_storage(
        &mut self,
        id: &[u8; 32],
        storage: &std::collections::BTreeMap<u64, u64>,
    ) {
        self.trie
            .insert(contract_store_key(id), encode_storage(storage));
    }

    /// Call an entry of a deployed contract. The contract's code and whole storage load from state, and
    /// the argument memory is the caller supplied words with the two trusted context words overwritten
    /// in place: the caller's reduced address at offset zero and the consensus time at offset eight, so
    /// a caller can never forge either. A clean halt commits the post execution storage. A call that
    /// records a native transfer effect is refused and commits nothing, because moving native value out
    /// of a contract needs the reduced word bridged back to a full address, which is a later step; so
    /// only a pure state contract runs today. Returns true when the call committed.
    pub fn call_contract(
        &mut self,
        caller: &str,
        contract: &str,
        selector: [u8; 4],
        user_memory: &[u8],
        now_seconds: u64,
        meter: u64,
    ) -> bool {
        let contract_id = match address_id(contract) {
            Some(id) => id,
            None => return false,
        };
        let code = match self.contract_code(&contract_id) {
            Some(code) => code,
            None => return false,
        };
        let storage = self.contract_storage(&contract_id);
        let mut memory = vec![0u8; user_memory.len().max(16)];
        memory[..user_memory.len()].copy_from_slice(user_memory);
        let caller_word = address_word(caller).unwrap_or(0);
        memory[0..8].copy_from_slice(&caller_word.to_be_bytes());
        memory[8..16].copy_from_slice(&now_seconds.to_be_bytes());
        match crate::execution::execute_contract_call(&code, selector, storage, &memory, meter) {
            Ok(outcome) => {
                // A contract initiated native transfer is not applied by the node yet, so a call that
                // records one is refused and no state moves. A call that only records events commits,
                // and its events are collected in emission order for the block event root.
                if outcome
                    .effects
                    .iter()
                    .any(|effect| matches!(effect, qtv_vm::interp::Effect::Transfer { .. }))
                {
                    return false;
                }
                for effect in &outcome.effects {
                    if let qtv_vm::interp::Effect::Event { selector, data } = effect {
                        self.block_events.push(BlockEvent {
                            contract: contract.to_string(),
                            selector: *selector,
                            data: data.clone(),
                        });
                    }
                }
                self.set_contract_storage(&contract_id, &outcome.storage);
                true
            }
            Err(_) => false,
        }
    }

    /// The reward earning validator set, the ids the session accrual pays. It is
    /// written at genesis from the committee set and read at every session close, so
    /// the accrual pays exactly the validators the chain committed to.
    pub fn validator_ids(&self) -> Vec<[u8; 32]> {
        let bytes = match self.trie.get(&stake_singleton_key(STAKE_VALIDATORS_TAG)) {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => return Vec::new(),
        };
        let mut ids = Vec::with_capacity(bytes.len() / KEY_LEN);
        for chunk in bytes.chunks_exact(KEY_LEN) {
            let mut id = [0u8; 32];
            id.copy_from_slice(chunk);
            ids.push(id);
        }
        ids
    }

    /// Record the validator id set, returning the state key and value so a
    /// persisting node can write it under the genesis root.
    pub fn seed_validator_set(&mut self, ids: &[[u8; 32]]) -> (Key, Vec<u8>) {
        let mut bytes = Vec::with_capacity(ids.len() * KEY_LEN);
        for id in ids {
            bytes.extend_from_slice(id);
        }
        let key = stake_singleton_key(STAKE_VALIDATORS_TAG);
        self.trie.insert(key, bytes.clone());
        (key, bytes)
    }

    /// Tick the session meter for a block and, when the session window closes, pay
    /// each validator its session reward from the pool. It is inert until governance
    /// sets the mainnet start, so a test network never meters or pays, and once
    /// mainnet is set it meters every block and pays at each window close, all a pure
    /// function of committed state so every node settles the session alike. The
    /// transaction count is the block's included count, identical on the builder and
    /// on every validator that re-executes the same body.
    pub fn settle_session(&mut self, now_day: u64, transactions: u64) {
        if self.stake_mainnet_start() == u64::MAX {
            return;
        }
        if let Some(session) = self.record_session(transactions, now_day) {
            for id in self.validator_ids() {
                self.accrue_reward_by_id(&id, session, now_day);
            }
        }
    }

    fn gov_next_id(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(GOV_NEXT_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical referendum counter"))
            .unwrap_or(1)
    }

    fn set_gov_next_id(&mut self, id: u64) {
        self.trie
            .insert(stake_singleton_key(GOV_NEXT_TAG), to_bytes(&id));
    }

    /// The governance electorate, the total value locked for voting across every
    /// live ballot. It is the denominator the support threshold is measured
    /// against, and it moves only as locks open and release, never as a referendum
    /// tallies, so support reads as the share of the locked electorate that voted.
    pub fn gov_total_locked(&self) -> u128 {
        self.trie
            .get(&stake_singleton_key(GOV_LOCKED_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical locked total"))
            .unwrap_or(0)
    }

    fn set_gov_total_locked(&mut self, amount: u128) {
        self.trie
            .insert(stake_singleton_key(GOV_LOCKED_TAG), to_bytes(&amount));
    }

    pub fn gov_referendum(&self, id: u64) -> Option<Referendum> {
        self.trie
            .get(&gov_referendum_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical referendum"))
    }

    fn set_gov_referendum(&mut self, id: u64, referendum: &Referendum) {
        self.trie
            .insert(gov_referendum_key(id), to_bytes(referendum));
    }

    fn gov_action(&self, id: u64) -> Option<Action> {
        self.trie
            .get(&gov_action_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical action"))
    }

    fn set_gov_action(&mut self, id: u64, action: &Action) {
        self.trie.insert(gov_action_key(id), to_bytes(action));
    }

    fn clear_gov_action(&mut self, id: u64) {
        self.trie.insert(gov_action_key(id), Vec::new());
    }

    /// The permanent enactment record for a referendum, written when it enacts and
    /// never cleared, so any enacted decision can be audited against the action hash,
    /// the recovery scope it was bound to, and the tally that carried it.
    pub fn gov_receipt(&self, id: u64) -> Option<EnactmentReceipt> {
        self.trie
            .get(&gov_receipt_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical receipt"))
    }

    fn set_gov_receipt(&mut self, id: u64, receipt: &EnactmentReceipt) {
        self.trie.insert(gov_receipt_key(id), to_bytes(receipt));
    }

    pub fn gov_ballot(&self, referendum: u64, voter: &[u8; 32]) -> Option<Ballot> {
        self.trie
            .get(&gov_ballot_key(referendum, voter))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical ballot"))
    }

    fn set_gov_ballot(&mut self, referendum: u64, voter: &[u8; 32], ballot: &Ballot) {
        self.trie
            .insert(gov_ballot_key(referendum, voter), to_bytes(ballot));
    }

    pub fn gov_lock(&self, voter: &[u8; 32]) -> Option<Lock> {
        self.trie
            .get(&gov_lock_key(voter))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical lock"))
    }

    fn set_gov_lock(&mut self, voter: &[u8; 32], lock: &Lock) {
        self.trie.insert(gov_lock_key(voter), to_bytes(lock));
    }

    fn clear_gov_lock(&mut self, voter: &[u8; 32]) {
        self.trie.insert(gov_lock_key(voter), Vec::new());
    }

    /// Whether recovery, freeze, or blacklist may never reach this account. The
    /// second constitutional invariant shields validator stake and governance
    /// locks, and the two protocol system accounts are shielded with them. An
    /// account carrying a bond or a lock is therefore untouchable by the recovery
    /// tracks, so a referendum can never seize consensus or voting collateral.
    fn is_protected_account(&self, addr: &[u8]) -> bool {
        let id = match id_from_slice(addr) {
            Some(id) => id,
            None => return false,
        };
        if self.stake_bond(&id).is_some() || self.gov_lock(&id).is_some() {
            return true;
        }
        let stake_id = sha3::sha3_256(b"qtv/stake/system");
        let gov_id = sha3::sha3_256(b"qtv/gov/system");
        id == stake_id || id == gov_id
    }

    /// Open a referendum on a track, debiting the track deposit from the proposer.
    /// The action must belong to the track, and the deposit is held until the
    /// referendum concludes, when it returns on reaching support or is forfeit to
    /// the treasury on spam or a kill. Returns the new referendum id.
    pub fn gov_propose(
        &mut self,
        proposer: &str,
        track: Track,
        action: Action,
        now: u64,
    ) -> Option<u64> {
        if action.track() != track {
            return None;
        }
        let proposer_id = address_id(proposer)?;
        let deposit = track.deposit();
        let mut account = self.account(proposer);
        if account.balance < deposit {
            return None;
        }
        account.balance -= deposit;
        self.set_account(proposer, &account);
        let id = self.gov_next_id();
        let referendum = Referendum::open(id, track, proposer_id.to_vec(), now);
        self.set_gov_referendum(id, &referendum);
        self.set_gov_action(id, &action);
        self.set_gov_next_id(id + 1);
        Some(id)
    }

    /// Cast a ballot on a live referendum. The stake is locked from the voter's
    /// balance into a governance lock, separate from any validator bond, so voting
    /// weight never draws on consensus collateral. Weight is the stake times the
    /// conviction factor; a voter votes once per referendum. The lock releases on
    /// the conviction schedule.
    pub fn gov_vote(
        &mut self,
        voter: &str,
        referendum_id: u64,
        aye: bool,
        conviction: Conviction,
        stake: u64,
        now: u64,
    ) -> bool {
        let voter_id = match address_id(voter) {
            Some(id) => id,
            None => return false,
        };
        let mut referendum = match self.gov_referendum(referendum_id) {
            Some(referendum) => referendum,
            None => return false,
        };
        if referendum.status != Status::Deciding || referendum.ready(now) {
            return false;
        }
        if self.gov_ballot(referendum_id, &voter_id).is_some() {
            return false;
        }
        let mut account = self.account(voter);
        if account.balance < stake {
            return false;
        }
        account.balance -= stake;
        self.set_account(voter, &account);
        let mut lock = self.gov_lock(&voter_id).unwrap_or(Lock { amount: 0, until: 0 });
        lock.amount = lock.amount.saturating_add(stake);
        let release = now.saturating_add(conviction.lock_seconds());
        if release > lock.until {
            lock.until = release;
        }
        self.set_gov_lock(&voter_id, &lock);
        self.set_gov_total_locked(self.gov_total_locked() + stake as u128);
        referendum.tally.record(aye, conviction, stake);
        self.set_gov_referendum(referendum_id, &referendum);
        self.set_gov_ballot(
            referendum_id,
            &voter_id,
            &Ballot {
                aye,
                conviction,
                stake,
            },
        );
        true
    }

    /// Resolve a referendum once its window closes, settling the deposit on the
    /// first resolution: returned to the proposer on reaching support, or forfeit
    /// to the treasury on spam or a kill. Idempotent once decided.
    pub fn gov_conclude(&mut self, referendum_id: u64, now: u64) -> Option<Status> {
        let mut referendum = self.gov_referendum(referendum_id)?;
        if referendum.status != Status::Deciding {
            return Some(referendum.status);
        }
        let electorate = self.gov_total_locked();
        let status = referendum.resolve(now, electorate);
        if status == Status::Deciding {
            return Some(status);
        }
        if referendum.deposit_refunded(electorate) {
            if let Some(addr) = id_bytes_to_address(&referendum.proposer) {
                let mut account = self.account(&addr);
                account.balance = account.balance.saturating_add(referendum.deposit);
                self.set_account(&addr, &account);
            }
        } else {
            self.set_stake_treasury(self.stake_treasury() + referendum.deposit);
        }
        self.set_gov_referendum(referendum_id, &referendum);
        Some(status)
    }

    /// Enact an approved referendum. It concludes first, then the constitution gate
    /// checks the action against its track, the committed recovery scope, and the
    /// protected accounts, and only a clean action executes. The action record is
    /// tombstoned on success so a referendum enacts exactly once.
    pub fn gov_enact(&mut self, referendum_id: u64, now: u64) -> Result<(), EnactError> {
        let status = self.gov_conclude(referendum_id, now).ok_or(EnactError::Unknown)?;
        if status != Status::Approved {
            return Err(EnactError::NotApproved);
        }
        let action = self.gov_action(referendum_id).ok_or(EnactError::Unknown)?;
        let referendum = self.gov_referendum(referendum_id).ok_or(EnactError::Unknown)?;
        let scope_ok = match &action {
            Action::FreezeRecovery {
                scope,
                victim,
                seizures,
            } => sha3::sha3_256(&Action::recovery_scope_preimage(victim, seizures)) == *scope,
            _ => true,
        };
        check_enactment(referendum.track, &action, scope_ok, |addr| {
            self.is_protected_account(addr)
        })
        .map_err(EnactError::Constitution)?;
        self.execute_action(&action)?;
        let scope = match &action {
            Action::FreezeRecovery { scope, .. } => *scope,
            _ => [0u8; 32],
        };
        let receipt = EnactmentReceipt {
            referendum: referendum_id,
            proposal_hash: sha3::sha3_256(&to_bytes(&action)),
            scope,
            tally: referendum.tally,
            enacted_at: now,
        };
        self.set_gov_receipt(referendum_id, &receipt);
        self.clear_gov_action(referendum_id);
        Ok(())
    }

    fn execute_action(&mut self, action: &Action) -> Result<(), EnactError> {
        match action {
            Action::Mint { to, amount } => {
                let addr = id_bytes_to_address(to).ok_or(EnactError::BadAddress)?;
                let mut account = self.account(&addr);
                account.balance = account.balance.saturating_add(*amount);
                self.set_account(&addr, &account);
                Ok(())
            }
            Action::Parameter { key, value } => self.apply_parameter(key, value),
            Action::Blacklist { target } => {
                if let Some(id) = id_from_slice(target) {
                    self.set_gov_blacklisted(&id);
                }
                Ok(())
            }
            Action::FreezeRecovery {
                victim, seizures, ..
            } => {
                let victim_addr = id_bytes_to_address(victim).ok_or(EnactError::BadAddress)?;
                let mut recovered = 0u64;
                for seizure in seizures {
                    if let Some(from_addr) = id_bytes_to_address(&seizure.from) {
                        let mut from = self.account(&from_addr);
                        let take = from.balance.min(seizure.amount);
                        from.balance -= take;
                        self.set_account(&from_addr, &from);
                        recovered = recovered.saturating_add(take);
                    }
                }
                let mut account = self.account(&victim_addr);
                account.balance = account.balance.saturating_add(recovered);
                self.set_account(&victim_addr, &account);
                Ok(())
            }
            Action::Upgrade { .. }
            | Action::BridgeMigration { .. }
            | Action::AddAsset { .. }
            | Action::Freeze { .. } => Ok(()),
        }
    }

    fn apply_parameter(&mut self, key: &[u8], value: &[u8]) -> Result<(), EnactError> {
        match key {
            b"price" => {
                self.set_stake_price(u128_from_le(value).ok_or(EnactError::BadValue)?);
                Ok(())
            }
            b"mainnet_start" => {
                let day = u64_from_le(value).ok_or(EnactError::BadValue)?;
                self.set_stake_mainnet_start(day);
                // Open the first session window on the mainnet start so the six month
                // sessions align to mainnet rather than to genesis.
                self.set_session_meter(&SessionMeter::new(day));
                Ok(())
            }
            _ => Err(EnactError::UnknownParameter),
        }
    }

    /// Return a released governance lock to the voter's balance and drop it from the
    /// electorate. Nothing moves while the conviction lock still holds.
    pub fn gov_release(&mut self, voter: &str, now: u64) -> u64 {
        let voter_id = match address_id(voter) {
            Some(id) => id,
            None => return 0,
        };
        let lock = match self.gov_lock(&voter_id) {
            Some(lock) if lock.withdrawable(now) => lock,
            _ => return 0,
        };
        self.clear_gov_lock(&voter_id);
        let locked = self.gov_total_locked();
        self.set_gov_total_locked(locked.saturating_sub(lock.amount as u128));
        let mut account = self.account(voter);
        account.balance = account.balance.saturating_add(lock.amount);
        self.set_account(voter, &account);
        lock.amount
    }

    pub fn bond(&mut self, address: &str, amount: u64, day: u64) -> bool {
        let id = match address_id(address) {
            Some(id) => id,
            None => return false,
        };
        if self.is_stake_banned(&id) || self.is_gov_blacklisted(&id) {
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
        if self.is_stake_banned(&id) || self.is_gov_blacklisted(&id) {
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
        self.collect_fee(fee);
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

    fn gov_addr(tag: u8) -> String {
        qtv_idfmt::render_address(&[tag; 32]).unwrap()
    }

    fn fund(l: &mut Ledger, address: &str, amount: u64) {
        l.set_account(address, &Account::funded(amount, 1, vec![]));
    }

    #[test]
    fn a_contract_call_injects_the_trusted_caller_and_persists_storage() {
        // An entry that reads the caller word at memory offset zero and stores it into slot zero.
        let code = qtv_vm::asm::assemble("LDI r1, 0\nMLOAD r0, r1\nLDI r2, 0\nSSTORE r2, r0\nHALT")
            .expect("the program assembles");
        let selector = [1u8, 2, 3, 4];
        let container = qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: vec![],
                    writes: vec![0],
                },
            }],
        );

        let mut l = Ledger::new();
        let contract = qtv_idfmt::render_address(&[70u8; 32]).unwrap();
        let contract_id = [70u8; 32];
        l.set_contract_code(&contract_id, &container.canonical_bytes());

        let caller = qtv_idfmt::render_address(&[9u8; 32]).unwrap();
        assert!(l.call_contract(&caller, &contract, selector, &[], 0, 100_000));
        // The stored word is the caller's reduced address, the node injected it, not the caller.
        let expected = u64::from_be_bytes([9u8; 8]);
        assert_eq!(l.contract_storage(&contract_id).get(&0), Some(&expected));

        // A call to an address that holds no contract is refused.
        let empty = qtv_idfmt::render_address(&[71u8; 32]).unwrap();
        assert!(!l.call_contract(&caller, &empty, selector, &[], 0, 100_000));
    }

    #[test]
    fn a_blacklisted_address_is_barred_from_staking_and_carries_no_weight() {
        let mut l = Ledger::new();
        let addr = gov_addr(50);
        let id = [50u8; 32];
        fund(&mut l, &addr, 10_000 * 1_000_000);
        l.set_gov_blacklisted(&id);
        assert!(l.is_blacklisted(&addr));
        // It can no longer bond.
        assert!(!l.bond(&addr, 2_000 * 1_000_000, 0));
        // Even a bond already on the books carries zero committee weight.
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        assert_eq!(l.staked_weight(&addr), 0);
    }

    #[test]
    fn a_qip_deposit_returns_on_support_and_a_spam_deposit_is_forfeit() {
        let mut l = Ledger::new();
        let proposer = gov_addr(20);
        fund(&mut l, &proposer, 20_000 * 1_000_000);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::Parameter, action, 0)
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(l.balance(&proposer), 5_000 * 1_000_000);

        let voter = gov_addr(21);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        assert!(l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0));
        assert_eq!(l.balance(&voter), 5_000 * 1_000_000);
        assert_eq!(l.gov_total_locked(), 5_000 * 1_000_000);
        // A voter votes once per referendum.
        assert!(!l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 100, 0));

        let close = 7 * 86_400 + 1;
        assert_eq!(l.gov_conclude(id, close), Some(qtv_governance::Status::Approved));
        assert_eq!(l.balance(&proposer), 20_000 * 1_000_000);

        // A second proposal that no one votes on forfeits its deposit to the treasury.
        let spam_action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 1u128.to_le_bytes().to_vec(),
        };
        let spam = l
            .gov_propose(&proposer, qtv_governance::Track::Parameter, spam_action, 0)
            .unwrap();
        assert_eq!(l.gov_conclude(spam, close), Some(qtv_governance::Status::Rejected));
        assert_eq!(l.balance(&proposer), 5_000 * 1_000_000);
        assert_eq!(l.stake_treasury(), 15_000 * 1_000_000);
    }

    #[test]
    fn governance_enacts_a_parameter_change_that_sets_the_reward_price() {
        let mut l = Ledger::new();
        let proposer = gov_addr(22);
        fund(&mut l, &proposer, 20_000 * 1_000_000);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::Parameter, action, 0)
            .unwrap();
        let voter = gov_addr(23);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);

        assert_eq!(l.stake_price(), 0);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        l.gov_enact(id, 7 * 86_400 + 1).unwrap();
        assert_eq!(l.stake_price(), 70_000_000);
        // A referendum enacts exactly once.
        assert!(l.gov_enact(id, 7 * 86_400 + 1).is_err());
        // The enactment is recorded permanently against the action hash and the tally.
        let receipt = l.gov_receipt(id).unwrap();
        assert_eq!(receipt.referendum, id);
        assert_eq!(
            receipt.proposal_hash,
            sha3::sha3_256(&qtv_codec::to_bytes(&action))
        );
        assert_eq!(receipt.enacted_at, 7 * 86_400 + 1);
        assert!(receipt.tally.turnout_stake > 0);
    }

    #[test]
    fn governance_mints_uncapped_to_the_target_on_the_mint_track() {
        let mut l = Ledger::new();
        let proposer = gov_addr(24);
        fund(&mut l, &proposer, 300_000 * 1_000_000);
        let target = gov_addr(30);
        let action = qtv_governance::Action::Mint {
            to: [30u8; 32].to_vec(),
            amount: 1_000_000 * 1_000_000,
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::Mint, action, 0)
            .unwrap();
        let voter = gov_addr(25);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(id, 3 * 86_400 + 1).unwrap();
        assert_eq!(l.balance(&target), 1_000_000 * 1_000_000);
    }

    #[test]
    fn the_constitution_refuses_a_recovery_that_reaches_bonded_stake() {
        let mut l = Ledger::new();
        let proposer = gov_addr(26);
        fund(&mut l, &proposer, 200_000 * 1_000_000);
        let bonded = gov_addr(41);
        l.seed_validator_bond(&bonded, 2_000 * 1_000_000);

        let seizures = vec![qtv_governance::Seizure {
            from: [41u8; 32].to_vec(),
            amount: 100,
        }];
        let scope = sha3::sha3_256(&qtv_governance::Action::recovery_scope_preimage(
            &[40u8; 32],
            &seizures,
        ));
        let action = qtv_governance::Action::FreezeRecovery {
            scope,
            victim: [40u8; 32].to_vec(),
            seizures,
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::FreezeRecovery, action, 0)
            .unwrap();
        let voter = gov_addr(27);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(id, 6 * 3_600 + 1),
            Err(EnactError::Constitution(
                qtv_governance::Violation::RecoveryTouchesProtected
            ))
        );
    }

    #[test]
    fn a_governance_lock_returns_to_balance_only_after_its_conviction_expires() {
        let mut l = Ledger::new();
        let proposer = gov_addr(28);
        fund(&mut l, &proposer, 20_000 * 1_000_000);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::Parameter, action, 0)
            .unwrap();
        let voter = gov_addr(29);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        // A one year conviction locks the stake for a year.
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Year, 4_000 * 1_000_000, 0);
        assert_eq!(l.balance(&voter), 6_000 * 1_000_000);
        // Before the lock expires nothing returns.
        assert_eq!(l.gov_release(&voter, 100), 0);
        assert_eq!(l.balance(&voter), 6_000 * 1_000_000);
        // After a year the whole lock returns and leaves the electorate.
        let year = 365 * 86_400;
        assert_eq!(l.gov_release(&voter, year), 4_000 * 1_000_000);
        assert_eq!(l.balance(&voter), 10_000 * 1_000_000);
        assert_eq!(l.gov_total_locked(), 0);
    }

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
    fn the_session_trigger_is_inert_until_mainnet_then_pays_after_the_blackout() {
        let mut l = Ledger::new();
        let v = gov_addr(60);
        let vid = [60u8; 32];
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&v, 2_000 * 1_000_000);
        l.seed_validator_set(&[vid]);

        // Inert while mainnet is unset: a session close pays nothing and the pool holds.
        l.settle_session(182, 5);
        l.settle_session(400, 5);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);
        assert_eq!(l.claimable_reward(&v, 1_000), 0);

        // Governance turns mainnet on at day zero with a published price.
        l.set_stake_mainnet_start(0);
        l.set_stake_price(70 * 1_000_000);

        // The first two closes fall in the twelve month blackout, so still nothing.
        l.settle_session(182, 5);
        l.settle_session(364, 5);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);

        // The close past the blackout pays one percent of the bond into a tranche.
        l.settle_session(546, 5);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000 - 20 * 1_000_000);
        assert_eq!(l.claimable_reward(&v, 546 + 365), 5 * 1_000_000);
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

/// A typed event a contract emitted in the block: the contract that emitted it, the four byte event
/// selector, and the operand payload. The block commits to these through the event root in the header,
/// so a light client proves an event without the full state (SPEC-blocks, SPEC-container).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEvent {
    pub contract: String,
    pub selector: [u8; 4],
    pub data: Vec<u8>,
}

impl BlockEvent {
    /// The canonical encoding of the event, the leaf the event root hashes. Each field is length
    /// prefixed so no two distinct events share an encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_bytes(self.contract.as_bytes());
        encoder.put_bytes(&self.selector);
        encoder.put_bytes(&self.data);
        encoder.into_bytes()
    }
}

/// The account state of the chain over the sparse Merkle trie.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    trie: Trie,
    /// The events emitted so far in the block being executed, in emission order. Transient and never
    /// part of the trie or the state root, it is committed to the block through the header event root
    /// and cleared at the start of each block.
    block_events: Vec<BlockEvent>,
}

impl Ledger {
    /// An empty ledger with no accounts.
    pub fn new() -> Self {
        Ledger {
            trie: Trie::new(),
            block_events: Vec::new(),
        }
    }

    /// A ledger over a trie loaded from disk. The trie holds the account leaves a
    /// store reopened, so a node restarted from its store rebuilds the exact state
    /// it committed, with the same state root.
    pub fn from_trie(mut trie: Trie) -> Self {
        // The reloaded state is already on disk, so nothing is pending persistence yet.
        trie.clear_persist_dirty();
        Ledger {
            trie,
            block_events: Vec::new(),
        }
    }

    /// Clear the block event buffer at the start of a block, so each block's event root covers only the
    /// events that block emitted.
    pub fn clear_block_events(&mut self) {
        self.block_events.clear();
    }

    /// The events emitted so far in the block being executed, in emission order.
    pub fn block_events(&self) -> &[BlockEvent] {
        &self.block_events
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

    /// The whole leaf map, for a reader that snapshots many account keys across threads. Used by the
    /// block executor to read a layer's accounts in parallel. It is a pure read and never touches the
    /// root cache.
    pub(crate) fn leaves(&self) -> &std::collections::BTreeMap<Key, Vec<u8>> {
        self.trie.leaves()
    }

    /// Store an already encoded account record under an already derived key, the write half of the
    /// parallel path once the encode and the key derivation have been done off the critical section.
    /// It lands on the identical trie state as set_account, which derives the key and encodes inline.
    pub(crate) fn insert_raw(&mut self, key: Key, bytes: Vec<u8>) {
        self.trie.insert(key, bytes);
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
