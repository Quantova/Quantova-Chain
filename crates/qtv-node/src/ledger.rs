
use qtv_codec::{from_bytes, to_bytes, Decode, Decoder, Encode, Encoder, Error};
use qtv_crypto::sha3;
use qtv_governance::{
    check_enactment, Action, Ballot, Conviction, EnactmentReceipt, Lock, Referendum, Status, Track,
    Violation,
};
use qtv_staking::{Bond, Session, SessionMeter};
use qtv_state::{Key, Trie, HASH_LEN, KEY_LEN};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: u64,
    pub scheme: u8,
    pub public_key: Vec<u8>,
}

impl Account {
    pub fn funded(balance: u64, scheme: u8, public_key: Vec<u8>) -> Self {
        Account {
            nonce: 0,
            balance,
            scheme,
            public_key,
        }
    }

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

const ACCOUNT_TAG: &[u8] = b"qtv/account/";

pub(crate) fn state_key(address: &str) -> Key {
    let payload = qtv_idfmt::parse_address(address).unwrap_or_default();
    let mut input = Vec::with_capacity(ACCOUNT_TAG.len() + payload.len());
    input.extend_from_slice(ACCOUNT_TAG);
    input.extend_from_slice(&payload);
    sha3::sha3_256(&input)
}

pub fn account_key(address: &str) -> Key {
    state_key(address)
}

const STAKE_BOND_TAG: &[u8] = b"qtv/stake/bond/";
const STAKE_REWARDS_TAG: &[u8] = b"qtv/stake/rewards/";
const STAKE_POOL_TAG: &[u8] = b"qtv/stake/pool";
const STAKE_TREASURY_TAG: &[u8] = b"qtv/stake/treasury";
const SUPPLY_TAG: &[u8] = b"qtv/supply";

pub const FEE_BURN_BPS: u64 = 7_000;
pub const FEE_PROPOSER_BPS: u64 = 1_000;
pub const FEE_GRANTS_BPS: u64 = 2_000;
const _: () = assert!(FEE_BURN_BPS + FEE_PROPOSER_BPS + FEE_GRANTS_BPS == 10_000);

const STAKE_PRICE_TAG: &[u8] = b"qtv/stake/price";
const STAKE_MAINNET_TAG: &[u8] = b"qtv/stake/mainnet";
const STAKE_METER_TAG: &[u8] = b"qtv/stake/meter";
const STAKE_VALIDATORS_TAG: &[u8] = b"qtv/stake/validators";
const STAKE_TOTAL_TAG: &[u8] = b"qtv/stake/total";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeSplit {
    pub burn: u64,
    pub proposer: u64,
    pub grants: u64,
}

impl FeeSplit {
    pub fn of(fee: u64) -> Self {
        let burn = ((fee as u128) * (FEE_BURN_BPS as u128) / 10_000) as u64;
        let proposer = ((fee as u128) * (FEE_PROPOSER_BPS as u128) / 10_000) as u64;
        let grants = fee - burn - proposer;
        FeeSplit {
            burn,
            proposer,
            grants,
        }
    }

    pub fn total(&self) -> u64 {
        self.burn
            .saturating_add(self.proposer)
            .saturating_add(self.grants)
    }

    pub fn add(&mut self, other: FeeSplit) {
        self.burn = self.burn.saturating_add(other.burn);
        self.proposer = self.proposer.saturating_add(other.proposer);
        self.grants = self.grants.saturating_add(other.grants);
    }
}

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

pub fn stake_claim_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/stake/claim"))
        .expect("a full hash reaches the address floor")
}

pub fn grants_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/gov/grants"))
        .expect("a full hash reaches the address floor")
}

pub fn stake_treasury_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(STAKE_TREASURY_TAG))
        .expect("a full hash reaches the address floor")
}

const GOV_NEXT_TAG: &[u8] = b"qtv/gov/next";
const GOV_LOCKED_TAG: &[u8] = b"qtv/gov/locked";
const GOV_REF_TAG: &[u8] = b"qtv/gov/ref/";
const GOV_ACTION_TAG: &[u8] = b"qtv/gov/action/";
const GOV_BALLOT_TAG: &[u8] = b"qtv/gov/ballot/";
const GOV_LOCK_TAG: &[u8] = b"qtv/gov/lock/";
const GOV_BLACKLIST_TAG: &[u8] = b"qtv/gov/blacklist/";
const GOV_FREEZE_TAG: &[u8] = b"qtv/gov/freeze/";
const GOV_RECEIPT_TAG: &[u8] = b"qtv/gov/receipt/";

fn gov_blacklist_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(GOV_BLACKLIST_TAG.len() + id.len());
    input.extend_from_slice(GOV_BLACKLIST_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

fn gov_freeze_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(GOV_FREEZE_TAG.len() + id.len());
    input.extend_from_slice(GOV_FREEZE_TAG);
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

pub fn key_register_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/key/register"))
        .expect("a full hash reaches the address floor")
}

const VM_CODE_TAG: &[u8] = b"qtv/vm/code/";
const VM_STORE_TAG: &[u8] = b"qtv/vm/store/";

pub fn vm_deploy_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/vm/deploy"))
        .expect("a full hash reaches the address floor")
}

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

pub const CONTRACT_CONTEXT_BYTES: usize = 72;

pub fn address_word(address: &str) -> Option<u64> {
    let id = address_id(address)?;
    Some(u64::from_be_bytes(id[..8].try_into().expect("eight bytes")))
}

type StorageKey = [u8; 32];

fn encode_storage(storage: &std::collections::BTreeMap<StorageKey, u64>) -> Vec<u8> {
    let mut encoder = qtv_codec::Encoder::new();
    (storage.len() as u64).encode(&mut encoder);
    for (key, value) in storage {
        encoder.put_bytes(key);
        value.encode(&mut encoder);
    }
    encoder.into_bytes()
}

fn decode_storage(bytes: &[u8]) -> std::collections::BTreeMap<StorageKey, u64> {
    let mut decoder = qtv_codec::Decoder::new(bytes);
    let mut storage = std::collections::BTreeMap::new();
    let count = u64::decode(&mut decoder).unwrap_or(0);
    for _ in 0..count {
        let key = match decoder.get_bytes() {
            Ok(bytes) if bytes.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(bytes);
                key
            }
            _ => break,
        };
        match u64::decode(&mut decoder) {
            Ok(value) => {
                storage.insert(key, value);
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
    NotImplemented,
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

fn action_is_enactable(action: &Action) -> bool {
    !matches!(
        action,
        Action::Upgrade { .. } | Action::BridgeMigration { .. } | Action::AddAsset { .. }
    )
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

    pub fn seed_validator_bond(&mut self, address: &str, amount: u64) -> Option<(Key, Vec<u8>)> {
        let id = address_id(address)?;
        let bond = Bond {
            amount,
            bonded_at_day: 0,
            exit_requested_at: None,
        };
        let existing = self.stake_bond(&id).map(|b| b.amount).unwrap_or(0);
        self.set_stake_bond(&id, &bond);
        if amount >= existing {
            self.credit_staked(amount - existing);
        } else {
            self.debit_staked(existing - amount);
        }
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

    pub fn total_staked(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(STAKE_TOTAL_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical staked total"))
            .unwrap_or(0)
    }

    fn set_total_staked(&mut self, amount: u64) {
        self.trie
            .insert(stake_singleton_key(STAKE_TOTAL_TAG), to_bytes(&amount));
    }

    fn credit_staked(&mut self, amount: u64) {
        if amount == 0 {
            return;
        }
        let next = self.total_staked().saturating_add(amount);
        self.set_total_staked(next);
    }

    fn debit_staked(&mut self, amount: u64) {
        if amount == 0 {
            return;
        }
        let next = self.total_staked().saturating_sub(amount);
        self.set_total_staked(next);
    }

    pub fn total_supply(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(SUPPLY_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical supply"))
            .unwrap_or(0)
    }

    fn set_total_supply(&mut self, amount: u64) {
        self.trie
            .insert(stake_singleton_key(SUPPLY_TAG), to_bytes(&amount));
    }

    pub fn credit_supply(&mut self, amount: u64) {
        if amount == 0 {
            return;
        }
        let next = self.total_supply().saturating_add(amount);
        self.set_total_supply(next);
    }

    pub fn debit_supply(&mut self, amount: u64) {
        if amount == 0 {
            return;
        }
        let next = self.total_supply().saturating_sub(amount);
        self.set_total_supply(next);
    }

    pub fn seed_supply(&mut self, amount: u64) -> (Key, Vec<u8>) {
        self.set_total_supply(amount);
        (stake_singleton_key(SUPPLY_TAG), to_bytes(&amount))
    }

    pub fn set_round_proposer(&mut self, address: &str) {
        self.round_proposer = if address.is_empty() {
            None
        } else {
            Some(address.to_string())
        };
    }

    pub fn round_proposer(&self) -> Option<&str> {
        self.round_proposer.as_deref()
    }

    fn credit_account(&mut self, address: &str, amount: u64) {
        if amount == 0 {
            return;
        }
        let mut account = self.account(address);
        account.balance = account.balance.saturating_add(amount);
        self.set_account(address, &account);
    }

    fn apply_balance_delta(&mut self, address: &str, delta: i128) {
        if delta == 0 {
            return;
        }
        let mut account = self.account(address);
        let updated = i128::from(account.balance) + delta;
        account.balance = if updated < 0 {
            0
        } else {
            u64::try_from(updated).unwrap_or(u64::MAX)
        };
        self.set_account(address, &account);
    }

    pub fn apply_fee_split(&mut self, split: FeeSplit) {
        let grants = grants_address();
        match self.round_proposer.clone() {
            Some(proposer) => self.credit_account(&proposer, split.proposer),
            None => self.credit_account(&grants, split.proposer),
        }
        self.credit_account(&grants, split.grants);
        self.debit_supply(split.burn);
    }

    pub fn collect_fee(&mut self, fee: u64) {
        if fee == 0 {
            return;
        }
        self.apply_fee_split(FeeSplit::of(fee));
    }

    pub fn seed_grants_account(&mut self) -> Vec<(Key, Vec<u8>)> {
        let address = grants_address();
        let account = self.account(&address);
        self.set_account(&address, &account);
        vec![(state_key(&address), to_bytes(&account))]
    }

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

    pub fn clear_dirty(&mut self) {
        self.trie.clear_persist_dirty();
    }

    pub fn is_stake_banned(&self, id: &[u8; 32]) -> bool {
        matches!(self.trie.get(&stake_banned_key(id)), Some(bytes) if !bytes.is_empty())
    }

    pub fn set_stake_banned(&mut self, id: &[u8; 32]) {
        self.trie.insert(stake_banned_key(id), vec![1]);
    }

    pub fn is_validator_banned(&self, address: &str) -> bool {
        match address_id(address) {
            Some(id) => self.is_stake_banned(&id),
            None => false,
        }
    }

    pub fn slash_validator(&mut self, address: &str) -> bool {
        let id = match address_id(address) {
            Some(id) => id,
            None => return false,
        };
        if self.is_stake_banned(&id) {
            return false;
        }
        self.set_stake_banned(&id);
        if let Some(bond) = self.stake_bond(&id) {
            self.debit_supply(bond.amount);
            self.debit_staked(bond.amount);
            self.clear_stake_bond(&id);
        }
        self.clear_stake_rewards(&id);
        true
    }

    fn is_gov_blacklisted(&self, id: &[u8; 32]) -> bool {
        matches!(self.trie.get(&gov_blacklist_key(id)), Some(bytes) if !bytes.is_empty())
    }

    fn set_gov_blacklisted(&mut self, id: &[u8; 32]) {
        self.trie.insert(gov_blacklist_key(id), vec![1]);
    }

    pub fn is_blacklisted(&self, address: &str) -> bool {
        match address_id(address) {
            Some(id) => self.is_gov_blacklisted(&id),
            None => false,
        }
    }

    fn is_frozen_id(&self, id: &[u8; 32]) -> bool {
        matches!(self.trie.get(&gov_freeze_key(id)), Some(bytes) if !bytes.is_empty())
    }

    fn set_frozen(&mut self, id: &[u8; 32]) {
        self.trie.insert(gov_freeze_key(id), vec![1]);
    }

    pub fn is_frozen(&self, address: &str) -> bool {
        match address_id(address) {
            Some(id) => self.is_frozen_id(&id),
            None => false,
        }
    }

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

    fn clear_stake_rewards(&mut self, id: &[u8; 32]) {
        self.trie.insert(stake_rewards_key(id), Vec::new());
    }

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

    pub fn claimable_reward(&self, address: &str, now_day: u64) -> u64 {
        let id = match address_id(address) {
            Some(id) => id,
            None => return 0,
        };
        if self.is_stake_banned(&id) || self.is_gov_blacklisted(&id) {
            return 0;
        }
        self.stake_rewards(&id)
            .tranches
            .iter()
            .map(|tranche| {
                qtv_staking::released(tranche.amount, now_day.saturating_sub(tranche.earned_day))
                    .saturating_sub(tranche.claimed)
            })
            .sum()
    }

    pub fn claim_reward(&mut self, address: &str, now_day: u64) -> u64 {
        let id = match address_id(address) {
            Some(id) => id,
            None => return 0,
        };
        if self.is_stake_banned(&id) || self.is_gov_blacklisted(&id) {
            return 0;
        }
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

    pub fn record_session(&mut self, transactions: u64, now_day: u64) -> Option<Session> {
        let mut meter = self.session_meter();
        meter.record(transactions);
        let closed = meter.close(now_day);
        self.set_session_meter(&meter);
        closed
    }

    pub fn is_contract(&self, address: &str) -> bool {
        match address_id(address) {
            Some(id) => self.contract_code(&id).is_some(),
            None => false,
        }
    }

    pub fn contract_code_at(&self, address: &str) -> Option<Vec<u8>> {
        self.contract_code(&address_id(address)?)
    }

    pub fn contract_storage_at(&self, address: &str) -> std::collections::BTreeMap<StorageKey, u64> {
        match address_id(address) {
            Some(id) => self.contract_storage(&id),
            None => std::collections::BTreeMap::new(),
        }
    }

    pub fn contract_code(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.trie
            .get(&contract_code_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| bytes.to_vec())
    }

    pub fn set_contract_code(&mut self, id: &[u8; 32], code: &[u8]) {
        self.trie.insert(contract_code_key(id), code.to_vec());
    }

    pub fn deploy_contract(&mut self, deployer: &str, nonce: u64, code: &[u8]) -> Option<String> {
        let container = crate::execution::decode_container(code)?;
        container.verify().ok()?;
        let contract = contract_address(deployer, nonce)?;
        let id = address_id(&contract)?;
        self.set_contract_code(&id, code);
        Some(contract)
    }

    pub fn contract_storage(&self, id: &[u8; 32]) -> std::collections::BTreeMap<StorageKey, u64> {
        match self.trie.get(&contract_store_key(id)) {
            Some(bytes) if !bytes.is_empty() => decode_storage(bytes),
            _ => std::collections::BTreeMap::new(),
        }
    }

    pub fn set_contract_storage(
        &mut self,
        id: &[u8; 32],
        storage: &std::collections::BTreeMap<StorageKey, u64>,
    ) {
        self.trie
            .insert(contract_store_key(id), encode_storage(storage));
    }

    pub fn call_contract(
        &mut self,
        caller: &str,
        contract: &str,
        selector: [u8; 4],
        user_memory: &[u8],
        now_seconds: u64,
        meter: u64,
        value: u64,
    ) -> bool {
        let contract_id = match address_id(contract) {
            Some(id) => id,
            None => return false,
        };
        let code = match self.contract_code(&contract_id) {
            Some(code) => code,
            None => return false,
        };
        if value > 0 && self.balance(caller) < value {
            return false;
        }
        let storage = self.contract_storage(&contract_id);
        let mut memory = vec![0u8; user_memory.len().max(CONTRACT_CONTEXT_BYTES)];
        memory[..user_memory.len()].copy_from_slice(user_memory);
        let caller_id = address_id(caller).unwrap_or([0u8; 32]);
        memory[0..32].copy_from_slice(&caller_id);
        memory[32..64].copy_from_slice(&contract_id);
        memory[64..72].copy_from_slice(&now_seconds.to_be_bytes());
        match crate::execution::execute_contract_call(&code, selector, storage, &memory, meter) {
            Ok(outcome) => {
                let mut credits: Vec<(String, u64)> = Vec::new();
                let mut total_sent: u64 = 0;
                for effect in &outcome.effects {
                    if let qtv_vm::interp::Effect::Transfer { to, amount } = effect {
                        let target = match id_bytes_to_address(to) {
                            Some(address) => address,
                            None => return false,
                        };
                        total_sent = match total_sent.checked_add(*amount) {
                            Some(sum) => sum,
                            None => return false,
                        };
                        credits.push((target, *amount));
                    }
                }
                let funded = match self.balance(contract).checked_add(value) {
                    Some(funded) => funded,
                    None => return false,
                };
                if funded < total_sent {
                    return false;
                }
                if value > 0 {
                    self.apply_balance_delta(caller, -i128::from(value));
                    self.apply_balance_delta(contract, i128::from(value));
                }
                for (target, amount) in &credits {
                    self.apply_balance_delta(contract, -i128::from(*amount));
                    self.apply_balance_delta(target, i128::from(*amount));
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

    pub fn seed_validator_set(&mut self, ids: &[[u8; 32]]) -> (Key, Vec<u8>) {
        let mut bytes = Vec::with_capacity(ids.len() * KEY_LEN);
        for id in ids {
            bytes.extend_from_slice(id);
        }
        let key = stake_singleton_key(STAKE_VALIDATORS_TAG);
        self.trie.insert(key, bytes.clone());
        (key, bytes)
    }

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
        if !action_is_enactable(&action) {
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

    pub fn gov_conclude(&mut self, referendum_id: u64, now: u64) -> Option<Status> {
        let mut referendum = self.gov_referendum(referendum_id)?;
        if referendum.status != Status::Deciding {
            return Some(referendum.status);
        }
        let electorate = self.total_staked() as u128;
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
                self.credit_supply(*amount);
                Ok(())
            }
            Action::Parameter { key, value } => self.apply_parameter(key, value),
            Action::Spend { from, to, amount } => {
                let to_addr = id_bytes_to_address(to).ok_or(EnactError::BadAddress)?;
                let from_id = id_from_slice(from).ok_or(EnactError::BadAddress)?;
                if from_id == sha3::sha3_256(b"qtv/gov/grants") {
                    let grants = grants_address();
                    let mut pot = self.account(&grants);
                    if pot.balance < *amount {
                        return Err(EnactError::BadValue);
                    }
                    pot.balance -= *amount;
                    self.set_account(&grants, &pot);
                } else if from_id == stake_singleton_key(STAKE_TREASURY_TAG) {
                    let treasury = self.stake_treasury();
                    if treasury < *amount {
                        return Err(EnactError::BadValue);
                    }
                    self.set_stake_treasury(treasury - *amount);
                } else {
                    return Err(EnactError::BadAddress);
                }
                let mut account = self.account(&to_addr);
                account.balance = account.balance.saturating_add(*amount);
                self.set_account(&to_addr, &account);
                Ok(())
            }
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
            Action::Freeze { targets } => {
                for target in targets {
                    if let Some(id) = id_from_slice(target) {
                        self.set_frozen(&id);
                    }
                }
                Ok(())
            }
            Action::Upgrade { .. }
            | Action::BridgeMigration { .. }
            | Action::AddAsset { .. } => Err(EnactError::NotImplemented),
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
                self.set_session_meter(&SessionMeter::new(day));
                Ok(())
            }
            _ => Err(EnactError::UnknownParameter),
        }
    }

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
        let total = match existing.checked_add(amount) {
            Some(total) => total,
            None => return false,
        };
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
        self.credit_staked(amount);
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
        self.credit_staked(amount);
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
        self.debit_staked(taken);
        if let qtv_staking::Fault::Attributable = fault {
            self.clear_stake_bond(&id);
            self.set_stake_banned(&id);
            self.clear_stake_rewards(&id);
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
        self.debit_staked(bond.amount);
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
        assert!(l.call_contract(&caller, &contract, selector, &[], 0, 100_000, 0));
        let expected = u64::from_be_bytes([9u8; 8]);
        assert_eq!(l.contract_storage(&contract_id).get(&[9u8; 32]), Some(&expected));

        let empty = qtv_idfmt::render_address(&[71u8; 32]).unwrap();
        assert!(!l.call_contract(&caller, &empty, selector, &[], 0, 100_000, 0));
    }

    #[test]
    fn a_contract_sees_the_whole_caller_address_not_a_leading_word() {
        let code = qtv_vm::asm::assemble(
            "LDI r1, 24\nMLOAD r0, r1\nLDI r2, 0\nSSTORE r2, r0\n\
             LDI r3, 32\nMLOAD r4, r3\nLDI r5, 32\nSSTORE r5, r4\nHALT",
        )
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
                    writes: vec![0, 1],
                },
            }],
        );
        let mut l = Ledger::new();
        let contract_id = [70u8; 32];
        let contract = qtv_idfmt::render_address(&contract_id).unwrap();
        l.set_contract_code(&contract_id, &container.canonical_bytes());

        let mut p1 = [5u8; 32];
        p1[24..].copy_from_slice(&[0xA1u8; 8]);
        let mut p2 = [5u8; 32];
        p2[24..].copy_from_slice(&[0xB2u8; 8]);
        let c1 = qtv_idfmt::render_address(&p1).unwrap();
        let c2 = qtv_idfmt::render_address(&p2).unwrap();

        assert!(l.call_contract(&c1, &contract, selector, &[], 0, 100_000, 0));
        let seen1 = *l.contract_storage(&contract_id).get(&p1).unwrap();
        assert_eq!(
            l.contract_storage(&contract_id).get(&contract_id),
            Some(&u64::from_be_bytes([70u8; 8]))
        );

        assert!(l.call_contract(&c2, &contract, selector, &[], 0, 100_000, 0));
        let seen2 = *l.contract_storage(&contract_id).get(&p2).unwrap();

        assert_eq!(seen1, u64::from_be_bytes([0xA1u8; 8]));
        assert_eq!(seen2, u64::from_be_bytes([0xB2u8; 8]));
        assert_ne!(
            seen1, seen2,
            "two callers sharing a leading word are distinct to the contract"
        );
    }

    #[test]
    fn a_blacklisted_address_is_barred_from_staking_and_carries_no_weight() {
        let mut l = Ledger::new();
        let addr = gov_addr(50);
        let id = [50u8; 32];
        fund(&mut l, &addr, 10_000 * 1_000_000);
        l.set_gov_blacklisted(&id);
        assert!(l.is_blacklisted(&addr));
        assert!(!l.bond(&addr, 2_000 * 1_000_000, 0));
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        assert_eq!(l.staked_weight(&addr), 0);
    }

    #[test]
    fn a_qip_deposit_returns_on_support_and_a_spam_deposit_is_forfeit() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
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
        assert!(!l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 100, 0));

        let close = 7 * 86_400 + 1;
        assert_eq!(l.gov_conclude(id, close), Some(qtv_governance::Status::Approved));
        assert_eq!(l.balance(&proposer), 20_000 * 1_000_000);

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
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
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
        assert!(l.gov_enact(id, 7 * 86_400 + 1).is_err());
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
    fn a_track_with_no_enactment_cannot_be_proposed_and_keeps_the_deposit() {
        let mut l = Ledger::new();
        let proposer = gov_addr(30);
        fund(&mut l, &proposer, 2_000_000 * 1_000_000);
        assert!(l
            .gov_propose(
                &proposer,
                qtv_governance::Track::ChainUpgrade,
                qtv_governance::Action::Upgrade { blob: vec![1, 2, 3] },
                0,
            )
            .is_none());
        assert!(l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::BridgeMigration { vault: vec![4; 32] },
                0,
            )
            .is_none());
        assert!(l
            .gov_propose(
                &proposer,
                qtv_governance::Track::AddAsset,
                qtv_governance::Action::AddAsset { asset: vec![6; 32] },
                0,
            )
            .is_none());
        assert_eq!(l.balance(&proposer), 2_000_000 * 1_000_000);
    }

    #[test]
    fn governance_freezes_a_named_account_and_shields_protected_stake_from_a_freeze() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        let proposer = gov_addr(40);
        fund(&mut l, &proposer, 300_000 * 1_000_000);
        let target = gov_addr(41);
        let id = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BlacklistKill,
                qtv_governance::Action::Freeze { targets: vec![[41u8; 32].to_vec()] },
                0,
            )
            .unwrap();
        let voter = gov_addr(42);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert!(!l.is_frozen(&target));
        l.gov_enact(id, 2 * 86_400 + 1).unwrap();
        assert!(l.is_frozen(&target));

        let bonded = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BlacklistKill,
                qtv_governance::Action::Freeze { targets: vec![[99u8; 32].to_vec()] },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, bonded, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(bonded, 2 * 86_400 + 1),
            Err(EnactError::Constitution(
                qtv_governance::Violation::FreezeTouchesProtected
            ))
        );
    }

    #[test]
    fn governance_mints_uncapped_to_the_target_on_the_mint_track() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
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
    fn a_lone_voter_no_longer_passes_a_proposal_a_real_supermajority_would_reject() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 1_000_000 * 1_000_000);
        assert_eq!(l.total_staked(), 1_000_000 * 1_000_000);

        let action = || qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let proposer = gov_addr(80);
        fund(&mut l, &proposer, 100_000 * 1_000_000);
        let close = 7 * 86_400 + 1;

        let lone = l
            .gov_propose(&proposer, qtv_governance::Track::Parameter, action(), 0)
            .unwrap();
        let solo = gov_addr(81);
        fund(&mut l, &solo, 10_000 * 1_000_000);
        assert!(l.gov_vote(&solo, lone, true, qtv_governance::Conviction::Liquid, 2_000 * 1_000_000, 0));
        assert!(l.gov_referendum(lone).unwrap().tally.reached_approval(qtv_governance::Track::Parameter));
        assert_eq!(l.gov_conclude(lone, close), Some(qtv_governance::Status::Rejected));

        let real = l
            .gov_propose(&proposer, qtv_governance::Track::Parameter, action(), 0)
            .unwrap();
        let backer = gov_addr(82);
        fund(&mut l, &backer, 600_000 * 1_000_000);
        assert!(l.gov_vote(&backer, real, true, qtv_governance::Conviction::Liquid, 500_000 * 1_000_000, 0));
        assert_eq!(l.gov_conclude(real, close), Some(qtv_governance::Status::Approved));
    }

    #[test]
    fn a_passed_vote_pays_out_of_the_keyless_pots_and_nothing_else_can() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        let proposer = gov_addr(50);
        fund(&mut l, &proposer, 600_000 * 1_000_000);
        let voter = gov_addr(51);
        fund(&mut l, &voter, 30_000 * 1_000_000);

        let grants = grants_address();
        fund(&mut l, &grants, 40_000 * 1_000_000);
        l.set_stake_treasury(5_000 * 1_000_000);
        assert!(!l.account(&grants).has_key(), "the grants pot carries no key to sign a spend");
        assert!(
            !l.account(&stake_treasury_address()).has_key(),
            "the treasury pot carries no key to sign a spend"
        );

        let recipient = gov_addr(52);
        let pass = |l: &mut Ledger, action: qtv_governance::Action| {
            let id = l
                .gov_propose(&proposer, qtv_governance::Track::Mint, action, 0)
                .unwrap();
            l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
            id
        };

        let from_grants = pass(
            &mut l,
            qtv_governance::Action::Spend {
                from: sha3::sha3_256(b"qtv/gov/grants").to_vec(),
                to: [52u8; 32].to_vec(),
                amount: 12_000 * 1_000_000,
            },
        );
        l.gov_enact(from_grants, 3 * 86_400 + 1).unwrap();
        assert_eq!(l.balance(&recipient), 12_000 * 1_000_000);
        assert_eq!(l.balance(&grants), 28_000 * 1_000_000);

        let from_treasury = pass(
            &mut l,
            qtv_governance::Action::Spend {
                from: stake_singleton_key(STAKE_TREASURY_TAG).to_vec(),
                to: [52u8; 32].to_vec(),
                amount: 5_000 * 1_000_000,
            },
        );
        l.gov_enact(from_treasury, 3 * 86_400 + 1).unwrap();
        assert_eq!(l.balance(&recipient), 17_000 * 1_000_000);
        assert_eq!(l.stake_treasury(), 0);

        let user = gov_addr(53);
        fund(&mut l, &user, 9_000 * 1_000_000);
        let steal = pass(
            &mut l,
            qtv_governance::Action::Spend {
                from: [53u8; 32].to_vec(),
                to: [52u8; 32].to_vec(),
                amount: 9_000 * 1_000_000,
            },
        );
        assert_eq!(l.gov_enact(steal, 3 * 86_400 + 1), Err(EnactError::BadAddress));
        assert_eq!(l.balance(&user), 9_000 * 1_000_000);
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
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Year, 4_000 * 1_000_000, 0);
        assert_eq!(l.balance(&voter), 6_000 * 1_000_000);
        assert_eq!(l.gov_release(&voter, 100), 0);
        assert_eq!(l.balance(&voter), 6_000 * 1_000_000);
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

        assert_eq!(l.accrue_reward(&addr, qtv_staking::Session::Low, 400), 0);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);

        l.set_stake_mainnet_start(0);
        assert_eq!(l.accrue_reward(&addr, qtv_staking::Session::Low, 400), 0);

        l.set_stake_price(70 * 1_000_000);
        let paid = l.accrue_reward(&addr, qtv_staking::Session::Low, 400);
        assert_eq!(paid, 20 * 1_000_000);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000 - 20 * 1_000_000);

        assert_eq!(l.claimable_reward(&addr, 400 + 364), 0);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), 5 * 1_000_000);
        assert_eq!(l.claim_reward(&addr, 400 + 365), 5 * 1_000_000);
        assert_eq!(l.balance(&addr), 5 * 1_000_000);
        assert_eq!(l.claim_reward(&addr, 400 + 365), 0);
        let full_day = 400 + 365 + 3 * 120;
        assert_eq!(l.claim_reward(&addr, full_day), 15 * 1_000_000);
        assert_eq!(l.balance(&addr), 20 * 1_000_000);
        assert_eq!(l.claimable_reward(&addr, full_day + 1_000), 0);
    }

    #[test]
    fn an_attributable_slash_wipes_accrued_rewards_and_a_banned_validator_cannot_claim() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[16u8; 32]).unwrap();
        let id = [16u8; 32];
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        l.set_stake_mainnet_start(0);
        l.set_stake_price(70 * 1_000_000);
        assert_eq!(l.accrue_reward(&addr, qtv_staking::Session::Low, 400), 20 * 1_000_000);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), 5 * 1_000_000);
        l.slash_stake(&addr, qtv_staking::Fault::Attributable);
        assert!(l.is_stake_banned(&id));
        assert_eq!(l.claimable_reward(&addr, 400 + 365), 0);
        assert_eq!(l.claim_reward(&addr, 400 + 365), 0);
        assert_eq!(l.balance(&addr), 0);
    }

    #[test]
    fn a_gov_blacklisted_validator_cannot_claim_accrued_rewards() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[17u8; 32]).unwrap();
        let id = [17u8; 32];
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        l.set_stake_mainnet_start(0);
        l.set_stake_price(70 * 1_000_000);
        l.accrue_reward(&addr, qtv_staking::Session::Low, 400);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), 5 * 1_000_000);
        l.set_gov_blacklisted(&id);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), 0);
        assert_eq!(l.claim_reward(&addr, 400 + 365), 0);
        assert_eq!(l.balance(&addr), 0);
    }

    #[test]
    fn the_reward_cap_binds_when_the_price_climbs() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[13u8; 32]).unwrap();
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        l.set_stake_mainnet_start(0);
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

        l.settle_session(182, 5);
        l.settle_session(400, 5);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);
        assert_eq!(l.claimable_reward(&v, 1_000), 0);

        l.set_stake_mainnet_start(0);
        l.set_stake_price(70 * 1_000_000);

        l.settle_session(182, 5);
        l.settle_session(364, 5);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);

        l.settle_session(546, 5);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000 - 20 * 1_000_000);
        assert_eq!(l.claimable_reward(&v, 546 + 365), 5 * 1_000_000);
    }

    #[test]
    fn the_session_meter_counts_across_blocks_and_closes_on_the_window() {
        let mut l = Ledger::new();
        assert_eq!(l.record_session(10, 100), None);
        assert_eq!(l.record_session(20, 150), None);
        assert_eq!(l.session_meter().count(), 30);
        assert_eq!(l.record_session(5, 182), Some(qtv_staking::Session::Low));
        assert_eq!(l.session_meter().count(), 0);
    }

    #[test]
    fn committee_weight_tracks_the_live_bond_in_whole_units() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[8u8; 32]).unwrap();
        let id = [8u8; 32];
        assert_eq!(l.staked_weight(&addr), 0);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000).unwrap();
        assert_eq!(l.staked_weight(&addr), 2_000);
        l.set_stake_bond(&id, &Bond::new(2_000 * 1_000_000 + 999_999, 0).unwrap());
        assert_eq!(l.staked_weight(&addr), 2_000);
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
    fn bond_rejects_an_addition_that_would_overflow_the_stake_word() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[15u8; 32]).unwrap();
        let id = [15u8; 32];
        l.set_account(&addr, &Account::funded(3_000 * 1_000_000, 1, vec![]));
        let ceiling = Bond {
            amount: u64::MAX - 1_000,
            bonded_at_day: 0,
            exit_requested_at: None,
        };
        l.set_stake_bond(&id, &ceiling);
        assert!(!l.bond(&addr, 2_000 * 1_000_000, 0));
        assert_eq!(l.balance(&addr), 3_000 * 1_000_000);
        assert_eq!(l.stake_bond(&id).unwrap().amount, u64::MAX - 1_000);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEvent {
    pub contract: String,
    pub selector: [u8; 4],
    pub data: Vec<u8>,
}

impl BlockEvent {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_bytes(self.contract.as_bytes());
        encoder.put_bytes(&self.selector);
        encoder.put_bytes(&self.data);
        encoder.into_bytes()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ledger {
    trie: Trie,
    block_events: Vec<BlockEvent>,
    round_proposer: Option<String>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger {
            trie: Trie::new(),
            block_events: Vec::new(),
            round_proposer: None,
        }
    }

    pub fn from_trie(mut trie: Trie) -> Self {
        trie.clear_persist_dirty();
        Ledger {
            trie,
            block_events: Vec::new(),
            round_proposer: None,
        }
    }

    pub fn clear_block_events(&mut self) {
        self.block_events.clear();
    }

    pub fn block_events(&self) -> &[BlockEvent] {
        &self.block_events
    }

    pub fn account(&self, address: &str) -> Account {
        match self.trie.get(&state_key(address)) {
            Some(bytes) => from_bytes(bytes).unwrap_or_default(),
            None => Account::default(),
        }
    }

    pub fn set_account(&mut self, address: &str, account: &Account) {
        self.trie.insert(state_key(address), to_bytes(account));
    }

    pub(crate) fn leaves(&self) -> &std::collections::BTreeMap<Key, Vec<u8>> {
        self.trie.leaves()
    }

    pub(crate) fn insert_raw(&mut self, key: Key, bytes: Vec<u8>) {
        self.trie.insert(key, bytes);
    }

    pub fn balance(&self, address: &str) -> u64 {
        self.account(address).balance
    }

    pub fn nonce(&self, address: &str) -> u64 {
        self.account(address).nonce
    }

    pub fn state_root(&self) -> [u8; HASH_LEN] {
        self.trie.root()
    }

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
    fn a_fee_split_is_seventy_ten_twenty_with_dust_to_grants() {
        let split = FeeSplit::of(1_000);
        assert_eq!(split.burn, 700, "seven tenths of the fee burn");
        assert_eq!(split.proposer, 100, "a tenth to the proposer");
        assert_eq!(split.grants, 200, "a fifth to grants");
        assert_eq!(split.total(), 1_000, "the shares sum to the fee");

        let odd = FeeSplit::of(7);
        assert_eq!(
            (odd.burn, odd.proposer),
            (4, 0),
            "the burn and proposer shares floor"
        );
        assert_eq!(odd.grants, 3, "the rounding dust lands in the grants share");
        assert_eq!(odd.total(), 7, "the split conserves the fee to the unit");
    }

    #[test]
    fn a_fee_burns_seventy_percent_of_the_supply_and_a_mint_raises_it() {
        let mut ledger = Ledger::new();
        ledger.seed_supply(1_000_000);
        assert_eq!(ledger.total_supply(), 1_000_000, "genesis fixes the supply");

        ledger.collect_fee(1_000);
        assert_eq!(
            ledger.total_supply(),
            1_000_000 - 700,
            "a fee burns seven tenths and lowers the supply by that much"
        );

        ledger.credit_supply(500);
        assert_eq!(
            ledger.total_supply(),
            1_000_000 - 700 + 500,
            "a mint raises the supply"
        );
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

    #[test]
    fn an_address_over_a_system_record_reads_as_the_default_and_never_panics() {
        let mut ledger = Ledger::new();
        ledger.set_stake_pool(9_000);
        let pool_key = stake_singleton_key(STAKE_POOL_TAG);
        let hostile = qtv_idfmt::render_address(&pool_key).expect("a full hash reaches the floor");
        assert_eq!(ledger.account(&hostile), Account::default());
        assert_eq!(ledger.stake_pool(), 9_000);
    }
}
