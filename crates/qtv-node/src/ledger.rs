// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_codec::{from_bytes, to_bytes, Decode, Decoder, Encode, Encoder, Error};
use qtv_crypto::sha3;
use qtv_governance::{
    check_enactment, Action, Ballot, BridgeFreeze, Conviction, EnactmentReceipt, Lock, Referendum,
    Status, Track, Violation,
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

// Genesis fee split per the v0.4 tokenomics, 20 percent burned so supply falls with real use, 60
// percent to the validators reward pool, and 20 percent to grants. Tunable by governance.
pub const FEE_BURN_BPS: u64 = 2_000;
pub const FEE_PROPOSER_BPS: u64 = 6_000;
pub const FEE_GRANTS_BPS: u64 = 2_000;
const _: () = assert!(FEE_BURN_BPS + FEE_PROPOSER_BPS + FEE_GRANTS_BPS == 10_000);

pub const RENT_EXEMPT_PER_BYTE: u64 = 1_000;
pub const RENT_PER_BYTE_PER_PERIOD: u64 = 1;

pub fn rent_exempt_minimum_for(footprint: usize) -> u64 {
    (footprint as u64).saturating_mul(RENT_EXEMPT_PER_BYTE)
}

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QAsset {
    pub supply: u128,
    pub cap: u128,
    pub epoch_cap: u128,
    pub requires_stark: bool,
}

impl Encode for QAsset {
    fn encode(&self, encoder: &mut Encoder) {
        self.supply.encode(encoder);
        self.cap.encode(encoder);
        self.epoch_cap.encode(encoder);
        encoder.put_u8(self.requires_stark as u8);
    }
}

impl Decode for QAsset {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(QAsset {
            supply: u128::decode(decoder)?,
            cap: u128::decode(decoder)?,
            epoch_cap: u128::decode(decoder)?,
            requires_stark: decoder.get_u8()? != 0,
        })
    }
}

const BRIDGE_ASSET_TAG: &[u8] = b"qtv/bridge/asset/";
const BRIDGE_BALANCE_TAG: &[u8] = b"qtv/bridge/bal/";
const BRIDGE_SEEN_TAG: &[u8] = b"qtv/bridge/seen/";
const BRIDGE_EPOCHMINT_TAG: &[u8] = b"qtv/bridge/epochmint/";
const BRIDGE_OPERATORS_TAG: &[u8] = b"qtv/bridge/operators";
const BRIDGE_DESTCHAIN_TAG: &[u8] = b"qtv/bridge/destchain";
const BRIDGE_EPOCH_TAG: &[u8] = b"qtv/bridge/epoch";
const BRIDGE_BURN_REF_DOMAIN: &[u8] = b"qtv/bridge/burn-ref/v1";

fn bridge_asset_key(asset_id: &[u8; 16]) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_ASSET_TAG.len() + asset_id.len());
    input.extend_from_slice(BRIDGE_ASSET_TAG);
    input.extend_from_slice(asset_id);
    sha3::sha3_256(&input)
}

fn bridge_balance_key(asset_id: &[u8; 16], holder: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_BALANCE_TAG.len() + asset_id.len() + holder.len());
    input.extend_from_slice(BRIDGE_BALANCE_TAG);
    input.extend_from_slice(asset_id);
    input.extend_from_slice(holder);
    sha3::sha3_256(&input)
}

fn bridge_seen_key(source_ref: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_SEEN_TAG.len() + source_ref.len());
    input.extend_from_slice(BRIDGE_SEEN_TAG);
    input.extend_from_slice(source_ref);
    sha3::sha3_256(&input)
}

fn bridge_epochmint_key(asset_id: &[u8; 16], epoch: u64) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_EPOCHMINT_TAG.len() + asset_id.len() + 8);
    input.extend_from_slice(BRIDGE_EPOCHMINT_TAG);
    input.extend_from_slice(asset_id);
    input.extend_from_slice(&epoch.to_le_bytes());
    sha3::sha3_256(&input)
}

pub fn bridge_burn_ref(
    chain_id: u64,
    asset_id: &[u8; 16],
    holder: &[u8; 32],
    amount: u128,
    destination: &[u8; 32],
    sender_nonce: u64,
    event_index: u64,
) -> [u8; 32] {
    let mut encoder = Encoder::new();
    encoder.put_bytes(BRIDGE_BURN_REF_DOMAIN);
    encoder.put_u64(chain_id);
    encoder.put_bytes(asset_id);
    encoder.put_bytes(holder);
    encoder.put_u128(amount);
    encoder.put_bytes(destination);
    encoder.put_u64(sender_nonce);
    encoder.put_u64(event_index);
    sha3::sha3_256(&encoder.into_bytes())
}

const STAKE_BANNED_TAG: &[u8] = b"qtv/stake/banned/";

fn stake_banned_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(STAKE_BANNED_TAG.len() + id.len());
    input.extend_from_slice(STAKE_BANNED_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

const STAKE_ATTEST_TAG: &[u8] = b"qtv/stake/attest/";

fn stake_attest_key(id: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(STAKE_ATTEST_TAG.len() + id.len());
    input.extend_from_slice(STAKE_ATTEST_TAG);
    input.extend_from_slice(id);
    sha3::sha3_256(&input)
}

pub fn evidence_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/evidence"))
        .expect("a full hash reaches the address floor")
}

pub fn registration_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/registration"))
        .expect("a full hash reaches the address floor")
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

/// A reserved recipient the apply path treats as a fault injection, present only in test
/// builds. A transfer to it drives a native transition that mutates state and then faults, so
/// a test can prove the atomic firewall rolls the partial write back.
#[cfg(test)]
pub(crate) fn fault_probe_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/native/fault-probe"))
        .expect("a full hash reaches the address floor")
}

pub fn stake_claim_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/stake/claim"))
        .expect("a full hash reaches the address floor")
}

pub fn stake_exit_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/stake/exit"))
        .expect("a full hash reaches the address floor")
}

pub fn stake_withdraw_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/stake/withdraw"))
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
const GOV_GUARDIAN_TAG: &[u8] = b"qtv/gov/guardians";
const GOV_RECEIPT_TAG: &[u8] = b"qtv/gov/receipt/";

const BRIDGE_FREEZE_TAG: &[u8] = b"qtv/bridge/freeze";
const BRIDGE_LAST_LIFT_TAG: &[u8] = b"qtv/bridge/lastlift";
const BRIDGE_VAULT_TAG: &[u8] = b"qtv/bridge/vault";
const BRIDGE_GATEWAY_TAG: &[u8] = b"qtv/bridge/gateway";

fn is_reserved_pot(id: &[u8; 32]) -> bool {
    const POTS: &[&[u8]] = &[
        b"qtv/gov/grants",
        b"qtv/stake/treasury",
        b"qtv/stake/pool",
        b"qtv/stake/system",
        b"qtv/gov/system",
        b"qtv/bridge/bond",
        b"qtv/ecosystem/marketing",
        b"qtv/ecosystem/market-maker",
        b"qtv/ecosystem/foundation",
    ];
    POTS.iter().any(|tag| sha3::sha3_256(tag) == *id)
}

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

pub fn bridge_freeze_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/freeze/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_unfreeze_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/unfreeze/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_bond_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/bond"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_mint_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/mint/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_exit_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/exit/system"))
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

pub const CONTRACT_CONTEXT_BYTES: usize = 80;

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
    BridgeNotFrozen,
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
    !matches!(action, Action::Upgrade { .. })
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
        self.write_leaf(stake_bond_key(id), to_bytes(bond));
    }

    pub fn clear_stake_bond(&mut self, id: &[u8; 32]) {
        self.write_leaf(stake_bond_key(id), Vec::new());
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
        self.write_leaf(stake_singleton_key(STAKE_POOL_TAG), to_bytes(&amount));
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
        self.write_leaf(stake_singleton_key(STAKE_TREASURY_TAG), to_bytes(&amount));
    }

    pub fn total_staked(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(STAKE_TOTAL_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical staked total"))
            .unwrap_or(0)
    }

    fn set_total_staked(&mut self, amount: u64) {
        self.write_leaf(stake_singleton_key(STAKE_TOTAL_TAG), to_bytes(&amount));
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
        self.write_leaf(stake_singleton_key(SUPPLY_TAG), to_bytes(&amount));
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
        self.write_leaf(stake_banned_key(id), vec![1]);
    }

    pub fn is_validator_banned(&self, address: &str) -> bool {
        match address_id(address) {
            Some(id) => self.is_stake_banned(&id),
            None => false,
        }
    }

    /// The registered attestation public key of a validator, held in state so a block can
    /// carry equivocation evidence and every node verifies and applies the slash from the
    /// same committed key with no access to the live roster.
    pub fn validator_attest_key(&self, address: &str) -> Option<Vec<u8>> {
        let id = address_id(address)?;
        self.trie
            .get(&stake_attest_key(&id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| bytes.to_vec())
    }

    pub fn set_validator_attest_key(&mut self, address: &str, attest_pk: &[u8]) {
        if let Some(id) = address_id(address) {
            self.write_leaf(stake_attest_key(&id), attest_pk.to_vec());
        }
    }

    pub fn seed_validator_attest_key(
        &mut self,
        address: &str,
        attest_pk: &[u8],
    ) -> Option<(Key, Vec<u8>)> {
        let id = address_id(address)?;
        let key = stake_attest_key(&id);
        self.write_leaf(key, attest_pk.to_vec());
        Some((key, attest_pk.to_vec()))
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
            self.record_slash_event(address, bond.amount);
        }
        self.clear_stake_rewards(&id);
        true
    }

    fn is_gov_blacklisted(&self, id: &[u8; 32]) -> bool {
        matches!(self.trie.get(&gov_blacklist_key(id)), Some(bytes) if !bytes.is_empty())
    }

    fn set_gov_blacklisted(&mut self, id: &[u8; 32]) {
        self.write_leaf(gov_blacklist_key(id), vec![1]);
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
        self.write_leaf(gov_freeze_key(id), vec![1]);
    }

    fn clear_frozen(&mut self, id: &[u8; 32]) {
        self.write_leaf(gov_freeze_key(id), Vec::new());
    }

    pub fn is_frozen(&self, address: &str) -> bool {
        match address_id(address) {
            Some(id) => self.is_frozen_id(&id),
            None => false,
        }
    }

    pub fn guardian_set(&self) -> qtv_governance::GuardianSet {
        self.trie
            .get(&stake_singleton_key(GOV_GUARDIAN_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical guardian set"))
            .unwrap_or_default()
    }

    pub fn set_guardian_set(&mut self, caucus: &qtv_governance::GuardianSet) {
        self.write_leaf(stake_singleton_key(GOV_GUARDIAN_TAG), to_bytes(caucus));
    }

    pub fn seed_guardian_set(&mut self, caucus: &qtv_governance::GuardianSet) -> (Key, Vec<u8>) {
        self.set_guardian_set(caucus);
        (stake_singleton_key(GOV_GUARDIAN_TAG), to_bytes(caucus))
    }

    pub fn guardian_freeze(&mut self, targets: &[[u8; 32]], approvers: &[[u8; 32]]) -> bool {
        if targets.is_empty() || !self.guardian_set().authorizes(approvers) {
            return false;
        }
        if targets.iter().any(|target| self.is_protected_account(target)) {
            return false;
        }
        for target in targets {
            self.set_frozen(target);
        }
        true
    }

    pub fn bridge_freeze(&self) -> Option<BridgeFreeze> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_FREEZE_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical bridge freeze"))
    }

    fn set_bridge_freeze(&mut self, record: &BridgeFreeze) {
        self.write_leaf(stake_singleton_key(BRIDGE_FREEZE_TAG), to_bytes(record));
    }

    fn clear_bridge_freeze(&mut self) {
        self.write_leaf(stake_singleton_key(BRIDGE_FREEZE_TAG), Vec::new());
    }

    pub fn bridge_is_frozen(&self) -> bool {
        self.bridge_freeze().is_some()
    }

    pub fn bridge_last_lift(&self) -> Option<u64> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_LAST_LIFT_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical bridge last lift"))
    }

    fn set_bridge_last_lift(&mut self, now: u64) {
        self.write_leaf(stake_singleton_key(BRIDGE_LAST_LIFT_TAG), to_bytes(&now));
    }

    pub fn bridge_pool_vault(&self) -> Option<[u8; 32]> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_VAULT_TAG))
            .filter(|bytes| bytes.len() == KEY_LEN)
            .map(|bytes| {
                let mut vault = [0u8; 32];
                vault.copy_from_slice(bytes);
                vault
            })
    }

    fn set_bridge_pool_vault(&mut self, vault: &[u8; 32]) {
        self.write_leaf(stake_singleton_key(BRIDGE_VAULT_TAG), vault.to_vec());
    }

    pub fn bridge_gateway(&self) -> Option<[u8; 32]> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_GATEWAY_TAG))
            .filter(|bytes| bytes.len() == KEY_LEN)
            .map(|bytes| {
                let mut gateway = [0u8; 32];
                gateway.copy_from_slice(bytes);
                gateway
            })
    }

    fn set_bridge_gateway(&mut self, gateway: &[u8; 32]) {
        self.write_leaf(stake_singleton_key(BRIDGE_GATEWAY_TAG), gateway.to_vec());
    }

    pub fn seed_bridge_gateway(&mut self, gateway: &[u8; 32]) -> (Key, Vec<u8>) {
        self.set_bridge_gateway(gateway);
        (stake_singleton_key(BRIDGE_GATEWAY_TAG), gateway.to_vec())
    }

    pub fn is_bridge_gateway(&self, address: &str) -> bool {
        match (self.bridge_gateway(), address_id(address)) {
            (Some(gateway), Some(id)) => gateway == id,
            _ => false,
        }
    }

    pub fn bridge_freeze_with_fee(&mut self, caller: &str, fee: u64, now: u64) -> bool {
        let id = match address_id(caller) {
            Some(id) => id,
            None => return false,
        };
        if self.is_gov_blacklisted(&id) {
            return false;
        }
        if self.bridge_freeze().is_some() {
            return false;
        }
        if let Some(last) = self.bridge_last_lift() {
            if now < last.saturating_add(qtv_governance::BRIDGE_FREEZE_COOLDOWN) {
                return false;
            }
        }
        let bond = qtv_governance::BRIDGE_FREEZE_BOND;
        let debit = match fee.checked_add(bond) {
            Some(debit) => debit,
            None => return false,
        };
        let mut account = self.account(caller);
        if account.balance < debit {
            return false;
        }
        account.balance -= debit;
        account.nonce += 1;
        self.set_account(caller, &account);
        self.collect_fee(fee);
        let pot_address = bridge_bond_address();
        let mut pot = self.account(&pot_address);
        pot.balance = pot.balance.saturating_add(bond);
        self.set_account(&pot_address, &pot);
        let until = now.saturating_add(qtv_governance::BRIDGE_FREEZE_DURATION);
        self.set_bridge_freeze(&BridgeFreeze {
            who: id,
            bond,
            until,
        });
        true
    }

    pub fn bridge_unfreeze_with_fee(&mut self, caller: &str, fee: u64, now: u64) -> bool {
        let id = match address_id(caller) {
            Some(id) => id,
            None => return false,
        };
        let record = match self.bridge_freeze() {
            Some(record) => record,
            None => return false,
        };
        if record.who != id {
            return false;
        }
        let mut account = self.account(caller);
        if account.balance < fee {
            return false;
        }
        account.balance -= fee;
        account.nonce += 1;
        self.set_account(caller, &account);
        self.collect_fee(fee);
        self.lift_bridge_freeze(now);
        true
    }

    pub fn guardian_bridge_unfreeze(&mut self, approvers: &[[u8; 32]], now: u64) -> bool {
        if self.bridge_freeze().is_none() {
            return false;
        }
        if !self.guardian_set().authorizes(approvers) {
            return false;
        }
        self.lift_bridge_freeze(now);
        true
    }

    pub fn bridge_expire(&mut self, now: u64) {
        if let Some(record) = self.bridge_freeze() {
            if now >= record.until {
                self.lift_bridge_freeze(now);
            }
        }
    }

    fn lift_bridge_freeze(&mut self, now: u64) {
        let record = match self.bridge_freeze() {
            Some(record) => record,
            None => return,
        };
        let pot_address = bridge_bond_address();
        let mut pot = self.account(&pot_address);
        pot.balance = pot.balance.saturating_sub(record.bond);
        self.set_account(&pot_address, &pot);
        if let Some(depositor) = id_bytes_to_address(&record.who) {
            let mut account = self.account(&depositor);
            account.balance = account.balance.saturating_add(record.bond);
            self.set_account(&depositor, &account);
        }
        self.clear_bridge_freeze();
        self.set_bridge_last_lift(now);
    }

    pub fn bridged_asset(&self, asset_id: &[u8; 16]) -> Option<QAsset> {
        self.trie
            .get(&bridge_asset_key(asset_id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical bridged asset"))
    }

    fn set_bridged_asset(&mut self, asset_id: &[u8; 16], asset: &QAsset) {
        self.write_leaf(bridge_asset_key(asset_id), to_bytes(asset));
    }

    pub fn register_bridged_asset(
        &mut self,
        asset_id: &[u8; 16],
        cap: u128,
        epoch_cap: u128,
        requires_stark: bool,
    ) -> (Key, Vec<u8>) {
        let supply = self.bridged_asset(asset_id).map(|a| a.supply).unwrap_or(0);
        let asset = QAsset {
            supply,
            cap,
            epoch_cap,
            requires_stark,
        };
        self.set_bridged_asset(asset_id, &asset);
        (bridge_asset_key(asset_id), to_bytes(&asset))
    }

    pub fn bridged_supply(&self, asset_id: &[u8; 16]) -> u128 {
        self.bridged_asset(asset_id).map(|a| a.supply).unwrap_or(0)
    }

    pub fn bridged_balance(&self, asset_id: &[u8; 16], holder: &[u8; 32]) -> u128 {
        self.trie
            .get(&bridge_balance_key(asset_id, holder))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical bridged balance"))
            .unwrap_or(0)
    }

    fn set_bridged_balance(&mut self, asset_id: &[u8; 16], holder: &[u8; 32], amount: u128) {
        self.write_leaf(bridge_balance_key(asset_id, holder), to_bytes(&amount));
    }

    pub fn bridge_operator_set(&self) -> Option<crate::bridge::OperatorSet> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_OPERATORS_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical operator set"))
    }

    pub fn seed_bridge_operator_set(&mut self, set: &crate::bridge::OperatorSet) -> (Key, Vec<u8>) {
        let key = stake_singleton_key(BRIDGE_OPERATORS_TAG);
        let bytes = to_bytes(set);
        self.write_leaf(key, bytes.clone());
        (key, bytes)
    }

    pub fn bridge_dest_chain(&self) -> Option<u32> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_DESTCHAIN_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical bridge dest chain"))
    }

    pub fn seed_bridge_dest_chain(&mut self, dest_chain: u32) -> (Key, Vec<u8>) {
        let key = stake_singleton_key(BRIDGE_DESTCHAIN_TAG);
        let bytes = to_bytes(&dest_chain);
        self.write_leaf(key, bytes.clone());
        (key, bytes)
    }

    pub fn bridge_epoch(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(BRIDGE_EPOCH_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical bridge epoch"))
            .unwrap_or(0)
    }

    pub fn set_bridge_epoch(&mut self, epoch: u64) {
        self.write_leaf(stake_singleton_key(BRIDGE_EPOCH_TAG), to_bytes(&epoch));
    }

    pub fn bridge_reference_seen(&self, source_ref: &[u8; 32]) -> bool {
        matches!(self.trie.get(&bridge_seen_key(source_ref)), Some(bytes) if !bytes.is_empty())
    }

    fn mark_bridge_reference(&mut self, source_ref: &[u8; 32]) {
        self.write_leaf(bridge_seen_key(source_ref), vec![1]);
    }

    pub fn bridge_epoch_minted(&self, asset_id: &[u8; 16], epoch: u64) -> u128 {
        self.trie
            .get(&bridge_epochmint_key(asset_id, epoch))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical epoch mint total"))
            .unwrap_or(0)
    }

    fn set_bridge_epoch_minted(&mut self, asset_id: &[u8; 16], epoch: u64, amount: u128) {
        self.write_leaf(bridge_epochmint_key(asset_id, epoch), to_bytes(&amount));
    }

    pub fn bridge_mint(&mut self, fact: &crate::bridge::Fact) -> bool {
        if fact.amount == 0 {
            return false;
        }
        let asset = match self.bridged_asset(&fact.asset_id) {
            Some(asset) => asset,
            None => return false,
        };
        if self.bridge_reference_seen(&fact.source_ref) {
            return false;
        }
        let new_supply = match asset.supply.checked_add(fact.amount) {
            Some(supply) => supply,
            None => return false,
        };
        if new_supply > asset.cap {
            return false;
        }
        let epoch = self.bridge_epoch();
        let minted = self.bridge_epoch_minted(&fact.asset_id, epoch);
        let new_minted = match minted.checked_add(fact.amount) {
            Some(minted) => minted,
            None => return false,
        };
        if new_minted > asset.epoch_cap {
            return false;
        }
        let credited = self
            .bridged_balance(&fact.asset_id, &fact.recipient)
            .saturating_add(fact.amount);
        self.set_bridged_balance(&fact.asset_id, &fact.recipient, credited);
        self.set_bridged_asset(
            &fact.asset_id,
            &QAsset {
                supply: new_supply,
                ..asset
            },
        );
        self.mark_bridge_reference(&fact.source_ref);
        self.set_bridge_epoch_minted(&fact.asset_id, epoch, new_minted);
        self.record_bridge_mint_event(&fact.asset_id, &fact.recipient, fact.amount);
        true
    }

    pub fn bridge_burn(
        &mut self,
        asset_id: &[u8; 16],
        holder: &[u8; 32],
        amount: u128,
        destination: &[u8; 32],
        chain_id: u64,
        sender_nonce: u64,
    ) -> bool {
        if amount == 0 {
            return false;
        }
        let asset = match self.bridged_asset(asset_id) {
            Some(asset) => asset,
            None => return false,
        };
        let balance = self.bridged_balance(asset_id, holder);
        if balance < amount {
            return false;
        }
        let new_supply = match asset.supply.checked_sub(amount) {
            Some(supply) => supply,
            None => return false,
        };
        self.set_bridged_balance(asset_id, holder, balance - amount);
        self.set_bridged_asset(
            asset_id,
            &QAsset {
                supply: new_supply,
                ..asset
            },
        );
        self.record_bridge_burn_event(
            asset_id,
            holder,
            amount,
            destination,
            chain_id,
            sender_nonce,
        );
        true
    }

    pub fn stake_price(&self) -> u128 {
        self.trie
            .get(&stake_singleton_key(STAKE_PRICE_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical price"))
            .unwrap_or(0)
    }

    pub fn set_stake_price(&mut self, rate_micro_usd_per_qtov: u128) {
        self.write_leaf(
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
        self.write_leaf(stake_singleton_key(STAKE_MAINNET_TAG), to_bytes(&day));
    }

    pub fn session_meter(&self) -> SessionMeter {
        self.trie
            .get(&stake_singleton_key(STAKE_METER_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical session meter"))
            .unwrap_or_else(|| SessionMeter::new(0))
    }

    pub fn set_session_meter(&mut self, meter: &SessionMeter) {
        self.write_leaf(stake_singleton_key(STAKE_METER_TAG), to_bytes(meter));
    }

    fn stake_rewards(&self, id: &[u8; 32]) -> RewardBook {
        self.trie
            .get(&stake_rewards_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical reward book"))
            .unwrap_or_default()
    }

    fn set_stake_rewards(&mut self, id: &[u8; 32], book: &RewardBook) {
        self.write_leaf(stake_rewards_key(id), to_bytes(book));
    }

    fn clear_stake_rewards(&mut self, id: &[u8; 32]) {
        self.write_leaf(stake_rewards_key(id), Vec::new());
    }

    pub fn accrue_reward(&mut self, address: &str, now_day: u64) -> u64 {
        match address_id(address) {
            Some(id) => self.accrue_reward_by_id(&id, now_day),
            None => 0,
        }
    }

    fn accrue_reward_by_id(&mut self, id: &[u8; 32], now_day: u64) -> u64 {
        if qtv_staking::in_blackout(now_day, self.stake_mainnet_start()) {
            return 0;
        }
        let stake = match self.stake_bond(id) {
            Some(bond) => bond.amount,
            None => return 0,
        };
        let paid = qtv_staking::session_reward(stake, self.total_staked()).min(self.stake_pool());
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
        if let Some(address) = id_bytes_to_address(id) {
            self.record_reward_event(&address, paid);
        }
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

    pub fn request_exit_with_fee(&mut self, address: &str, fee: u64, now_day: u64) -> bool {
        let id = match address_id(address) {
            Some(id) => id,
            None => return false,
        };
        let ready = matches!(
            self.stake_bond(&id),
            Some(bond) if bond.exit_requested_at.is_none() && bond.can_request_exit(now_day)
        );
        if !ready {
            return false;
        }
        let mut account = self.account(address);
        if account.balance < fee {
            return false;
        }
        account.balance -= fee;
        account.nonce += 1;
        self.set_account(address, &account);
        self.collect_fee(fee);
        self.request_stake_exit(address, now_day)
    }

    pub fn withdraw_with_fee(&mut self, address: &str, fee: u64, now_day: u64) -> bool {
        let id = match address_id(address) {
            Some(id) => id,
            None => return false,
        };
        let ready = matches!(self.stake_bond(&id), Some(bond) if bond.can_withdraw(now_day));
        if !ready {
            return false;
        }
        let mut account = self.account(address);
        if account.balance < fee {
            return false;
        }
        account.balance -= fee;
        account.nonce += 1;
        self.set_account(address, &account);
        self.collect_fee(fee);
        self.withdraw_stake(address, now_day)
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
        self.write_leaf(contract_code_key(id), code.to_vec());
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
        self.write_leaf(contract_store_key(id), encode_storage(storage));
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
        chain_id: u64,
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
        // The node injects its own chain identity at @chain, a fixed context word right after @time. A
        // signed or quorum order folds this word into its message tag, so an order authorised for one
        // chain does not verify on another. The caller can never set it; the host always overwrites it.
        memory[72..80].copy_from_slice(&chain_id.to_be_bytes());
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
        self.write_leaf(key, bytes.clone());
        (key, bytes)
    }

    pub fn settle_session(&mut self, now_day: u64, transactions: u64) {
        if self.stake_mainnet_start() == u64::MAX {
            return;
        }
        // record_session marks the session boundary; a completed session accrues the emergent reward to
        // every validator, pro rata by stake, no longer scaled by the session activity level.
        if self.record_session(transactions, now_day).is_some() {
            for id in self.validator_ids() {
                self.accrue_reward_by_id(&id, now_day);
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
        self.write_leaf(stake_singleton_key(GOV_NEXT_TAG), to_bytes(&id));
    }

    pub fn gov_total_locked(&self) -> u128 {
        self.trie
            .get(&stake_singleton_key(GOV_LOCKED_TAG))
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical locked total"))
            .unwrap_or(0)
    }

    fn set_gov_total_locked(&mut self, amount: u128) {
        self.write_leaf(stake_singleton_key(GOV_LOCKED_TAG), to_bytes(&amount));
    }

    pub fn gov_referendum(&self, id: u64) -> Option<Referendum> {
        self.trie
            .get(&gov_referendum_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical referendum"))
    }

    fn set_gov_referendum(&mut self, id: u64, referendum: &Referendum) {
        self.write_leaf(gov_referendum_key(id), to_bytes(referendum));
    }

    fn gov_action(&self, id: u64) -> Option<Action> {
        self.trie
            .get(&gov_action_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical action"))
    }

    fn set_gov_action(&mut self, id: u64, action: &Action) {
        self.write_leaf(gov_action_key(id), to_bytes(action));
    }

    fn clear_gov_action(&mut self, id: u64) {
        self.write_leaf(gov_action_key(id), Vec::new());
    }

    pub fn gov_receipt(&self, id: u64) -> Option<EnactmentReceipt> {
        self.trie
            .get(&gov_receipt_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical receipt"))
    }

    fn set_gov_receipt(&mut self, id: u64, receipt: &EnactmentReceipt) {
        self.write_leaf(gov_receipt_key(id), to_bytes(receipt));
    }

    pub fn gov_ballot(&self, referendum: u64, voter: &[u8; 32]) -> Option<Ballot> {
        self.trie
            .get(&gov_ballot_key(referendum, voter))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical ballot"))
    }

    fn set_gov_ballot(&mut self, referendum: u64, voter: &[u8; 32], ballot: &Ballot) {
        self.write_leaf(gov_ballot_key(referendum, voter), to_bytes(ballot));
    }

    pub fn gov_lock(&self, voter: &[u8; 32]) -> Option<Lock> {
        self.trie
            .get(&gov_lock_key(voter))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical lock"))
    }

    fn set_gov_lock(&mut self, voter: &[u8; 32], lock: &Lock) {
        self.write_leaf(gov_lock_key(voter), to_bytes(lock));
    }

    fn clear_gov_lock(&mut self, voter: &[u8; 32]) {
        self.write_leaf(gov_lock_key(voter), Vec::new());
    }

    fn is_protected_account(&self, addr: &[u8]) -> bool {
        let id = match id_from_slice(addr) {
            Some(id) => id,
            None => return false,
        };
        if self.stake_bond(&id).is_some() || self.gov_lock(&id).is_some() {
            return true;
        }
        is_reserved_pot(&id)
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
        referendum.tally.record(aye, stake);
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
                self.record_mint_event(&addr, *amount);
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
            Action::Unfreeze { targets } => {
                for target in targets {
                    if let Some(id) = id_from_slice(target) {
                        self.clear_frozen(&id);
                    }
                }
                Ok(())
            }
            Action::BridgeMigration { vault } => {
                if !self.bridge_is_frozen() {
                    return Err(EnactError::BridgeNotFrozen);
                }
                let vault_id = id_from_slice(vault).ok_or(EnactError::BadAddress)?;
                self.set_bridge_pool_vault(&vault_id);
                Ok(())
            }
            Action::Upgrade { .. } => Err(EnactError::NotImplemented),
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
            b"bridge_gateway" => {
                let gateway = id_from_slice(value).ok_or(EnactError::BadValue)?;
                self.set_bridge_gateway(&gateway);
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
        self.record_bond_event(address, amount, fee);
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
        if taken > 0 {
            self.record_slash_event(address, taken);
        }
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
        self.record_unbond_event(address, bond.amount);
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
        // Store the injected caller word at scalar slot zero. Key pointer 1024 points into the zero
        // region of memory, whose 32 zero bytes are the canonical key of scalar slot zero.
        let code = qtv_vm::asm::assemble("LDI r1, 0\nMLOAD r0, r1\nLDI r2, 1024\nSSTORE r2, r0\nHALT")
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
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );

        let mut l = Ledger::new();
        let contract = qtv_idfmt::render_address(&[70u8; 32]).unwrap();
        let contract_id = [70u8; 32];
        l.set_contract_code(&contract_id, &container.canonical_bytes());

        let caller = qtv_idfmt::render_address(&[9u8; 32]).unwrap();
        assert!(l.call_contract(&caller, &contract, selector, &[], 0, 100_000, 0, 0));
        let expected = u64::from_be_bytes([9u8; 8]);
        assert_eq!(
            l.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(0)),
            Some(&expected)
        );

        let empty = qtv_idfmt::render_address(&[71u8; 32]).unwrap();
        assert!(!l.call_contract(&caller, &empty, selector, &[], 0, 100_000, 0, 0));
    }

    #[test]
    fn a_contract_sees_the_whole_caller_address_not_a_leading_word() {
        // Store the caller's trailing word at scalar slot zero and the contract's leading word at
        // scalar slot one. Key pointer 1024 is scalar_key(0), the 32 zero bytes of the zero region;
        // pointer 1088 becomes scalar_key(1) once a one is written into its low word at 1112. Both are
        // declared slots the manifest authorises.
        let code = qtv_vm::asm::assemble(
            "LDI r1, 24\nMLOAD r0, r1\nLDI r2, 1024\nSSTORE r2, r0\n\
             LDI r3, 32\nMLOAD r4, r3\nLDI r6, 1112\nLDI r7, 1\nMSTORE r6, r7\n\
             LDI r5, 1088\nSSTORE r5, r4\nHALT",
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
                    keyed_reads: vec![],
                    keyed_writes: vec![],
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

        assert!(l.call_contract(&c1, &contract, selector, &[], 0, 100_000, 0, 0));
        let seen1 = *l.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(0)).unwrap();
        assert_eq!(
            l.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(1)),
            Some(&u64::from_be_bytes([70u8; 8]))
        );

        assert!(l.call_contract(&c2, &contract, selector, &[], 0, 100_000, 0, 0));
        let seen2 = *l.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(0)).unwrap();

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
    fn a_deposit_returns_when_the_bar_is_met_and_a_missed_deposit_is_forfeit() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        let proposer = gov_addr(20);
        fund(&mut l, &proposer, 2_250_000 * 1_000_000);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action, 0)
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(l.balance(&proposer), 0);

        let voter = gov_addr(21);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        assert!(l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0));
        assert_eq!(l.balance(&voter), 5_000 * 1_000_000);
        assert_eq!(l.gov_total_locked(), 5_000 * 1_000_000);
        assert!(!l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 100, 0));

        let close = 14 * 86_400 + 1;
        assert_eq!(l.gov_conclude(id, close), Some(qtv_governance::Status::Approved));
        assert_eq!(l.balance(&proposer), 2_250_000 * 1_000_000);

        let spam_action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 1u128.to_le_bytes().to_vec(),
        };
        let spam = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, spam_action, 0)
            .unwrap();
        assert_eq!(l.gov_conclude(spam, close), Some(qtv_governance::Status::Rejected));
        assert_eq!(l.balance(&proposer), 0);
        assert_eq!(l.stake_treasury(), 2_250_000 * 1_000_000);
    }

    #[test]
    fn governance_enacts_a_parameter_change_that_sets_the_reward_price() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        let proposer = gov_addr(22);
        fund(&mut l, &proposer, 2_250_000 * 1_000_000);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action, 0)
            .unwrap();
        let voter = gov_addr(23);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);

        assert_eq!(l.stake_price(), 0);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        l.gov_enact(id, 14 * 86_400 + 1).unwrap();
        assert_eq!(l.stake_price(), 70_000_000);
        assert!(l.gov_enact(id, 14 * 86_400 + 1).is_err());
        let receipt = l.gov_receipt(id).unwrap();
        assert_eq!(receipt.referendum, id);
        assert_eq!(
            receipt.proposal_hash,
            sha3::sha3_256(&qtv_codec::to_bytes(&action))
        );
        assert_eq!(receipt.enacted_at, 14 * 86_400 + 1);
        assert!(receipt.tally.aye_stake > 0);
    }

    #[test]
    fn a_non_enactable_action_and_a_mis_routed_parameter_cannot_be_proposed() {
        let mut l = Ledger::new();
        let proposer = gov_addr(30);
        fund(&mut l, &proposer, 3_000_000 * 1_000_000);
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
                qtv_governance::Track::Mint,
                qtv_governance::Action::Parameter {
                    key: b"price".to_vec(),
                    value: 70_000_000u128.to_le_bytes().to_vec(),
                },
                0,
            )
            .is_none());
        assert!(qtv_governance::Track::from_code(6).is_none());
        assert!(qtv_governance::Track::from_code(7).is_none());
        assert_eq!(l.balance(&proposer), 3_000_000 * 1_000_000);
    }

    #[test]
    fn a_parameter_change_is_only_enactable_through_the_chain_upgrade_track() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        let proposer = gov_addr(31);
        fund(&mut l, &proposer, 2_250_000 * 1_000_000);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action, 0)
            .unwrap();
        let voter = gov_addr(32);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(id, 14 * 86_400 + 1).unwrap();
        assert_eq!(l.stake_price(), 70_000_000);
    }

    #[test]
    fn every_track_deposit_matches_the_published_transparency_figure() {
        let page: [(qtv_governance::Track, u64); 5] = [
            (qtv_governance::Track::ChainUpgrade, 2_250_000),
            (qtv_governance::Track::Mint, 4_000_000),
            (qtv_governance::Track::BridgeMigration, 1_500_000),
            (qtv_governance::Track::FreezeRecovery, 292_500),
            (qtv_governance::Track::BlacklistKill, 390_000),
        ];
        for (track, whole_qtov) in page {
            assert_eq!(track.deposit(), whole_qtov * qtv_governance::NATIVE_UNIT);
        }
        assert_eq!(
            qtv_governance::BRIDGE_FREEZE_BOND,
            1_500_000 * qtv_governance::NATIVE_UNIT
        );
    }

    #[test]
    fn governance_freezes_a_named_account_and_shields_protected_stake_from_a_freeze() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        let proposer = gov_addr(40);
        fund(&mut l, &proposer, 400_000 * 1_000_000);
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
        fund(&mut l, &proposer, 4_000_000 * 1_000_000);
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
    fn a_lone_voter_no_longer_passes_a_proposal_a_real_turnout_would_carry() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 1_000_000 * 1_000_000);
        assert_eq!(l.total_staked(), 1_000_000 * 1_000_000);

        let action = || qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let proposer = gov_addr(80);
        fund(&mut l, &proposer, 5_000_000 * 1_000_000);
        let close = 14 * 86_400 + 1;

        let lone = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action(), 0)
            .unwrap();
        let solo = gov_addr(81);
        fund(&mut l, &solo, 10_000 * 1_000_000);
        assert!(l.gov_vote(&solo, lone, true, qtv_governance::Conviction::Liquid, 2_000 * 1_000_000, 0));
        let electorate = l.total_staked() as u128;
        assert!(!l.gov_referendum(lone).unwrap().tally.approved(electorate));
        assert_eq!(l.gov_conclude(lone, close), Some(qtv_governance::Status::Rejected));

        let real = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action(), 0)
            .unwrap();
        let backer = gov_addr(82);
        fund(&mut l, &backer, 600_000 * 1_000_000);
        assert!(l.gov_vote(&backer, real, true, qtv_governance::Conviction::Liquid, 500_000 * 1_000_000, 0));
        assert_eq!(l.gov_conclude(real, close), Some(qtv_governance::Status::Approved));
    }

    #[test]
    fn a_guardian_caucus_freezes_ahead_of_a_vote_and_a_vote_reverses_it() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[201u8; 32], [202u8; 32], [203u8; 32]],
            2,
        ));

        let target_id = [60u8; 32];
        let target = qtv_idfmt::render_address(&target_id).unwrap();

        assert!(!l.guardian_freeze(&[target_id], &[[201u8; 32]]));
        assert!(!l.is_frozen(&target));

        assert!(l.guardian_freeze(&[target_id], &[[201u8; 32], [202u8; 32]]));
        assert!(l.is_frozen(&target));

        let treasury_id = sha3::sha3_256(STAKE_TREASURY_TAG);
        assert!(!l.guardian_freeze(&[treasury_id], &[[201u8; 32], [202u8; 32]]));
        assert!(!l.is_frozen(&stake_treasury_address()));

        let proposer = gov_addr(61);
        fund(&mut l, &proposer, 400_000 * 1_000_000);
        let voter = gov_addr(62);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        let id = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BlacklistKill,
                qtv_governance::Action::Unfreeze { targets: vec![target_id.to_vec()] },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(id, 2 * 86_400 + 1).unwrap();
        assert!(!l.is_frozen(&target), "the full vote reversed the emergency freeze");
    }

    #[test]
    fn a_passed_vote_pays_out_of_the_keyless_pots_and_nothing_else_can() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        let proposer = gov_addr(50);
        fund(&mut l, &proposer, 4_000_000 * 1_000_000);
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
        fund(&mut l, &proposer, 300_000 * 1_000_000);
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
        fund(&mut l, &proposer, 2_250_000 * 1_000_000);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action, 0)
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
    fn rewards_accrue_vest_and_claim_only_after_the_blackout() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[12u8; 32]).unwrap();
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);

        // Nothing pays before mainnet starts; the whole first year is a blackout.
        assert_eq!(l.accrue_reward(&addr, 400), 0);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);

        l.set_stake_mainnet_start(0);
        // A sole staker past the blackout earns the whole emergent session emission, no rate needed.
        let emission = qtv_staking::SESSION_EMISSION;
        assert_eq!(l.accrue_reward(&addr, 400), emission);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000 - emission);

        // The reward is locked for twelve months, then fully claimable in one go.
        assert_eq!(l.claimable_reward(&addr, 400 + 364), 0);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), emission);
        assert_eq!(l.claim_reward(&addr, 400 + 365), emission);
        assert_eq!(l.balance(&addr), emission);
        assert_eq!(l.claim_reward(&addr, 400 + 365), 0);
        assert_eq!(l.claimable_reward(&addr, 400 + 365 + 1_000), 0);
    }

    #[test]
    fn an_attributable_slash_wipes_accrued_rewards_and_a_banned_validator_cannot_claim() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[16u8; 32]).unwrap();
        let id = [16u8; 32];
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        l.set_stake_mainnet_start(0);
        let emission = qtv_staking::SESSION_EMISSION;
        assert_eq!(l.accrue_reward(&addr, 400), emission);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), emission);
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
        l.accrue_reward(&addr, 400);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), qtv_staking::SESSION_EMISSION);
        l.set_gov_blacklisted(&id);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), 0);
        assert_eq!(l.claim_reward(&addr, 400 + 365), 0);
        assert_eq!(l.balance(&addr), 0);
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
        // Past the blackout the sole validator accrues the whole emergent session emission, which is
        // then fully claimable twelve months later.
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000 - qtv_staking::SESSION_EMISSION);
        assert_eq!(l.claimable_reward(&v, 546 + 365), qtv_staking::SESSION_EMISSION);
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
    fn exit_and_withdraw_run_through_the_fee_charging_wrappers() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[18u8; 32]).unwrap();
        let id = [18u8; 32];
        l.set_account(&addr, &Account::funded(5_000 * 1_000_000, 1, vec![]));
        assert!(l.bond(&addr, 2_000 * 1_000_000, 0));
        assert_eq!(l.total_staked(), 2_000 * 1_000_000);

        assert!(!l.request_exit_with_fee(&addr, 1_000_000, 89));
        assert_eq!(l.balance(&addr), 3_000 * 1_000_000, "a refused exit charges no fee");
        assert_eq!(l.account(&addr).nonce, 0);

        assert!(l.request_exit_with_fee(&addr, 1_000_000, 90));
        assert_eq!(l.balance(&addr), 3_000 * 1_000_000 - 1_000_000);
        assert_eq!(l.account(&addr).nonce, 1);

        assert!(!l.withdraw_with_fee(&addr, 1_000_000, 90 + 20));
        assert!(l.withdraw_with_fee(&addr, 1_000_000, 90 + 21));
        assert_eq!(
            l.balance(&addr),
            3_000 * 1_000_000 - 2_000_000 + 2_000 * 1_000_000
        );
        assert_eq!(l.account(&addr).nonce, 2);
        assert!(l.stake_bond(&id).is_none());
        assert_eq!(l.total_staked(), 0);
    }

    #[test]
    fn the_stake_system_address_is_fixed_and_reserved() {
        let a = stake_system_address();
        assert!(a.starts_with("Q1"));
        assert_eq!(stake_system_address(), a);
        assert!(qtv_idfmt::parse_address(&a).is_ok());
    }

    #[test]
    fn a_bridge_freeze_is_instant_and_the_deposit_returns_on_unfreeze() {
        let mut l = Ledger::new();
        let freezer = gov_addr(70);
        let bond = qtv_governance::BRIDGE_FREEZE_BOND;
        fund(&mut l, &freezer, 2_000_000 * 1_000_000);
        assert!(!l.bridge_is_frozen());

        assert!(l.bridge_freeze_with_fee(&freezer, 0, 100));
        assert!(
            l.bridge_is_frozen(),
            "the freeze halts the bridge in the block it lands"
        );
        assert_eq!(l.balance(&freezer), 500_000 * 1_000_000, "the bond leaves the caller");
        assert_eq!(l.balance(&bridge_bond_address()), bond, "the bond rests in the keyless pot");
        let record = l.bridge_freeze().unwrap();
        assert_eq!(record.who, [70u8; 32]);
        assert_eq!(record.bond, bond);
        assert_eq!(record.until, 100 + qtv_governance::BRIDGE_FREEZE_DURATION);

        let rival = gov_addr(71);
        fund(&mut l, &rival, 200_000 * 1_000_000);
        assert!(
            !l.bridge_freeze_with_fee(&rival, 0, 100),
            "only one freeze is active at a time"
        );

        assert!(l.bridge_unfreeze_with_fee(&freezer, 0, 200));
        assert!(!l.bridge_is_frozen());
        assert_eq!(
            l.balance(&freezer),
            2_000_000 * 1_000_000,
            "the full bond returns to the depositor and is never slashed"
        );
        assert_eq!(l.balance(&bridge_bond_address()), 0);
        assert_eq!(l.bridge_last_lift(), Some(200));
    }

    #[test]
    fn an_expired_bridge_freeze_returns_the_full_bond_and_is_never_slashed() {
        let mut l = Ledger::new();
        let freezer = gov_addr(72);
        fund(&mut l, &freezer, 1_500_000 * 1_000_000);
        assert!(l.bridge_freeze_with_fee(&freezer, 0, 1_000));
        let until = 1_000 + qtv_governance::BRIDGE_FREEZE_DURATION;

        l.bridge_expire(until - 1);
        assert!(l.bridge_is_frozen(), "the freeze holds until its horizon");

        l.bridge_expire(until);
        assert!(!l.bridge_is_frozen(), "the freeze lifts itself at the horizon");
        assert_eq!(
            l.balance(&freezer),
            1_500_000 * 1_000_000,
            "auto expiry returns the whole bond"
        );
        assert_eq!(l.balance(&bridge_bond_address()), 0);
        assert_eq!(l.bridge_last_lift(), Some(until));
    }

    #[test]
    fn a_bridge_freeze_cooldown_blocks_an_immediate_refreeze() {
        let mut l = Ledger::new();
        let freezer = gov_addr(73);
        fund(&mut l, &freezer, 1_500_000 * 1_000_000);
        assert!(l.bridge_freeze_with_fee(&freezer, 0, 1_000));
        assert!(l.bridge_unfreeze_with_fee(&freezer, 0, 2_000));
        assert_eq!(l.bridge_last_lift(), Some(2_000));

        let cooldown = qtv_governance::BRIDGE_FREEZE_COOLDOWN;
        assert!(
            !l.bridge_freeze_with_fee(&freezer, 0, 2_000 + cooldown - 1),
            "a refreeze inside the cooldown window is refused"
        );
        assert!(!l.bridge_is_frozen());
        assert!(
            l.bridge_freeze_with_fee(&freezer, 0, 2_000 + cooldown),
            "once the cooldown elapses a fresh freeze lands"
        );
        assert!(l.bridge_is_frozen());
    }

    #[test]
    fn a_blacklisted_caller_cannot_freeze_the_bridge() {
        let mut l = Ledger::new();
        let abuser = gov_addr(74);
        fund(&mut l, &abuser, 200_000 * 1_000_000);
        l.set_gov_blacklisted(&[74u8; 32]);
        assert!(!l.bridge_freeze_with_fee(&abuser, 0, 100));
        assert!(!l.bridge_is_frozen());
    }

    #[test]
    fn a_guardian_caucus_lifts_the_bridge_freeze_and_returns_the_bond() {
        let mut l = Ledger::new();
        let freezer = gov_addr(75);
        fund(&mut l, &freezer, 1_500_000 * 1_000_000);
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            2,
        ));
        assert!(l.bridge_freeze_with_fee(&freezer, 0, 500));

        assert!(
            !l.guardian_bridge_unfreeze(&[[1u8; 32]], 600),
            "one guardian is not a caucus"
        );
        assert!(l.bridge_is_frozen());

        assert!(l.guardian_bridge_unfreeze(&[[1u8; 32], [2u8; 32]], 600));
        assert!(!l.bridge_is_frozen());
        assert_eq!(
            l.balance(&freezer),
            1_500_000 * 1_000_000,
            "governance lifting the freeze returns the bond to the original depositor"
        );
        assert_eq!(l.bridge_last_lift(), Some(600));
    }

    #[test]
    fn a_bridge_migration_needs_a_frozen_bridge_and_records_the_new_vault() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 10_000 * 1_000_000);
        let proposer = gov_addr(80);
        fund(&mut l, &proposer, 1_500_000 * 1_000_000);
        let voter = gov_addr(81);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        let vault = vec![0x0Cu8; 32];

        let open = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::BridgeMigration { vault: vault.clone() },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, open, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(open, 5 * 86_400 + 1),
            Err(EnactError::BridgeNotFrozen),
            "a migration is rejected while the bridge is open"
        );
        assert!(l.bridge_pool_vault().is_none());

        let freezer = gov_addr(82);
        fund(&mut l, &freezer, 1_500_000 * 1_000_000);
        assert!(l.bridge_freeze_with_fee(&freezer, 0, 0));

        let migrate = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::BridgeMigration { vault: vault.clone() },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, migrate, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(migrate, 5 * 86_400 + 1).unwrap();
        assert_eq!(
            l.bridge_pool_vault(),
            Some([0x0Cu8; 32]),
            "the migration records the designated pool vault"
        );
        assert!(l.bridge_is_frozen(), "the freeze still holds through the migration");
    }

    #[test]
    fn a_registered_gateway_is_recognised_and_a_parameter_sets_it() {
        let mut l = Ledger::new();
        let gateway = qtv_idfmt::render_address(&[0x0Du8; 32]).unwrap();
        assert!(!l.is_bridge_gateway(&gateway));
        l.apply_parameter(b"bridge_gateway", &[0x0Du8; 32]).unwrap();
        assert_eq!(l.bridge_gateway(), Some([0x0Du8; 32]));
        assert!(l.is_bridge_gateway(&gateway));
        assert!(!l.is_bridge_gateway(&gov_addr(90)));
    }

    #[test]
    fn a_bond_records_a_native_bond_event() {
        let mut l = Ledger::new();
        let addr = gov_addr(60);
        fund(&mut l, &addr, 10_000 * 1_000_000);
        assert!(l.bond_with_fee(&addr, 2_000 * 1_000_000, 500, 0));
        let events = l.block_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].contract, NATIVE_EVENT_SOURCE);
        assert_eq!(events[0].selector, EVENT_BOND);
        let mut decoder = Decoder::new(&events[0].data);
        assert_eq!(decoder.get_bytes().unwrap(), addr.as_bytes());
        assert_eq!(decoder.get_u64().unwrap(), 2_000 * 1_000_000);
        assert_eq!(decoder.get_u64().unwrap(), 500);
    }

    #[test]
    fn an_unbond_records_a_native_unbond_event() {
        let mut l = Ledger::new();
        let addr = gov_addr(61);
        fund(&mut l, &addr, 10_000 * 1_000_000);
        assert!(l.bond_with_fee(&addr, 2_000 * 1_000_000, 0, 0));
        l.clear_block_events();
        assert!(l.request_stake_exit(&addr, qtv_staking::BOND_LOCK_DAYS));
        assert!(l.withdraw_stake(&addr, qtv_staking::EARLIEST_EXIT_DAYS));
        let events = l.block_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].selector, EVENT_UNBOND);
        let mut decoder = Decoder::new(&events[0].data);
        assert_eq!(decoder.get_bytes().unwrap(), addr.as_bytes());
        assert_eq!(decoder.get_u64().unwrap(), 2_000 * 1_000_000);
    }

    #[test]
    fn a_slash_records_a_native_slash_event() {
        let mut l = Ledger::new();
        let addr = gov_addr(62);
        fund(&mut l, &addr, 10_000 * 1_000_000);
        assert!(l.bond_with_fee(&addr, 2_000 * 1_000_000, 0, 0));
        l.clear_block_events();
        assert!(l.slash_validator(&addr));
        let events = l.block_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].selector, EVENT_SLASH);
        let mut decoder = Decoder::new(&events[0].data);
        assert_eq!(decoder.get_bytes().unwrap(), addr.as_bytes());
        assert_eq!(decoder.get_u64().unwrap(), 2_000 * 1_000_000);
    }

    #[test]
    fn a_mint_records_a_native_mint_event() {
        let mut l = Ledger::new();
        let target = gov_addr(63);
        l.execute_action(&Action::Mint {
            to: [63u8; 32].to_vec(),
            amount: 5_000,
        })
        .unwrap();
        let events = l.block_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].selector, EVENT_MINT);
        let mut decoder = Decoder::new(&events[0].data);
        assert_eq!(decoder.get_bytes().unwrap(), target.as_bytes());
        assert_eq!(decoder.get_u64().unwrap(), 5_000);
    }

    #[test]
    fn a_reward_accrual_records_a_native_reward_event() {
        let mut l = Ledger::new();
        let addr = gov_addr(64);
        fund(&mut l, &addr, 10_000 * 1_000_000);
        assert!(l.bond_with_fee(&addr, 2_000 * 1_000_000, 0, 0));
        l.set_stake_mainnet_start(0);
        l.set_stake_price(1);
        l.set_stake_pool(1_000_000 * 1_000_000);
        l.clear_block_events();
        let paid = l.accrue_reward(&addr, 400);
        assert!(paid > 0);
        let events = l.block_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].selector, EVENT_REWARD);
        let mut decoder = Decoder::new(&events[0].data);
        assert_eq!(decoder.get_bytes().unwrap(), addr.as_bytes());
        assert_eq!(decoder.get_u64().unwrap(), paid);
    }

    #[test]
    fn apply_atomic_rolls_back_every_write_and_event_when_a_transition_faults() {
        let mut l = Ledger::new();
        let addr = gov_addr(70);
        fund(&mut l, &addr, 1_000);
        let root_before = l.state_root();

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let applied = l.apply_atomic(|l| {
            let mut account = l.account(&addr);
            account.balance = 42;
            l.set_account(&addr, &account);
            l.record_transfer_event(&addr, &addr, 1, 0);
            panic!("a fault partway through the transition");
        });
        std::panic::set_hook(previous);

        assert!(!applied, "a faulted transition does not apply");
        assert_eq!(l.balance(&addr), 1_000, "the balance is exactly as it began");
        assert_eq!(l.state_root(), root_before, "the state root is unmoved");
        assert!(l.block_events().is_empty(), "the faulted transition left no event");
    }

    #[test]
    fn apply_atomic_keeps_the_writes_of_a_transition_that_completes() {
        let mut l = Ledger::new();
        let addr = gov_addr(71);
        fund(&mut l, &addr, 1_000);
        let applied = l.apply_atomic(|l| {
            let mut account = l.account(&addr);
            account.balance = 42;
            l.set_account(&addr, &account);
            l.record_transfer_event(&addr, &addr, 5, 0);
            true
        });
        assert!(applied, "a completed transition applies");
        assert_eq!(l.balance(&addr), 42, "the write stands");
        assert_eq!(l.block_events().len(), 1, "the event stands");
    }

    type BurnLeaf = ([u8; 16], [u8; 32], u128, [u8; 32], u64, u64, u64, [u8; 32]);

    fn decode_burn_leaf(data: &[u8]) -> BurnLeaf {
        let mut d = Decoder::new(data);
        let asset = <[u8; 16]>::try_from(d.get_bytes().unwrap()).unwrap();
        let holder = <[u8; 32]>::try_from(d.get_bytes().unwrap()).unwrap();
        let amount = d.get_u128().unwrap();
        let destination = <[u8; 32]>::try_from(d.get_bytes().unwrap()).unwrap();
        let chain_id = d.get_u64().unwrap();
        let sender_nonce = d.get_u64().unwrap();
        let event_index = d.get_u64().unwrap();
        let burn_ref = <[u8; 32]>::try_from(d.get_bytes().unwrap()).unwrap();
        d.finish().unwrap();
        (asset, holder, amount, destination, chain_id, sender_nonce, event_index, burn_ref)
    }

    fn seed_burnable(l: &mut Ledger, asset: &[u8; 16], holder: &[u8; 32], supply: u128) {
        l.set_bridged_asset(
            asset,
            &QAsset { supply, cap: supply, epoch_cap: supply, requires_stark: false },
        );
        l.set_bridged_balance(asset, holder, supply);
    }

    #[test]
    fn two_identical_burns_get_distinct_recomputable_refs() {
        let mut l = Ledger::new();
        let asset = [7u8; 16];
        let holder = [9u8; 32];
        let destination = [0xEE; 32];
        let chain_id = 42u64;
        seed_burnable(&mut l, &asset, &holder, 1_000_000);

        assert!(l.bridge_burn(&asset, &holder, 100_000, &destination, chain_id, 0));
        assert!(l.bridge_burn(&asset, &holder, 100_000, &destination, chain_id, 0));
        let first = decode_burn_leaf(&l.block_events()[0].data);
        let second = decode_burn_leaf(&l.block_events()[1].data);

        assert_eq!(first.6, 0, "the first burn sits at event index zero");
        assert_eq!(second.6, 1, "the second burn sits at the next event index");
        assert_ne!(first.7, second.7, "two identical burns in one block get distinct refs");
        assert_eq!(
            first.7,
            bridge_burn_ref(first.4, &first.0, &first.1, first.2, &first.3, first.5, first.6),
            "the first ref recomputes from its leaf fields"
        );
        assert_eq!(
            second.7,
            bridge_burn_ref(second.4, &second.0, &second.1, second.2, &second.3, second.5, second.6),
            "the second ref recomputes from its leaf fields"
        );

        l.clear_block_events();
        assert!(l.bridge_burn(&asset, &holder, 100_000, &destination, chain_id, 1));
        let third = decode_burn_leaf(&l.block_events()[0].data);
        assert_eq!(third.6, 0, "a fresh block restarts the event index");
        assert_ne!(third.7, first.7, "an identical burn in a later block differs by the sender nonce");
        assert_eq!(
            third.7,
            bridge_burn_ref(third.4, &third.0, &third.1, third.2, &third.3, third.5, third.6),
            "the later ref recomputes from its leaf fields"
        );
    }
}

/// The source marker a native economic event carries in the block event log. Contract
/// effects carry their contract address in this field, so a native transition carries this
/// reserved marker instead and an indexer separates the native economy from contract
/// effects by it, then reads the kind from the selector. Native events record into the same
/// log the contract effects use, so the header event root covers the native economy with no
/// change to the event root function.
pub const NATIVE_EVENT_SOURCE: &str = "qtv/native";

/// A plain value send that moved an amount and paid a fee.
pub const EVENT_TRANSFER: [u8; 4] = *b"QXFR";
/// A stake bond that locked an amount into a validator bond.
pub const EVENT_BOND: [u8; 4] = *b"QBND";
/// A stake unbond that returned a withdrawn bond to a spendable balance.
pub const EVENT_UNBOND: [u8; 4] = *b"QUBD";
/// A slash that removed an amount from a validator bond.
pub const EVENT_SLASH: [u8; 4] = *b"QSLH";
/// A mint that raised the supply and credited a target.
pub const EVENT_MINT: [u8; 4] = *b"QMNT";
/// A staking reward the pool paid out to a validator.
pub const EVENT_REWARD: [u8; 4] = *b"QRWD";
pub const EVENT_BRIDGE_MINT: [u8; 4] = *b"QBMT";
pub const EVENT_BRIDGE_BURN: [u8; 4] = *b"QBBN";

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

    /// A native economic event, shaped exactly like a contract effect event so the existing
    /// event root function covers it unchanged. The reserved native source stands in for the
    /// contract address, the kind selector names the transition, and the data holds the
    /// parties and amount.
    pub fn native(kind: [u8; 4], data: Vec<u8>) -> Self {
        BlockEvent {
            contract: NATIVE_EVENT_SOURCE.to_string(),
            selector: kind,
            data,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ledger {
    trie: Trie,
    block_events: Vec<BlockEvent>,
    round_proposer: Option<String>,
    // An undo log of prior leaf images, present only while a transition applies under
    // apply_atomic. Every leaf write records its prior value here so a fault partway through
    // a transition rolls the leaves back to the pre transition image. It is an internal
    // mechanism only and never enters the state root, the block encoding, or the wire.
    journal: Option<Vec<(Key, Option<Vec<u8>>)>>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger {
            trie: Trie::new(),
            block_events: Vec::new(),
            round_proposer: None,
            journal: None,
        }
    }

    pub fn from_trie(mut trie: Trie) -> Self {
        trie.clear_persist_dirty();
        Ledger {
            trie,
            block_events: Vec::new(),
            round_proposer: None,
            journal: None,
        }
    }

    /// Write a leaf, recording its prior image in the undo log when a transition is applying
    /// under apply_atomic. Every leaf mutation in the native path funnels through here so a
    /// faulted transition can be rolled back to exactly the state it began in.
    fn write_leaf(&mut self, key: Key, value: Vec<u8>) {
        if self.journal.is_some() {
            let prior = self.trie.get(&key).map(|bytes| bytes.to_vec());
            self.journal.as_mut().expect("the journal is present").push((key, prior));
        }
        let trie = &mut self.trie;
        trie.insert(key, value);
    }

    /// Erase a leaf, recording its prior image in the undo log when a transition is applying
    /// under apply_atomic. Returns whether a leaf was present, matching the trie.
    fn erase_leaf(&mut self, key: &Key) -> bool {
        if self.journal.is_some() {
            let prior = self.trie.get(key).map(|bytes| bytes.to_vec());
            self.journal.as_mut().expect("the journal is present").push((*key, prior));
        }
        let trie = &mut self.trie;
        trie.remove(key)
    }

    /// Apply a native transition as an all or nothing unit. A panic partway through leaves no
    /// partial write: the undo log restores every touched leaf to its pre transition image and
    /// any events the transition recorded are dropped, matching the atomic rollback the VM
    /// path already has for a faulted call. A clean rejection returns false with no writes,
    /// exactly as the hand ordered check before write path already intends. This is an
    /// internal firewall only and moves neither the state root nor the block encoding.
    pub(crate) fn apply_atomic<F>(&mut self, f: F) -> bool
    where
        F: FnOnce(&mut Ledger) -> bool,
    {
        let events_mark = self.block_events.len();
        let restore = self.journal.take();
        self.journal = Some(Vec::new());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
        let unwound = self.journal.take().unwrap_or_default();
        self.journal = restore;
        let committed = matches!(outcome, Ok(true));
        if !committed {
            let trie = &mut self.trie;
            for (key, prior) in unwound.into_iter().rev() {
                match prior {
                    Some(bytes) => trie.insert(key, bytes),
                    None => {
                        trie.remove(&key);
                    }
                }
            }
            self.block_events.truncate(events_mark);
        }
        committed
    }

    pub fn clear_block_events(&mut self) {
        self.block_events.clear();
    }

    pub fn block_events(&self) -> &[BlockEvent] {
        &self.block_events
    }

    fn record_native_event(&mut self, kind: [u8; 4], data: Vec<u8>) {
        self.block_events.push(BlockEvent::native(kind, data));
    }

    /// Record a plain value send into the block event log. The apply path drives this at the
    /// point a transfer moves an amount, so the header event root follows every native send.
    pub(crate) fn record_transfer_event(&mut self, from: &str, to: &str, amount: u64, fee: u64) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(from.as_bytes());
        encoder.put_bytes(to.as_bytes());
        encoder.put_u64(amount);
        encoder.put_u64(fee);
        self.record_native_event(EVENT_TRANSFER, encoder.into_bytes());
    }

    fn record_bond_event(&mut self, address: &str, amount: u64, fee: u64) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(address.as_bytes());
        encoder.put_u64(amount);
        encoder.put_u64(fee);
        self.record_native_event(EVENT_BOND, encoder.into_bytes());
    }

    fn record_unbond_event(&mut self, address: &str, amount: u64) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(address.as_bytes());
        encoder.put_u64(amount);
        self.record_native_event(EVENT_UNBOND, encoder.into_bytes());
    }

    fn record_slash_event(&mut self, address: &str, amount: u64) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(address.as_bytes());
        encoder.put_u64(amount);
        self.record_native_event(EVENT_SLASH, encoder.into_bytes());
    }

    fn record_mint_event(&mut self, to: &str, amount: u64) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(to.as_bytes());
        encoder.put_u64(amount);
        self.record_native_event(EVENT_MINT, encoder.into_bytes());
    }

    fn record_reward_event(&mut self, address: &str, amount: u64) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(address.as_bytes());
        encoder.put_u64(amount);
        self.record_native_event(EVENT_REWARD, encoder.into_bytes());
    }

    fn record_bridge_mint_event(&mut self, asset_id: &[u8; 16], recipient: &[u8; 32], amount: u128) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(asset_id);
        encoder.put_bytes(recipient);
        encoder.put_u128(amount);
        self.record_native_event(EVENT_BRIDGE_MINT, encoder.into_bytes());
    }

    fn record_bridge_burn_event(
        &mut self,
        asset_id: &[u8; 16],
        holder: &[u8; 32],
        amount: u128,
        destination: &[u8; 32],
        chain_id: u64,
        sender_nonce: u64,
    ) {
        let event_index = self.block_events.len() as u64;
        let burn_ref = bridge_burn_ref(
            chain_id,
            asset_id,
            holder,
            amount,
            destination,
            sender_nonce,
            event_index,
        );
        let mut encoder = Encoder::new();
        encoder.put_bytes(asset_id);
        encoder.put_bytes(holder);
        encoder.put_u128(amount);
        encoder.put_bytes(destination);
        encoder.put_u64(chain_id);
        encoder.put_u64(sender_nonce);
        encoder.put_u64(event_index);
        encoder.put_bytes(&burn_ref);
        self.record_native_event(EVENT_BRIDGE_BURN, encoder.into_bytes());
    }

    pub fn account(&self, address: &str) -> Account {
        match self.trie.get(&state_key(address)) {
            Some(bytes) => from_bytes(bytes).unwrap_or_default(),
            None => Account::default(),
        }
    }

    pub fn set_account(&mut self, address: &str, account: &Account) {
        self.write_leaf(state_key(address), to_bytes(account));
    }

    pub(crate) fn leaves(&self) -> &std::collections::BTreeMap<Key, Vec<u8>> {
        self.trie.leaves()
    }

    pub(crate) fn insert_raw(&mut self, key: Key, bytes: Vec<u8>) {
        self.write_leaf(key, bytes);
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

    /// The number of state bytes an address occupies, its account record plus any contract
    /// code and storage held under it. The rent exempt deposit is proportional to it, so a
    /// larger footprint costs proportionally more to keep permanently.
    pub fn account_footprint(&self, address: &str) -> usize {
        let mut bytes = to_bytes(&self.account(address)).len();
        if let Some(id) = address_id(address) {
            if let Some(code) = self.contract_code(&id) {
                bytes += code.len();
                bytes += encode_storage(&self.contract_storage(&id)).len();
            }
        }
        bytes
    }

    /// The refundable storage deposit an address must hold to be rent exempt. It is
    /// proportional to the address's state footprint. An address holding at least this much
    /// is never rent charged and its deposit stays its own, withdrawable in full.
    pub fn rent_exempt_minimum(&self, address: &str) -> u64 {
        rent_exempt_minimum_for(self.account_footprint(address))
    }

    pub fn is_rent_exempt(&self, address: &str) -> bool {
        self.balance(address) >= self.rent_exempt_minimum(address)
    }

    /// Charge rent to an address that holds less than its rent exempt deposit, proportional
    /// to its footprint and the periods elapsed, never more than its balance. A rent exempt
    /// address is untouched. An address the charge empties is reaped, freeing its slot. The
    /// rent is burned from supply, so a reaped address returns nothing to anyone.
    pub fn charge_rent(&mut self, address: &str, periods: u64) -> u64 {
        let footprint = self.account_footprint(address);
        let mut account = self.account(address);
        if account.balance >= rent_exempt_minimum_for(footprint) {
            return 0;
        }
        let due = (footprint as u64)
            .saturating_mul(RENT_PER_BYTE_PER_PERIOD)
            .saturating_mul(periods);
        let charged = due.min(account.balance);
        if charged == 0 {
            return 0;
        }
        account.balance -= charged;
        self.debit_supply(charged);
        self.set_account(address, &account);
        if account.balance == 0 {
            self.reap(address);
        }
        charged
    }

    /// Reap an empty address, removing its account record and any contract code and storage
    /// from the trie so the slot frees. A funded address and a reserved system pot are never
    /// reaped. Reaping credits no one.
    pub fn reap(&mut self, address: &str) -> bool {
        let account = self.account(address);
        if account.balance != 0 {
            return false;
        }
        if account.nonce != 0 {
            return false;
        }
        if let Some(id) = address_id(address) {
            if is_reserved_pot(&id) {
                return false;
            }
        }
        let mut freed = self.erase_leaf(&state_key(address));
        if let Some(id) = address_id(address) {
            if self.contract_code(&id).is_some() {
                freed |= self.erase_leaf(&contract_code_key(&id));
                freed |= self.erase_leaf(&contract_store_key(&id));
            }
        }
        freed
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
    fn the_registration_address_is_a_distinct_canonical_system_address() {
        let reg = registration_address();
        assert!(
            qtv_idfmt::parse_address(&reg).is_ok(),
            "the registration address is a canonical address"
        );
        assert_ne!(reg, evidence_address(), "it is its own system address");
        assert_eq!(registration_address(), reg, "and it is fixed");
    }

    #[test]
    fn the_rent_exempt_deposit_is_proportional_to_the_state_footprint() {
        let mut ledger = Ledger::new();
        let small = qtv_account::derive(&[7u8; 32], 10);
        let large = qtv_account::derive(&[7u8; 32], 11);
        ledger.set_account(
            &small.address(),
            &Account::funded(0, small.scheme(), small.public_key()[..8].to_vec()),
        );
        ledger.set_account(
            &large.address(),
            &Account::funded(0, large.scheme(), large.public_key().to_vec()),
        );

        let f_small = ledger.account_footprint(&small.address());
        let f_large = ledger.account_footprint(&large.address());
        assert!(f_large > f_small, "the larger record occupies more state");
        assert_eq!(
            ledger.rent_exempt_minimum(&small.address()),
            f_small as u64 * RENT_EXEMPT_PER_BYTE,
            "the deposit is exactly the per byte rate times the footprint"
        );
        assert_eq!(
            ledger.rent_exempt_minimum(&large.address()),
            f_large as u64 * RENT_EXEMPT_PER_BYTE,
        );
        assert!(
            ledger.rent_exempt_minimum(&large.address())
                > ledger.rent_exempt_minimum(&small.address()),
            "adding state costs proportionally more to keep permanently"
        );
    }

    #[test]
    fn a_well_funded_account_is_rent_exempt_and_its_deposit_is_never_taken() {
        let mut ledger = Ledger::new();
        ledger.seed_supply(10_000_000);
        let holder = qtv_account::derive(&[7u8; 32], 12);
        ledger.set_account(
            &holder.address(),
            &Account::funded(5_000_000, holder.scheme(), holder.public_key().to_vec()),
        );
        assert!(ledger.is_rent_exempt(&holder.address()));
        assert_eq!(
            ledger.charge_rent(&holder.address(), 1_000_000),
            0,
            "a rent exempt account is never charged"
        );
        assert_eq!(
            ledger.balance(&holder.address()),
            5_000_000,
            "the refundable deposit stays the holder's in full"
        );
    }

    #[test]
    fn a_reaped_account_frees_its_slot_and_returns_nothing_to_an_attacker() {
        let mut ledger = Ledger::new();
        let supply = 10_000_000u64;
        ledger.seed_supply(supply);
        let victim = qtv_account::derive(&[7u8; 32], 20);
        let victim_account = Account::funded(1_000_000, victim.scheme(), victim.public_key().to_vec());
        ledger.set_account(&victim.address(), &victim_account);
        let grants = grants_address();

        let attacker = qtv_account::derive(&[7u8; 32], 21);
        let dust = 40u64;
        ledger.set_account(
            &attacker.address(),
            &Account::funded(dust, attacker.scheme(), attacker.public_key().to_vec()),
        );
        assert!(
            !ledger.is_rent_exempt(&attacker.address()),
            "the dust account is below its rent exempt deposit"
        );

        let footprint = ledger.account_footprint(&attacker.address());
        let charged = ledger.charge_rent(&attacker.address(), footprint as u64 * dust);
        assert_eq!(charged, dust, "the whole dust balance is charged as rent, never more");

        assert_eq!(ledger.balance(&attacker.address()), 0, "the account is emptied");
        assert_eq!(
            ledger.account(&attacker.address()),
            Account::default(),
            "the reaped account record is gone from state"
        );

        let mut reference = Ledger::new();
        reference.seed_supply(supply - dust);
        reference.set_account(&victim.address(), &victim_account);
        assert_eq!(
            ledger.state_root(),
            reference.state_root(),
            "the reaped slot is freed, the state is identical to one that never held it"
        );

        assert_eq!(ledger.total_supply(), supply - dust, "the dust is burned, not paid out");
        assert_eq!(ledger.balance(&victim.address()), 1_000_000, "no other balance changed");
        assert_eq!(ledger.balance(&grants), 0, "the reap credits no one");
    }

    #[test]
    fn an_account_past_nonce_zero_keeps_its_record_so_a_reap_cannot_reset_its_nonce() {
        let mut ledger = Ledger::new();
        ledger.seed_supply(10_000_000);
        let spender = qtv_account::derive(&[7u8; 32], 30);
        let mut account =
            Account::funded(50, spender.scheme(), spender.public_key().to_vec());
        account.nonce = 3;
        ledger.set_account(&spender.address(), &account);
        assert!(!ledger.is_rent_exempt(&spender.address()));

        let footprint = ledger.account_footprint(&spender.address());
        ledger.charge_rent(&spender.address(), footprint as u64 * 50);
        assert_eq!(ledger.balance(&spender.address()), 0, "the balance is spent to rent");
        assert_eq!(
            ledger.nonce(&spender.address()),
            3,
            "the nonce floor survives, so a recreated account cannot replay a lower nonce"
        );
        assert!(
            ledger.account(&spender.address()).has_key(),
            "the record is kept rather than reaped"
        );
        assert!(
            !ledger.reap(&spender.address()),
            "an emptied account past nonce zero is never reaped"
        );

        let fresh = qtv_account::derive(&[7u8; 32], 31);
        ledger.set_account(
            &fresh.address(),
            &Account::funded(0, fresh.scheme(), fresh.public_key().to_vec()),
        );
        assert!(
            ledger.reap(&fresh.address()),
            "an emptied account still at nonce zero authored nothing to replay and is reaped"
        );
    }

    #[test]
    fn a_fee_split_is_twenty_sixty_twenty_with_dust_to_grants() {
        let split = FeeSplit::of(1_000);
        assert_eq!(split.burn, 200, "a fifth of the fee burns");
        assert_eq!(split.proposer, 600, "three fifths to the validators");
        assert_eq!(split.grants, 200, "a fifth to grants");
        assert_eq!(split.total(), 1_000, "the shares sum to the fee");

        let odd = FeeSplit::of(7);
        assert_eq!(
            (odd.burn, odd.proposer),
            (1, 4),
            "the burn and proposer shares floor"
        );
        assert_eq!(odd.grants, 2, "the rounding dust lands in the grants share");
        assert_eq!(odd.total(), 7, "the split conserves the fee to the unit");
    }

    #[test]
    fn a_fee_burns_twenty_percent_of_the_supply_and_a_mint_raises_it() {
        let mut ledger = Ledger::new();
        ledger.seed_supply(1_000_000);
        assert_eq!(ledger.total_supply(), 1_000_000, "genesis fixes the supply");

        ledger.collect_fee(1_000);
        assert_eq!(
            ledger.total_supply(),
            1_000_000 - 200,
            "a fee burns a fifth and lowers the supply by that much"
        );

        ledger.credit_supply(500);
        assert_eq!(
            ledger.total_supply(),
            1_000_000 - 200 + 500,
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
