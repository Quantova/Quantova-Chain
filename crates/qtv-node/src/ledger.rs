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
const ACCOUNT_UNPARSED_TAG: &[u8] = b"qtv/account-unparsed/";
const _: () = assert!(
    ACCOUNT_TAG.len() <= ACCOUNT_UNPARSED_TAG.len()
        && ACCOUNT_TAG[ACCOUNT_TAG.len() - 1] != ACCOUNT_UNPARSED_TAG[ACCOUNT_TAG.len() - 1],
    "the unparsed account tag must not nest under the parsed account tag"
);

pub(crate) fn state_key(address: &str) -> Key {
    match qtv_idfmt::parse_address(address) {
        Ok(payload) => {
            let mut input = Vec::with_capacity(ACCOUNT_TAG.len() + payload.len());
            input.extend_from_slice(ACCOUNT_TAG);
            input.extend_from_slice(&payload);
            sha3::sha3_256(&input)
        }
        Err(_) => {
            let mut input = Vec::with_capacity(ACCOUNT_UNPARSED_TAG.len() + address.len());
            input.extend_from_slice(ACCOUNT_UNPARSED_TAG);
            input.extend_from_slice(address.as_bytes());
            sha3::sha3_256(&input)
        }
    }
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
        let mut tranches = Vec::new();
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutstandingBurn {
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub beneficiary: [u8; 32],
}

impl Encode for OutstandingBurn {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_bytes(&self.asset_id);
        self.amount.encode(encoder);
        encoder.put_bytes(&self.beneficiary);
    }
}

impl Decode for OutstandingBurn {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let asset_bytes = decoder.get_bytes()?;
        let asset_id = <[u8; 16]>::try_from(asset_bytes).map_err(|_| Error::Truncated {
            needed: 16,
            found: asset_bytes.len(),
        })?;
        let amount = u128::decode(decoder)?;
        let beneficiary_bytes = decoder.get_bytes()?;
        let beneficiary = <[u8; 32]>::try_from(beneficiary_bytes).map_err(|_| Error::Truncated {
            needed: 32,
            found: beneficiary_bytes.len(),
        })?;
        Ok(OutstandingBurn {
            asset_id,
            amount,
            beneficiary,
        })
    }
}

const BRIDGE_ASSET_TAG: &[u8] = b"qtv/bridge/asset/";
const BRIDGE_BALANCE_TAG: &[u8] = b"qtv/bridge/bal/";
const ASSET_BALANCE_TAG: &[u8] = b"qtv/asset/bal/";
const ASSET_SUPPLY_TAG: &[u8] = b"qtv/asset/supply/";
const ASSET_ID_DOMAIN: &[u8] = b"qtv/asset/id/v1";
const ASSET_MINT_SELECTOR: [u8; 4] = *b"MINT";
const BRIDGE_SEEN_TAG: &[u8] = b"qtv/bridge/seen/";
const BRIDGE_EPOCHMINT_TAG: &[u8] = b"qtv/bridge/epochmint/";
const BRIDGE_OPERATORS_TAG: &[u8] = b"qtv/bridge/operators";
const GUARDIAN_ENACT_NONCE_TAG: &[u8] = b"qtv/guardian/enact-nonce";
const BRIDGE_VAULTBAL_TAG: &[u8] = b"qtv/bridge/vaultbal/";
const BRIDGE_ASSET_LIST_TAG: &[u8] = b"qtv/bridge/assetlist";
const BRIDGE_DESTCHAIN_TAG: &[u8] = b"qtv/bridge/destchain";
const BRIDGE_ERA_TAG: &[u8] = b"qtv/bridge/era";
const BRIDGE_BTC_ANCHOR_TAG: &[u8] = b"qtv/bridge/btcanchor";
const BRIDGE_ETH_ANCHOR_TAG: &[u8] = b"qtv/bridge/ethanchor/";
const BRIDGE_COSMOS_ANCHOR_TAG: &[u8] = b"qtv/bridge/cosmosanchor/";
const CHAIN_GENESIS_TIME_TAG: &[u8] = b"qtv/chain/genesistime";
const BRIDGE_EPOCH_TAG: &[u8] = b"qtv/bridge/epoch";
const BRIDGE_BURN_REF_DOMAIN: &[u8] = b"qtv/bridge/burn-ref/v1";
const BRIDGE_EXIT_SEEN_TAG: &[u8] = b"qtv/bridge/exitseen/";
const BRIDGE_OUTSTANDING_TAG: &[u8] = b"qtv/bridge/outstanding/";
const BRIDGE_EPOCHPAY_TAG: &[u8] = b"qtv/bridge/epochpay/";
const BRIDGE_EPOCHPAYG_TAG: &[u8] = b"qtv/bridge/epochpayglobal/";

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

fn asset_balance_key(asset_id: &[u8; 16], holder: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(ASSET_BALANCE_TAG.len() + asset_id.len() + holder.len());
    input.extend_from_slice(ASSET_BALANCE_TAG);
    input.extend_from_slice(asset_id);
    input.extend_from_slice(holder);
    sha3::sha3_256(&input)
}

fn asset_supply_key(asset_id: &[u8; 16]) -> Key {
    let mut input = Vec::with_capacity(ASSET_SUPPLY_TAG.len() + asset_id.len());
    input.extend_from_slice(ASSET_SUPPLY_TAG);
    input.extend_from_slice(asset_id);
    sha3::sha3_256(&input)
}

pub fn asset_id_of(issuer: &[u8; 32]) -> [u8; 16] {
    let mut input = Vec::with_capacity(ASSET_ID_DOMAIN.len() + issuer.len());
    input.extend_from_slice(ASSET_ID_DOMAIN);
    input.extend_from_slice(issuer);
    let digest = sha3::sha3_256(&input);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn bridge_seen_key(source_chain: u32, source_ref: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_SEEN_TAG.len() + 4 + source_ref.len());
    input.extend_from_slice(BRIDGE_SEEN_TAG);
    input.extend_from_slice(&source_chain.to_le_bytes());
    input.extend_from_slice(source_ref);
    sha3::sha3_256(&input)
}

fn feature_gate_key(feature: &[u8]) -> Key {
    let mut input = Vec::with_capacity(GOV_FEATURE_TAG.len() + feature.len());
    input.extend_from_slice(GOV_FEATURE_TAG);
    input.extend_from_slice(feature);
    sha3::sha3_256(&input)
}

fn bridge_vault_custody_key(vault: &[u8; 32], asset_id: &[u8; 16]) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_VAULTBAL_TAG.len() + vault.len() + asset_id.len());
    input.extend_from_slice(BRIDGE_VAULTBAL_TAG);
    input.extend_from_slice(vault);
    input.extend_from_slice(asset_id);
    sha3::sha3_256(&input)
}

fn bridge_eth_anchor_key(selector: u8) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_ETH_ANCHOR_TAG.len() + 1);
    input.extend_from_slice(BRIDGE_ETH_ANCHOR_TAG);
    input.push(selector);
    sha3::sha3_256(&input)
}

fn bridge_cosmos_anchor_key(selector: u8) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_COSMOS_ANCHOR_TAG.len() + 1);
    input.extend_from_slice(BRIDGE_COSMOS_ANCHOR_TAG);
    input.push(selector);
    sha3::sha3_256(&input)
}

fn bridge_epochmint_key(asset_id: &[u8; 16], epoch: u64) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_EPOCHMINT_TAG.len() + asset_id.len() + 8);
    input.extend_from_slice(BRIDGE_EPOCHMINT_TAG);
    input.extend_from_slice(asset_id);
    input.extend_from_slice(&epoch.to_le_bytes());
    sha3::sha3_256(&input)
}

fn bridge_exit_seen_key(burn_ref: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_EXIT_SEEN_TAG.len() + burn_ref.len());
    input.extend_from_slice(BRIDGE_EXIT_SEEN_TAG);
    input.extend_from_slice(burn_ref);
    sha3::sha3_256(&input)
}

fn bridge_outstanding_key(burn_ref: &[u8; 32]) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_OUTSTANDING_TAG.len() + burn_ref.len());
    input.extend_from_slice(BRIDGE_OUTSTANDING_TAG);
    input.extend_from_slice(burn_ref);
    sha3::sha3_256(&input)
}

fn bridge_epochpay_key(asset_id: &[u8; 16], epoch: u64) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_EPOCHPAY_TAG.len() + asset_id.len() + 8);
    input.extend_from_slice(BRIDGE_EPOCHPAY_TAG);
    input.extend_from_slice(asset_id);
    input.extend_from_slice(&epoch.to_le_bytes());
    sha3::sha3_256(&input)
}

fn bridge_epochpay_global_key(epoch: u64) -> Key {
    let mut input = Vec::with_capacity(BRIDGE_EPOCHPAYG_TAG.len() + 8);
    input.extend_from_slice(BRIDGE_EPOCHPAYG_TAG);
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
const GOV_FEATURE_TAG: &[u8] = b"qtv/gov/feature/";
const GOV_GUARDIAN_TAG: &[u8] = b"qtv/gov/guardians";
const GOV_GUARDIAN_EPOCH_TAG: &[u8] = b"qtv/gov/guardian/epoch";
const GOV_GUARDIAN_FREEZE_TARGETS_TAG: &[u8] = b"qtv/gov/guardian/freeze/targets";
const GUARDIAN_FREEZE_WINDOW_SECONDS: u64 = 7 * 86_400;
const GOV_RECEIPT_TAG: &[u8] = b"qtv/gov/receipt/";
const GOV_ELECTORATE_TAG: &[u8] = b"qtv/gov/electorate/";

const BRIDGE_FREEZE_TAG: &[u8] = b"qtv/bridge/freeze";
const BRIDGE_LAST_LIFT_TAG: &[u8] = b"qtv/bridge/lastlift";
const BRIDGE_VAULT_TAG: &[u8] = b"qtv/bridge/vault";
const BRIDGE_GATEWAY_TAG: &[u8] = b"qtv/bridge/gateway";
const BRIDGE_EXITS_TAG: &[u8] = b"qtv/bridge/exits";
const BRIDGE_PAYOUTCAP_TAG: &[u8] = b"qtv/bridge/payoutcap";

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

fn gov_electorate_key(id: u64) -> Key {
    let mut input = Vec::with_capacity(GOV_ELECTORATE_TAG.len() + 8);
    input.extend_from_slice(GOV_ELECTORATE_TAG);
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

pub fn bridge_guardian_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/guardian/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_mint_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/mint/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_btc_mint_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/mint/btc/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_eth_mint_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/mint/eth/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_cosmos_mint_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/mint/cosmos/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_exit_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/exit/system"))
        .expect("a full hash reaches the address floor")
}

pub fn bridge_settle_address() -> String {
    qtv_idfmt::render_address(&sha3::sha3_256(b"qtv/bridge/settle/system"))
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

pub const CONTRACT_CONTEXT_BYTES: usize = 88;

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

const MAX_RPC_STORAGE_BYTES: usize = 512 * 1024;

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
    NoCommittee,
    NotImplemented,
    Overflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreezeLift {
    Refund,
    Slash,
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
    match action {
        Action::Activate { feature, .. } => !feature.is_empty(),
        _ => true,
    }
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

    pub fn set_execution_height(&mut self, height: u64) {
        self.execution_height = height;
    }

    pub fn execution_height(&self) -> u64 {
        self.execution_height
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
        assert!(updated >= 0, "balance delta underflows the account");
        account.balance = u64::try_from(updated).expect("balance delta overflows a u64 balance");
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

    pub fn take_dirty_entries(&mut self) -> Vec<(Key, Option<Vec<u8>>)> {
        self.trie
            .take_persist_dirty()
            .into_iter()
            .map(|key| {
                let value = self.trie.get(&key).map(|v| v.to_vec());
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
            self.record_side_event(SideEvent::Slash {
                validator: address.to_string(),
                amount: bond.amount,
                disposition: SLASH_DISPOSITION_BURN,
            });
        }
        let forfeited = self.stake_rewards_outstanding(&id);
        if forfeited > 0 {
            self.debit_supply(forfeited);
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

    pub fn guardian_freeze_epoch(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(GOV_GUARDIAN_EPOCH_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical guardian freeze epoch"))
            .unwrap_or(0)
    }

    fn set_guardian_freeze_epoch(&mut self, epoch: u64) {
        self.write_leaf(stake_singleton_key(GOV_GUARDIAN_EPOCH_TAG), to_bytes(&epoch));
    }

    pub fn guardian_freeze(&mut self, bound: u64, targets: &[[u8; 32]], approvers: &[[u8; 32]], now: u64) -> bool {
        if targets.is_empty() || !self.guardian_set().authorizes(approvers) {
            return false;
        }
        if bound != self.guardian_freeze_epoch() {
            return false;
        }
        if targets.iter().any(|target| self.is_protected_account(target)) {
            return false;
        }
        let until = now.saturating_add(GUARDIAN_FREEZE_WINDOW_SECONDS);
        let mut entries = self.guardian_freeze_entries();
        for target in targets {
            self.set_frozen(target);
            if let Some(addr) = id_bytes_to_address(target) {
                self.record_side_event(SideEvent::GuardianFreeze {
                    target: addr,
                    bound,
                });
            }
            match entries.iter().position(|(id, _)| id == target) {
                Some(i) => entries[i].1 = until,
                None => entries.push((*target, until)),
            }
        }
        self.write_guardian_freeze_entries(&entries);
        self.set_guardian_freeze_epoch(bound.saturating_add(1));
        true
    }

    pub fn guardian_expire(&mut self, now: u64) {
        let entries = self.guardian_freeze_entries();
        if entries.is_empty() {
            return;
        }
        let mut survivors = Vec::with_capacity(entries.len());
        for (id, until) in entries {
            if now >= until {
                self.clear_frozen(&id);
            } else {
                survivors.push((id, until));
            }
        }
        self.write_guardian_freeze_entries(&survivors);
    }

    fn guardian_freeze_forget(&mut self, targets: &[[u8; 32]]) {
        let mut entries = self.guardian_freeze_entries();
        entries.retain(|(id, _)| !targets.contains(id));
        self.write_guardian_freeze_entries(&entries);
    }

    fn guardian_freeze_entries(&self) -> Vec<([u8; 32], u64)> {
        match self
            .trie
            .get(&stake_singleton_key(GOV_GUARDIAN_FREEZE_TARGETS_TAG))
        {
            Some(packed) if packed.len() >= 40 => packed
                .chunks_exact(40)
                .map(|chunk| {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&chunk[..32]);
                    let mut u = [0u8; 8];
                    u.copy_from_slice(&chunk[32..40]);
                    (id, u64::from_le_bytes(u))
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn write_guardian_freeze_entries(&mut self, entries: &[([u8; 32], u64)]) {
        let mut packed = Vec::with_capacity(entries.len() * 40);
        for (id, until) in entries {
            packed.extend_from_slice(id);
            packed.extend_from_slice(&until.to_le_bytes());
        }
        self.write_leaf(stake_singleton_key(GOV_GUARDIAN_FREEZE_TARGETS_TAG), packed);
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

    pub fn seed_bridge_pool_vault(&mut self, vault: &[u8; 32]) -> (Key, Vec<u8>) {
        self.set_bridge_pool_vault(vault);
        (stake_singleton_key(BRIDGE_VAULT_TAG), vault.to_vec())
    }

    pub fn seed_bridge_vault_custody(
        &mut self,
        vault: &[u8; 32],
        asset_id: &[u8; 16],
        amount: u128,
    ) -> (Key, Vec<u8>) {
        self.set_bridge_vault_custody(vault, asset_id, amount);
        (bridge_vault_custody_key(vault, asset_id), to_bytes(&amount))
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

    pub fn bridge_exits_enabled(&self) -> bool {
        matches!(
            self.trie.get(&stake_singleton_key(BRIDGE_EXITS_TAG)),
            Some(bytes) if bytes.first() == Some(&1)
        )
    }

    fn set_bridge_exits_enabled(&mut self, enabled: bool) {
        self.write_leaf(stake_singleton_key(BRIDGE_EXITS_TAG), vec![enabled as u8]);
    }

    pub fn seed_bridge_exits_enabled(&mut self, enabled: bool) -> (Key, Vec<u8>) {
        let bytes = vec![enabled as u8];
        self.write_leaf(stake_singleton_key(BRIDGE_EXITS_TAG), bytes.clone());
        (stake_singleton_key(BRIDGE_EXITS_TAG), bytes)
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
        self.lift_bridge_freeze(now, FreezeLift::Refund);
        true
    }

    pub fn guardian_bridge_unfreeze(&mut self, approvers: &[[u8; 32]], now: u64) -> bool {
        if self.bridge_freeze().is_none() {
            return false;
        }
        if !self.guardian_set().authorizes(approvers) {
            return false;
        }
        self.lift_bridge_freeze(now, FreezeLift::Slash);
        true
    }

    pub fn gov_unfreeze_bridge(&mut self, now: u64) -> Result<(), EnactError> {
        if self.bridge_freeze().is_none() {
            return Err(EnactError::BridgeNotFrozen);
        }
        self.lift_bridge_freeze(now, FreezeLift::Slash);
        Ok(())
    }

    pub fn bridge_expire(&mut self, now: u64) {
        if let Some(record) = self.bridge_freeze() {
            if now >= record.until {
                self.lift_bridge_freeze(now, FreezeLift::Refund);
            }
        }
    }

    fn lift_bridge_freeze(&mut self, now: u64, outcome: FreezeLift) {
        let record = match self.bridge_freeze() {
            Some(record) => record,
            None => return,
        };
        let pot_address = bridge_bond_address();
        let mut pot = self.account(&pot_address);
        pot.balance = pot.balance.saturating_sub(record.bond);
        self.set_account(&pot_address, &pot);
        match outcome {
            FreezeLift::Refund => {
                if let Some(depositor) = id_bytes_to_address(&record.who) {
                    let mut account = self.account(&depositor);
                    account.balance = account.balance.saturating_add(record.bond);
                    self.set_account(&depositor, &account);
                }
            }
            FreezeLift::Slash => {
                self.set_stake_treasury(self.stake_treasury().saturating_add(record.bond));
            }
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

    fn bridge_asset_ids(&self) -> Vec<[u8; 16]> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_ASSET_LIST_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| {
                bytes
                    .chunks_exact(16)
                    .map(|chunk| <[u8; 16]>::try_from(chunk).expect("a chunk is sixteen bytes"))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn record_bridge_asset_id(&mut self, asset_id: &[u8; 16]) {
        let mut ids = self.bridge_asset_ids();
        if ids.contains(asset_id) {
            return;
        }
        ids.push(*asset_id);
        let mut bytes = Vec::with_capacity(ids.len() * 16);
        for id in &ids {
            bytes.extend_from_slice(id);
        }
        self.write_leaf(stake_singleton_key(BRIDGE_ASSET_LIST_TAG), bytes);
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
        self.record_bridge_asset_id(asset_id);
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

    pub fn asset_balance(&self, asset_id: &[u8; 16], holder: &[u8; 32]) -> u128 {
        self.trie
            .get(&asset_balance_key(asset_id, holder))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical asset balance"))
            .unwrap_or(0)
    }

    fn set_asset_balance(&mut self, asset_id: &[u8; 16], holder: &[u8; 32], amount: u128) {
        self.write_leaf(asset_balance_key(asset_id, holder), to_bytes(&amount));
    }

    pub fn asset_supply(&self, asset_id: &[u8; 16]) -> u128 {
        self.trie
            .get(&asset_supply_key(asset_id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical asset supply"))
            .unwrap_or(0)
    }

    fn set_asset_supply(&mut self, asset_id: &[u8; 16], supply: u128) {
        self.write_leaf(asset_supply_key(asset_id), to_bytes(&supply));
    }

    pub fn asset_balance_by_issuer(&self, issuer: &[u8; 32], holder: &[u8; 32]) -> u128 {
        self.asset_balance(&asset_id_of(issuer), holder)
    }

    pub fn asset_supply_by_issuer(&self, issuer: &[u8; 32]) -> u128 {
        self.asset_supply(&asset_id_of(issuer))
    }

    fn credit_asset(&mut self, asset_id: &[u8; 16], holder: &[u8; 32], amount: u128) -> bool {
        let updated = match self.asset_balance(asset_id, holder).checked_add(amount) {
            Some(sum) => sum,
            None => return false,
        };
        self.set_asset_balance(asset_id, holder, updated);
        true
    }

    fn debit_asset(&mut self, asset_id: &[u8; 16], holder: &[u8; 32], amount: u128) -> bool {
        let current = self.asset_balance(asset_id, holder);
        let updated = match current.checked_sub(amount) {
            Some(rest) => rest,
            None => return false,
        };
        self.set_asset_balance(asset_id, holder, updated);
        true
    }

    pub fn issue_asset(&mut self, issuer: &[u8; 32], holder: &[u8; 32], amount: u128) -> Option<[u8; 16]> {
        let asset_id = asset_id_of(issuer);
        if self.asset_supply(&asset_id) != 0 {
            return None;
        }
        if amount == 0 {
            return None;
        }
        self.set_asset_supply(&asset_id, amount);
        self.set_asset_balance(&asset_id, holder, amount);
        Some(asset_id)
    }

    pub fn mint_asset(&mut self, issuer: &[u8; 32], holder: &[u8; 32], amount: u128) -> bool {
        if amount == 0 {
            return false;
        }
        let asset_id = asset_id_of(issuer);
        let supply = match self.asset_supply(&asset_id).checked_add(amount) {
            Some(supply) => supply,
            None => return false,
        };
        if !self.credit_asset(&asset_id, holder, amount) {
            return false;
        }
        self.set_asset_supply(&asset_id, supply);
        true
    }

    #[cfg(test)]
    pub(crate) fn seed_outstanding_burn(
        &mut self,
        burn_ref: &[u8; 32],
        asset_id: &[u8; 16],
        amount: u128,
        beneficiary: &[u8; 32],
    ) {
        self.record_outstanding_burn(burn_ref, asset_id, amount, beneficiary);
    }

    pub fn bridge_vault_custody(&self, vault: &[u8; 32], asset_id: &[u8; 16]) -> u128 {
        self.trie
            .get(&bridge_vault_custody_key(vault, asset_id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical vault custody"))
            .unwrap_or(0)
    }

    fn set_bridge_vault_custody(&mut self, vault: &[u8; 32], asset_id: &[u8; 16], amount: u128) {
        self.write_leaf(bridge_vault_custody_key(vault, asset_id), to_bytes(&amount));
    }

    fn credit_vault_custody(&mut self, asset_id: &[u8; 16], amount: u128) -> bool {
        if let Some(vault) = self.bridge_pool_vault() {
            let held = match self.bridge_vault_custody(&vault, asset_id).checked_add(amount) {
                Some(held) => held,
                None => return false,
            };
            self.set_bridge_vault_custody(&vault, asset_id, held);
        }
        true
    }

    pub fn bridge_operator_set(&self) -> Option<crate::bridge::OperatorSet> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_OPERATORS_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical operator set"))
    }

    pub fn seed_bridge_operator_set(
        &mut self,
        set: &crate::bridge::OperatorSet,
    ) -> Option<(Key, Vec<u8>)> {
        if set.threshold < 2 {
            return None;
        }
        let key = stake_singleton_key(BRIDGE_OPERATORS_TAG);
        let bytes = to_bytes(set);
        self.write_leaf(key, bytes.clone());
        Some((key, bytes))
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

    pub fn bridge_bitcoin_anchor(&self) -> Option<crate::bridge_btc::BitcoinAnchor> {
        self.trie
            .get(&stake_singleton_key(BRIDGE_BTC_ANCHOR_TAG))
            .filter(|bytes| !bytes.is_empty())
            .and_then(|bytes| crate::bridge_btc::BitcoinAnchor::decode(bytes))
    }

    pub fn seed_bridge_bitcoin_anchor(
        &mut self,
        anchor: &crate::bridge_btc::BitcoinAnchor,
    ) -> (Key, Vec<u8>) {
        let key = stake_singleton_key(BRIDGE_BTC_ANCHOR_TAG);
        let bytes = anchor.encode();
        self.write_leaf(key, bytes.clone());
        (key, bytes)
    }

    pub fn bridge_eth_anchor(&self, selector: u8) -> Option<crate::bridge_eth::EthAnchor> {
        self.trie
            .get(&bridge_eth_anchor_key(selector))
            .filter(|bytes| !bytes.is_empty())
            .and_then(|bytes| crate::bridge_eth::EthAnchor::decode(bytes))
    }

    pub fn seed_bridge_eth_anchor(
        &mut self,
        anchor: &crate::bridge_eth::EthAnchor,
    ) -> (Key, Vec<u8>) {
        let key = bridge_eth_anchor_key(anchor.config_selector);
        let bytes = anchor.encode();
        self.write_leaf(key, bytes.clone());
        (key, bytes)
    }

    pub fn bridge_cosmos_anchor(&self, selector: u8) -> Option<crate::bridge_cosmos::CosmosAnchor> {
        self.trie
            .get(&bridge_cosmos_anchor_key(selector))
            .filter(|bytes| !bytes.is_empty())
            .and_then(|bytes| crate::bridge_cosmos::CosmosAnchor::decode(bytes))
    }

    pub fn seed_bridge_cosmos_anchor(
        &mut self,
        anchor: &crate::bridge_cosmos::CosmosAnchor,
    ) -> (Key, Vec<u8>) {
        let key = bridge_cosmos_anchor_key(anchor.config_selector);
        let bytes = anchor.encode();
        self.write_leaf(key, bytes.clone());
        (key, bytes)
    }

    pub fn chain_genesis_time(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(CHAIN_GENESIS_TIME_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical genesis time"))
            .unwrap_or(0)
    }

    pub fn seed_chain_genesis_time(&mut self, genesis_time: u64) -> (Key, Vec<u8>) {
        let key = stake_singleton_key(CHAIN_GENESIS_TIME_TAG);
        let bytes = to_bytes(&genesis_time);
        self.write_leaf(key, bytes.clone());
        (key, bytes)
    }

    pub fn bridge_era(&self) -> [u8; 32] {
        self.trie
            .get(&stake_singleton_key(BRIDGE_ERA_TAG))
            .filter(|bytes| bytes.len() == 32)
            .map(|bytes| {
                let mut era = [0u8; 32];
                era.copy_from_slice(bytes);
                era
            })
            .unwrap_or([0u8; 32])
    }

    pub fn seed_bridge_era(&mut self, era: &[u8; 32]) -> (Key, Vec<u8>) {
        let key = stake_singleton_key(BRIDGE_ERA_TAG);
        let bytes = era.to_vec();
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

    pub fn bridge_reference_seen(&self, source_chain: u32, source_ref: &[u8; 32]) -> bool {
        matches!(self.trie.get(&bridge_seen_key(source_chain, source_ref)), Some(bytes) if !bytes.is_empty())
    }

    fn mark_bridge_reference(&mut self, source_chain: u32, source_ref: &[u8; 32]) {
        self.write_leaf(bridge_seen_key(source_chain, source_ref), vec![1]);
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
        if self.bridge_pool_vault().is_none() {
            return false;
        }
        if self.execution_height() > fact.expiry_height {
            return false;
        }
        let asset = match self.bridged_asset(&fact.asset_id) {
            Some(asset) => asset,
            None => return false,
        };
        if self.bridge_reference_seen(fact.source_chain, &fact.source_ref) {
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
        let credited = match self
            .bridged_balance(&fact.asset_id, &fact.recipient)
            .checked_add(fact.amount)
        {
            Some(credited) => credited,
            None => return false,
        };
        if !self.credit_vault_custody(&fact.asset_id, fact.amount) {
            return false;
        }
        self.set_bridged_balance(&fact.asset_id, &fact.recipient, credited);
        self.set_bridged_asset(
            &fact.asset_id,
            &QAsset {
                supply: new_supply,
                ..asset
            },
        );
        self.mark_bridge_reference(fact.source_chain, &fact.source_ref);
        self.set_bridge_epoch_minted(&fact.asset_id, epoch, new_minted);
        self.record_bridge_mint_event(&fact.asset_id, &fact.recipient, fact.amount);
        self.record_side_event(SideEvent::BridgeMint {
            asset_id: fact.asset_id,
            recipient: fact.recipient,
            amount: fact.amount,
        });
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
        self.record_outstanding_burn(&burn_ref, asset_id, amount, holder);
        self.record_bridge_burn_event(
            asset_id,
            holder,
            amount,
            destination,
            chain_id,
            sender_nonce,
            event_index,
            &burn_ref,
        );
        self.record_side_event(SideEvent::BridgeBurn {
            asset_id: *asset_id,
            holder: *holder,
            amount,
            destination: *destination,
            chain_id,
            burn_ref,
        });
        true
    }

    pub fn bridge_exit_settled(&self, burn_ref: &[u8; 32]) -> bool {
        matches!(self.trie.get(&bridge_exit_seen_key(burn_ref)), Some(bytes) if !bytes.is_empty())
    }

    fn mark_bridge_exit_settled(&mut self, burn_ref: &[u8; 32]) {
        self.write_leaf(bridge_exit_seen_key(burn_ref), vec![1]);
    }

    pub fn bridge_outstanding_burn(&self, burn_ref: &[u8; 32]) -> Option<OutstandingBurn> {
        self.trie
            .get(&bridge_outstanding_key(burn_ref))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical outstanding burn"))
    }

    fn record_outstanding_burn(
        &mut self,
        burn_ref: &[u8; 32],
        asset_id: &[u8; 16],
        amount: u128,
        beneficiary: &[u8; 32],
    ) {
        let record = OutstandingBurn {
            asset_id: *asset_id,
            amount,
            beneficiary: *beneficiary,
        };
        self.write_leaf(bridge_outstanding_key(burn_ref), to_bytes(&record));
    }

    fn outstanding_burn_matches(
        &self,
        burn_ref: &[u8; 32],
        asset_id: &[u8; 16],
        amount: u128,
        beneficiary: &[u8; 32],
    ) -> bool {
        matches!(
            self.bridge_outstanding_burn(burn_ref),
            Some(record)
                if record.asset_id == *asset_id
                    && record.amount == amount
                    && record.beneficiary == *beneficiary
        )
    }

    fn consume_outstanding_burn(&mut self, burn_ref: &[u8; 32]) {
        self.erase_leaf(&bridge_outstanding_key(burn_ref));
    }

    pub fn bridge_epoch_paid(&self, asset_id: &[u8; 16], epoch: u64) -> u128 {
        self.trie
            .get(&bridge_epochpay_key(asset_id, epoch))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical epoch payout total"))
            .unwrap_or(0)
    }

    fn set_bridge_epoch_paid(&mut self, asset_id: &[u8; 16], epoch: u64, amount: u128) {
        self.write_leaf(bridge_epochpay_key(asset_id, epoch), to_bytes(&amount));
    }

    pub fn bridge_epoch_paid_global(&self, epoch: u64) -> u128 {
        self.trie
            .get(&bridge_epochpay_global_key(epoch))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical global epoch payout total"))
            .unwrap_or(0)
    }

    fn set_bridge_epoch_paid_global(&mut self, epoch: u64, amount: u128) {
        self.write_leaf(bridge_epochpay_global_key(epoch), to_bytes(&amount));
    }

    pub fn bridge_payout_cap(&self) -> u128 {
        self.trie
            .get(&stake_singleton_key(BRIDGE_PAYOUTCAP_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical payout cap"))
            .unwrap_or(0)
    }

    fn set_bridge_payout_cap(&mut self, cap: u128) {
        self.write_leaf(stake_singleton_key(BRIDGE_PAYOUTCAP_TAG), to_bytes(&cap));
    }

    pub fn seed_bridge_payout_cap(&mut self, cap: u128) -> (Key, Vec<u8>) {
        self.set_bridge_payout_cap(cap);
        (stake_singleton_key(BRIDGE_PAYOUTCAP_TAG), to_bytes(&cap))
    }

    pub fn bridge_settle(&mut self, fact: &crate::bridge::ExitFact) -> bool {
        if !self.bridge_exits_enabled() {
            return false;
        }
        if self.bridge_is_frozen() {
            return false;
        }
        let vault = match self.bridge_pool_vault() {
            Some(vault) => vault,
            None => return false,
        };
        if fact.amount == 0 {
            return false;
        }
        let asset = match self.bridged_asset(&fact.asset_id) {
            Some(asset) => asset,
            None => return false,
        };
        if self.bridge_exit_settled(&fact.burn_ref) {
            return false;
        }
        if !self.outstanding_burn_matches(&fact.burn_ref, &fact.asset_id, fact.amount, &fact.beneficiary) {
            return false;
        }
        let held = match self.bridge_vault_custody(&vault, &fact.asset_id).checked_sub(fact.amount) {
            Some(held) => held,
            None => return false,
        };
        if held < asset.supply {
            return false;
        }
        self.mark_bridge_exit_settled(&fact.burn_ref);
        self.consume_outstanding_burn(&fact.burn_ref);
        self.set_bridge_vault_custody(&vault, &fact.asset_id, held);
        self.record_bridge_settle_event(&fact.asset_id, &fact.beneficiary, fact.amount, &fact.burn_ref);
        self.record_side_event(SideEvent::BridgeSettle {
            asset_id: fact.asset_id,
            beneficiary: fact.beneficiary,
            amount: fact.amount,
            burn_ref: fact.burn_ref,
        });
        true
    }

    pub fn bridge_slash(&mut self, fact: &crate::bridge::ExitFact) -> bool {
        if !self.bridge_exits_enabled() {
            return false;
        }
        if self.bridge_is_frozen() {
            return false;
        }
        let vault = match self.bridge_pool_vault() {
            Some(vault) => vault,
            None => return false,
        };
        if fact.amount == 0 {
            return false;
        }
        let asset = match self.bridged_asset(&fact.asset_id) {
            Some(asset) => asset,
            None => return false,
        };
        if self.bridge_exit_settled(&fact.burn_ref) {
            return false;
        }
        if !self.outstanding_burn_matches(&fact.burn_ref, &fact.asset_id, fact.amount, &fact.beneficiary) {
            return false;
        }
        let epoch = self.bridge_epoch();
        let new_asset_paid = match self.bridge_epoch_paid(&fact.asset_id, epoch).checked_add(fact.amount) {
            Some(total) => total,
            None => return false,
        };
        if new_asset_paid > asset.epoch_cap {
            return false;
        }
        let new_global_paid = match self.bridge_epoch_paid_global(epoch).checked_add(fact.amount) {
            Some(total) => total,
            None => return false,
        };
        if new_global_paid > self.bridge_payout_cap() {
            return false;
        }
        let new_supply = match asset.supply.checked_add(fact.amount) {
            Some(supply) => supply,
            None => return false,
        };
        if new_supply > asset.cap {
            return false;
        }
        if new_supply > self.bridge_vault_custody(&vault, &fact.asset_id) {
            return false;
        }
        let credited = match self
            .bridged_balance(&fact.asset_id, &fact.beneficiary)
            .checked_add(fact.amount)
        {
            Some(credited) => credited,
            None => return false,
        };
        self.mark_bridge_exit_settled(&fact.burn_ref);
        self.consume_outstanding_burn(&fact.burn_ref);
        self.set_bridged_balance(&fact.asset_id, &fact.beneficiary, credited);
        self.set_bridged_asset(&fact.asset_id, &QAsset { supply: new_supply, ..asset });
        self.set_bridge_epoch_paid(&fact.asset_id, epoch, new_asset_paid);
        self.set_bridge_epoch_paid_global(epoch, new_global_paid);
        self.record_bridge_slash_event(&fact.asset_id, &fact.beneficiary, fact.amount, &fact.burn_ref);
        self.record_side_event(SideEvent::BridgeSlash {
            asset_id: fact.asset_id,
            beneficiary: fact.beneficiary,
            amount: fact.amount,
            burn_ref: fact.burn_ref,
        });
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

    fn stake_rewards_outstanding(&self, id: &[u8; 32]) -> u64 {
        self.stake_rewards(id)
            .tranches
            .iter()
            .map(|tranche| tranche.amount.saturating_sub(tranche.claimed))
            .sum()
    }

    pub fn accrue_reward(&mut self, address: &str, now_day: u64) -> u64 {
        match address_id(address) {
            Some(id) => {
                let denom = self.total_staked();
                self.accrue_reward_by_id(&id, now_day, denom)
            }
            None => 0,
        }
    }

    fn roster_reward_denominator(&self) -> u64 {
        self.validator_ids()
            .iter()
            .filter(|id| !self.is_stake_banned(id) && !self.is_gov_blacklisted(id))
            .filter_map(|id| self.stake_bond(id).map(|bond| bond.amount))
            .sum()
    }

    fn accrue_reward_by_id(&mut self, id: &[u8; 32], now_day: u64, denom: u64) -> u64 {
        if qtv_staking::in_blackout(now_day, self.stake_mainnet_start()) {
            return 0;
        }
        if self.is_stake_banned(id) || self.is_gov_blacklisted(id) {
            return 0;
        }
        let stake = match self.stake_bond(id) {
            Some(bond) => bond.amount,
            None => return 0,
        };
        let paid = qtv_staking::session_reward(stake, denom).min(self.stake_pool());
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
            self.record_side_event(SideEvent::Reward {
                validator: address,
                amount: paid,
            });
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
        self.record_side_event(SideEvent::RewardClaim {
            validator: address.to_string(),
            amount: credited,
        });
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

    pub fn contract_storage_at_capped(
        &self,
        address: &str,
    ) -> Option<std::collections::BTreeMap<StorageKey, u64>> {
        let id = match address_id(address) {
            Some(id) => id,
            None => return Some(std::collections::BTreeMap::new()),
        };
        match self.trie.get(&contract_store_key(&id)) {
            Some(bytes) if bytes.len() > MAX_RPC_STORAGE_BYTES => None,
            Some(bytes) if !bytes.is_empty() => Some(decode_storage(bytes)),
            _ => Some(std::collections::BTreeMap::new()),
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

    pub fn clear_contract_code(&mut self, address: &str) {
        if let Some(id) = address_id(address) {
            self.erase_leaf(&contract_code_key(&id));
        }
    }

    pub fn deploy_contract(&mut self, deployer: &str, nonce: u64, code: &[u8]) -> Option<String> {
        let container = crate::execution::decode_container(code)?;
        container.verify().ok()?;
        if container.canonical_bytes().as_slice() != code {
            return None;
        }
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
        in_asset: Option<[u8; 32]>,
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
        let caller_id = address_id(caller).unwrap_or([0u8; 32]);
        let in_asset_id = in_asset.map(|issuer| asset_id_of(&issuer));
        if value > 0 {
            match in_asset_id {
                None => {
                    if self.balance(caller) < value {
                        return false;
                    }
                }
                Some(asset) => {
                    if self.asset_balance(&asset, &caller_id) < u128::from(value) {
                        return false;
                    }
                }
            }
        }
        let storage = self.contract_storage(&contract_id);
        let mut memory = vec![0u8; user_memory.len().max(CONTRACT_CONTEXT_BYTES)];
        memory[..user_memory.len()].copy_from_slice(user_memory);
        memory[0..32].copy_from_slice(&caller_id);
        memory[32..64].copy_from_slice(&contract_id);
        memory[64..72].copy_from_slice(&now_seconds.to_be_bytes());
        memory[72..80].copy_from_slice(&chain_id.to_be_bytes());
        memory[80..88].copy_from_slice(&value.to_be_bytes());
        match crate::execution::execute_contract_call(&code, selector, storage, &memory, meter) {
            Ok(outcome) => {
                let mut native_credits: Vec<(String, u64)> = Vec::new();
                let mut native_sent: u64 = 0;
                let mut asset_credits: Vec<([u8; 16], [u8; 32], u128)> = Vec::new();
                let mut asset_sent: std::collections::BTreeMap<[u8; 16], u128> =
                    std::collections::BTreeMap::new();
                for effect in &outcome.effects {
                    if let qtv_vm::interp::Effect::Transfer { to, amount } = effect {
                        if to.len() == 32 {
                            let target = match id_bytes_to_address(to) {
                                Some(address) => address,
                                None => return false,
                            };
                            native_sent = match native_sent.checked_add(*amount) {
                                Some(sum) => sum,
                                None => return false,
                            };
                            native_credits.push((target, *amount));
                        } else if to.len() == 64 {
                            let mut issuer = [0u8; 32];
                            issuer.copy_from_slice(&to[..32]);
                            let mut holder = [0u8; 32];
                            holder.copy_from_slice(&to[32..64]);
                            let asset = asset_id_of(&issuer);
                            let moved = u128::from(*amount);
                            let running = asset_sent.entry(asset).or_insert(0);
                            *running = match running.checked_add(moved) {
                                Some(sum) => sum,
                                None => return false,
                            };
                            asset_credits.push((asset, holder, moved));
                        } else {
                            return false;
                        }
                    }
                }
                let native_in = if in_asset_id.is_none() { value } else { 0 };
                let native_funded = match self.balance(contract).checked_add(native_in) {
                    Some(funded) => funded,
                    None => return false,
                };
                if native_funded < native_sent {
                    return false;
                }
                for (asset, sent) in &asset_sent {
                    let asset_in = match in_asset_id {
                        Some(a) if a == *asset => u128::from(value),
                        _ => 0,
                    };
                    let funded = match self.asset_balance(asset, &contract_id).checked_add(asset_in) {
                        Some(funded) => funded,
                        None => return false,
                    };
                    if funded < *sent {
                        return false;
                    }
                }
                let mut projected_credit: std::collections::BTreeMap<([u8; 16], [u8; 32]), u128> =
                    std::collections::BTreeMap::new();
                for (asset, holder, amount) in &asset_credits {
                    let slot = projected_credit
                        .entry((*asset, *holder))
                        .or_insert_with(|| self.asset_balance(asset, holder));
                    match slot.checked_add(*amount) {
                        Some(sum) => *slot = sum,
                        None => return false,
                    }
                }
                if value > 0 {
                    match in_asset_id {
                        None => {
                            self.apply_balance_delta(caller, -i128::from(value));
                            self.apply_balance_delta(contract, i128::from(value));
                        }
                        Some(asset) => {
                            if self
                                .asset_balance(&asset, &contract_id)
                                .checked_add(u128::from(value))
                                .is_none()
                            {
                                return false;
                            }
                            if !self.debit_asset(&asset, &caller_id, u128::from(value)) {
                                return false;
                            }
                            if !self.credit_asset(&asset, &contract_id, u128::from(value)) {
                                return false;
                            }
                        }
                    }
                }
                for (target, amount) in &native_credits {
                    self.apply_balance_delta(contract, -i128::from(*amount));
                    self.apply_balance_delta(target, i128::from(*amount));
                    self.record_side_event(SideEvent::ContractTransfer {
                        contract: contract.to_string(),
                        to: target.clone(),
                        amount: *amount,
                    });
                }
                for (asset, holder, amount) in &asset_credits {
                    if self.asset_balance(asset, holder).checked_add(*amount).is_none() {
                        return false;
                    }
                    if !self.debit_asset(asset, &contract_id, *amount) {
                        return false;
                    }
                    if !self.credit_asset(asset, holder, *amount) {
                        return false;
                    }
                }
                for effect in &outcome.effects {
                    if let qtv_vm::interp::Effect::Event { selector, data } = effect {
                        if *selector == ASSET_MINT_SELECTOR && data.len() >= 40 {
                            let mut holder = [0u8; 32];
                            holder.copy_from_slice(&data[..32]);
                            let amount = u64::from_be_bytes(data[32..40].try_into().unwrap());
                            self.mint_asset(&contract_id, &holder, u128::from(amount));
                            continue;
                        }
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
        let mut sorted: Vec<[u8; 32]> = ids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut bytes = Vec::with_capacity(sorted.len() * KEY_LEN);
        for id in &sorted {
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
        if self.record_session(transactions, now_day).is_some() {
            let denom = self.roster_reward_denominator();
            for id in self.validator_ids() {
                self.accrue_reward_by_id(&id, now_day, denom);
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

    pub fn gov_referenda(&self, limit: usize) -> Vec<Referendum> {
        let next = self.gov_next_id();
        let start = next.saturating_sub(limit as u64).max(1);
        let mut out = Vec::new();
        for id in start..next {
            if let Some(referendum) = self.gov_referendum(id) {
                out.push(referendum);
            }
        }
        out
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

    fn gov_electorate(&self, id: u64) -> Option<u64> {
        self.trie
            .get(&gov_electorate_key(id))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical electorate snapshot"))
    }

    fn set_gov_electorate(&mut self, id: u64, amount: u64) {
        self.write_leaf(gov_electorate_key(id), to_bytes(&amount));
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

    pub(crate) fn is_protected_account(&self, addr: &[u8]) -> bool {
        match id_from_slice(addr) {
            Some(id) => is_reserved_pot(&id),
            None => false,
        }
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
        self.set_gov_electorate(id, self.total_staked());
        self.set_gov_next_id(id + 1);
        self.record_side_event(SideEvent::GovPropose {
            referendum: id,
            proposer: proposer.to_string(),
            track: track.code(),
            action: action_kind(&action),
            deposit,
        });
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
        let bonded = self.staked_weight(voter) as u128 * qtv_staking::NATIVE_UNIT as u128;
        if u128::from(stake) > bonded {
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
        self.record_side_event(SideEvent::GovVote {
            referendum: referendum_id,
            voter: voter.to_string(),
            aye,
            conviction: conviction.code(),
            stake,
        });
        true
    }

    pub fn gov_conclude(&mut self, referendum_id: u64, now: u64) -> Option<Status> {
        let mut referendum = self.gov_referendum(referendum_id)?;
        if referendum.status != Status::Deciding {
            return Some(referendum.status);
        }
        let live = self.total_staked();
        let electorate = u128::from(self.gov_electorate(referendum_id).unwrap_or(live).max(live));
        let status = referendum.resolve(now, electorate);
        if status == Status::Deciding {
            return Some(status);
        }
        if referendum.deposit_refunded(electorate) {
            if let Some(addr) = id_bytes_to_address(&referendum.proposer) {
                let mut account = self.account(&addr);
                account.balance = account.balance.saturating_add(referendum.deposit);
                self.set_account(&addr, &account);
            } else {
                self.set_stake_treasury(self.stake_treasury() + referendum.deposit);
            }
        } else {
            self.set_stake_treasury(self.stake_treasury() + referendum.deposit);
        }
        self.set_gov_referendum(referendum_id, &referendum);
        self.record_side_event(SideEvent::GovTally {
            referendum: referendum_id,
            status: status_kind(status),
            aye_stake: referendum.tally.aye_stake,
            nay_stake: referendum.tally.nay_stake,
        });
        Some(status)
    }

    pub fn gov_enact(&mut self, referendum_id: u64, now: u64, chain_id: u64) -> Result<(), EnactError> {
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
            } => sha3::sha3_256(&Action::recovery_scope_preimage(chain_id, victim, seizures)) == *scope,
            _ => true,
        };
        check_enactment(referendum.track, &action, scope_ok, |addr| {
            self.is_protected_account(addr)
        })
        .map_err(EnactError::Constitution)?;
        self.execute_action(&action, now, chain_id)?;
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
        self.record_side_event(SideEvent::GovEnact {
            referendum: referendum_id,
            action: action_kind(&action),
            proposal_hash: receipt.proposal_hash,
        });
        Ok(())
    }

    fn execute_action(&mut self, action: &Action, now: u64, chain_id: u64) -> Result<(), EnactError> {
        match action {
            Action::Mint { to, amount } => {
                let addr = id_bytes_to_address(to).ok_or(EnactError::BadAddress)?;
                let mut account = self.account(&addr);
                account.balance = account.balance.checked_add(*amount).ok_or(EnactError::Overflow)?;
                let supply = self.total_supply().checked_add(*amount).ok_or(EnactError::Overflow)?;
                if supply > qtv_staking::MAX_SUPPLY {
                    return Err(EnactError::BadValue);
                }
                self.set_account(&addr, &account);
                self.set_total_supply(supply);
                self.record_mint_event(&addr, *amount);
                self.record_side_event(SideEvent::Mint {
                    to: addr,
                    amount: *amount,
                });
                Ok(())
            }
            Action::Parameter { key, value } => {
                self.apply_parameter(key, value)?;
                self.record_side_event(SideEvent::Parameter {
                    key: key.clone(),
                    value: value.clone(),
                });
                Ok(())
            }
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
                let source = if from_id == sha3::sha3_256(b"qtv/gov/grants") {
                    "gov/grants".to_string()
                } else {
                    "stake/treasury".to_string()
                };
                self.record_side_event(SideEvent::Spend {
                    source,
                    to: to_addr,
                    amount: *amount,
                });
                Ok(())
            }
            Action::Blacklist { target } => {
                if let Some(id) = id_from_slice(target) {
                    self.set_gov_blacklisted(&id);
                    if let Some(addr) = id_bytes_to_address(&id) {
                        self.record_side_event(SideEvent::Blacklist { target: addr });
                    }
                }
                Ok(())
            }
            Action::FreezeRecovery {
                victim,
                seizures,
                scope,
            } => {
                let victim_addr = id_bytes_to_address(victim).ok_or(EnactError::BadAddress)?;
                let mut recovered = 0u64;
                for seizure in seizures {
                    if let Some(from_addr) = id_bytes_to_address(&seizure.from) {
                        let mut from = self.account(&from_addr);
                        let mut take = from.balance.min(seizure.amount);
                        from.balance -= take;
                        self.set_account(&from_addr, &from);
                        let remaining = seizure.amount - take;
                        if remaining > 0 {
                            if let Some(from_id) = id_from_slice(&seizure.from) {
                                if self.is_frozen_id(&from_id) {
                                    if let Some(bond) = self.stake_bond(&from_id) {
                                        let from_bond = bond.amount.min(remaining);
                                        if from_bond > 0 {
                                            let residue = bond.amount - from_bond;
                                            self.clear_stake_bond(&from_id);
                                            self.debit_staked(bond.amount);
                                            if residue > 0 {
                                                let mut holder = self.account(&from_addr);
                                                holder.balance = holder.balance.saturating_add(residue);
                                                self.set_account(&from_addr, &holder);
                                            }
                                            take = take.saturating_add(from_bond);
                                        }
                                    }
                                }
                            }
                        }
                        recovered = recovered.saturating_add(take);
                        self.record_side_event(SideEvent::RecoverySeizure {
                            victim: victim_addr.clone(),
                            from: from_addr,
                            amount: take,
                            scope: *scope,
                        });
                    }
                }
                let mut account = self.account(&victim_addr);
                account.balance = account.balance.saturating_add(recovered);
                self.set_account(&victim_addr, &account);
                self.record_side_event(SideEvent::RecoveryCredit {
                    victim: victim_addr,
                    amount: recovered,
                    scope: *scope,
                });
                let handled: Vec<[u8; 32]> = seizures
                    .iter()
                    .filter_map(|seizure| <[u8; 32]>::try_from(seizure.from.as_slice()).ok())
                    .collect();
                self.guardian_freeze_forget(&handled);
                Ok(())
            }
            Action::Freeze { targets } => {
                let mut handled: Vec<[u8; 32]> = Vec::new();
                for target in targets {
                    if let Some(id) = id_from_slice(target) {
                        self.set_frozen(&id);
                        handled.push(id);
                        if let Some(addr) = id_bytes_to_address(&id) {
                            self.record_side_event(SideEvent::Freeze { target: addr });
                        }
                    }
                }
                self.guardian_freeze_forget(&handled);
                Ok(())
            }
            Action::Unfreeze { targets } => {
                let mut handled: Vec<[u8; 32]> = Vec::new();
                for target in targets {
                    if let Some(id) = id_from_slice(target) {
                        self.clear_frozen(&id);
                        handled.push(id);
                        if let Some(addr) = id_bytes_to_address(&id) {
                            self.record_side_event(SideEvent::Unfreeze { target: addr });
                        }
                    }
                }
                self.guardian_freeze_forget(&handled);
                Ok(())
            }
            Action::BridgeMigration { vault } => {
                if !self.bridge_is_frozen() {
                    return Err(EnactError::BridgeNotFrozen);
                }
                let vault_id = id_from_slice(vault).ok_or(EnactError::BadAddress)?;
                if let Some(old_vault) = self.bridge_pool_vault() {
                    if old_vault != vault_id {
                        for asset_id in self.bridge_asset_ids() {
                            let held = self.bridge_vault_custody(&old_vault, &asset_id);
                            if held == 0 {
                                continue;
                            }
                            self.set_bridge_vault_custody(&old_vault, &asset_id, 0);
                            let carried =
                                self.bridge_vault_custody(&vault_id, &asset_id).saturating_add(held);
                            self.set_bridge_vault_custody(&vault_id, &asset_id, carried);
                        }
                    }
                }
                self.set_bridge_pool_vault(&vault_id);
                if let Some(addr) = id_bytes_to_address(&vault_id) {
                    self.record_side_event(SideEvent::BridgeMigration { vault: addr });
                }
                Ok(())
            }
            Action::BridgeUnfreeze => {
                self.gov_unfreeze_bridge(now)?;
                self.record_side_event(SideEvent::BridgeUnfreeze);
                Ok(())
            }
            Action::GuardianRotate { set } => {
                if !set.well_formed() {
                    return Err(EnactError::BadValue);
                }
                self.set_guardian_set(set);
                self.record_side_event(SideEvent::GuardianRotate {
                    size: set.members.len() as u32,
                    threshold: set.threshold,
                });
                Ok(())
            }
            Action::CommitteeRotate { rotation } => {
                if rotation.threshold < 2 {
                    return Err(EnactError::BadValue);
                }
                let mut operators: Vec<(u32, Vec<u8>)> = Vec::with_capacity(rotation.operators.len());
                for claim in &rotation.operators {
                    if operators.iter().any(|(id, _)| *id == claim.operator_id) {
                        return Err(EnactError::BadValue);
                    }
                    if operators.iter().any(|(_, key)| *key == claim.public_key) {
                        return Err(EnactError::BadValue);
                    }
                    if !crate::bridge::operator_pop_ok(
                        claim.operator_id,
                        &claim.public_key,
                        &claim.pop,
                        chain_id,
                    ) {
                        return Err(EnactError::BadValue);
                    }
                    operators.push((claim.operator_id, claim.public_key.clone()));
                }
                if (rotation.threshold as usize) > operators.len() {
                    return Err(EnactError::BadValue);
                }
                if (rotation.threshold as usize) * 3 < operators.len() * 2 {
                    return Err(EnactError::BadValue);
                }
                let committee_size = operators.len() as u32;
                self.seed_bridge_operator_set(&crate::bridge::OperatorSet::new(
                    operators,
                    rotation.threshold,
                ));
                self.record_side_event(SideEvent::CommitteeRotate {
                    operators: committee_size,
                    threshold: rotation.threshold,
                });
                Ok(())
            }
            Action::OperatorRevoke { operator_id } => {
                let mut set = self.bridge_operator_set().ok_or(EnactError::NoCommittee)?;
                if !set.revoke(*operator_id) {
                    return Err(EnactError::BadValue);
                }
                self.seed_bridge_operator_set(&set);
                self.record_side_event(SideEvent::OperatorRevoke {
                    operator_id: *operator_id,
                });
                Ok(())
            }
            Action::AssetRegister {
                asset_id,
                cap,
                epoch_cap,
                requires_stark,
            } => {
                if *cap == 0 || *epoch_cap == 0 {
                    return Err(EnactError::BadValue);
                }
                self.register_bridged_asset(asset_id, *cap, *epoch_cap, *requires_stark);
                self.record_side_event(SideEvent::AssetRegister {
                    asset_id: *asset_id,
                    cap: *cap,
                    epoch_cap: *epoch_cap,
                    requires_stark: *requires_stark,
                });
                Ok(())
            }
            Action::EpochAdvance => {
                let next = self.bridge_epoch().checked_add(1).ok_or(EnactError::BadValue)?;
                self.set_bridge_epoch(next);
                self.record_side_event(SideEvent::EpochAdvance { epoch: next });
                Ok(())
            }
            Action::Activate { feature, version } => {
                if feature.is_empty() || *version <= self.feature_version(feature) {
                    return Err(EnactError::BadValue);
                }
                self.set_feature_version(feature, *version);
                self.record_side_event(SideEvent::Activate {
                    feature: feature.clone(),
                    version: *version,
                });
                Ok(())
            }
        }
    }

    pub fn guardian_enact_nonce(&self) -> u64 {
        self.trie
            .get(&stake_singleton_key(GUARDIAN_ENACT_NONCE_TAG))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical guardian enact nonce"))
            .unwrap_or(0)
    }

    fn set_guardian_enact_nonce(&mut self, nonce: u64) {
        let key = stake_singleton_key(GUARDIAN_ENACT_NONCE_TAG);
        self.write_leaf(key, to_bytes(&nonce));
    }

    pub fn guardian_enact_bridge_action(
        &mut self,
        action: &Action,
        enact_nonce: u64,
        now: u64,
        chain_id: u64,
    ) -> bool {
        if self.guardian_enact_nonce() != enact_nonce {
            return false;
        }
        let ok = match action {
            Action::CommitteeRotate { .. } | Action::AssetRegister { .. } => {
                self.execute_action(action, now, chain_id).is_ok()
            }
            _ => false,
        };
        if ok {
            self.set_guardian_enact_nonce(enact_nonce.saturating_add(1));
        }
        ok
    }

    pub fn feature_version(&self, feature: &[u8]) -> u64 {
        self.trie
            .get(&feature_gate_key(feature))
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| from_bytes(bytes).expect("state holds a canonical feature version"))
            .unwrap_or(0)
    }

    pub fn feature_active(&self, feature: &[u8]) -> bool {
        self.feature_version(feature) > 0
    }

    fn set_feature_version(&mut self, feature: &[u8], version: u64) {
        self.write_leaf(feature_gate_key(feature), to_bytes(&version));
    }

    pub fn seed_feature_version(&mut self, feature: &[u8], version: u64) -> (Key, Vec<u8>) {
        let key = feature_gate_key(feature);
        let bytes = to_bytes(&version);
        self.write_leaf(key, bytes.clone());
        (key, bytes)
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
            b"bridge_exits" => {
                let enabled = match value {
                    [0] => false,
                    [1] => true,
                    _ => return Err(EnactError::BadValue),
                };
                self.set_bridge_exits_enabled(enabled);
                Ok(())
            }
            b"bridge_payout_cap" => {
                self.set_bridge_payout_cap(u128_from_le(value).ok_or(EnactError::BadValue)?);
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
        self.record_side_event(SideEvent::Bond {
            validator: address.to_string(),
            amount,
            fee,
        });
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
            self.record_side_event(SideEvent::Slash {
                validator: address.to_string(),
                amount: taken,
                disposition: SLASH_DISPOSITION_TREASURY,
            });
        }
        if let qtv_staking::Fault::Attributable = fault {
            self.clear_stake_bond(&id);
            self.set_stake_banned(&id);
            let forfeited = self.stake_rewards_outstanding(&id);
            if forfeited > 0 {
                self.set_stake_treasury(self.stake_treasury() + forfeited);
            }
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
        self.record_side_event(SideEvent::Unbond {
            validator: address.to_string(),
            amount: bond.amount,
        });
        true
    }
}

#[cfg(test)]
mod stake_state_tests {
    use super::*;

    const TEST_CHAIN: u64 = qtv_tx::LOCAL_CHAIN_ID;

    fn gov_addr(tag: u8) -> String {
        qtv_idfmt::render_address(&[tag; 32]).unwrap()
    }

    fn fund(l: &mut Ledger, address: &str, amount: u64) {
        l.set_account(address, &Account::funded(amount, 1, vec![]));
    }

    fn operator_claim(index: u64, operator_id: u32) -> qtv_governance::OperatorClaim {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&index.to_le_bytes());
        let (pk, sk) = qtv_crypto::ml_dsa::keygen(&seed);
        let pop = qtv_crypto::ml_dsa::sign(
            &sk,
            &crate::bridge::operator_pop_challenge(operator_id, &pk, TEST_CHAIN),
            crate::bridge::POP_DOMAIN,
            &[0u8; 32],
        )
        .expect("the pop challenge stays within the length bound")
        .to_vec();
        qtv_governance::OperatorClaim {
            operator_id,
            public_key: pk.to_vec(),
            pop,
        }
    }

    #[test]
    fn a_non_roster_bond_does_not_dilute_the_roster_reward_split() {
        let mut l = Ledger::new();
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        let outsider = [9u8; 32];
        let a1 = qtv_idfmt::render_address(&v1).unwrap();
        let a2 = qtv_idfmt::render_address(&v2).unwrap();
        let ao = qtv_idfmt::render_address(&outsider).unwrap();
        l.seed_validator_set(&[v1, v2]);
        l.seed_validator_bond(&a1, 3_000);
        l.seed_validator_bond(&a2, 2_000);
        l.seed_validator_bond(&ao, 30_000);
        assert_eq!(l.total_staked(), 35_000, "total staked counts every bond");
        assert_eq!(
            l.roster_reward_denominator(),
            5_000,
            "the reward split counts only the roster stake so an outsider cannot dilute it"
        );
    }

    #[test]
    fn a_duplicated_genesis_validator_is_recorded_once() {
        let mut l = Ledger::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        l.seed_validator_set(&[a, b, a]);
        assert_eq!(
            l.validator_ids(),
            vec![a, b],
            "a repeated validator id is recorded once so it cannot accrue twice"
        );
    }

    #[test]
    fn a_contract_call_injects_the_trusted_caller_and_persists_storage() {
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
        assert!(l.call_contract(&caller, &contract, selector, &[], 0, 100_000, 0, None, 0));
        let expected = u64::from_be_bytes([9u8; 8]);
        assert_eq!(
            l.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(0)),
            Some(&expected)
        );

        let empty = qtv_idfmt::render_address(&[71u8; 32]).unwrap();
        assert!(!l.call_contract(&caller, &empty, selector, &[], 0, 100_000, 0, None, 0));
    }

    fn asset_sender_container(selector: [u8; 4]) -> qtv_vm::container::Container {
        let code = qtv_vm::asm::assemble("LDI r1, 88\nLDI r2, 64\nLDI r3, 40\nSEND r1, r2, r3\nHALT")
            .expect("the program assembles");
        qtv_vm::container::Container::new(
            code,
            vec![],
            vec![qtv_vm::container::Entry {
                selector,
                offset: 0,
                access: qtv_vm::container::StateAccess {
                    reads: vec![],
                    writes: vec![],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        )
    }

    #[test]
    fn a_contract_swaps_one_asset_in_for_another_out_and_both_conserve() {
        let selector = [1u8, 2, 3, 4];
        let mut l = Ledger::new();
        let contract_id = [70u8; 32];
        let contract = qtv_idfmt::render_address(&contract_id).unwrap();
        l.set_contract_code(&contract_id, &asset_sender_container(selector).canonical_bytes());

        let caller_id = [9u8; 32];
        let caller = qtv_idfmt::render_address(&caller_id).unwrap();
        let issuer_a = [0xA1u8; 32];
        let issuer_b = [0xB2u8; 32];
        let asset_a = asset_id_of(&issuer_a);
        let asset_b = asset_id_of(&issuer_b);
        l.set_asset_balance(&asset_a, &caller_id, 50);
        l.set_asset_balance(&asset_b, &contract_id, 100);

        let mut payload = vec![0u8; 88];
        payload.extend_from_slice(&issuer_b);
        payload.extend_from_slice(&caller_id);

        assert!(l.call_contract(&caller, &contract, selector, &payload, 0, 1_000_000, 10, Some(issuer_a), 0));

        assert_eq!(l.asset_balance(&asset_a, &caller_id), 40);
        assert_eq!(l.asset_balance(&asset_a, &contract_id), 10);
        assert_eq!(l.asset_balance(&asset_b, &contract_id), 60);
        assert_eq!(l.asset_balance(&asset_b, &caller_id), 40);
        assert_eq!(l.asset_balance(&asset_a, &caller_id) + l.asset_balance(&asset_a, &contract_id), 50);
        assert_eq!(l.asset_balance(&asset_b, &caller_id) + l.asset_balance(&asset_b, &contract_id), 100);
    }

    #[test]
    fn a_deposit_that_would_overflow_the_contract_asset_balance_strands_nothing() {
        let selector = [1u8, 2, 3, 4];
        let mut l = Ledger::new();
        let contract_id = [70u8; 32];
        let contract = qtv_idfmt::render_address(&contract_id).unwrap();
        l.set_contract_code(&contract_id, &asset_sender_container(selector).canonical_bytes());

        let caller_id = [9u8; 32];
        let caller = qtv_idfmt::render_address(&caller_id).unwrap();
        let issuer_a = [0xA1u8; 32];
        let issuer_b = [0xB2u8; 32];
        let asset_a = asset_id_of(&issuer_a);
        let asset_b = asset_id_of(&issuer_b);
        l.set_asset_balance(&asset_a, &contract_id, u128::MAX - 5);
        l.set_asset_balance(&asset_a, &caller_id, 10);
        l.set_asset_balance(&asset_b, &contract_id, 100);

        let mut payload = vec![0u8; 88];
        payload.extend_from_slice(&issuer_b);
        payload.extend_from_slice(&caller_id);

        assert!(!l.call_contract(&caller, &contract, selector, &payload, 0, 1_000_000, 10, Some(issuer_a), 0));
        assert_eq!(l.asset_balance(&asset_a, &caller_id), 10, "the caller keeps its asset, nothing is debited");
        assert_eq!(l.asset_balance(&asset_a, &contract_id), u128::MAX - 5, "the contract balance is untouched");
        assert_eq!(l.asset_balance(&asset_b, &contract_id), 100, "no asset moved on the refused call");
    }

    #[test]
    fn a_contract_cannot_send_more_of_an_asset_than_it_holds() {
        let selector = [1u8, 2, 3, 4];
        let mut l = Ledger::new();
        let contract_id = [70u8; 32];
        let contract = qtv_idfmt::render_address(&contract_id).unwrap();
        l.set_contract_code(&contract_id, &asset_sender_container(selector).canonical_bytes());

        let caller_id = [9u8; 32];
        let caller = qtv_idfmt::render_address(&caller_id).unwrap();
        let issuer_b = [0xB2u8; 32];
        let asset_b = asset_id_of(&issuer_b);
        l.set_asset_balance(&asset_b, &contract_id, 30);

        let mut payload = vec![0u8; 88];
        payload.extend_from_slice(&issuer_b);
        payload.extend_from_slice(&caller_id);

        assert!(!l.call_contract(&caller, &contract, selector, &payload, 0, 1_000_000, 0, None, 0));
        assert_eq!(l.asset_balance(&asset_b, &contract_id), 30);
        assert_eq!(l.asset_balance(&asset_b, &caller_id), 0);
    }

    #[test]
    fn a_call_that_carries_an_asset_the_caller_lacks_is_refused() {
        let selector = [1u8, 2, 3, 4];
        let mut l = Ledger::new();
        let contract_id = [70u8; 32];
        let contract = qtv_idfmt::render_address(&contract_id).unwrap();
        l.set_contract_code(&contract_id, &asset_sender_container(selector).canonical_bytes());
        let issuer_b = [0xB2u8; 32];
        let asset_b = asset_id_of(&issuer_b);
        l.set_asset_balance(&asset_b, &contract_id, 100);

        let caller_id = [9u8; 32];
        let caller = qtv_idfmt::render_address(&caller_id).unwrap();
        let issuer_a = [0xA1u8; 32];
        let asset_a = asset_id_of(&issuer_a);

        let mut payload = vec![0u8; 88];
        payload.extend_from_slice(&issuer_b);
        payload.extend_from_slice(&caller_id);

        assert!(!l.call_contract(&caller, &contract, selector, &payload, 0, 1_000_000, 5, Some(issuer_a), 0));
        assert_eq!(l.asset_balance(&asset_a, &contract_id), 0);
        assert_eq!(l.asset_balance(&asset_b, &contract_id), 100);
    }

    #[test]
    fn a_contract_mints_its_own_asset_to_a_holder_and_grows_supply() {
        let mint_selector: u64 = u32::from_be_bytes(*b"MINT") as u64;
        let code = qtv_vm::asm::assemble(&format!(
            "LDI r1, 88\nLDI r2, 40\nLDI r3, {mint_selector}\nEMIT r1, r2, r3\nHALT"
        ))
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
                    writes: vec![],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );
        let mut l = Ledger::new();
        let contract_id = [70u8; 32];
        let contract = qtv_idfmt::render_address(&contract_id).unwrap();
        l.set_contract_code(&contract_id, &container.canonical_bytes());

        let caller = qtv_idfmt::render_address(&[9u8; 32]).unwrap();
        let holder = [0xCCu8; 32];
        let mut payload = vec![0u8; 88];
        payload.extend_from_slice(&holder);
        payload.extend_from_slice(&40u64.to_be_bytes());

        assert!(l.call_contract(&caller, &contract, selector, &payload, 0, 1_000_000, 0, None, 0));
        let asset = asset_id_of(&contract_id);
        assert_eq!(l.asset_balance(&asset, &holder), 40);
        assert_eq!(l.asset_supply(&asset), 40);
    }

    #[test]
    fn a_contracts_mint_can_only_ever_credit_its_own_asset() {
        let mint_selector: u64 = u32::from_be_bytes(*b"MINT") as u64;
        let code = qtv_vm::asm::assemble(&format!(
            "LDI r1, 88\nLDI r2, 40\nLDI r3, {mint_selector}\nEMIT r1, r2, r3\nHALT"
        ))
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
                    writes: vec![],
                    keyed_reads: vec![],
                    keyed_writes: vec![],
                },
            }],
        );
        let mut l = Ledger::new();
        let contract_id = [70u8; 32];
        let contract = qtv_idfmt::render_address(&contract_id).unwrap();
        l.set_contract_code(&contract_id, &container.canonical_bytes());
        let caller = qtv_idfmt::render_address(&[9u8; 32]).unwrap();

        let mut payload = vec![0u8; 88];
        payload.extend_from_slice(&[0xCCu8; 32]);
        payload.extend_from_slice(&500u64.to_be_bytes());
        assert!(l.call_contract(&caller, &contract, selector, &payload, 0, 1_000_000, 0, None, 0));

        let own = asset_id_of(&contract_id);
        let victim = asset_id_of(&[71u8; 32]);
        assert_eq!(l.asset_supply(&own), 500, "the contract mints its own asset");
        assert_eq!(l.asset_supply(&victim), 0, "another contract's asset is untouched");
        assert_eq!(l.asset_balance(&victim, &[0xCCu8; 32]), 0);
    }

    #[test]
    fn issue_asset_sets_supply_once_and_rejects_reissue_and_zero() {
        let mut l = Ledger::new();
        let issuer = [3u8; 32];
        let holder = [4u8; 32];
        let id = l.issue_asset(&issuer, &holder, 1_000).expect("first issuance succeeds");
        assert_eq!(id, asset_id_of(&issuer));
        assert_eq!(l.asset_supply(&id), 1_000);
        assert_eq!(l.asset_balance(&id, &holder), 1_000);
        assert!(l.issue_asset(&issuer, &holder, 1).is_none(), "an asset id issues only once");
        assert!(l.issue_asset(&[7u8; 32], &holder, 0).is_none(), "a zero supply is not an issuance");
    }

    #[test]
    fn a_contract_sees_the_whole_caller_address_not_a_leading_word() {
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

        assert!(l.call_contract(&c1, &contract, selector, &[], 0, 100_000, 0, None, 0));
        let seen1 = *l.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(0)).unwrap();
        assert_eq!(
            l.contract_storage(&contract_id).get(&qtv_vm::abi::scalar_key(1)),
            Some(&u64::from_be_bytes([70u8; 8]))
        );

        assert!(l.call_contract(&c2, &contract, selector, &[], 0, 100_000, 0, None, 0));
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
        l.seed_validator_bond(&gov_addr(21), 10_000 * 1_000_000);
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
        l.seed_validator_bond(&gov_addr(23), 10_000 * 1_000_000);
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
        l.gov_enact(id, 14 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert_eq!(l.stake_price(), 70_000_000);
        assert!(l.gov_enact(id, 14 * 86_400 + 1, TEST_CHAIN).is_err());
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
                qtv_governance::Action::Activate { feature: vec![], version: 1 },
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
    fn a_governance_vote_activates_a_dormant_feature_without_a_fork() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(41), 10_000 * 1_000_000);
        let proposer = gov_addr(40);
        fund(&mut l, &proposer, 2_250_000 * 1_000_000);
        let voter = gov_addr(41);
        fund(&mut l, &voter, 10_000 * 1_000_000);

        assert!(!l.feature_active(b"parallel_state"));
        assert_eq!(l.feature_version(b"parallel_state"), 0);

        let action = qtv_governance::Action::Activate { feature: b"parallel_state".to_vec(), version: 2 };
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action, 0)
            .unwrap();
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(id, 14 * 86_400 + 1, TEST_CHAIN).unwrap();

        assert!(l.feature_active(b"parallel_state"));
        assert_eq!(l.feature_version(b"parallel_state"), 2);

        assert_eq!(
            l.execute_action(
                &qtv_governance::Action::Activate {
                    feature: b"parallel_state".to_vec(),
                    version: 1,
                },
                14 * 86_400 + 1,
                TEST_CHAIN,
            ),
            Err(EnactError::BadValue),
            "a feature version cannot be lowered by a passed vote"
        );
        assert_eq!(
            l.execute_action(
                &qtv_governance::Action::Activate {
                    feature: b"parallel_state".to_vec(),
                    version: 0,
                },
                14 * 86_400 + 1,
                TEST_CHAIN,
            ),
            Err(EnactError::BadValue),
            "a passed vote cannot deactivate a feature by setting version zero"
        );
        assert_eq!(l.feature_version(b"parallel_state"), 2, "the version stays at its raised value");
    }

    #[test]
    fn a_feature_activation_off_the_chain_upgrade_track_is_refused() {
        let mut l = Ledger::new();
        let proposer = gov_addr(42);
        fund(&mut l, &proposer, 3_000_000 * 1_000_000);
        assert!(l
            .gov_propose(
                &proposer,
                qtv_governance::Track::Mint,
                qtv_governance::Action::Activate { feature: b"parallel_state".to_vec(), version: 1 },
                0,
            )
            .is_none());
        assert_eq!(l.balance(&proposer), 3_000_000 * 1_000_000);
    }

    #[test]
    fn a_parameter_change_is_only_enactable_through_the_chain_upgrade_track() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(32), 10_000 * 1_000_000);
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
        l.gov_enact(id, 14 * 86_400 + 1, TEST_CHAIN).unwrap();
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
            390_000 * qtv_governance::NATIVE_UNIT
        );
    }

    #[test]
    fn a_freeze_reaches_an_ordinary_or_bonded_account_but_never_a_reserved_pot() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(99), 5_000 * 1_000_000);
        let bond_before = l.stake_bond(&[99u8; 32]).unwrap().amount;
        let proposer = gov_addr(40);
        fund(&mut l, &proposer, 400_000 * 1_000_000);
        let ordinary = gov_addr(41);
        let bonded = gov_addr(99);
        let voter = gov_addr(42);
        fund(&mut l, &voter, 20_000 * 1_000_000);
        l.seed_validator_bond(&voter, 5_000 * 1_000_000);

        let hit = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BlacklistKill,
                qtv_governance::Action::Freeze {
                    targets: vec![[41u8; 32].to_vec(), [99u8; 32].to_vec()],
                },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, hit, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert!(!l.is_frozen(&ordinary));
        assert!(!l.is_frozen(&bonded));
        l.gov_enact(hit, 2 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert!(l.is_frozen(&ordinary));
        assert!(l.is_frozen(&bonded), "a bond is not a shield against a freeze");
        assert_eq!(
            l.stake_bond(&[99u8; 32]).unwrap().amount,
            bond_before,
            "the freeze never confiscates the consensus bond"
        );
        assert_eq!(l.total_staked(), 10_000 * 1_000_000);

        let pot = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BlacklistKill,
                qtv_governance::Action::Freeze {
                    targets: vec![sha3::sha3_256(STAKE_TREASURY_TAG).to_vec()],
                },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, pot, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(pot, 2 * 86_400 + 1, TEST_CHAIN),
            Err(EnactError::Constitution(
                qtv_governance::Violation::FreezeTouchesProtected
            ))
        );
        assert!(!l.is_frozen(&stake_treasury_address()));
    }

    #[test]
    fn governance_mints_uncapped_to_the_target_on_the_mint_track() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(25), 10_000 * 1_000_000);
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
        l.gov_enact(id, 3 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert_eq!(l.balance(&target), 1_000_000 * 1_000_000);
    }

    #[test]
    fn a_governance_enactment_leaves_a_side_trace_and_no_side_event_moves_a_consensus_root() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(25), 10_000 * 1_000_000);
        let proposer = gov_addr(24);
        fund(&mut l, &proposer, 4_000_000 * 1_000_000);
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
        l.gov_enact(id, 3 * 86_400 + 1, TEST_CHAIN).unwrap();

        let kinds: Vec<&str> = l.side_events().iter().map(SideEvent::kind).collect();
        assert!(kinds.contains(&"gov_propose"), "the proposal reaches the side log");
        assert!(kinds.contains(&"gov_vote"), "the vote reaches the side log");
        assert!(kinds.contains(&"gov_enact"), "the enactment reaches the side log");
        assert!(kinds.contains(&"mint"), "the enacted mint reaches the side log");

        let q_before = l.q_root();
        let leaves_before: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        let event_root_before = qtv_block::event_root(&leaves_before);
        let side_before = l.side_events().len();

        for tag in 0..16u8 {
            l.record_side_event(SideEvent::Freeze { target: gov_addr(tag) });
        }

        let leaves_after: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        assert_eq!(
            q_before,
            l.q_root(),
            "recording side events must not move the state root"
        );
        assert_eq!(
            event_root_before,
            qtv_block::event_root(&leaves_after),
            "recording side events must not move the block event root"
        );
        assert!(
            l.side_events().len() > side_before,
            "the side log carries the extra observability records"
        );
    }

    #[test]
    fn bridge_side_events_are_root_invariant_and_reach_the_side_log() {
        let mut l = Ledger::new();
        l.record_transfer_event("qtv1payer", "qtv1payee", 10, 1);
        l.record_transfer_event("qtv1other", "qtv1sink", 5, 1);

        let q_before = l.q_root();
        let leaves_before: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        let event_root_before = qtv_block::event_root(&leaves_before);
        let committed_before = l.block_events().len();
        let side_before = l.side_events().len();

        let asset_id = [7u8; 16];
        let party = [9u8; 32];
        let burn_ref = [3u8; 32];
        l.record_side_event(SideEvent::BridgeMint {
            asset_id,
            recipient: party,
            amount: 1_000,
        });
        l.record_side_event(SideEvent::BridgeBurn {
            asset_id,
            holder: party,
            amount: 400,
            destination: [1u8; 32],
            chain_id: 2,
            burn_ref,
        });
        l.record_side_event(SideEvent::BridgeSettle {
            asset_id,
            beneficiary: party,
            amount: 400,
            burn_ref,
        });
        l.record_side_event(SideEvent::BridgeSlash {
            asset_id,
            beneficiary: party,
            amount: 400,
            burn_ref,
        });

        let leaves_after: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        assert_eq!(
            q_before,
            l.q_root(),
            "recording bridge side events must not move the state root"
        );
        assert_eq!(
            event_root_before,
            qtv_block::event_root(&leaves_after),
            "recording bridge side events must not move the block event root"
        );
        assert_eq!(
            committed_before,
            l.block_events().len(),
            "the side log adds no leaf to the committed event log"
        );
        let kinds: Vec<&str> = l.side_events()[side_before..]
            .iter()
            .map(SideEvent::kind)
            .collect();
        assert_eq!(
            kinds,
            vec!["bridge_mint", "bridge_burn", "bridge_settle", "bridge_slash"],
            "every bridge economic transition reaches the node local side log"
        );
    }

    #[test]
    fn a_lone_voter_cannot_carry_a_proposal_against_a_real_governance_electorate() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(90), 10_000_000 * 1_000_000);
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
        l.seed_validator_bond(&solo, 2_000 * 1_000_000);
        assert!(l.gov_vote(&solo, lone, true, qtv_governance::Conviction::Liquid, 2_000 * 1_000_000, 0));
        assert!(
            l.gov_referendum(lone).unwrap().tally.approved(l.gov_total_locked()),
            "the lone vote would have carried under a self referential electorate"
        );
        assert_eq!(
            l.gov_conclude(lone, close),
            Some(qtv_governance::Status::Rejected),
            "against the bonded electorate the lone vote cannot carry"
        );

        let real = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action(), 0)
            .unwrap();
        let backer = gov_addr(90);
        fund(&mut l, &backer, 6_000_000 * 1_000_000);
        assert!(l.gov_vote(&backer, real, true, qtv_governance::Conviction::Liquid, 5_000_000 * 1_000_000, 0));
        assert_eq!(l.gov_conclude(real, close), Some(qtv_governance::Status::Approved));
    }

    #[test]
    fn collapsing_the_live_electorate_after_a_minority_vote_does_not_lower_the_bar() {
        let mut l = Ledger::new();
        let whale = gov_addr(70);
        l.seed_validator_bond(&whale, 10_000_000 * 1_000_000);
        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let proposer = gov_addr(71);
        fund(&mut l, &proposer, 5_000_000 * 1_000_000);
        let id = l
            .gov_propose(&proposer, qtv_governance::Track::ChainUpgrade, action, 0)
            .unwrap();

        let attacker = gov_addr(72);
        fund(&mut l, &attacker, 3_000_000 * 1_000_000);
        l.seed_validator_bond(&attacker, 3_000_000 * 1_000_000);
        assert!(l.gov_vote(
            &attacker,
            id,
            true,
            qtv_governance::Conviction::Liquid,
            3_000_000 * 1_000_000,
            0
        ));

        l.slash_stake(&whale, qtv_staking::Fault::Attributable);
        assert!(l.total_staked() <= 3_000_000 * 1_000_000, "the live stake collapsed");
        assert!(
            l.gov_referendum(id).unwrap().tally.approved(u128::from(l.total_staked())),
            "against the collapsed live electorate the minority would have carried"
        );

        let close = 14 * 86_400 + 1;
        assert_eq!(
            l.gov_conclude(id, close),
            Some(qtv_governance::Status::Rejected),
            "the max of the propose snapshot and the live total keeps the bar at the larger electorate"
        );
    }

    #[test]
    fn a_guardian_caucus_freezes_ahead_of_a_vote_and_a_vote_reverses_it() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(62), 10_000 * 1_000_000);
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[201u8; 32], [202u8; 32], [203u8; 32]],
            2,
        ));

        let target_id = [60u8; 32];
        let target = qtv_idfmt::render_address(&target_id).unwrap();

        assert!(!l.guardian_freeze(0, &[target_id], &[[201u8; 32]], 0));
        assert!(!l.is_frozen(&target));

        assert!(l.guardian_freeze(0, &[target_id], &[[201u8; 32], [202u8; 32]], 0));
        assert!(l.is_frozen(&target));

        let treasury_id = sha3::sha3_256(STAKE_TREASURY_TAG);
        assert!(!l.guardian_freeze(1, &[treasury_id], &[[201u8; 32], [202u8; 32]], 0));
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
        l.gov_enact(id, 2 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert!(!l.is_frozen(&target), "the full vote reversed the emergency freeze");
    }

    #[test]
    fn a_governance_freeze_survives_the_guardian_windows_expiry() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(62), 10_000 * 1_000_000);
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[201u8; 32], [202u8; 32], [203u8; 32]],
            2,
        ));

        let target_id = [60u8; 32];
        let target = qtv_idfmt::render_address(&target_id).unwrap();

        assert!(l.guardian_freeze(0, &[target_id], &[[201u8; 32], [202u8; 32]], 0));
        assert!(l.is_frozen(&target));

        let proposer = gov_addr(61);
        fund(&mut l, &proposer, 400_000 * 1_000_000);
        let voter = gov_addr(62);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        let id = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BlacklistKill,
                qtv_governance::Action::Freeze { targets: vec![target_id.to_vec()] },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(id, 2 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert!(l.is_frozen(&target));

        l.guardian_expire(100 * 86_400);
        assert!(l.is_frozen(&target), "the governance freeze outlives the guardian window");
    }

    #[test]
    fn a_voter_cannot_shrink_the_electorate_by_unbonding_after_a_vote() {
        let mut l = Ledger::new();
        let attacker = gov_addr(1);
        fund(&mut l, &attacker, 3_000_000 * 1_000_000);
        l.seed_validator_bond(&attacker, 30_000 * 1_000_000);
        l.seed_validator_bond(&gov_addr(2), 70_000 * 1_000_000);

        let action = qtv_governance::Action::Parameter {
            key: b"price".to_vec(),
            value: 70_000_000u128.to_le_bytes().to_vec(),
        };
        let id = l
            .gov_propose(&attacker, qtv_governance::Track::ChainUpgrade, action, 0)
            .unwrap();
        assert!(l.gov_vote(
            &attacker,
            id,
            true,
            qtv_governance::Conviction::Liquid,
            30_000 * 1_000_000,
            0
        ));

        assert!(l.request_stake_exit(&attacker, 90));
        assert!(l.withdraw_stake(&attacker, 111));
        assert_eq!(l.total_staked(), 70_000 * 1_000_000);

        assert_eq!(
            l.gov_conclude(id, 200 * 86_400),
            Some(qtv_governance::Status::Rejected),
            "a post vote unbond must not shrink the electorate into an approval"
        );
    }

    #[test]
    fn a_consumed_guardian_freeze_act_cannot_be_replayed_past_a_vote() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(72), 10_000 * 1_000_000);
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[201u8; 32], [202u8; 32], [203u8; 32]],
            2,
        ));

        let target_id = [0x71u8; 32];
        let target = qtv_idfmt::render_address(&target_id).unwrap();

        assert_eq!(l.guardian_freeze_epoch(), 0);
        assert!(l.guardian_freeze(0, &[target_id], &[[201u8; 32], [202u8; 32]], 0));
        assert!(l.is_frozen(&target));
        assert_eq!(l.guardian_freeze_epoch(), 1, "the freeze consumes its epoch");

        let proposer = gov_addr(71);
        fund(&mut l, &proposer, 400_000 * 1_000_000);
        let voter = gov_addr(72);
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
        l.gov_enact(id, 2 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert!(!l.is_frozen(&target), "a vote clears the account freeze");

        assert!(
            !l.guardian_freeze(0, &[target_id], &[[201u8; 32], [202u8; 32]], 0),
            "the consumed act replayed at the old epoch is refused"
        );
        assert!(!l.is_frozen(&target), "the replayed act never re-freezes the account");

        assert!(
            l.guardian_freeze(1, &[target_id], &[[201u8; 32], [202u8; 32]], 0),
            "a fresh quorum signing the current epoch can still freeze"
        );
        assert!(l.is_frozen(&target));
        assert_eq!(l.guardian_freeze_epoch(), 2);
    }

    #[test]
    fn a_guardian_freeze_lifts_itself_when_its_window_passes() {
        let mut l = Ledger::new();
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[201u8; 32], [202u8; 32], [203u8; 32]],
            2,
        ));
        let target_id = [0x44u8; 32];
        let target = qtv_idfmt::render_address(&target_id).unwrap();
        let now = 1_000_000u64;
        assert!(l.guardian_freeze(0, &[target_id], &[[201u8; 32], [202u8; 32]], now));
        assert!(l.is_frozen(&target), "the caucus freeze takes effect");
        l.guardian_expire(now + GUARDIAN_FREEZE_WINDOW_SECONDS - 1);
        assert!(l.is_frozen(&target), "the freeze holds inside its window");
        l.guardian_expire(now + GUARDIAN_FREEZE_WINDOW_SECONDS);
        assert!(!l.is_frozen(&target), "the freeze lifts itself once the window passes with no confirming vote");
    }

    #[test]
    fn a_confirmed_guardian_freeze_is_not_lifted_by_the_window_sweep() {
        let mut l = Ledger::new();
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[201u8; 32], [202u8; 32], [203u8; 32]],
            2,
        ));
        let target_id = [0x45u8; 32];
        let target = qtv_idfmt::render_address(&target_id).unwrap();
        let now = 2_000_000u64;
        assert!(l.guardian_freeze(0, &[target_id], &[[201u8; 32], [202u8; 32]], now));
        l.guardian_freeze_forget(&[target_id]);
        l.guardian_expire(now + GUARDIAN_FREEZE_WINDOW_SECONDS + 1);
        assert!(l.is_frozen(&target), "a confirmed freeze is not lifted by the window sweep");
    }

    #[test]
    fn two_concurrent_guardian_freezes_each_expire_on_their_own_window() {
        let mut l = Ledger::new();
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[201u8; 32], [202u8; 32], [203u8; 32]],
            2,
        ));
        let a_id = [0x51u8; 32];
        let b_id = [0x52u8; 32];
        let a = qtv_idfmt::render_address(&a_id).unwrap();
        let b = qtv_idfmt::render_address(&b_id).unwrap();
        let t0 = 1_000_000u64;
        assert!(l.guardian_freeze(0, &[a_id], &[[201u8; 32], [202u8; 32]], t0));
        let t1 = t0 + 3 * 86_400;
        assert!(l.guardian_freeze(1, &[b_id], &[[201u8; 32], [202u8; 32]], t1));
        assert!(l.is_frozen(&a) && l.is_frozen(&b), "both freezes are live");
        l.guardian_expire(t0 + GUARDIAN_FREEZE_WINDOW_SECONDS);
        assert!(!l.is_frozen(&a), "the first freeze lifts on its own window");
        assert!(l.is_frozen(&b), "the second freeze is untouched by the first expiring");
        l.guardian_expire(t1 + GUARDIAN_FREEZE_WINDOW_SECONDS);
        assert!(!l.is_frozen(&b), "the second freeze lifts on its own window");
    }

    #[test]
    fn a_passed_vote_pays_out_of_the_keyless_pots_and_nothing_else_can() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(51), 10_000 * 1_000_000);
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
        let pass = |l: &mut Ledger, action: qtv_governance::Action, stake: u64| {
            let id = l
                .gov_propose(&proposer, qtv_governance::Track::Mint, action, 0)
                .unwrap();
            l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, stake, 0);
            id
        };

        let from_grants = pass(
            &mut l,
            qtv_governance::Action::Spend {
                from: sha3::sha3_256(b"qtv/gov/grants").to_vec(),
                to: [52u8; 32].to_vec(),
                amount: 12_000 * 1_000_000,
            },
            5_000 * 1_000_000,
        );
        l.gov_enact(from_grants, 3 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert_eq!(l.balance(&recipient), 12_000 * 1_000_000);
        assert_eq!(l.balance(&grants), 28_000 * 1_000_000);

        let from_treasury = pass(
            &mut l,
            qtv_governance::Action::Spend {
                from: stake_singleton_key(STAKE_TREASURY_TAG).to_vec(),
                to: [52u8; 32].to_vec(),
                amount: 5_000 * 1_000_000,
            },
            5_000 * 1_000_000,
        );
        l.gov_enact(from_treasury, 3 * 86_400 + 1, TEST_CHAIN).unwrap();
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
            10_000 * 1_000_000,
        );
        assert_eq!(l.gov_enact(steal, 3 * 86_400 + 1, TEST_CHAIN), Err(EnactError::BadAddress));
        assert_eq!(l.balance(&user), 9_000 * 1_000_000);
    }

    #[test]
    fn a_recovery_reaches_a_thiefs_free_balance_and_its_staked_bond() {
        let mut l = Ledger::new();
        let proposer = gov_addr(26);
        fund(&mut l, &proposer, 300_000 * 1_000_000);
        let thief = gov_addr(41);
        l.seed_validator_bond(&thief, 2_000 * 1_000_000);
        fund(&mut l, &thief, 5_000 * 1_000_000);
        l.set_frozen(&[41u8; 32]);
        let victim = gov_addr(40);
        let supply_before = l.total_supply();

        let seizures = vec![qtv_governance::Seizure {
            from: [41u8; 32].to_vec(),
            amount: 7_000 * 1_000_000,
        }];
        let scope = sha3::sha3_256(&qtv_governance::Action::recovery_scope_preimage(
            TEST_CHAIN,
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
        l.seed_validator_bond(&voter, 5_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(id, 6 * 3_600 + 1, TEST_CHAIN).unwrap();

        assert_eq!(l.balance(&thief), 0, "the thief's free balance is recovered");
        assert!(
            l.stake_bond(&[41u8; 32]).is_none(),
            "the staked loot is recovered so it can never buy consensus"
        );
        assert_eq!(
            l.balance(&victim),
            7_000 * 1_000_000,
            "the victim is made whole from the free balance and the bond"
        );
        assert_eq!(l.total_staked(), 5_000 * 1_000_000, "only the honest voter's bond remains staked");
        assert_eq!(l.total_supply(), supply_before, "the recovery moves value between buckets and conserves supply");
    }

    #[test]
    fn a_recovery_still_cannot_seize_a_reserved_protocol_pot() {
        let mut l = Ledger::new();
        let proposer = gov_addr(26);
        fund(&mut l, &proposer, 300_000 * 1_000_000);
        let pot = sha3::sha3_256(b"qtv/stake/treasury");
        let seizures = vec![qtv_governance::Seizure { from: pot.to_vec(), amount: 1_000 }];
        let scope = sha3::sha3_256(&qtv_governance::Action::recovery_scope_preimage(
            TEST_CHAIN,
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
        l.seed_validator_bond(&voter, 5_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert!(
            l.gov_enact(id, 6 * 3_600 + 1, TEST_CHAIN).is_err(),
            "a recovery aimed at a reserved protocol pot is refused"
        );
    }

    #[test]
    fn a_recovery_cannot_reach_the_stake_of_a_validator_that_was_never_frozen() {
        let mut l = Ledger::new();
        let proposer = gov_addr(26);
        fund(&mut l, &proposer, 300_000 * 1_000_000);
        let honest = gov_addr(41);
        l.seed_validator_bond(&honest, 2_000 * 1_000_000);
        fund(&mut l, &honest, 5_000 * 1_000_000);
        let victim = gov_addr(40);

        let seizures = vec![qtv_governance::Seizure { from: [41u8; 32].to_vec(), amount: 7_000 * 1_000_000 }];
        let scope = sha3::sha3_256(&qtv_governance::Action::recovery_scope_preimage(TEST_CHAIN, &[40u8; 32], &seizures));
        let action = qtv_governance::Action::FreezeRecovery { scope, victim: [40u8; 32].to_vec(), seizures };
        let id = l.gov_propose(&proposer, qtv_governance::Track::FreezeRecovery, action, 0).unwrap();
        let voter = gov_addr(27);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        l.seed_validator_bond(&voter, 5_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(id, 6 * 3_600 + 1, TEST_CHAIN).unwrap();

        assert_eq!(l.balance(&honest), 0, "the free balance is still recovered");
        assert_eq!(
            l.stake_bond(&[41u8; 32]).unwrap().amount,
            2_000 * 1_000_000,
            "the stake of a validator that was never frozen is untouched"
        );
        assert_eq!(l.balance(&victim), 5_000 * 1_000_000, "the victim receives only the free balance");
    }

    #[test]
    fn a_partial_bond_recovery_dissolves_the_whole_bond_and_returns_the_residue() {
        let mut l = Ledger::new();
        let proposer = gov_addr(26);
        fund(&mut l, &proposer, 300_000 * 1_000_000);
        let thief = gov_addr(41);
        l.seed_validator_bond(&thief, 2_000 * 1_000_000);
        fund(&mut l, &thief, 5_000 * 1_000_000);
        l.set_frozen(&[41u8; 32]);
        let victim = gov_addr(40);
        let supply_before = l.total_supply();

        let seizures = vec![qtv_governance::Seizure { from: [41u8; 32].to_vec(), amount: 5_500 * 1_000_000 }];
        let scope = sha3::sha3_256(&qtv_governance::Action::recovery_scope_preimage(TEST_CHAIN, &[40u8; 32], &seizures));
        let action = qtv_governance::Action::FreezeRecovery { scope, victim: [40u8; 32].to_vec(), seizures };
        let id = l.gov_propose(&proposer, qtv_governance::Track::FreezeRecovery, action, 0).unwrap();
        let voter = gov_addr(27);
        fund(&mut l, &voter, 10_000 * 1_000_000);
        l.seed_validator_bond(&voter, 5_000 * 1_000_000);
        l.gov_vote(&voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(id, 6 * 3_600 + 1, TEST_CHAIN).unwrap();

        assert!(l.stake_bond(&[41u8; 32]).is_none(), "the whole bond is dissolved so no dust weight lingers");
        assert_eq!(l.balance(&victim), 5_500 * 1_000_000, "the victim gets the free balance plus the seized bond part");
        assert_eq!(l.balance(&thief), 1_500 * 1_000_000, "the unseized bond residue returns to the holder free balance");
        assert_eq!(l.total_staked(), 5_000 * 1_000_000, "the whole bond left the stake, only the voter remains");
        assert_eq!(l.total_supply(), supply_before, "the recovery conserves supply");
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
        l.seed_validator_bond(&voter, 4_000 * 1_000_000);
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

        assert_eq!(l.accrue_reward(&addr, 400), 0);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);

        l.set_stake_mainnet_start(0);
        let emission = qtv_staking::SESSION_EMISSION;
        assert_eq!(l.accrue_reward(&addr, 400), emission);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000 - emission);

        assert_eq!(l.claimable_reward(&addr, 400 + 364), 0);
        assert_eq!(l.claimable_reward(&addr, 400 + 365), emission);
        assert_eq!(l.claim_reward(&addr, 400 + 365), emission);
        assert_eq!(l.balance(&addr), emission);
        assert_eq!(l.claim_reward(&addr, 400 + 365), 0);
        assert_eq!(l.claimable_reward(&addr, 400 + 365 + 1_000), 0);
    }

    #[test]
    fn a_gov_blacklisted_validator_accrues_nothing_and_does_not_drain_the_pool() {
        let mut l = Ledger::new();
        let id = [77u8; 32];
        let addr = qtv_idfmt::render_address(&id).unwrap();
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        l.set_stake_mainnet_start(0);
        l.set_gov_blacklisted(&id);
        assert_eq!(l.accrue_reward(&addr, 400), 0);
        assert_eq!(l.stake_pool(), 700_000 * 1_000_000);
    }

    #[test]
    fn a_reward_claim_records_the_spendable_credit_as_a_root_invariant_side_event() {
        let mut l = Ledger::new();
        let addr = qtv_idfmt::render_address(&[21u8; 32]).unwrap();
        l.seed_stake_pool(700_000 * 1_000_000);
        l.seed_validator_bond(&addr, 2_000 * 1_000_000);
        l.set_stake_mainnet_start(0);
        let emission = qtv_staking::SESSION_EMISSION;
        assert_eq!(l.accrue_reward(&addr, 400), emission);

        assert_eq!(l.balance(&addr), 0);
        let after_accrual: Vec<&str> = l.side_events().iter().map(SideEvent::kind).collect();
        assert!(after_accrual.contains(&"reward"));
        assert!(!after_accrual.contains(&"reward_claim"));

        let leaves_before: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        let event_root_before = qtv_block::event_root(&leaves_before);
        let committed_before = l.block_events().len();

        let credited = l.claim_reward(&addr, 400 + 365);
        assert_eq!(credited, emission);
        assert_eq!(l.balance(&addr), emission, "the claim credits the spendable balance");

        let claim = l
            .side_events()
            .iter()
            .find(|event| event.kind() == "reward_claim")
            .expect("the claim records a reward_claim side event");
        match claim {
            SideEvent::RewardClaim { validator, amount } => {
                assert_eq!(validator, &addr);
                assert_eq!(*amount, credited, "the side event carries the exact spendable credit");
            }
            other => panic!("expected a reward_claim, got {other:?}"),
        }

        let leaves_after: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        assert_eq!(l.block_events().len(), committed_before);
        assert_eq!(event_root_before, qtv_block::event_root(&leaves_after));

        let q_fixed = l.q_root();
        for tag in 0..8u8 {
            l.record_side_event(SideEvent::Freeze { target: gov_addr(tag) });
        }
        let leaves_marker: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        assert_eq!(q_fixed, l.q_root(), "a side event moves no state root");
        assert_eq!(event_root_before, qtv_block::event_root(&leaves_marker));
    }

    #[test]
    fn a_slash_side_event_names_its_supply_disposition_and_the_field_stays_off_every_root() {
        let mut burn = Ledger::new();
        let v1 = qtv_idfmt::render_address(&[31u8; 32]).unwrap();
        burn.credit_supply(5_000 * 1_000_000);
        burn.seed_validator_bond(&v1, 2_000 * 1_000_000);
        let supply_before = burn.total_supply();
        assert!(burn.slash_validator(&v1));
        assert_eq!(
            burn.total_supply(),
            supply_before - 2_000 * 1_000_000,
            "a burn slash removes the bond from the supply",
        );
        let burn_event = burn
            .side_events()
            .iter()
            .find(|event| event.kind() == "slash")
            .expect("a burn slash records a slash side event");
        let burn_leaf = match burn.block_events().iter().find(|event| event.selector == EVENT_SLASH) {
            Some(event) => event.encode(),
            None => panic!("a burn slash records a committed slash event"),
        };
        match burn_event {
            SideEvent::Slash { disposition, amount, .. } => {
                assert_eq!(*disposition, SLASH_DISPOSITION_BURN);
                assert_eq!(*amount, 2_000 * 1_000_000);
            }
            other => panic!("expected a slash, got {other:?}"),
        }

        let mut treasury = Ledger::new();
        let v2 = qtv_idfmt::render_address(&[31u8; 32]).unwrap();
        treasury.credit_supply(5_000 * 1_000_000);
        treasury.set_account(&v2, &Account::funded(3_000 * 1_000_000, 1, vec![]));
        treasury.credit_supply(3_000 * 1_000_000);
        assert!(treasury.bond(&v2, 2_000 * 1_000_000, 0));
        let supply_held = treasury.total_supply();
        assert_eq!(
            treasury.slash_stake(&v2, qtv_staking::Fault::Attributable),
            2_000 * 1_000_000,
        );
        assert_eq!(treasury.total_supply(), supply_held, "a treasury slash leaves the supply fixed");
        assert_eq!(treasury.stake_treasury(), 2_000 * 1_000_000, "the bond lands in the treasury");
        let treasury_event = treasury
            .side_events()
            .iter()
            .find(|event| event.kind() == "slash")
            .expect("a treasury slash records a slash side event");
        let treasury_leaf = match treasury.block_events().iter().find(|event| event.selector == EVENT_SLASH) {
            Some(event) => event.encode(),
            None => panic!("a treasury slash records a committed slash event"),
        };
        match treasury_event {
            SideEvent::Slash { disposition, amount, .. } => {
                assert_eq!(*disposition, SLASH_DISPOSITION_TREASURY);
                assert_eq!(*amount, 2_000 * 1_000_000);
            }
            other => panic!("expected a slash, got {other:?}"),
        }

        assert_eq!(
            burn_leaf, treasury_leaf,
            "the disposition never enters the committed slash event",
        );
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
    fn a_slash_disposes_the_forfeited_reward_and_conserves_supply() {
        let emission = qtv_staking::SESSION_EMISSION;
        let pool = 700_000 * 1_000_000;
        let bond = 2_000 * 1_000_000;

        let mut burn = Ledger::new();
        let v1 = qtv_idfmt::render_address(&[19u8; 32]).unwrap();
        burn.credit_supply(pool + bond);
        burn.seed_stake_pool(pool);
        burn.seed_validator_bond(&v1, bond);
        burn.set_stake_mainnet_start(0);
        assert_eq!(burn.accrue_reward(&v1, 400), emission);
        let supply_before = burn.total_supply();
        assert!(burn.slash_validator(&v1));
        assert_eq!(
            burn.total_supply(),
            supply_before - bond - emission,
            "a burn slash removes the bond and the forfeited reward from the supply",
        );

        let mut treasury = Ledger::new();
        let v2 = qtv_idfmt::render_address(&[20u8; 32]).unwrap();
        treasury.credit_supply(pool + bond);
        treasury.seed_stake_pool(pool);
        treasury.seed_validator_bond(&v2, bond);
        treasury.set_stake_mainnet_start(0);
        assert_eq!(treasury.accrue_reward(&v2, 400), emission);
        let supply_held = treasury.total_supply();
        assert_eq!(treasury.slash_stake(&v2, qtv_staking::Fault::Attributable), bond);
        assert_eq!(
            treasury.total_supply(),
            supply_held,
            "a treasury slash leaves the supply fixed",
        );
        assert_eq!(
            treasury.stake_treasury(),
            bond + emission,
            "the treasury absorbs the bond and the forfeited reward",
        );
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
        assert_eq!(l.balance(&freezer), 1_610_000 * 1_000_000, "the bond leaves the caller");
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
    fn a_guardian_caucus_lifts_the_bridge_freeze_and_slashes_the_bond() {
        let mut l = Ledger::new();
        let freezer = gov_addr(75);
        let bond = qtv_governance::BRIDGE_FREEZE_BOND;
        fund(&mut l, &freezer, 390_000 * 1_000_000);
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            2,
        ));
        assert!(l.bridge_freeze_with_fee(&freezer, 0, 500));
        assert_eq!(l.balance(&freezer), 0, "the bond leaves the freezer");

        assert!(
            !l.guardian_bridge_unfreeze(&[[1u8; 32]], 600),
            "one guardian is not a caucus"
        );
        assert!(l.bridge_is_frozen());

        assert!(l.guardian_bridge_unfreeze(&[[1u8; 32], [2u8; 32]], 600));
        assert!(!l.bridge_is_frozen());
        assert_eq!(
            l.balance(&freezer),
            0,
            "a guardian override treats the freeze as malicious and never refunds the bond"
        );
        assert_eq!(
            l.stake_treasury(),
            bond,
            "the slashed bond lands in the treasury"
        );
        assert_eq!(l.balance(&bridge_bond_address()), 0);
        assert_eq!(l.bridge_last_lift(), Some(600));
    }

    #[test]
    fn a_governance_early_unfreeze_slashes_the_bond_to_the_treasury() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(85), 10_000 * 1_000_000);
        let bond = qtv_governance::BRIDGE_FREEZE_BOND;
        let freezer = gov_addr(83);
        fund(&mut l, &freezer, 390_000 * 1_000_000);
        assert!(l.bridge_freeze_with_fee(&freezer, 0, 100));

        let proposer = gov_addr(84);
        fund(&mut l, &proposer, 1_500_000 * 1_000_000);
        let voter = gov_addr(85);
        fund(&mut l, &voter, 10_000 * 1_000_000);

        let unseen = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BlacklistKill,
                qtv_governance::Action::BridgeUnfreeze,
                0,
            )
            .unwrap();
        l.gov_vote(&voter, unseen, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(unseen, 5 * 86_400 + 1, TEST_CHAIN).unwrap();

        assert!(!l.bridge_is_frozen(), "the vote lifts the freeze ahead of its horizon");
        assert_eq!(
            l.balance(&freezer),
            0,
            "a governance lift never refunds the freezer"
        );
        assert_eq!(l.stake_treasury(), bond, "the slashed bond lands in the treasury");
        assert_eq!(l.bridge_last_lift(), Some(5 * 86_400 + 1));
    }

    #[test]
    fn a_governance_early_unfreeze_needs_a_frozen_bridge() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(87), 10_000 * 1_000_000);
        let proposer = gov_addr(86);
        fund(&mut l, &proposer, 1_500_000 * 1_000_000);
        let voter = gov_addr(87);
        fund(&mut l, &voter, 10_000 * 1_000_000);

        let open = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BlacklistKill,
                qtv_governance::Action::BridgeUnfreeze,
                0,
            )
            .unwrap();
        l.gov_vote(&voter, open, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(open, 5 * 86_400 + 1, TEST_CHAIN),
            Err(EnactError::BridgeNotFrozen),
            "an early unfreeze is refused when no freeze is active"
        );
    }

    #[test]
    fn only_a_vote_rotates_the_guardian_set_and_a_malformed_set_is_refused() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(89), 10_000 * 1_000_000);
        l.set_guardian_set(&qtv_governance::GuardianSet::new(
            vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            2,
        ));
        let proposer = gov_addr(88);
        fund(&mut l, &proposer, 2_250_000 * 1_000_000);
        let voter = gov_addr(89);
        fund(&mut l, &voter, 10_000 * 1_000_000);

        let thin = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::ChainUpgrade,
                qtv_governance::Action::GuardianRotate {
                    set: qtv_governance::GuardianSet::new(vec![[5u8; 32]], 2),
                },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, thin, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(thin, 14 * 86_400 + 1, TEST_CHAIN),
            Err(EnactError::BadValue),
            "a set whose threshold outruns its membership never lands"
        );
        assert_eq!(
            l.guardian_set().members,
            vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            "the malformed rotation left the seeded caucus untouched"
        );

        let rotate = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::ChainUpgrade,
                qtv_governance::Action::GuardianRotate {
                    set: qtv_governance::GuardianSet::new(vec![[10u8; 32], [11u8; 32], [12u8; 32]], 3),
                },
                14 * 86_400 + 2,
            )
            .unwrap();
        l.gov_vote(&voter, rotate, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 14 * 86_400 + 2);
        l.gov_enact(rotate, 28 * 86_400 + 3, TEST_CHAIN).unwrap();
        assert_eq!(l.guardian_set().threshold, 3);
        assert_eq!(l.guardian_set().members, vec![[10u8; 32], [11u8; 32], [12u8; 32]]);
    }

    #[test]
    fn only_a_vote_rotates_the_committee_and_a_key_without_a_pop_is_refused() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(91), 10_000 * 1_000_000);
        let proposer = gov_addr(90);
        fund(&mut l, &proposer, 4_000_000 * 1_000_000);
        let voter = gov_addr(91);
        fund(&mut l, &voter, 30_000 * 1_000_000);

        assert!(
            l.bridge_operator_set().is_none(),
            "the bridge starts with no committee and is inert"
        );

        let mut forged = qtv_governance::CommitteeRotation {
            operators: vec![operator_claim(1, 0), operator_claim(2, 1)],
            threshold: 2,
        };
        let pop_len = forged.operators[1].pop.len();
        forged.operators[1].pop = vec![0u8; pop_len];
        let bad = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::CommitteeRotate { rotation: forged },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, bad, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(bad, 5 * 86_400 + 1, TEST_CHAIN),
            Err(EnactError::BadValue),
            "a key that cannot prove possession sinks the whole rotation"
        );
        assert!(l.bridge_operator_set().is_none(), "the failed rotation left the bridge inert");

        let good = qtv_governance::CommitteeRotation {
            operators: vec![operator_claim(1, 0), operator_claim(2, 1), operator_claim(3, 2)],
            threshold: 2,
        };
        let rotate = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::CommitteeRotate { rotation: good },
                5 * 86_400 + 2,
            )
            .unwrap();
        l.gov_vote(&voter, rotate, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 5 * 86_400 + 2);
        l.gov_enact(rotate, 10 * 86_400 + 3, TEST_CHAIN).unwrap();
        let set = l.bridge_operator_set().unwrap();
        assert_eq!(set.operators.len(), 3);
        assert_eq!(set.threshold, 2);
        assert!(set.revoked.is_empty());

        let revoke = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::OperatorRevoke { operator_id: 1 },
                10 * 86_400 + 4,
            )
            .unwrap();
        l.gov_vote(&voter, revoke, true, qtv_governance::Conviction::Liquid, 10_000 * 1_000_000, 10 * 86_400 + 4);
        l.gov_enact(revoke, 15 * 86_400 + 5, TEST_CHAIN).unwrap();
        assert!(
            l.bridge_operator_set().unwrap().is_revoked(1),
            "a vote strikes a single operator from the seated committee"
        );
    }

    #[test]
    fn a_committee_rotation_refuses_a_shared_key_and_a_thin_threshold() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(95), 10_000 * 1_000_000);
        let proposer = gov_addr(94);
        fund(&mut l, &proposer, 4_000_000 * 1_000_000);
        let voter = gov_addr(95);
        fund(&mut l, &voter, 30_000 * 1_000_000);

        let shared = qtv_governance::CommitteeRotation {
            operators: vec![operator_claim(5, 0), operator_claim(5, 1), operator_claim(6, 2)],
            threshold: 2,
        };
        let dup = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::CommitteeRotate { rotation: shared },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, dup, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(dup, 5 * 86_400 + 1, TEST_CHAIN),
            Err(EnactError::BadValue),
            "two operator ids may not share one public key"
        );
        assert!(l.bridge_operator_set().is_none(), "the shared key rotation left the bridge inert");

        let thin = qtv_governance::CommitteeRotation {
            operators: vec![operator_claim(1, 0), operator_claim(2, 1)],
            threshold: 1,
        };
        let single = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::CommitteeRotate { rotation: thin },
                5 * 86_400 + 2,
            )
            .unwrap();
        l.gov_vote(&voter, single, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 5 * 86_400 + 2);
        assert_eq!(
            l.gov_enact(single, 10 * 86_400 + 3, TEST_CHAIN),
            Err(EnactError::BadValue),
            "a committee needs a threshold of at least two"
        );
        assert!(l.bridge_operator_set().is_none(), "the thin threshold rotation left the bridge inert");
    }

    #[test]
    fn a_committee_rotation_refuses_a_sub_supermajority_threshold() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(91), 10_000 * 1_000_000);
        let proposer = gov_addr(90);
        fund(&mut l, &proposer, 4_000_000 * 1_000_000);
        let voter = gov_addr(91);
        fund(&mut l, &voter, 30_000 * 1_000_000);

        let below = qtv_governance::CommitteeRotation {
            operators: vec![
                operator_claim(1, 0),
                operator_claim(2, 1),
                operator_claim(3, 2),
                operator_claim(4, 3),
            ],
            threshold: 2,
        };
        let weak = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::CommitteeRotate { rotation: below },
                0,
            )
            .unwrap();
        l.gov_vote(&voter, weak, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        assert_eq!(
            l.gov_enact(weak, 5 * 86_400 + 1, TEST_CHAIN),
            Err(EnactError::BadValue),
            "a committee threshold below a two thirds supermajority is refused"
        );
        assert!(
            l.bridge_operator_set().is_none(),
            "the sub supermajority rotation left the bridge inert"
        );
    }

    #[test]
    fn a_vote_advances_the_bridge_epoch_and_registers_an_asset() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(93), 10_000 * 1_000_000);
        let proposer = gov_addr(92);
        fund(&mut l, &proposer, 3_000_000 * 1_000_000);
        let voter = gov_addr(93);
        fund(&mut l, &voter, 20_000 * 1_000_000);

        assert_eq!(l.bridge_epoch(), 0);
        let advance = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::EpochAdvance,
                0,
            )
            .unwrap();
        l.gov_vote(&voter, advance, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 0);
        l.gov_enact(advance, 5 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert_eq!(l.bridge_epoch(), 1, "only a vote advances the epoch");

        let asset = [0xA1u8; 16];
        assert!(l.bridged_asset(&asset).is_none());
        let register = l
            .gov_propose(
                &proposer,
                qtv_governance::Track::BridgeMigration,
                qtv_governance::Action::AssetRegister {
                    asset_id: asset,
                    cap: 1_000_000,
                    epoch_cap: 250_000,
                    requires_stark: true,
                },
                5 * 86_400 + 2,
            )
            .unwrap();
        l.gov_vote(&voter, register, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, 5 * 86_400 + 2);
        l.gov_enact(register, 10 * 86_400 + 3, TEST_CHAIN).unwrap();
        let registered = l.bridged_asset(&asset).unwrap();
        assert_eq!(registered.cap, 1_000_000);
        assert_eq!(registered.epoch_cap, 250_000);
        assert!(registered.requires_stark);
    }

    #[test]
    fn a_bridge_migration_needs_a_frozen_bridge_and_records_the_new_vault() {
        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(81), 10_000 * 1_000_000);
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
            l.gov_enact(open, 5 * 86_400 + 1, TEST_CHAIN),
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
        l.gov_enact(migrate, 5 * 86_400 + 1, TEST_CHAIN).unwrap();
        assert_eq!(
            l.bridge_pool_vault(),
            Some([0x0Cu8; 32]),
            "the migration records the designated pool vault"
        );
        assert!(l.bridge_is_frozen(), "the freeze still holds through the migration");
    }

    #[test]
    fn a_governance_migration_routes_bridged_custody_to_the_new_vault() {
        fn migrate(l: &mut Ledger, proposer: &str, voter: &str, vault: Vec<u8>, at: u64) {
            let id = l
                .gov_propose(
                    proposer,
                    qtv_governance::Track::BridgeMigration,
                    qtv_governance::Action::BridgeMigration { vault },
                    at,
                )
                .unwrap();
            l.gov_vote(voter, id, true, qtv_governance::Conviction::Liquid, 5_000 * 1_000_000, at);
            l.gov_enact(id, at + 5 * 86_400 + 1, TEST_CHAIN).unwrap();
        }

        let mut l = Ledger::new();
        l.seed_validator_bond(&gov_addr(97), 10_000 * 1_000_000);
        let proposer = gov_addr(96);
        fund(&mut l, &proposer, 3_000_000 * 1_000_000);
        let voter = gov_addr(97);
        fund(&mut l, &voter, 20_000 * 1_000_000);
        let freezer = gov_addr(98);
        fund(&mut l, &freezer, 1_500_000 * 1_000_000);

        let asset = [0xB2u8; 16];
        let recipient = [0xEEu8; 32];
        l.register_bridged_asset(&asset, 10_000_000, 10_000_000, false);
        assert!(l.bridge_freeze_with_fee(&freezer, 0, 0));

        let vault_a = [0x0Au8; 32];
        let vault_b = [0x0Bu8; 32];
        migrate(&mut l, &proposer, &voter, vault_a.to_vec(), 0);
        assert_eq!(l.bridge_pool_vault(), Some(vault_a));

        assert!(l.bridge_mint(&crate::bridge::Fact {
            version: crate::bridge::FACT_VERSION,
            source_chain: 1,
            dest_chain: 9_000,
            route_id: 7,
            direction: crate::bridge::Direction::Deposit,
            nonce: 1,
            source_ref: [0x01u8; 32],
            asset_id: asset,
            amount: 1_000,
            recipient,
            finality_depth: 6,
            observed_height: 10,
            expiry_height: 100,
        }));
        assert_eq!(
            l.bridge_vault_custody(&vault_a, &asset),
            1_000,
            "a mint credits the vault that controls the bridge at the time"
        );

        migrate(&mut l, &proposer, &voter, vault_b.to_vec(), 6 * 86_400);
        assert_eq!(l.bridge_pool_vault(), Some(vault_b));
        assert_eq!(
            l.bridge_vault_custody(&vault_b, &asset),
            1_000,
            "the migration carries the old vault's custody to the new vault"
        );
        assert_eq!(
            l.bridge_vault_custody(&vault_a, &asset),
            0,
            "the migration empties the old vault it moved custody from"
        );

        assert!(l.bridge_mint(&crate::bridge::Fact {
            version: crate::bridge::FACT_VERSION,
            source_chain: 1,
            dest_chain: 9_000,
            route_id: 7,
            direction: crate::bridge::Direction::Deposit,
            nonce: 2,
            source_ref: [0x02u8; 32],
            asset_id: asset,
            amount: 2_000,
            recipient,
            finality_depth: 6,
            observed_height: 10,
            expiry_height: 100,
        }));
        assert_eq!(
            l.bridge_vault_custody(&vault_b, &asset),
            3_000,
            "a fresh mint adds to the carried custody in the new vault"
        );
        assert_eq!(l.bridge_vault_custody(&vault_a, &asset), 0);

        assert!(l.bridge_burn(&asset, &recipient, 500, &[0x07u8; 32], 42, 1));
        assert_eq!(
            l.bridge_vault_custody(&vault_b, &asset),
            3_000,
            "the burn retires supply but leaves the migrated vault's custody in place"
        );
        assert_eq!(l.bridge_vault_custody(&vault_a, &asset), 0);
    }

    #[test]
    fn a_bridge_mint_without_a_pool_vault_is_refused() {
        let mut l = Ledger::new();
        let asset = [0xC7u8; 16];
        let holder = [0xE1u8; 32];
        l.register_bridged_asset(&asset, 10_000_000, 10_000_000, false);
        let refused = l.bridge_mint(&crate::bridge::Fact {
            version: crate::bridge::FACT_VERSION,
            source_chain: 1,
            dest_chain: 9_000,
            route_id: 7,
            direction: crate::bridge::Direction::Deposit,
            nonce: 1,
            source_ref: [0x02u8; 32],
            asset_id: asset,
            amount: 1_000,
            recipient: holder,
            finality_depth: 6,
            observed_height: 10,
            expiry_height: 100,
        });
        assert!(!refused, "a mint with no pool vault is refused so wrapped tokens are never unbacked");
        assert_eq!(l.bridged_supply(&asset), 0, "the refused mint issues no supply");
    }

    #[test]
    fn an_underflowing_vault_debit_fails_closed() {
        let mut l = Ledger::new();
        let asset = [0xC3u8; 16];
        let holder = [0xEEu8; 32];
        l.register_bridged_asset(&asset, 10_000_000, 10_000_000, false);

        let vault = [0x0Au8; 32];
        l.seed_bridge_pool_vault(&vault);
        assert!(l.bridge_mint(&crate::bridge::Fact {
            version: crate::bridge::FACT_VERSION,
            source_chain: 1,
            dest_chain: 9_000,
            route_id: 7,
            direction: crate::bridge::Direction::Deposit,
            nonce: 1,
            source_ref: [0x01u8; 32],
            asset_id: asset,
            amount: 1_000,
            recipient: holder,
            finality_depth: 6,
            observed_height: 10,
            expiry_height: 100,
        }));
        assert_eq!(l.bridged_balance(&asset, &holder), 1_000);
        assert_eq!(l.bridged_supply(&asset), 1_000);

        l.seed_bridge_exits_enabled(true);
        l.seed_bridge_payout_cap(10_000_000);
        l.seed_bridge_vault_custody(&vault, &asset, 0);
        assert_eq!(
            l.bridge_vault_custody(&vault, &asset),
            0,
            "the vault holds no custody for this asset"
        );

        l.seed_outstanding_burn(&[0x07u8; 32], &asset, 500, &holder);
        let settle = crate::bridge::ExitFact {
            version: crate::bridge::EXIT_FACT_VERSION,
            corridor: 1,
            dest_chain: 9_000,
            asset_id: asset,
            amount: 500,
            beneficiary: holder,
            burn_ref: [0x07u8; 32],
            outcome: crate::bridge::ExitOutcome::Settle,
        };
        assert!(!l.bridge_settle(&settle), "a settle beyond the vault custody fails closed");
        assert_eq!(l.bridge_vault_custody(&vault, &asset), 0);
        assert_eq!(l.bridged_supply(&asset), 1_000, "the refused settle moves no supply");

        l.seed_outstanding_burn(&[0x08u8; 32], &asset, 500, &holder);
        let slash = crate::bridge::ExitFact {
            version: crate::bridge::EXIT_FACT_VERSION,
            corridor: 1,
            dest_chain: 9_000,
            asset_id: asset,
            amount: 500,
            beneficiary: holder,
            burn_ref: [0x08u8; 32],
            outcome: crate::bridge::ExitOutcome::Slash,
        };
        assert!(!l.bridge_slash(&slash), "a refund above the vault custody fails closed");
        assert_eq!(l.bridged_supply(&asset), 1_000, "the refused refund moves no supply");
    }

    #[test]
    fn a_seeded_outstanding_burn_resolves_by_settle_xor_slash_and_never_twice() {
        let mut st = 0x0fed_cba9_8765_4321u64;
        let mut rng = || {
            st = st.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = st;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let mut l = Ledger::new();
        let vault = [0x0Fu8; 32];
        let asset = [0xa1u8; 16];
        let beneficiary = [0x22u8; 32];
        l.seed_bridge_pool_vault(&vault);
        l.seed_bridge_exits_enabled(true);
        l.seed_bridge_payout_cap(u128::MAX);
        l.register_bridged_asset(&asset, u128::MAX, u128::MAX, false);
        l.seed_bridge_vault_custody(&vault, &asset, u128::MAX / 4);
        for i in 0..600u64 {
            let mut burn_ref = [0u8; 32];
            burn_ref[..8].copy_from_slice(&i.to_le_bytes());
            let amount = 100u128;
            l.seed_outstanding_burn(&burn_ref, &asset, amount, &beneficiary);
            let settle = crate::bridge::ExitFact {
                version: crate::bridge::EXIT_FACT_VERSION,
                corridor: 1,
                dest_chain: 9_000,
                asset_id: asset,
                amount,
                beneficiary,
                burn_ref,
                outcome: crate::bridge::ExitOutcome::Settle,
            };
            let slash = crate::bridge::ExitFact {
                version: crate::bridge::EXIT_FACT_VERSION,
                corridor: 1,
                dest_chain: 9_000,
                asset_id: asset,
                amount,
                beneficiary,
                burn_ref,
                outcome: crate::bridge::ExitOutcome::Slash,
            };
            let (first, second) = if rng() % 2 == 0 {
                (l.bridge_settle(&settle), l.bridge_slash(&slash))
            } else {
                (l.bridge_slash(&slash), l.bridge_settle(&settle))
            };
            assert!(first, "the first resolution of a fresh burn succeeds");
            assert!(
                !second,
                "a burn already resolved by settle or slash cannot be resolved a second time"
            );
            assert!(l.bridge_exit_settled(&burn_ref), "the resolved burn is marked settled");
        }
    }

    #[test]
    fn a_mint_credit_that_would_overflow_the_holder_balance_is_refused_not_saturated() {
        let mut l = Ledger::new();
        let asset = [0xC4u8; 16];
        let holder = [0xEFu8; 32];
        l.register_bridged_asset(&asset, u128::MAX, u128::MAX, false);
        l.set_bridged_balance(&asset, &holder, u128::MAX - 10);

        let refused = l.bridge_mint(&crate::bridge::Fact {
            version: crate::bridge::FACT_VERSION,
            source_chain: 1,
            dest_chain: 9_000,
            route_id: 7,
            direction: crate::bridge::Direction::Deposit,
            nonce: 1,
            source_ref: [0x44u8; 32],
            asset_id: asset,
            amount: 100,
            recipient: holder,
            finality_depth: 6,
            observed_height: 10,
            expiry_height: 100,
        });
        assert!(!refused, "a credit that would overflow the holder balance is refused");
        assert_eq!(
            l.bridged_balance(&asset, &holder),
            u128::MAX - 10,
            "the refused mint leaves the balance unsaturated"
        );
        assert!(
            !l.bridge_reference_seen(1, &[0x44u8; 32]),
            "the refused mint leaves the reference unseen"
        );
    }

    #[test]
    fn a_mint_credit_that_would_overflow_the_vault_custody_is_refused_not_saturated() {
        let mut l = Ledger::new();
        let asset = [0xC5u8; 16];
        let holder = [0xF0u8; 32];
        let vault = [0x0Du8; 32];
        l.register_bridged_asset(&asset, u128::MAX, u128::MAX, false);
        l.set_bridge_pool_vault(&vault);
        l.set_bridge_vault_custody(&vault, &asset, u128::MAX - 10);

        let refused = l.bridge_mint(&crate::bridge::Fact {
            version: crate::bridge::FACT_VERSION,
            source_chain: 1,
            dest_chain: 9_000,
            route_id: 7,
            direction: crate::bridge::Direction::Deposit,
            nonce: 1,
            source_ref: [0x55u8; 32],
            asset_id: asset,
            amount: 100,
            recipient: holder,
            finality_depth: 6,
            observed_height: 10,
            expiry_height: 100,
        });
        assert!(!refused, "a credit that would overflow the vault custody is refused");
        assert_eq!(
            l.bridge_vault_custody(&vault, &asset),
            u128::MAX - 10,
            "the refused mint leaves the custody unsaturated"
        );
        assert_eq!(l.bridged_balance(&asset, &holder), 0, "the refused mint credits no balance");
        assert_eq!(l.bridged_supply(&asset), 0, "the refused mint moves no supply");
        assert!(
            !l.bridge_reference_seen(1, &[0x55u8; 32]),
            "the refused mint leaves the reference unseen"
        );
    }

    #[test]
    fn a_random_walk_of_bridge_mints_keeps_supply_equal_to_custody_and_within_cap() {
        let mut st = 0x0123_4567_89ab_cdefu64;
        let mut rng = || {
            st = st.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = st;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let mut l = Ledger::new();
        let vault = [0x0Fu8; 32];
        l.set_bridge_pool_vault(&vault);
        let assets = [[0xa1u8; 16], [0xa2u8; 16], [0xa3u8; 16]];
        let mut expected: std::collections::BTreeMap<[u8; 16], u128> = Default::default();
        for a in &assets {
            l.register_bridged_asset(a, 50_000, u128::MAX, false);
            expected.insert(*a, 0);
        }
        let mut nonce = 0u64;
        for _ in 0..4000 {
            let a = assets[(rng() % 3) as usize];
            let amt = (rng() % 400) as u128;
            if amt > 0 {
                nonce += 1;
                let mut sref = [0u8; 32];
                sref[..8].copy_from_slice(&nonce.to_le_bytes());
                let minted = l.bridge_mint(&crate::bridge::Fact {
                    version: crate::bridge::FACT_VERSION,
                    source_chain: 1,
                    dest_chain: 9_000,
                    route_id: 7,
                    direction: crate::bridge::Direction::Deposit,
                    nonce,
                    source_ref: sref,
                    asset_id: a,
                    amount: amt,
                    recipient: [0xEEu8; 32],
                    finality_depth: 6,
                    observed_height: 10,
                    expiry_height: 1_000_000,
                });
                if minted {
                    *expected.get_mut(&a).expect("registered asset") += amt;
                }
            }
            for a in &assets {
                let supply = l.bridged_supply(a);
                assert_eq!(supply, expected[a], "supply drifted from the sum of admitted mints");
                assert_eq!(
                    supply,
                    l.bridge_vault_custody(&vault, a),
                    "supply is not backed one for one by custody"
                );
                assert!(supply <= 50_000, "supply exceeded the per-asset cap");
            }
        }
    }

    #[test]
    fn a_shared_reference_on_two_corridors_both_mint_and_a_same_corridor_replay_is_refused() {
        let mut l = Ledger::new();
        let asset = [0xD6u8; 16];
        let holder = [0xF1u8; 32];
        let vault = [0x0Eu8; 32];
        l.register_bridged_asset(&asset, u128::MAX, u128::MAX, false);
        l.set_bridge_pool_vault(&vault);
        let shared = |source_chain: u32| crate::bridge::Fact {
            version: crate::bridge::FACT_VERSION,
            source_chain,
            dest_chain: 9_000,
            route_id: 7,
            direction: crate::bridge::Direction::Deposit,
            nonce: 1,
            source_ref: [0x77u8; 32],
            asset_id: asset,
            amount: 1_000,
            recipient: holder,
            finality_depth: 6,
            observed_height: 10,
            expiry_height: 100,
        };
        assert!(l.bridge_mint(&shared(1)), "the first corridor deposit mints");
        assert!(
            l.bridge_mint(&shared(2)),
            "a distinct deposit on another corridor sharing the reference must mint, not lock funds"
        );
        assert_eq!(
            l.bridged_balance(&asset, &holder),
            2_000,
            "both corridor deposits are credited"
        );
        assert!(!l.bridge_mint(&shared(1)), "a same corridor replay is refused");
        assert!(!l.bridge_mint(&shared(2)), "a same corridor replay is refused");
        assert_eq!(
            l.bridged_balance(&asset, &holder),
            2_000,
            "the replays credit nothing"
        );
        assert!(l.bridge_reference_seen(1, &[0x77u8; 32]), "the reference is marked on corridor 1");
        assert!(l.bridge_reference_seen(2, &[0x77u8; 32]), "and independently on corridor 2");
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
        l.execute_action(
            &Action::Mint {
                to: [63u8; 32].to_vec(),
                amount: 5_000,
            },
            0,
            TEST_CHAIN,
        )
        .unwrap();
        let events = l.block_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].selector, EVENT_MINT);
        let mut decoder = Decoder::new(&events[0].data);
        assert_eq!(decoder.get_bytes().unwrap(), target.as_bytes());
        assert_eq!(decoder.get_u64().unwrap(), 5_000);
    }

    #[test]
    fn a_mint_is_capped_at_the_published_supply() {
        let mut l = Ledger::new();
        l.credit_supply(qtv_staking::MAX_SUPPLY - 1_000);
        l.execute_action(
            &Action::Mint { to: [63u8; 32].to_vec(), amount: 1_000 },
            0,
            TEST_CHAIN,
        )
        .expect("a mint up to the published ceiling is allowed");
        assert_eq!(l.total_supply(), qtv_staking::MAX_SUPPLY);
        assert_eq!(
            l.execute_action(
                &Action::Mint { to: [63u8; 32].to_vec(), amount: 1 },
                0,
                TEST_CHAIN,
            ),
            Err(EnactError::BadValue),
            "a mint past the published ceiling is refused"
        );
        assert_eq!(l.total_supply(), qtv_staking::MAX_SUPPLY, "the refused mint left the supply at the cap");
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
        let root_before = l.q_root();

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
        assert_eq!(l.q_root(), root_before, "the state root is unmoved");
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

    #[test]
    fn a_burn_inclusion_proof_verifies_under_the_block_event_root() {
        let mut l = Ledger::new();
        let asset = [7u8; 16];
        let holder = [9u8; 32];
        let destination = [0xEE; 32];
        let chain_id = 42u64;
        seed_burnable(&mut l, &asset, &holder, 1_000_000);

        l.record_transfer_event("qtv1payer", "qtv1payee", 10, 1);
        assert!(l.bridge_burn(&asset, &holder, 100_000, &destination, chain_id, 0));
        l.record_transfer_event("qtv1other", "qtv1sink", 5, 1);

        let leaf = decode_burn_leaf(&l.block_events()[1].data);
        let burn_ref = leaf.7;
        let inclusion = l.prove_bridge_burn(&burn_ref).expect("the burn is present");
        assert_eq!(inclusion.event_index, 1);
        assert_eq!(bridge_burn_leaf_ref(&l.block_events()[1].data), Some(burn_ref));

        let leaves: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        let root = qtv_block::event_root(&leaves);
        assert!(qtv_block::verify_inclusion(&root, &inclusion.leaf, &inclusion.proof));
    }

    #[test]
    fn a_tampered_burn_leaf_or_branch_does_not_verify() {
        let mut l = Ledger::new();
        let asset = [7u8; 16];
        let holder = [9u8; 32];
        seed_burnable(&mut l, &asset, &holder, 1_000_000);
        l.record_transfer_event("qtv1a", "qtv1b", 10, 1);
        assert!(l.bridge_burn(&asset, &holder, 100_000, &[0xEE; 32], 42, 0));
        l.record_transfer_event("qtv1c", "qtv1d", 5, 1);
        l.record_transfer_event("qtv1e", "qtv1f", 5, 1);

        let burn_ref = decode_burn_leaf(&l.block_events()[1].data).7;
        let inclusion = l.prove_bridge_burn(&burn_ref).unwrap();
        let leaves: Vec<Vec<u8>> = l.block_events().iter().map(BlockEvent::encode).collect();
        let root = qtv_block::event_root(&leaves);

        let mut tampered_leaf = inclusion.leaf.clone();
        let last = tampered_leaf.len() - 1;
        tampered_leaf[last] ^= 0xff;
        assert!(!qtv_block::verify_inclusion(&root, &tampered_leaf, &inclusion.proof));

        let mut wrong_branch = inclusion.proof.clone();
        wrong_branch.steps[0].sibling[0] ^= 0xff;
        assert!(!qtv_block::verify_inclusion(&root, &inclusion.leaf, &wrong_branch));
    }

    #[test]
    fn an_unknown_burn_ref_has_no_inclusion_proof() {
        let mut l = Ledger::new();
        let asset = [7u8; 16];
        let holder = [9u8; 32];
        seed_burnable(&mut l, &asset, &holder, 1_000_000);
        assert!(l.bridge_burn(&asset, &holder, 100_000, &[0xEE; 32], 42, 0));
        assert!(l.prove_bridge_burn(&[0x00; 32]).is_none());
    }
}

pub const NATIVE_EVENT_SOURCE: &str = "qtv/native";

pub const SLASH_DISPOSITION_BURN: &str = "burn";
pub const SLASH_DISPOSITION_TREASURY: &str = "treasury";

pub const EVENT_TRANSFER: [u8; 4] = *b"QXFR";
pub const EVENT_BOND: [u8; 4] = *b"QBND";
pub const EVENT_UNBOND: [u8; 4] = *b"QUBD";
pub const EVENT_SLASH: [u8; 4] = *b"QSLH";
pub const EVENT_MINT: [u8; 4] = *b"QMNT";
pub const EVENT_REWARD: [u8; 4] = *b"QRWD";
pub const EVENT_BRIDGE_MINT: [u8; 4] = *b"QBMT";
pub const EVENT_BRIDGE_BURN: [u8; 4] = *b"QBBN";
pub const EVENT_BRIDGE_SETTLE: [u8; 4] = *b"QBSE";
pub const EVENT_BRIDGE_SLASH: [u8; 4] = *b"QBSL";

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

    pub fn native(kind: [u8; 4], data: Vec<u8>) -> Self {
        BlockEvent {
            contract: NATIVE_EVENT_SOURCE.to_string(),
            selector: kind,
            data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideEvent {
    GovPropose {
        referendum: u64,
        proposer: String,
        track: u8,
        action: &'static str,
        deposit: u64,
    },
    GovVote {
        referendum: u64,
        voter: String,
        aye: bool,
        conviction: u8,
        stake: u64,
    },
    GovTally {
        referendum: u64,
        status: &'static str,
        aye_stake: u128,
        nay_stake: u128,
    },
    GovEnact {
        referendum: u64,
        action: &'static str,
        proposal_hash: [u8; 32],
    },
    Mint {
        to: String,
        amount: u64,
    },
    Spend {
        source: String,
        to: String,
        amount: u64,
    },
    Parameter {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Blacklist {
        target: String,
    },
    Freeze {
        target: String,
    },
    Unfreeze {
        target: String,
    },
    RecoverySeizure {
        victim: String,
        from: String,
        amount: u64,
        scope: [u8; 32],
    },
    RecoveryCredit {
        victim: String,
        amount: u64,
        scope: [u8; 32],
    },
    GuardianFreeze {
        target: String,
        bound: u64,
    },
    GuardianRotate {
        size: u32,
        threshold: u32,
    },
    CommitteeRotate {
        operators: u32,
        threshold: u32,
    },
    OperatorRevoke {
        operator_id: u32,
    },
    AssetRegister {
        asset_id: [u8; 16],
        cap: u128,
        epoch_cap: u128,
        requires_stark: bool,
    },
    EpochAdvance {
        epoch: u64,
    },
    Activate {
        feature: Vec<u8>,
        version: u64,
    },
    BridgeMigration {
        vault: String,
    },
    BridgeUnfreeze,
    Bond {
        validator: String,
        amount: u64,
        fee: u64,
    },
    Unbond {
        validator: String,
        amount: u64,
    },
    Slash {
        validator: String,
        amount: u64,
        disposition: &'static str,
    },
    Reward {
        validator: String,
        amount: u64,
    },
    RewardClaim {
        validator: String,
        amount: u64,
    },
    ContractTransfer {
        contract: String,
        to: String,
        amount: u64,
    },
    BridgeMint {
        asset_id: [u8; 16],
        recipient: [u8; 32],
        amount: u128,
    },
    BridgeBurn {
        asset_id: [u8; 16],
        holder: [u8; 32],
        amount: u128,
        destination: [u8; 32],
        chain_id: u64,
        burn_ref: [u8; 32],
    },
    BridgeSettle {
        asset_id: [u8; 16],
        beneficiary: [u8; 32],
        amount: u128,
        burn_ref: [u8; 32],
    },
    BridgeSlash {
        asset_id: [u8; 16],
        beneficiary: [u8; 32],
        amount: u128,
        burn_ref: [u8; 32],
    },
}

impl SideEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            SideEvent::GovPropose { .. } => "gov_propose",
            SideEvent::GovVote { .. } => "gov_vote",
            SideEvent::GovTally { .. } => "gov_tally",
            SideEvent::GovEnact { .. } => "gov_enact",
            SideEvent::Mint { .. } => "mint",
            SideEvent::Spend { .. } => "spend",
            SideEvent::Parameter { .. } => "parameter",
            SideEvent::Blacklist { .. } => "blacklist",
            SideEvent::Freeze { .. } => "freeze",
            SideEvent::Unfreeze { .. } => "unfreeze",
            SideEvent::RecoverySeizure { .. } => "recovery_seizure",
            SideEvent::RecoveryCredit { .. } => "recovery_credit",
            SideEvent::GuardianFreeze { .. } => "guardian_freeze",
            SideEvent::GuardianRotate { .. } => "guardian_rotate",
            SideEvent::CommitteeRotate { .. } => "committee_rotate",
            SideEvent::OperatorRevoke { .. } => "operator_revoke",
            SideEvent::AssetRegister { .. } => "asset_register",
            SideEvent::EpochAdvance { .. } => "epoch_advance",
            SideEvent::Activate { .. } => "activate",
            SideEvent::BridgeMigration { .. } => "bridge_migration",
            SideEvent::BridgeUnfreeze => "bridge_unfreeze",
            SideEvent::Bond { .. } => "bond",
            SideEvent::Unbond { .. } => "unbond",
            SideEvent::Slash { .. } => "slash",
            SideEvent::Reward { .. } => "reward",
            SideEvent::RewardClaim { .. } => "reward_claim",
            SideEvent::ContractTransfer { .. } => "contract_transfer",
            SideEvent::BridgeMint { .. } => "bridge_mint",
            SideEvent::BridgeBurn { .. } => "bridge_burn",
            SideEvent::BridgeSettle { .. } => "bridge_settle",
            SideEvent::BridgeSlash { .. } => "bridge_slash",
        }
    }
}

fn action_kind(action: &Action) -> &'static str {
    match action {
        Action::Activate { .. } => "activate",
        Action::Mint { .. } => "mint",
        Action::BridgeMigration { .. } => "bridge_migration",
        Action::BridgeUnfreeze => "bridge_unfreeze",
        Action::GuardianRotate { .. } => "guardian_rotate",
        Action::CommitteeRotate { .. } => "committee_rotate",
        Action::AssetRegister { .. } => "asset_register",
        Action::EpochAdvance => "epoch_advance",
        Action::OperatorRevoke { .. } => "operator_revoke",
        Action::FreezeRecovery { .. } => "freeze_recovery",
        Action::Blacklist { .. } => "blacklist",
        Action::Freeze { .. } => "freeze",
        Action::Parameter { .. } => "parameter",
        Action::Spend { .. } => "spend",
        Action::Unfreeze { .. } => "unfreeze",
    }
}

fn status_kind(status: Status) -> &'static str {
    match status {
        Status::Deciding => "deciding",
        Status::Approved => "approved",
        Status::Rejected => "rejected",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnInclusion {
    pub event_index: u64,
    pub leaf: Vec<u8>,
    pub proof: qtv_block::MerkleProof,
}

pub fn bridge_burn_leaf_ref(data: &[u8]) -> Option<[u8; 32]> {
    let mut decoder = qtv_codec::Decoder::new(data);
    let _asset_id = decoder.get_bytes().ok()?;
    let _holder = decoder.get_bytes().ok()?;
    let _amount = decoder.get_u128().ok()?;
    let _destination = decoder.get_bytes().ok()?;
    let _chain_id = decoder.get_u64().ok()?;
    let _sender_nonce = decoder.get_u64().ok()?;
    let _event_index = decoder.get_u64().ok()?;
    let burn_ref = decoder.get_bytes().ok()?;
    <[u8; 32]>::try_from(burn_ref).ok()
}

#[derive(Debug, Clone, Default)]
pub struct Ledger {
    trie: Trie,
    block_events: Vec<BlockEvent>,
    side_events: Vec<SideEvent>,
    round_proposer: Option<String>,
    execution_height: u64,
    journal: Option<Vec<(Key, Option<Vec<u8>>)>>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger {
            trie: Trie::new(),
            block_events: Vec::new(),
            side_events: Vec::new(),
            round_proposer: None,
            execution_height: 0,
            journal: None,
        }
    }

    pub fn from_trie(mut trie: Trie) -> Self {
        trie.clear_persist_dirty();
        Ledger {
            trie,
            block_events: Vec::new(),
            side_events: Vec::new(),
            round_proposer: None,
            execution_height: 0,
            journal: None,
        }
    }

    fn write_leaf(&mut self, key: Key, value: Vec<u8>) {
        if self.journal.is_some() {
            let prior = self.trie.get(&key).map(|bytes| bytes.to_vec());
            self.journal.as_mut().expect("the journal is present").push((key, prior));
        }
        let trie = &mut self.trie;
        trie.insert(key, value);
    }

    fn erase_leaf(&mut self, key: &Key) -> bool {
        if self.journal.is_some() {
            let prior = self.trie.get(key).map(|bytes| bytes.to_vec());
            self.journal.as_mut().expect("the journal is present").push((*key, prior));
        }
        let trie = &mut self.trie;
        trie.remove(key)
    }

    pub(crate) fn apply_atomic<F>(&mut self, f: F) -> bool
    where
        F: FnOnce(&mut Ledger) -> bool,
    {
        let events_mark = self.block_events.len();
        let side_mark = self.side_events.len();
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
            self.side_events.truncate(side_mark);
        }
        committed
    }

    pub fn clear_block_events(&mut self) {
        self.block_events.clear();
        self.side_events.clear();
    }

    pub fn block_events(&self) -> &[BlockEvent] {
        &self.block_events
    }

    pub fn side_events(&self) -> &[SideEvent] {
        &self.side_events
    }

    fn record_side_event(&mut self, event: SideEvent) {
        self.side_events.push(event);
    }

    pub fn prove_bridge_burn(&self, burn_ref: &[u8; 32]) -> Option<BurnInclusion> {
        let leaves: Vec<Vec<u8>> = self.block_events.iter().map(BlockEvent::encode).collect();
        for (index, event) in self.block_events.iter().enumerate() {
            if event.selector != EVENT_BRIDGE_BURN || event.contract != NATIVE_EVENT_SOURCE {
                continue;
            }
            if bridge_burn_leaf_ref(&event.data) == Some(*burn_ref) {
                let proof = qtv_block::prove_inclusion(&leaves, index)?;
                return Some(BurnInclusion {
                    event_index: index as u64,
                    leaf: leaves[index].clone(),
                    proof,
                });
            }
        }
        None
    }

    fn record_native_event(&mut self, kind: [u8; 4], data: Vec<u8>) {
        self.block_events.push(BlockEvent::native(kind, data));
    }

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

    #[allow(clippy::too_many_arguments)]
    fn record_bridge_burn_event(
        &mut self,
        asset_id: &[u8; 16],
        holder: &[u8; 32],
        amount: u128,
        destination: &[u8; 32],
        chain_id: u64,
        sender_nonce: u64,
        event_index: u64,
        burn_ref: &[u8; 32],
    ) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(asset_id);
        encoder.put_bytes(holder);
        encoder.put_u128(amount);
        encoder.put_bytes(destination);
        encoder.put_u64(chain_id);
        encoder.put_u64(sender_nonce);
        encoder.put_u64(event_index);
        encoder.put_bytes(burn_ref);
        self.record_native_event(EVENT_BRIDGE_BURN, encoder.into_bytes());
    }

    fn record_bridge_settle_event(
        &mut self,
        asset_id: &[u8; 16],
        beneficiary: &[u8; 32],
        amount: u128,
        burn_ref: &[u8; 32],
    ) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(asset_id);
        encoder.put_bytes(beneficiary);
        encoder.put_u128(amount);
        encoder.put_bytes(burn_ref);
        self.record_native_event(EVENT_BRIDGE_SETTLE, encoder.into_bytes());
    }

    fn record_bridge_slash_event(
        &mut self,
        asset_id: &[u8; 16],
        beneficiary: &[u8; 32],
        amount: u128,
        burn_ref: &[u8; 32],
    ) {
        let mut encoder = Encoder::new();
        encoder.put_bytes(asset_id);
        encoder.put_bytes(beneficiary);
        encoder.put_u128(amount);
        encoder.put_bytes(burn_ref);
        self.record_native_event(EVENT_BRIDGE_SLASH, encoder.into_bytes());
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

    pub fn q_root(&self) -> [u8; HASH_LEN] {
        self.trie.root()
    }

    pub fn q_root_id(&self) -> String {
        qtv_idfmt::render_state(&self.q_root())
            .expect("a state root is the fixed digest length")
    }

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

    pub fn rent_exempt_minimum(&self, address: &str) -> u64 {
        rent_exempt_minimum_for(self.account_footprint(address))
    }

    pub fn is_rent_exempt(&self, address: &str) -> bool {
        self.balance(address) >= self.rent_exempt_minimum(address)
    }

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
    fn a_canonical_address_never_shares_a_leaf_with_the_unparsed_fallback() {
        let tail = b"hello-not-an-address!!!";
        assert_eq!(tail.len(), 23);
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(b"unparsed/");
        payload.extend_from_slice(tail);
        assert_eq!(payload.len(), qtv_idfmt::DIGEST_LEN);

        let canonical = qtv_idfmt::render_address(&payload).expect("a full payload renders");
        assert_eq!(
            qtv_idfmt::parse_address(&canonical).ok().as_deref(),
            Some(payload.as_slice()),
            "the crafted address is canonical and round trips"
        );
        let fallback = std::str::from_utf8(tail).expect("valid text");
        assert!(
            qtv_idfmt::parse_address(fallback).is_err(),
            "the fallback string is not a parseable address"
        );

        assert_ne!(
            state_key(&canonical),
            state_key(fallback),
            "a canonical account and an unparsed fallback share a state leaf"
        );
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
            ledger.q_root(),
            reference.q_root(),
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
    fn a_fee_split_is_seventy_ten_twenty_with_dust_to_grants() {
        let split = FeeSplit::of(1_000);
        assert_eq!(split.burn, 700, "seven tenths of the fee burns");
        assert_eq!(split.proposer, 100, "a tenth to the round proposer");
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
        let before = ledger.q_root();
        ledger.set_account(&addr, &Account::funded(2, 0, Vec::new()));
        assert_ne!(before, ledger.q_root());
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
        assert_eq!(one.q_root(), two.q_root());
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
