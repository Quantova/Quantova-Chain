// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_codec::{Decode, Decoder, Encoder};
use qtv_crypto::sha3;

const ROSTER_KEY_TAG: &[u8] = b"qtv/chain/roster/";
const ROSTER_DOMAIN: &[u8] = b"QUANTOVA/ROSTER/v1";
const ACCOUNT_TAG: &[u8] = b"qtv/account/";
const ACCOUNT_UNPARSED_TAG: &[u8] = b"qtv/account-unparsed/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub id: u64,
    pub stake: u64,
    pub attest_pk: Vec<u8>,
    pub root_digest: [u8; 32],
    pub root_slots: u64,
}

pub fn bridge_epoch_key() -> [u8; 32] {
    sha3::sha3_256(b"qtv/bridge/epoch")
}

pub fn roster_commitment_key(epoch: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(ROSTER_KEY_TAG.len() + 8);
    input.extend_from_slice(ROSTER_KEY_TAG);
    input.extend_from_slice(&epoch.to_le_bytes());
    sha3::sha3_256(&input)
}

pub fn roster_commitment(epoch: u64, entries: &[RosterEntry]) -> [u8; 32] {
    let mut sorted: Vec<&RosterEntry> = entries.iter().collect();
    sorted.sort_by_key(|entry| entry.id);
    let mut encoder = Encoder::new();
    encoder.put_bytes(ROSTER_DOMAIN);
    encoder.put_u64(epoch);
    encoder.put_u64(sorted.len() as u64);
    for entry in sorted {
        encoder.put_u64(entry.id);
        encoder.put_u64(entry.stake);
        encoder.put_bytes(&entry.attest_pk);
        encoder.put_bytes(&entry.root_digest);
        encoder.put_u64(entry.root_slots);
    }
    sha3::sha3_256(encoder.as_slice())
}

pub fn account_state_key(address: &str) -> [u8; 32] {
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccountLeaf {
    pub nonce: u64,
    pub balance: u64,
    pub scheme: u8,
    pub public_key: Vec<u8>,
}

pub fn decode_account_leaf(bytes: &[u8]) -> Option<AccountLeaf> {
    let mut decoder = Decoder::new(bytes);
    let leaf = AccountLeaf {
        nonce: u64::decode(&mut decoder).ok()?,
        balance: u64::decode(&mut decoder).ok()?,
        scheme: u8::decode(&mut decoder).ok()?,
        public_key: Vec::<u8>::decode(&mut decoder).ok()?,
    };
    decoder.finish().ok()?;
    Some(leaf)
}

pub fn encode_roster(entries: &[RosterEntry]) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.put_u64(entries.len() as u64);
    for entry in entries {
        encoder.put_u64(entry.id);
        encoder.put_u64(entry.stake);
        encoder.put_bytes(&entry.attest_pk);
        encoder.put_bytes(&entry.root_digest);
        encoder.put_u64(entry.root_slots);
    }
    encoder.into_bytes()
}

pub const MAX_ROSTER_ENTRIES: u64 = 4096;

pub fn decode_roster(bytes: &[u8]) -> Option<Vec<RosterEntry>> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.get_u64().ok()?;
    if count > MAX_ROSTER_ENTRIES {
        return None;
    }
    let mut entries = Vec::new();
    for _ in 0..count {
        let id = decoder.get_u64().ok()?;
        let stake = decoder.get_u64().ok()?;
        let attest_pk = decoder.get_bytes().ok()?.to_vec();
        let root_digest = <[u8; 32]>::try_from(decoder.get_bytes().ok()?).ok()?;
        let root_slots = decoder.get_u64().ok()?;
        entries.push(RosterEntry {
            id,
            stake,
            attest_pk,
            root_digest,
            root_slots,
        });
    }
    decoder.finish().ok()?;
    Some(entries)
}
