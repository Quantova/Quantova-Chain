// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::Path;

use qtv_account::address_for_key;
use qtv_crypto::sha3;
use qtv_devnet::config::DEFAULT_SLOTS;
use qtv_node::fee::FeeParams;
use qtv_node::bridge::{operator_pop_ok, OperatorSet};
use qtv_governance::GuardianSet;
use qtv_node::node::{Genesis, GenesisAccount, GenesisBridgedAsset, Root, ValidatorSpec};

use crate::config::{parse_kv, Field};
use crate::util::from_hex;

const PK_BYTES: usize = qtv_crypto::ml_dsa::PUBLIC_KEY_BYTES;

pub struct GenesisFile {
    pub chain_id: String,
    pub message: String,
    pub genesis: Genesis,
    pub slots: u64,
    pub asset: String,
    pub hash: [u8; 32],
}

impl GenesisFile {
    pub fn load(path: &Path) -> Result<GenesisFile, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading genesis file {}: {e}", path.display()))?;
        let fields = parse_kv(&text, path)?;

        let mut chain_id: Option<String> = None;
        let mut message = String::new();
        let mut asset = String::from("QTOV");
        let mut genesis_time: Option<u64> = None;
        let mut slots: u64 = DEFAULT_SLOTS;
        let mut transfer_micro_usd: Option<u128> = None;
        let mut rate_micro_usd_per_qtov: Option<u128> = None;
        let mut native_unit: Option<u128> = None;
        let mut max_fee_native: Option<u64> = None;
        let mut bridge_dest_chain: Option<u32> = None;
        let mut guardian_members: Vec<[u8; 32]> = Vec::new();
        let mut guardian_threshold: Option<u32> = None;
        let mut bridge_ops: Vec<(u32, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut bridge_threshold: Option<u32> = None;
        let mut bridged: Vec<GenesisBridgedAsset> = Vec::new();
        let mut validators: Vec<ValidatorSpec> = Vec::new();
        let mut accounts: Vec<GenesisAccount> = Vec::new();

        for field in &fields {
            match field.key.as_str() {
                "chain_id" => chain_id = Some(field.value.clone()),
                "message" => message = field.value.clone(),
                "asset" => asset = field.value.clone(),
                "genesis_time" => genesis_time = Some(field.u64("genesis_time")?),
                "slots" => slots = field.u64("slots")?,
                "fee_transfer_micro_usd" => {
                    transfer_micro_usd = Some(field.u128("fee_transfer_micro_usd")?)
                }
                "fee_rate_micro_usd_per_qtov" => {
                    rate_micro_usd_per_qtov = Some(field.u128("fee_rate_micro_usd_per_qtov")?)
                }
                "fee_native_unit" => native_unit = Some(field.u128("fee_native_unit")?),
                "fee_max_native" => max_fee_native = Some(field.u64("fee_max_native")?),
                "bridge_dest_chain" => bridge_dest_chain = Some(field.u32("bridge_dest_chain")?),
                "validator" => {}
                "account" => accounts.push(parse_account(field)?),
                "guardian" => {
                    let id: [u8; 32] = from_hex(field.value.trim())
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .ok_or_else(|| field.error("guardian expects a thirty two byte member id in hex"))?;
                    guardian_members.push(id);
                }
                "guardian_threshold" => guardian_threshold = Some(field.u32("guardian_threshold")?),
                "bridge_operator" => {
                    let mut parts = field.value.split_whitespace();
                    let id: u32 = parts.next().and_then(|s| s.parse().ok())
                        .ok_or_else(|| field.error("bridge_operator expects '<id> <public_key_hex> <pop_hex>'"))?;
                    let pk = parts.next().and_then(|s| from_hex(s).ok())
                        .ok_or_else(|| field.error("bridge_operator expects '<id> <public_key_hex> <pop_hex>'"))?;
                    let pop = parts.next().and_then(|s| from_hex(s).ok())
                        .ok_or_else(|| field.error("bridge_operator expects '<id> <public_key_hex> <pop_hex>' (missing proof-of-possession)"))?;
                    bridge_ops.push((id, pk, pop));
                }
                "bridge_threshold" => bridge_threshold = Some(field.u32("bridge_threshold")?),
                "bridged_asset" => {
                    let mut parts = field.value.split_whitespace();
                    let asset_id: [u8; 16] = parts.next().and_then(|s| from_hex(s).ok())
                        .and_then(|b| b.try_into().ok())
                        .ok_or_else(|| field.error("bridged_asset expects '<asset_hex16> <cap> <epoch_cap> <stark 0|1>'"))?;
                    let cap: u128 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| field.error("bridged_asset cap"))?;
                    let epoch_cap: u128 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| field.error("bridged_asset epoch_cap"))?;
                    let requires_stark = parts.next().map(|s| s == "1" || s.eq_ignore_ascii_case("true")).unwrap_or(false);
                    if cap == 0 || epoch_cap == 0 {
                        return Err(field.error("bridged_asset cap and epoch_cap must be nonzero"));
                    }
                    if requires_stark {
                        return Err(field.error("bridged_asset requires_stark is not enforced yet (FRI verification unwired); refusing a false STARK assurance"));
                    }
                    bridged.push(GenesisBridgedAsset { asset_id, cap, epoch_cap, requires_stark });
                }
                other => {
                    return Err(field.error(&format!("unknown genesis key '{other}'")));
                }
            }
        }

        for field in &fields {
            if field.key == "validator" {
                validators.push(parse_validator(field, slots)?);
            }
        }

        let chain_id = chain_id.ok_or("the genesis is missing 'chain_id'")?;
        let genesis_time = genesis_time.ok_or("the genesis is missing 'genesis_time'")?;
        let chain_binding = u64::from_be_bytes(
            sha3::sha3_256(chain_id.as_bytes())[..8]
                .try_into()
                .expect("eight bytes"),
        );
        let fee_params = FeeParams {
            transfer_micro_usd: transfer_micro_usd
                .ok_or("the genesis is missing 'fee_transfer_micro_usd'")?,
            rate_micro_usd_per_qtov: rate_micro_usd_per_qtov
                .ok_or("the genesis is missing 'fee_rate_micro_usd_per_qtov'")?,
            native_unit: native_unit.ok_or("the genesis is missing 'fee_native_unit'")?,
            max_fee_native: max_fee_native.ok_or("the genesis is missing 'fee_max_native'")?,
            chain_id: chain_binding,
        };
        if fee_params.rate_micro_usd_per_qtov == 0 {
            return Err("the genesis 'fee_rate_micro_usd_per_qtov' is zero, so the fee \
                        conversion would divide by zero on the first transaction"
                .to_string());
        }
        if fee_params.native_unit == 0 {
            return Err("the genesis 'fee_native_unit' is zero, so every fee rounds away and \
                        transfers would be free"
                .to_string());
        }
        if fee_params.transfer_fee() == 0 {
            return Err("the genesis fee schedule rounds a transfer fee to zero at this rate \
                        and native unit, so a transfer would carry no fee"
                .to_string());
        }
        if fee_params.max_fee_native < fee_params.floor_native_uncapped() {
            return Err("the genesis 'fee_max_native' is below the band floor at this rate, \
                        so the native ceiling would clamp a transfer below the advertised \
                        floor fee. Set it to at least the floor, and to the band ceiling at \
                        this rate for the band to work fully before the rate goes stale"
                .to_string());
        }
        if validators.is_empty() {
            return Err("the genesis names no validators, so no committee can form".to_string());
        }
        if slots == 0 {
            return Err("the genesis slot budget is zero, so no height can finalise".to_string());
        }
        enforce_no_capture(&validators, &accounts)?;

        let guardians = if guardian_members.is_empty() {
            GuardianSet::default()
        } else {
            let threshold = guardian_threshold.unwrap_or(2);
            let mut seen: Vec<[u8; 32]> = Vec::with_capacity(guardian_members.len());
            for m in &guardian_members {
                if seen.contains(m) {
                    return Err("genesis guardian members must be distinct".to_string());
                }
                seen.push(*m);
            }
            if threshold < 2 || (threshold as usize) > guardian_members.len() {
                return Err("genesis guardian_threshold must be >=2 and <= the number of guardians".to_string());
            }
            GuardianSet::new(guardian_members, threshold)
        };
        let bridge_operators = if bridge_ops.is_empty() {
            None
        } else {
            let threshold = bridge_threshold.unwrap_or(2);
            let mut operators: Vec<(u32, Vec<u8>)> = Vec::with_capacity(bridge_ops.len());
            for (id, pk, pop) in &bridge_ops {
                if operators.iter().any(|(oid, _)| oid == id) {
                    return Err(format!("genesis bridge_operator id {id} is duplicated"));
                }
                if operators.iter().any(|(_, opk)| opk == pk) {
                    return Err("genesis bridge_operator public keys must be distinct".to_string());
                }
                if !operator_pop_ok(*id, pk, pop, chain_binding) {
                    return Err(format!("genesis bridge_operator {id} has an invalid proof-of-possession"));
                }
                operators.push((*id, pk.clone()));
            }
            if threshold < 2 {
                return Err("genesis bridge_threshold must be at least 2".to_string());
            }
            if (threshold as usize) > operators.len() {
                return Err("genesis bridge_threshold exceeds the committee size".to_string());
            }
            if (threshold as usize) * 3 < operators.len() * 2 {
                return Err("genesis bridge_threshold is below the two thirds BFT safety ratio".to_string());
            }
            Some(OperatorSet::new(operators, threshold))
        };
        let genesis = Genesis {
            fee_params,
            accounts,
            validators,
            genesis_time,
            guardians,
            bridge_dest_chain,
            bridge_operators,
            bridged_assets: bridged,
            bridge_era: None,
            bridge_bitcoin_anchor: None,
            bridge_eth_anchors: Vec::new(),
        };
        let hash = genesis_hash(&chain_id, &message, slots, &genesis);
        Ok(GenesisFile {
            chain_id,
            message,
            genesis,
            slots,
            asset,
            hash,
        })
    }
}

pub const CAPTURE_CAP_NUM: u128 = 1;
pub const CAPTURE_CAP_DEN: u128 = 3;

fn reaches_fault_threshold(holding: u128, total: u128) -> bool {
    holding * CAPTURE_CAP_DEN >= total * CAPTURE_CAP_NUM
}

fn enforce_no_capture(
    validators: &[ValidatorSpec],
    accounts: &[GenesisAccount],
) -> Result<(), String> {
    if validators.len() >= 2 {
        let total_stake: u128 = validators.iter().map(|v| v.stake as u128).sum();
        for v in validators {
            if reaches_fault_threshold(v.stake as u128, total_stake) {
                return Err(format!(
                    "validator {} bonds {} of {} total genesis stake, a {} in {} share or more, \
                     which reaches the BFT fault threshold and could stall or capture the chain at \
                     launch. Spread the stake so no single validator bonds a {} in {} share of the \
                     total or more",
                    v.id, v.stake, total_stake, CAPTURE_CAP_NUM, CAPTURE_CAP_DEN, CAPTURE_CAP_NUM,
                    CAPTURE_CAP_DEN
                ));
            }
        }
    }

    if accounts.len() >= 2 {
        let total_balance: u128 = accounts.iter().map(|a| a.balance as u128).sum();
        for a in accounts {
            if reaches_fault_threshold(a.balance as u128, total_balance) {
                return Err(format!(
                    "account {} holds {} of {} total genesis balance, a {} in {} share or more it \
                     could bond, which reaches the BFT fault threshold and could stall or capture \
                     the chain at launch. Spread the supply so no single account holds a {} in {} \
                     share of the total or more",
                    a.address, a.balance, total_balance, CAPTURE_CAP_NUM, CAPTURE_CAP_DEN,
                    CAPTURE_CAP_NUM, CAPTURE_CAP_DEN
                ));
            }
        }
    }
    Ok(())
}

fn parse_validator(field: &Field, slots: u64) -> Result<ValidatorSpec, String> {
    let parts: Vec<&str> = field.value.split_whitespace().collect();
    if parts.len() != 7 {
        return Err(field.error(
            "a validator is '<id> <stake> <online|offline> <bond_address> \
             <sortition_root_hex> <attest_pk_hex> <p2p_public_hex>', each field the \
             operator's own published registration",
        ));
    }
    let id: u64 = parts[0]
        .parse()
        .map_err(|_| field.error("the validator id is not a number"))?;
    let stake: u64 = parts[1]
        .parse()
        .map_err(|_| field.error("the validator stake is not a number"))?;
    let online = match parts[2] {
        "online" => true,
        "offline" => false,
        other => return Err(field.error(&format!("'{other}' is not 'online' or 'offline'"))),
    };
    let bond_address = parts[3].to_string();
    let digest = fixed_hex::<32>(parts[4], field, "the sortition root")?;
    let attest_pk = fixed_hex::<PK_BYTES>(parts[5], field, "the attestation public key")?;
    let p2p_public = fixed_hex::<PK_BYTES>(parts[6], field, "the peer identity public key")?;
    Ok(ValidatorSpec {
        id,
        stake,
        online,
        bond_address,
        root: Root { digest, slots },
        attest_pk,
        p2p_public,
    })
}

fn fixed_hex<const N: usize>(s: &str, field: &Field, what: &str) -> Result<[u8; N], String> {
    let bytes = from_hex(s).map_err(|e| field.error(&format!("{what} {e}")))?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| field.error(&format!("{what} must be {N} bytes, found {}", bytes.len())))
}

fn parse_account(field: &Field) -> Result<GenesisAccount, String> {
    let parts: Vec<&str> = field.value.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(field.error("an account is '<scheme> <public_key_hex> <balance>'"));
    }
    let scheme: u8 = parts[0]
        .parse()
        .map_err(|_| field.error("the account scheme is not a byte"))?;
    let public_key = from_hex(parts[1]).map_err(|e| field.error(&format!("public key {e}")))?;
    let balance: u64 = parts[2]
        .parse()
        .map_err(|_| field.error("the account balance is not a number"))?;
    let address = address_for_key(scheme, &public_key);
    Ok(GenesisAccount {
        address,
        balance,
        scheme,
        public_key,
    })
}

fn genesis_hash(chain_id: &str, message: &str, slots: u64, genesis: &Genesis) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"QTV-GENESIS-V4");
    put_bytes(&mut buf, chain_id.as_bytes());
    put_bytes(&mut buf, message.as_bytes());
    buf.extend_from_slice(&genesis.genesis_time.to_le_bytes());
    buf.extend_from_slice(&slots.to_le_bytes());
    buf.extend_from_slice(&genesis.fee_params.transfer_micro_usd.to_le_bytes());
    buf.extend_from_slice(&genesis.fee_params.rate_micro_usd_per_qtov.to_le_bytes());
    buf.extend_from_slice(&genesis.fee_params.native_unit.to_le_bytes());
    buf.extend_from_slice(&genesis.fee_params.max_fee_native.to_le_bytes());
    if let Some(dest_chain) = genesis.bridge_dest_chain {
        buf.extend_from_slice(&dest_chain.to_le_bytes());
    }

    let mut validators = genesis.validators.clone();
    validators.sort_by_key(|v| v.id);
    buf.extend_from_slice(&(validators.len() as u64).to_le_bytes());
    for v in &validators {
        buf.extend_from_slice(&v.id.to_le_bytes());
        buf.extend_from_slice(&v.stake.to_le_bytes());
        buf.push(v.online as u8);
        put_bytes(&mut buf, v.bond_address.as_bytes());
        buf.extend_from_slice(&v.root.digest);
        buf.extend_from_slice(&v.root.slots.to_le_bytes());
        put_bytes(&mut buf, &v.attest_pk);
        put_bytes(&mut buf, &v.p2p_public);
    }

    let mut accounts = genesis.accounts.clone();
    accounts.sort_by(|a, b| a.address.cmp(&b.address));
    buf.extend_from_slice(&(accounts.len() as u64).to_le_bytes());
    for a in &accounts {
        put_bytes(&mut buf, a.address.as_bytes());
        buf.push(a.scheme);
        put_bytes(&mut buf, &a.public_key);
        buf.extend_from_slice(&a.balance.to_le_bytes());
    }

    sha3::sha3_256(&buf)
}

fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator(id: u64, stake: u64) -> ValidatorSpec {
        ValidatorSpec::from_secret(id, stake, true, &[id as u8; 32], 64)
    }

    fn account(tag: u8, balance: u64) -> GenesisAccount {
        GenesisAccount {
            address: format!("qtv1account{tag}"),
            balance,
            scheme: 0,
            public_key: vec![tag],
        }
    }

    fn sample_genesis(bridge_dest_chain: Option<u32>) -> Genesis {
        Genesis {
            fee_params: FeeParams {
                transfer_micro_usd: 1_000,
                rate_micro_usd_per_qtov: 500,
                native_unit: 1_000_000,
                max_fee_native: 10_000,
                chain_id: 42,
            },
            accounts: vec![account(1, 100), account(2, 100)],
            validators: vec![validator(1, 2_000), validator(2, 2_000)],
            genesis_time: 1_700_000_000,
            guardians: Default::default(),
            bridge_dest_chain,
            bridge_operators: None,
            bridged_assets: Vec::new(),
            bridge_era: None,
            bridge_bitcoin_anchor: None,
            bridge_eth_anchors: Vec::new(),
        }
    }

    fn legacy_v4_hash(chain_id: &str, message: &str, slots: u64, genesis: &Genesis) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"QTV-GENESIS-V4");
        put_bytes(&mut buf, chain_id.as_bytes());
        put_bytes(&mut buf, message.as_bytes());
        buf.extend_from_slice(&genesis.genesis_time.to_le_bytes());
        buf.extend_from_slice(&slots.to_le_bytes());
        buf.extend_from_slice(&genesis.fee_params.transfer_micro_usd.to_le_bytes());
        buf.extend_from_slice(&genesis.fee_params.rate_micro_usd_per_qtov.to_le_bytes());
        buf.extend_from_slice(&genesis.fee_params.native_unit.to_le_bytes());
        buf.extend_from_slice(&genesis.fee_params.max_fee_native.to_le_bytes());

        let mut validators = genesis.validators.clone();
        validators.sort_by_key(|v| v.id);
        buf.extend_from_slice(&(validators.len() as u64).to_le_bytes());
        for v in &validators {
            buf.extend_from_slice(&v.id.to_le_bytes());
            buf.extend_from_slice(&v.stake.to_le_bytes());
            buf.push(v.online as u8);
            put_bytes(&mut buf, v.bond_address.as_bytes());
            buf.extend_from_slice(&v.root.digest);
            buf.extend_from_slice(&v.root.slots.to_le_bytes());
            put_bytes(&mut buf, &v.attest_pk);
            put_bytes(&mut buf, &v.p2p_public);
        }

        let mut accounts = genesis.accounts.clone();
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        buf.extend_from_slice(&(accounts.len() as u64).to_le_bytes());
        for a in &accounts {
            put_bytes(&mut buf, a.address.as_bytes());
            buf.push(a.scheme);
            put_bytes(&mut buf, &a.public_key);
            buf.extend_from_slice(&a.balance.to_le_bytes());
        }

        sha3::sha3_256(&buf)
    }

    #[test]
    fn an_unset_bridge_dest_chain_reproduces_the_v4_genesis_hash() {
        let genesis = sample_genesis(None);
        let produced = genesis_hash("Q-test-net-1", "genesis", 64, &genesis);
        let legacy = legacy_v4_hash("Q-test-net-1", "genesis", 64, &genesis);
        assert_eq!(
            produced, legacy,
            "an unset bridge destination must hash to the exact pre-field V4 preimage, so a node \
             carrying the field reproduces the genesis hash the live testnet was launched on"
        );
    }

    #[test]
    fn a_set_bridge_dest_chain_moves_the_genesis_hash() {
        let unset = genesis_hash("Q-test-net-1", "genesis", 64, &sample_genesis(None));
        let set = genesis_hash("Q-test-net-1", "genesis", 64, &sample_genesis(Some(7)));
        assert_ne!(
            unset, set,
            "a set bridge destination must bind into the genesis hash, so a chain that fixes its \
             bridge target commits to that target at genesis"
        );
    }

    #[test]
    fn a_spread_validator_set_and_account_set_pass_the_cap() {
        let validators = vec![
            validator(1, 2_000),
            validator(2, 2_000),
            validator(3, 2_000),
            validator(4, 2_000),
        ];
        let accounts = vec![account(1, 100), account(2, 100), account(3, 100), account(4, 100)];
        assert!(
            enforce_no_capture(&validators, &accounts).is_ok(),
            "a spread where every share sits strictly under a third clears the cap"
        );
    }

    #[test]
    fn a_single_validator_and_faucet_bootstrap_is_allowed() {
        let validators = vec![validator(1, 2_000)];
        let accounts = vec![account(1, 1_000_000_000_000)];
        assert!(
            enforce_no_capture(&validators, &accounts).is_ok(),
            "a lone bootstrap validator and faucet has no committee to capture from"
        );
    }

    #[test]
    fn a_validator_at_the_fault_threshold_bond_is_rejected() {
        let validators = vec![validator(1, 2_000), validator(2, 2_000), validator(3, 2_000)];
        let err = enforce_no_capture(&validators, &[])
            .expect_err("a share at exactly a third is rejected");
        assert!(err.contains("validator 1"), "{err}");
        assert!(err.contains("fault threshold"), "{err}");
    }

    #[test]
    fn a_validator_over_the_fault_threshold_bond_is_rejected() {
        let validators = vec![
            validator(1, 2_000),
            validator(2, 2_000),
            validator(3, 2_000),
            validator(4, 9_000),
        ];
        let err = enforce_no_capture(&validators, &[]).expect_err("the whale validator is rejected");
        assert!(err.contains("validator 4"), "{err}");
    }

    #[test]
    fn two_equal_validators_each_at_half_are_rejected() {
        let validators = vec![validator(1, 2_000), validator(2, 2_000)];
        assert!(
            enforce_no_capture(&validators, &[]).is_err(),
            "half the stake is at or above the fault threshold"
        );
    }

    #[test]
    fn an_account_over_the_fault_threshold_balance_is_rejected() {
        let accounts = vec![account(1, 1_000), account(2, 9_000), account(3, 1_000)];
        let validators = vec![
            validator(1, 2_000),
            validator(2, 2_000),
            validator(3, 2_000),
            validator(4, 2_000),
        ];
        let err = enforce_no_capture(&validators, &accounts)
            .expect_err("the whale account is rejected");
        assert!(err.contains("account qtv1account2"), "{err}");
    }
}
