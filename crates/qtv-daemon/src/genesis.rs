
use std::path::Path;

use qtv_account::address_for_key;
use qtv_crypto::sha3;
use qtv_devnet::config::DEFAULT_SLOTS;
use qtv_node::fee::FeeParams;
use qtv_node::node::{Genesis, GenesisAccount, Root, ValidatorSpec};

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
                "validator" => {}
                "account" => accounts.push(parse_account(field)?),
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
        let fee_params = FeeParams {
            transfer_micro_usd: transfer_micro_usd
                .ok_or("the genesis is missing 'fee_transfer_micro_usd'")?,
            rate_micro_usd_per_qtov: rate_micro_usd_per_qtov
                .ok_or("the genesis is missing 'fee_rate_micro_usd_per_qtov'")?,
            native_unit: native_unit.ok_or("the genesis is missing 'fee_native_unit'")?,
            max_fee_native: max_fee_native.ok_or("the genesis is missing 'fee_max_native'")?,
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

        let genesis = Genesis {
            fee_params,
            accounts,
            validators,
            genesis_time,
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
