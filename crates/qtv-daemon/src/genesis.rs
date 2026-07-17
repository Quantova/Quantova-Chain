//! The genesis file, the shared and byte identical starting point every validator
//! opens from.
//!
//! One file fixes the whole network: its chain id, its genesis time, its committee
//! slot budget, its fee schedule, its funded accounts, and its validator set. Every
//! node parses the same file into the same genesis, so every node computes the
//! identical genesis state root and draws the identical committee. The format is a
//! plain `key = value` text we parse ourselves, comments after `#`, so the chain
//! graph keeps its property of carrying no outside serialization crate.
//!
//! A NOTE ON KEYS, READ IT. This build derives every validator's network and
//! attestation identity deterministically from its numeric id, through
//! `qtv_devnet::node::net_identity`. That means whoever holds this genesis and can
//! name a validator id controls that validator's identity. It is acceptable only on
//! a single operator's own machines and is unacceptable the moment a second party
//! runs a node, because the second party's identity would be one the first party can
//! forge. The daemon refuses to start under this key model unless a local
//! development flag is set, so the shortcut cannot leave by accident. Operator held
//! keys, one secret per validator that no one else can derive, are the required next
//! step before the network leaves one pair of hands.
//!
//! The chain id is bound through the genesis hash below. Two nodes that parsed
//! different genesis files, a different chain id, a different validator set, a
//! different fund, produce different genesis hashes, and the mesh refuses a peer
//! whose genesis hash is not this node's. So a node built on the wrong genesis
//! cannot feed this one consensus records, which is the cheap network identity that
//! is far more expensive to retrofit once two live networks exist.

use std::path::Path;

use qtv_account::{address_for_key, Tier};
use qtv_crypto::sha3;
use qtv_devnet::config::DEFAULT_SLOTS;
use qtv_node::fee::FeeParams;
use qtv_node::node::{Genesis, GenesisAccount, ValidatorSpec};

use crate::config::{parse_kv, Field};
use crate::util::from_hex;

/// A parsed genesis file: the chain id it names, the genesis the node opens from,
/// the committee slot budget, and the hash that fixes this network's identity.
pub struct GenesisFile {
    /// The human chain id, reported in logs and carried for the operator's eye. The
    /// binding check is the hash, which commits to this and to every other field.
    pub chain_id: String,
    /// The genesis every node funds and draws its committee from.
    pub genesis: Genesis,
    /// The one time sortition slot budget every validator tree is sized to. One slot
    /// is spent per finalised height, so this bounds the chain to that many heights
    /// before the sortition keys are exhausted and the daemon can no longer select a
    /// committee. Running past it needs an epoch or key rotation mechanism in the
    /// consensus, which is a named open item and not something the daemon papers
    /// over. The daemon logs the budget and the heights remaining so the boundary is
    /// never a surprise.
    pub slots: u64,
    /// The SHA3 hash over the whole genesis, chain id included. This is the network
    /// identity the mesh pins a peer against.
    pub hash: [u8; 32],
}

impl GenesisFile {
    /// Load and parse a genesis file, deriving each funded account's address from its
    /// scheme and public key and computing the genesis hash. Every failure names the
    /// file and the line so a malformed genesis is caught at load rather than at the
    /// first block.
    pub fn load(path: &Path) -> Result<GenesisFile, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading genesis file {}: {e}", path.display()))?;
        let fields = parse_kv(&text, path)?;

        let mut chain_id: Option<String> = None;
        let mut genesis_time: Option<u64> = None;
        let mut slots: u64 = DEFAULT_SLOTS;
        let mut transfer_micro_usd: Option<u128> = None;
        let mut rate_micro_usd_per_qtov: Option<u128> = None;
        let mut native_unit: Option<u128> = None;
        let mut validators: Vec<ValidatorSpec> = Vec::new();
        let mut accounts: Vec<GenesisAccount> = Vec::new();

        for field in &fields {
            match field.key.as_str() {
                "chain_id" => chain_id = Some(field.value.clone()),
                "genesis_time" => genesis_time = Some(field.u64("genesis_time")?),
                "slots" => slots = field.u64("slots")?,
                "fee_transfer_micro_usd" => {
                    transfer_micro_usd = Some(field.u128("fee_transfer_micro_usd")?)
                }
                "fee_rate_micro_usd_per_qtov" => {
                    rate_micro_usd_per_qtov = Some(field.u128("fee_rate_micro_usd_per_qtov")?)
                }
                "fee_native_unit" => native_unit = Some(field.u128("fee_native_unit")?),
                "validator" => validators.push(parse_validator(field)?),
                "account" => accounts.push(parse_account(field)?),
                other => {
                    return Err(field.error(&format!("unknown genesis key '{other}'")));
                }
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
        };
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
        let hash = genesis_hash(&chain_id, slots, &genesis);
        Ok(GenesisFile {
            chain_id,
            genesis,
            slots,
            hash,
        })
    }
}

/// Parse a validator line, `validator = <id> <stake> <online|offline>`. The stake is
/// the native weight the sortition draws the committee against, so it is part of
/// genesis and the same on every node.
fn parse_validator(field: &Field) -> Result<ValidatorSpec, String> {
    let parts: Vec<&str> = field.value.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(field.error("a validator is '<id> <stake> <online|offline>'"));
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
    Ok(ValidatorSpec { id, stake, online })
}

/// Parse a funded account line, `account = <scheme> <public_key_hex> <balance>`. The
/// address is derived from the scheme and the public key at the canonical tier, the
/// same derivation a wallet computes, so the funded account is the one the holder of
/// that key signs from.
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
    let address = address_for_key(scheme, &public_key, Tier::Canonical);
    Ok(GenesisAccount {
        address,
        balance,
        scheme,
        public_key,
    })
}

/// The SHA3 hash over the whole genesis, the network identity a peer is pinned
/// against. The validators and accounts are folded in sorted order, validators by
/// id and accounts by address, so two genesis files that list the same set in a
/// different line order still hash equal and name the same network. Every field is
/// length prefixed or fixed width, so no two distinct genesis inputs collide onto
/// one hash.
fn genesis_hash(chain_id: &str, slots: u64, genesis: &Genesis) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"QTV-GENESIS-V1");
    put_bytes(&mut buf, chain_id.as_bytes());
    buf.extend_from_slice(&genesis.genesis_time.to_le_bytes());
    buf.extend_from_slice(&slots.to_le_bytes());
    buf.extend_from_slice(&genesis.fee_params.transfer_micro_usd.to_le_bytes());
    buf.extend_from_slice(&genesis.fee_params.rate_micro_usd_per_qtov.to_le_bytes());
    buf.extend_from_slice(&genesis.fee_params.native_unit.to_le_bytes());

    let mut validators = genesis.validators.clone();
    validators.sort_by_key(|v| v.id);
    buf.extend_from_slice(&(validators.len() as u64).to_le_bytes());
    for v in &validators {
        buf.extend_from_slice(&v.id.to_le_bytes());
        buf.extend_from_slice(&v.stake.to_le_bytes());
        buf.push(v.online as u8);
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

/// Append a length prefixed byte string, so a field boundary is unambiguous and two
/// distinct field splits cannot fold to the same bytes.
fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}
