// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_devnet::wire::wrapper_from_bytes;
use qtv_devnet::DevNode;
use qtv_node::fee::FeeParams;
use qtv_node::ledger::SideEvent;
use qtv_node::mempool::{Admitted, Reject};
use qtv_tx::Wrapper;

use crate::json::{object, Json};

pub struct NodeContext {
    pub chain_id: String,
    pub genesis_hash_hex: String,
    pub asset: String,
    pub fee_params: FeeParams,
    pub version: String,
}

pub enum BlockSelector {
    Height(u64),
    Id(String),
}

pub enum Request {
    NodeInfo,
    Account(String),
    Submit(Vec<u8>),
    Transaction(String),
    Block(BlockSelector),
    Head,
    Validators,
    ChainParams,
    StakingState,
    Pending,
    Container(String),
    Storage(String),
    StorageAt { address: String, keys: Vec<[u8; 32]> },
    Supply,
    Events(u64),
    SideEvents(u64),
    FinalizedHead,
    BurnBlock(u64),
    BurnHeightsAfter(u64),
    BridgedBalance { asset_id: [u8; 16], holder: [u8; 32] },
    BridgedSupply { asset_id: [u8; 16] },
    AssetBalance { issuer: [u8; 32], holder: [u8; 32] },
    AssetSupply { issuer: [u8; 32] },
    GovernanceReferenda,
    GenesisAccounts,
}

pub struct ClientError {
    pub code: String,
    pub message: String,
    pub http: u16,
}

impl ClientError {
    fn bad(code: &str, message: impl Into<String>) -> ClientError {
        ClientError {
            code: code.to_string(),
            message: message.into(),
            http: 400,
        }
    }

    fn not_found(message: impl Into<String>) -> ClientError {
        ClientError {
            code: "not_found".to_string(),
            message: message.into(),
            http: 404,
        }
    }

    pub fn render(&self) -> String {
        object(vec![
            ("error", Json::str(&self.code)),
            ("message", Json::str(&self.message)),
        ])
        .render()
    }
}

pub fn build_request(method: &str, body: &Json) -> Result<Request, ClientError> {
    match method {
        "node_info" => Ok(Request::NodeInfo),
        "head" => Ok(Request::Head),
        "validators" => Ok(Request::Validators),
        "chain_params" => Ok(Request::ChainParams),
        "staking_state" => Ok(Request::StakingState),
        "get_account" => Ok(Request::Account(string_field(body, "address")?)),
        "get_transaction" => Ok(Request::Transaction(string_field(body, "tx_id")?)),
        "submit_transaction" => {
            let hex = string_field(body, "tx")?;
            let bytes = crate::json::from_hex(&hex)
                .map_err(|e| ClientError::bad("bad_request", format!("the tx field is not hex, {e}")))?;
            Ok(Request::Submit(bytes))
        }
        "get_block" => {
            if let Some(height) = body.get("height").and_then(Json::as_u64) {
                Ok(Request::Block(BlockSelector::Height(height)))
            } else if let Some(id) = body.get("block").and_then(Json::as_str) {
                Ok(Request::Block(BlockSelector::Id(id.to_string())))
            } else {
                Err(ClientError::bad(
                    "bad_request",
                    "get_block needs a height or a block id",
                ))
            }
        }
        "pending" => Ok(Request::Pending),
        "supply" => Ok(Request::Supply),
        "get_container" => Ok(Request::Container(string_field(body, "address")?)),
        "get_storage" => Ok(Request::Storage(string_field(body, "address")?)),
        "get_storage_at" => Ok(Request::StorageAt {
            address: string_field(body, "address")?,
            keys: key_list(body)?,
        }),
        "get_events" => {
            let height = body
                .get("height")
                .and_then(Json::as_u64)
                .ok_or_else(|| ClientError::bad("bad_request", "get_events needs a height"))?;
            Ok(Request::Events(height))
        }
        "get_side_events" => {
            let height = body
                .get("height")
                .and_then(Json::as_u64)
                .ok_or_else(|| ClientError::bad("bad_request", "get_side_events needs a height"))?;
            Ok(Request::SideEvents(height))
        }
        "get_bridged_balance" => Ok(Request::BridgedBalance {
            asset_id: hex_bytes::<16>(body, "asset_id")?,
            holder: holder_id(body)?,
        }),
        "get_bridged_supply" => Ok(Request::BridgedSupply {
            asset_id: hex_bytes::<16>(body, "asset_id")?,
        }),
        "get_asset_balance" => Ok(Request::AssetBalance {
            issuer: issuer_id(body)?,
            holder: holder_id(body)?,
        }),
        "get_asset_supply" => Ok(Request::AssetSupply {
            issuer: issuer_id(body)?,
        }),
        "governance_referenda" => Ok(Request::GovernanceReferenda),
        "genesis_accounts" => Ok(Request::GenesisAccounts),
        "finalized_head" => Ok(Request::FinalizedHead),
        "burn_block" => {
            let height = body
                .get("height")
                .and_then(Json::as_u64)
                .ok_or_else(|| ClientError::bad("bad_request", "burn_block needs a height"))?;
            Ok(Request::BurnBlock(height))
        }
        "burn_heights_after" => {
            let cursor = body
                .get("cursor")
                .and_then(Json::as_u64)
                .ok_or_else(|| ClientError::bad("bad_request", "burn_heights_after needs a cursor"))?;
            Ok(Request::BurnHeightsAfter(cursor))
        }
        other => Err(ClientError {
            code: "unknown_method".to_string(),
            message: format!("no method named {other}"),
            http: 404,
        }),
    }
}

fn string_field(body: &Json, key: &str) -> Result<String, ClientError> {
    body.get(key)
        .and_then(Json::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| ClientError::bad("bad_request", format!("missing string field {key}")))
}

const MAX_STORAGE_KEYS: usize = 64;

fn key_list(body: &Json) -> Result<Vec<[u8; 32]>, ClientError> {
    let array = body
        .get("keys")
        .and_then(Json::as_array)
        .ok_or_else(|| ClientError::bad("bad_request", "get_storage_at needs a keys array"))?;
    if array.len() > MAX_STORAGE_KEYS {
        return Err(ClientError::bad(
            "bad_request",
            format!("at most {MAX_STORAGE_KEYS} keys per request"),
        ));
    }
    let mut keys = Vec::with_capacity(array.len());
    for item in array {
        let hex = item
            .as_str()
            .ok_or_else(|| ClientError::bad("bad_request", "a storage key is not a hex string"))?;
        let bytes = crate::json::from_hex(hex)
            .map_err(|e| ClientError::bad("bad_request", format!("a storage key is not hex, {e}")))?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::bad("bad_request", "a storage key is not thirty two bytes"))?;
        keys.push(key);
    }
    Ok(keys)
}

fn storage_at(node: &DevNode, address: &str, keys: &[[u8; 32]]) -> Result<Json, ClientError> {
    if qtv_idfmt::parse_address(address).is_err() {
        return Err(ClientError::bad("bad_address", "the address is not a q1 address"));
    }
    let all = node
        .ledger()
        .contract_storage_at_capped(address)
        .ok_or_else(|| ClientError::bad("storage_too_large", "the contract storage is too large to serve over rpc"))?;
    let slots: Vec<Json> = keys
        .iter()
        .filter_map(|key| {
            all.get(key).map(|value| {
                let slot_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
                object(vec![
                    ("slot", Json::str(slot_hex)),
                    ("value", Json::str(value.to_string())),
                ])
            })
        })
        .collect();
    Ok(object(vec![
        ("address", Json::str(address)),
        ("slots", Json::Array(slots)),
    ]))
}

fn hex_bytes<const N: usize>(body: &Json, key: &str) -> Result<[u8; N], ClientError> {
    let hex = string_field(body, key)?;
    let bytes = crate::json::from_hex(&hex)
        .map_err(|e| ClientError::bad("bad_request", format!("the {key} field is not hex, {e}")))?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| ClientError::bad("bad_request", format!("the {key} field must be {N} bytes")))
}

fn holder_id(body: &Json) -> Result<[u8; 32], ClientError> {
    let holder = string_field(body, "holder")?;
    if let Ok(payload) = qtv_idfmt::parse_address(&holder) {
        return <[u8; 32]>::try_from(payload.as_slice())
            .map_err(|_| ClientError::bad("bad_request", "the holder address is not 32 bytes"));
    }
    hex_bytes::<32>(body, "holder")
}

fn issuer_id(body: &Json) -> Result<[u8; 32], ClientError> {
    let issuer = string_field(body, "issuer")?;
    if let Ok(payload) = qtv_idfmt::parse_address(&issuer) {
        return <[u8; 32]>::try_from(payload.as_slice())
            .map_err(|_| ClientError::bad("bad_request", "the issuer address is not 32 bytes"));
    }
    hex_bytes::<32>(body, "issuer")
}

pub fn handle(ctx: &NodeContext, node: &mut DevNode, request: Request) -> Result<Json, ClientError> {
    match request {
        Request::NodeInfo => Ok(node_info(ctx, node)),
        Request::Head => Ok(head(node)),
        Request::Account(address) => account(node, &address),
        Request::Transaction(tx_id) => Ok(transaction(node, &tx_id)),
        Request::Submit(bytes) => Ok(submit(node, bytes)),
        Request::Block(selector) => block(node, selector),
        Request::Validators => Ok(validators(node)),
        Request::ChainParams => Ok(chain_params()),
        Request::StakingState => Ok(staking_state(node)),
        Request::Pending => Ok(pending(node)),
        Request::Supply => Ok(supply(node)),
        Request::Container(address) => container(node, &address),
        Request::Storage(address) => storage(node, &address),
        Request::StorageAt { address, keys } => storage_at(node, &address, &keys),
        Request::Events(height) => Ok(events(node, height)),
        Request::SideEvents(height) => Ok(side_events(node, height)),
        Request::FinalizedHead => Ok(finalized_head(node)),
        Request::BurnBlock(height) => burn_block(node, height),
        Request::BurnHeightsAfter(cursor) => Ok(burn_heights_after(node, cursor)),
        Request::BridgedBalance { asset_id, holder } => Ok(bridged_balance(node, &asset_id, &holder)),
        Request::BridgedSupply { asset_id } => Ok(bridged_supply(node, &asset_id)),
        Request::AssetBalance { issuer, holder } => Ok(asset_balance(node, &issuer, &holder)),
        Request::AssetSupply { issuer } => Ok(asset_supply(node, &issuer)),
        Request::GovernanceReferenda => Ok(governance_referenda(node)),
        Request::GenesisAccounts => Ok(genesis_accounts(node)),
    }
}

fn bridged_balance(node: &DevNode, asset_id: &[u8; 16], holder: &[u8; 32]) -> Json {
    let ledger = node.ledger();
    object(vec![
        ("asset_id", Json::str(crate::json::to_hex(asset_id))),
        ("holder", Json::str(crate::json::to_hex(holder))),
        (
            "holder_address",
            Json::str(qtv_idfmt::render_address(holder).unwrap_or_default()),
        ),
        ("balance", amount_str(ledger.bridged_balance(asset_id, holder))),
        ("supply", amount_str(ledger.bridged_supply(asset_id))),
    ])
}

fn asset_balance(node: &DevNode, issuer: &[u8; 32], holder: &[u8; 32]) -> Json {
    let ledger = node.ledger();
    object(vec![
        (
            "issuer",
            Json::str(qtv_idfmt::render_address(issuer).unwrap_or_default()),
        ),
        (
            "holder",
            Json::str(qtv_idfmt::render_address(holder).unwrap_or_default()),
        ),
        ("balance", amount_str(ledger.asset_balance_by_issuer(issuer, holder))),
        ("supply", amount_str(ledger.asset_supply_by_issuer(issuer))),
    ])
}

fn asset_supply(node: &DevNode, issuer: &[u8; 32]) -> Json {
    let ledger = node.ledger();
    object(vec![
        (
            "issuer",
            Json::str(qtv_idfmt::render_address(issuer).unwrap_or_default()),
        ),
        ("supply", amount_str(ledger.asset_supply_by_issuer(issuer))),
    ])
}

fn governance_referenda(node: &DevNode) -> Json {
    let ledger = node.ledger();
    let items: Vec<Json> = ledger
        .gov_referenda(MAX_LIST_ITEMS)
        .into_iter()
        .map(|r| {
            let mut proposer = [0u8; 32];
            if r.proposer.len() == 32 {
                proposer.copy_from_slice(&r.proposer);
            }
            let status = match r.status {
                qtv_governance::Status::Deciding => "deciding",
                qtv_governance::Status::Approved => "approved",
                qtv_governance::Status::Rejected => "rejected",
            };
            object(vec![
                ("id", Json::Int(r.id)),
                ("track", Json::Int(r.track.code() as u64)),
                (
                    "proposer",
                    Json::str(qtv_idfmt::render_address(&proposer).unwrap_or_default()),
                ),
                ("deposit", amount_str(r.deposit as u128)),
                ("submitted_at", Json::Int(r.submitted_at)),
                ("aye_stake", amount_str(r.tally.aye_stake)),
                ("nay_stake", amount_str(r.tally.nay_stake)),
                ("status", Json::str(status)),
                ("killed", Json::Bool(r.killed)),
            ])
        })
        .collect();
    object(vec![("referenda", Json::Array(items))])
}

fn bridged_supply(node: &DevNode, asset_id: &[u8; 16]) -> Json {
    let ledger = node.ledger();
    let asset = ledger.bridged_asset(asset_id);
    object(vec![
        ("asset_id", Json::str(crate::json::to_hex(asset_id))),
        ("supply", amount_str(ledger.bridged_supply(asset_id))),
        (
            "cap",
            amount_str(asset.as_ref().map(|a| a.cap).unwrap_or(0)),
        ),
        ("registered", Json::Bool(asset.is_some())),
    ])
}

fn genesis_accounts(node: &DevNode) -> Json {
    let all = node.genesis_accounts();
    let total = all.len();
    let accounts: Vec<Json> = all
        .iter()
        .take(MAX_LIST_ITEMS)
        .map(|account| {
            object(vec![
                ("address", Json::str(&account.address)),
                ("balance", Json::str(account.balance.to_string())),
                ("scheme", Json::Int(account.scheme as u64)),
            ])
        })
        .collect();
    object(vec![
        ("count", Json::Int(total as u64)),
        ("returned", Json::Int(accounts.len() as u64)),
        ("truncated", Json::Bool(total > accounts.len())),
        ("supply_quon", Json::str(node.genesis_supply().to_string())),
        ("accounts", Json::Array(accounts)),
    ])
}

fn finalized_head(node: &DevNode) -> Json {
    object(vec![("head", Json::Int(node.finalized_head()))])
}

fn burn_block(node: &DevNode, height: u64) -> Result<Json, ClientError> {
    match node.burn_block(height) {
        Some(entry) => {
            let events: Vec<Json> = entry
                .events
                .iter()
                .map(|leaf| Json::str(crate::json::to_hex(leaf)))
                .collect();
            Ok(object(vec![
                ("height", Json::Int(entry.height)),
                (
                    "header_bytes",
                    Json::str(crate::json::to_hex(&entry.header_bytes)),
                ),
                (
                    "certificate",
                    Json::str(crate::json::to_hex(&entry.certificate)),
                ),
                ("events", Json::Array(events)),
            ]))
        }
        None => Err(ClientError::not_found(format!(
            "no archived burn block at height {height}"
        ))),
    }
}

fn burn_heights_after(node: &DevNode, cursor: u64) -> Json {
    let items: Vec<Json> = node
        .burn_heights_after(cursor)
        .into_iter()
        .map(Json::Int)
        .collect();
    object(vec![
        ("cursor", Json::Int(cursor)),
        ("count", Json::Int(items.len() as u64)),
        ("heights", Json::Array(items)),
    ])
}

fn staking_state(node: &DevNode) -> Json {
    let ledger = node.ledger();
    let mainnet_start = ledger.stake_mainnet_start();
    object(vec![
        ("reward_pool", Json::Int(ledger.stake_pool())),
        ("treasury", Json::Int(ledger.stake_treasury())),
        (
            "price_micro_usd_per_qtov",
            Json::str(&ledger.stake_price().to_string()),
        ),
        ("mainnet_started", Json::Bool(mainnet_start != u64::MAX)),
        (
            "governance_locked",
            Json::str(&ledger.gov_total_locked().to_string()),
        ),
    ])
}

fn chain_params() -> Json {
    let tracks: Vec<Json> = qtv_governance::Track::all()
        .iter()
        .map(|track| {
            object(vec![
                ("code", Json::Int(u64::from(track.code()))),
                ("deposit", Json::Int(track.deposit())),
                ("threshold_bps", Json::Int(qtv_governance::THRESHOLD_BPS as u64)),
                ("period_seconds", Json::Int(track.period_seconds())),
            ])
        })
        .collect();
    object(vec![
        (
            "staking",
            object(vec![
                ("native_unit", Json::Int(qtv_staking::NATIVE_UNIT as u64)),
                ("min_stake", Json::Int(qtv_staking::MIN_STAKE)),
                ("staking_pool", Json::Int(qtv_staking::STAKING_POOL)),
                ("session_emission", Json::Int(qtv_staking::SESSION_EMISSION)),
                ("session_days", Json::Int(qtv_staking::SESSION_DAYS)),
                ("high_session_tx", Json::Int(qtv_staking::HIGH_SESSION_TX)),
                (
                    "mainnet_blackout_days",
                    Json::Int(qtv_staking::MAINNET_BLACKOUT_DAYS),
                ),
                ("bond_lock_days", Json::Int(qtv_staking::BOND_LOCK_DAYS)),
                ("unbonding_days", Json::Int(qtv_staking::UNBONDING_DAYS)),
                ("reward_vest_days", Json::Int(qtv_staking::REWARD_VEST_DAYS)),
            ]),
        ),
        (
            "governance",
            object(vec![
                (
                    "conviction_max_x10",
                    Json::Int(qtv_governance::Conviction::TwoYear.factor_x10() as u64),
                ),
                ("tracks", Json::Array(tracks)),
            ]),
        ),
    ])
}

fn validators(node: &DevNode) -> Json {
    let ledger = node.ledger();
    let mut list = Vec::new();
    for id in ledger.validator_ids() {
        let Ok(address) = qtv_idfmt::render_address(&id) else {
            continue;
        };
        let stake = ledger.staked_weight(&address);
        list.push(object(vec![
            ("address", Json::str(&address)),
            ("stake", Json::Int(stake)),
        ]));
    }
    object(vec![
        ("count", Json::Int(list.len() as u64)),
        ("validators", Json::Array(list)),
    ])
}

fn node_info(ctx: &NodeContext, node: &DevNode) -> Json {
    let fee = &ctx.fee_params;
    object(vec![
        ("chain_id", Json::str(&ctx.chain_id)),
        ("genesis_hash", Json::str(&ctx.genesis_hash_hex)),
        ("head_height", Json::Int(node.height().saturating_sub(1))),
        ("asset", Json::str(&ctx.asset)),
        ("denomination", Json::str("Quon")),
        (
            "fee",
            object(vec![
                ("transfer_micro_usd", Json::str(fee.transfer_micro_usd.to_string())),
                (
                    "rate_micro_usd_per_qtov",
                    Json::str(fee.rate_micro_usd_per_qtov.to_string()),
                ),
                ("quon_per_qtov", Json::str(fee.native_unit.to_string())),
                ("transfer_quon", Json::str(fee.transfer_fee().to_string())),
            ]),
        ),
        ("version", Json::str(&ctx.version)),
    ])
}

fn head(node: &DevNode) -> Json {
    let head_height = node.height().saturating_sub(1);
    let q_root = node.ledger().q_root_id();
    let block = if head_height >= qtv_bft::params::MIN_HEIGHT {
        Json::str(qtv_idfmt::render_block(&node.head_hash()).expect("a header hash is digest length"))
    } else {
        Json::Null
    };
    object(vec![
        ("height", Json::Int(head_height)),
        ("block", block),
        ("q_root", Json::str(q_root)),
    ])
}

fn account(node: &DevNode, address: &str) -> Result<Json, ClientError> {
    if qtv_idfmt::parse_address(address).is_err() {
        return Err(ClientError::bad(
            "bad_address",
            "the address is not a q1 Bech32m address",
        ));
    }
    let account = node.ledger().account(address);
    Ok(object(vec![
        ("address", Json::str(address)),
        ("nonce", Json::Int(account.nonce)),
        ("balance", Json::str(account.balance.to_string())),
        ("scheme", Json::Int(account.scheme as u64)),
        ("has_key", Json::Bool(account.has_key())),
    ]))
}

struct SystemAddrs {
    deploy: String,
    bridge_mint: String,
    bridge_exit: String,
    bridge_settle: String,
    bridge_guardian: String,
    registration: String,
    key_register: String,
    evidence: String,
    governance: String,
}

fn system_addrs() -> &'static SystemAddrs {
    static CACHE: std::sync::OnceLock<SystemAddrs> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        use qtv_node::ledger as l;
        SystemAddrs {
            deploy: l::vm_deploy_address(),
            bridge_mint: l::bridge_mint_address(),
            bridge_exit: l::bridge_exit_address(),
            bridge_settle: l::bridge_settle_address(),
            bridge_guardian: l::bridge_guardian_address(),
            registration: l::registration_address(),
            key_register: l::key_register_address(),
            evidence: l::evidence_address(),
            governance: l::gov_system_address(),
        }
    })
}

fn tx_kind(node: &DevNode, sender: &str, target: &str, nonce: u64) -> (&'static str, Option<String>) {
    let s = system_addrs();
    if target == s.deploy {
        return ("deploy", qtv_node::ledger::contract_address(sender, nonce));
    }
    if node.ledger().is_contract(target) {
        return ("call", None);
    }
    if target == s.bridge_mint {
        return ("bridge_mint", None);
    }
    if target == s.bridge_exit {
        return ("bridge_exit", None);
    }
    if target == s.bridge_settle {
        return ("bridge_settle", None);
    }
    if target == s.bridge_guardian {
        return ("bridge_guardian", None);
    }
    if target == s.registration {
        return ("register", None);
    }
    if target == s.key_register {
        return ("key_register", None);
    }
    if target == s.evidence {
        return ("evidence", None);
    }
    if target == s.governance {
        return ("governance", None);
    }
    ("transfer", None)
}

fn tx_fields(node: &DevNode, wrapper: &Wrapper) -> Vec<(&'static str, Json)> {
    let body = wrapper.body();
    let target = body.call().target();
    let amount = qtv_node::execution::transfer_amount(body.call()).unwrap_or(0);
    let (kind, contract) = tx_kind(node, body.sender(), target, body.nonce());
    let mut fields = vec![
        ("from", Json::str(body.sender())),
        ("to", Json::str(target)),
        ("kind", Json::str(kind)),
        ("value", Json::str(amount.to_string())),
        ("fee", Json::str(body.fee().to_string())),
        ("nonce", Json::Int(body.nonce())),
        ("meter_limit", Json::Int(body.meter_limit())),
        ("scheme", Json::Int(u64::from(wrapper.scheme()))),
        ("signature", Json::str(crate::json::to_hex(wrapper.signature()))),
        ("raw", Json::str(crate::json::to_hex(&qtv_codec::to_bytes(wrapper)))),
    ];
    if let Some(contract) = contract {
        fields.push(("contract", Json::str(contract)));
    }
    fields
}

fn transaction(node: &DevNode, tx_id: &str) -> Json {
    if let Some(height) = node.finalized_height(tx_id) {
        let mut fields = vec![
            ("tx_id", Json::str(tx_id)),
            ("status", Json::str("finalised")),
            ("height", Json::Int(height)),
        ];
        if let Some(block) = node.block_at_height(height) {
            fields.push(("block", Json::str(block.id())));
            if let Some(wrapper) = block.body().iter().find(|w| w.id() == tx_id) {
                fields.extend(tx_fields(node, wrapper));
            }
        }
        object(fields)
    } else if node.is_pending(tx_id) {
        let mut fields = vec![
            ("tx_id", Json::str(tx_id)),
            ("status", Json::str("pending")),
        ];
        if let Some(wrapper) = node.pending_transaction(tx_id) {
            fields.extend(tx_fields(node, &wrapper));
        }
        object(fields)
    } else {
        object(vec![
            ("tx_id", Json::str(tx_id)),
            ("status", Json::str("unknown")),
        ])
    }
}

// Cap list entries per RPC response, so a large mempool or contract cannot build a huge string on the consensus thread.
const MAX_LIST_ITEMS: usize = 1_000;

const MAX_LIST_RESPONSE_BYTES: usize = 512 * 1024;

fn pending(node: &DevNode) -> Json {
    let total = node.pending_count();
    let top = node.pending_snapshot(MAX_LIST_ITEMS);
    let mut items: Vec<Json> = Vec::new();
    let mut budget = MAX_LIST_RESPONSE_BYTES;
    for wrapper in &top {
        let mut fields = vec![("tx_id", Json::str(wrapper.id()))];
        fields.extend(tx_fields(node, wrapper));
        let item = object(fields);
        let size = item.render().len();
        if size > budget && !items.is_empty() {
            break;
        }
        budget = budget.saturating_sub(size);
        items.push(item);
    }
    object(vec![
        ("count", Json::Int(total as u64)),
        ("returned", Json::Int(items.len() as u64)),
        ("truncated", Json::Bool(total > items.len())),
        ("transactions", Json::Array(items)),
    ])
}

fn supply(node: &DevNode) -> Json {
    object(vec![(
        "supply_quon",
        Json::str(node.ledger().total_supply().to_string()),
    )])
}

fn events(node: &DevNode, height: u64) -> Json {
    let items: Vec<Json> = node
        .events_at(height)
        .iter()
        .map(|event| {
            object(vec![
                ("contract", Json::str(&event.contract)),
                ("selector", Json::str(crate::json::to_hex(&event.selector))),
                ("data", Json::str(crate::json::to_hex(&event.data))),
            ])
        })
        .collect();
    object(vec![
        ("height", Json::Int(height)),
        ("count", Json::Int(items.len() as u64)),
        ("events", Json::Array(items)),
    ])
}

fn side_events(node: &DevNode, height: u64) -> Json {
    let items: Vec<Json> = node
        .side_events_at(height)
        .iter()
        .enumerate()
        .map(|(index, event)| side_event_json(index as u64, event))
        .collect();
    object(vec![
        ("height", Json::Int(height)),
        ("count", Json::Int(items.len() as u64)),
        ("events", Json::Array(items)),
    ])
}

fn amount_str(amount: u128) -> Json {
    Json::str(amount.to_string())
}

fn id_address(id: &[u8; 32]) -> String {
    qtv_idfmt::render_address(id).unwrap_or_else(|_| crate::json::to_hex(id))
}

fn side_event_json(index: u64, event: &SideEvent) -> Json {
    let mut fields: Vec<(&str, Json)> = vec![
        ("index", Json::Int(index)),
        ("kind", Json::str(event.kind())),
        ("actor", Json::str("")),
        ("target", Json::str("")),
        ("amount", Json::str("0")),
        ("ref", Json::Int(0)),
        ("aux", Json::Int(0)),
    ];
    let set = |fields: &mut Vec<(&str, Json)>, key: &str, value: Json| {
        if let Some(slot) = fields.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        }
    };
    match event {
        SideEvent::GovPropose {
            referendum,
            proposer,
            track,
            action,
            deposit,
        } => {
            set(&mut fields, "actor", Json::str(proposer));
            set(&mut fields, "amount", amount_str(*deposit as u128));
            set(&mut fields, "ref", Json::Int(*referendum));
            set(&mut fields, "aux", Json::Int(*track as u64));
            fields.push(("action", Json::str(*action)));
        }
        SideEvent::GovVote {
            referendum,
            voter,
            aye,
            conviction,
            stake,
        } => {
            set(&mut fields, "actor", Json::str(voter));
            set(&mut fields, "amount", amount_str(*stake as u128));
            set(&mut fields, "ref", Json::Int(*referendum));
            set(&mut fields, "aux", Json::Int(*conviction as u64));
            fields.push(("aye", Json::Bool(*aye)));
        }
        SideEvent::GovTally {
            referendum,
            status,
            aye_stake,
            nay_stake,
        } => {
            set(&mut fields, "ref", Json::Int(*referendum));
            set(&mut fields, "amount", amount_str(*aye_stake));
            fields.push(("status", Json::str(*status)));
            fields.push(("aye_stake", amount_str(*aye_stake)));
            fields.push(("nay_stake", amount_str(*nay_stake)));
        }
        SideEvent::GovEnact {
            referendum,
            action,
            proposal_hash,
        } => {
            set(&mut fields, "ref", Json::Int(*referendum));
            fields.push(("action", Json::str(*action)));
            fields.push(("proposal_hash", Json::str(crate::json::to_hex(proposal_hash))));
        }
        SideEvent::Mint { to, amount } => {
            set(&mut fields, "target", Json::str(to));
            set(&mut fields, "amount", amount_str(*amount as u128));
        }
        SideEvent::Spend { source, to, amount } => {
            set(&mut fields, "actor", Json::str(source));
            set(&mut fields, "target", Json::str(to));
            set(&mut fields, "amount", amount_str(*amount as u128));
        }
        SideEvent::Parameter { key, value } => {
            fields.push(("key", Json::str(crate::json::to_hex(key))));
            fields.push(("value", Json::str(crate::json::to_hex(value))));
        }
        SideEvent::Blacklist { target } => {
            set(&mut fields, "target", Json::str(target));
        }
        SideEvent::Freeze { target } => {
            set(&mut fields, "target", Json::str(target));
        }
        SideEvent::Unfreeze { target } => {
            set(&mut fields, "target", Json::str(target));
        }
        SideEvent::RecoverySeizure {
            victim,
            from,
            amount,
            scope,
        } => {
            set(&mut fields, "actor", Json::str(from));
            set(&mut fields, "target", Json::str(victim));
            set(&mut fields, "amount", amount_str(*amount as u128));
            fields.push(("scope", Json::str(crate::json::to_hex(scope))));
        }
        SideEvent::RecoveryCredit {
            victim,
            amount,
            scope,
        } => {
            set(&mut fields, "target", Json::str(victim));
            set(&mut fields, "amount", amount_str(*amount as u128));
            fields.push(("scope", Json::str(crate::json::to_hex(scope))));
        }
        SideEvent::GuardianFreeze { target, bound } => {
            set(&mut fields, "target", Json::str(target));
            set(&mut fields, "aux", Json::Int(*bound));
        }
        SideEvent::GuardianRotate { size, threshold } => {
            set(&mut fields, "aux", Json::Int(*threshold as u64));
            fields.push(("size", Json::Int(*size as u64)));
            fields.push(("threshold", Json::Int(*threshold as u64)));
        }
        SideEvent::CommitteeRotate {
            operators,
            threshold,
        } => {
            set(&mut fields, "aux", Json::Int(*threshold as u64));
            fields.push(("operators", Json::Int(*operators as u64)));
            fields.push(("threshold", Json::Int(*threshold as u64)));
        }
        SideEvent::OperatorRevoke { operator_id } => {
            set(&mut fields, "aux", Json::Int(*operator_id as u64));
            fields.push(("operator_id", Json::Int(*operator_id as u64)));
        }
        SideEvent::AssetRegister {
            asset_id,
            cap,
            epoch_cap,
            requires_stark,
        } => {
            set(&mut fields, "amount", amount_str(*cap));
            fields.push(("asset_id", Json::str(crate::json::to_hex(asset_id))));
            fields.push(("cap", amount_str(*cap)));
            fields.push(("epoch_cap", amount_str(*epoch_cap)));
            fields.push(("requires_stark", Json::Bool(*requires_stark)));
        }
        SideEvent::EpochAdvance { epoch } => {
            set(&mut fields, "aux", Json::Int(*epoch));
            fields.push(("epoch", Json::Int(*epoch)));
        }
        SideEvent::Activate { feature, version } => {
            set(&mut fields, "aux", Json::Int(*version));
            fields.push(("feature", Json::str(crate::json::to_hex(feature))));
            fields.push(("version", Json::Int(*version)));
        }
        SideEvent::BridgeMigration { vault } => {
            set(&mut fields, "target", Json::str(vault));
        }
        SideEvent::BridgeUnfreeze => {}
        SideEvent::Bond {
            validator,
            amount,
            fee,
        } => {
            set(&mut fields, "actor", Json::str(validator));
            set(&mut fields, "amount", amount_str(*amount as u128));
            fields.push(("fee", amount_str(*fee as u128)));
        }
        SideEvent::Unbond { validator, amount } => {
            set(&mut fields, "actor", Json::str(validator));
            set(&mut fields, "amount", amount_str(*amount as u128));
        }
        SideEvent::Slash {
            validator,
            amount,
            disposition,
        } => {
            set(&mut fields, "actor", Json::str(validator));
            set(&mut fields, "amount", amount_str(*amount as u128));
            fields.push(("disposition", Json::str(*disposition)));
        }
        SideEvent::Reward { validator, amount } => {
            set(&mut fields, "actor", Json::str(validator));
            set(&mut fields, "amount", amount_str(*amount as u128));
        }
        SideEvent::RewardClaim { validator, amount } => {
            set(&mut fields, "actor", Json::str(validator));
            set(&mut fields, "amount", amount_str(*amount as u128));
        }
        SideEvent::ContractTransfer {
            contract,
            to,
            amount,
        } => {
            set(&mut fields, "actor", Json::str(contract));
            set(&mut fields, "target", Json::str(to));
            set(&mut fields, "amount", amount_str(*amount as u128));
        }
        SideEvent::BridgeMint {
            asset_id,
            recipient,
            amount,
        } => {
            set(&mut fields, "target", Json::str(id_address(recipient)));
            set(&mut fields, "amount", amount_str(*amount));
            fields.push(("asset_id", Json::str(crate::json::to_hex(asset_id))));
        }
        SideEvent::BridgeBurn {
            asset_id,
            holder,
            amount,
            destination,
            chain_id,
            burn_ref,
        } => {
            set(&mut fields, "actor", Json::str(id_address(holder)));
            set(&mut fields, "amount", amount_str(*amount));
            set(&mut fields, "aux", Json::Int(*chain_id));
            fields.push(("asset_id", Json::str(crate::json::to_hex(asset_id))));
            fields.push(("destination", Json::str(crate::json::to_hex(destination))));
            fields.push(("chain_id", Json::Int(*chain_id)));
            fields.push(("burn_ref", Json::str(crate::json::to_hex(burn_ref))));
        }
        SideEvent::BridgeSettle {
            asset_id,
            beneficiary,
            amount,
            burn_ref,
        } => {
            set(&mut fields, "target", Json::str(id_address(beneficiary)));
            set(&mut fields, "amount", amount_str(*amount));
            fields.push(("asset_id", Json::str(crate::json::to_hex(asset_id))));
            fields.push(("burn_ref", Json::str(crate::json::to_hex(burn_ref))));
        }
        SideEvent::BridgeSlash {
            asset_id,
            beneficiary,
            amount,
            burn_ref,
        } => {
            set(&mut fields, "target", Json::str(id_address(beneficiary)));
            set(&mut fields, "amount", amount_str(*amount));
            fields.push(("asset_id", Json::str(crate::json::to_hex(asset_id))));
            fields.push(("burn_ref", Json::str(crate::json::to_hex(burn_ref))));
        }
    }
    object(fields)
}

fn container(node: &DevNode, address: &str) -> Result<Json, ClientError> {
    if qtv_idfmt::parse_address(address).is_err() {
        return Err(ClientError::bad("bad_address", "the address is not a q1 address"));
    }
    match node.ledger().contract_code_at(address) {
        Some(code) => Ok(object(vec![
            ("address", Json::str(address)),
            ("container", Json::str(crate::json::to_hex(&code))),
            ("size", Json::Int(code.len() as u64)),
        ])),
        None => Err(ClientError::not_found("the address holds no contract")),
    }
}

fn storage(node: &DevNode, address: &str) -> Result<Json, ClientError> {
    if qtv_idfmt::parse_address(address).is_err() {
        return Err(ClientError::bad("bad_address", "the address is not a q1 address"));
    }
    let all = node
        .ledger()
        .contract_storage_at_capped(address)
        .ok_or_else(|| ClientError::bad("storage_too_large", "the contract storage is too large to serve over rpc"))?;
    let total = all.len();
    let slots: Vec<Json> = all
        .into_iter()
        .take(MAX_LIST_ITEMS)
        .map(|(slot, value)| {
            let slot_hex: String = slot.iter().map(|b| format!("{b:02x}")).collect();
            object(vec![
                ("slot", Json::str(slot_hex)),
                ("value", Json::str(value.to_string())),
            ])
        })
        .collect();
    Ok(object(vec![
        ("address", Json::str(address)),
        ("count", Json::Int(total as u64)),
        ("returned", Json::Int(slots.len() as u64)),
        ("truncated", Json::Bool(total > slots.len())),
        ("slots", Json::Array(slots)),
    ]))
}

fn submit(node: &mut DevNode, bytes: Vec<u8>) -> Json {
    let wrapper: Wrapper = match wrapper_from_bytes(&bytes) {
        Ok(wrapper) => wrapper,
        Err(_) => {
            return object(vec![
                ("verdict", Json::str("rejected")),
                ("reason", Json::str("malformed")),
            ]);
        }
    };
    let tx_id = wrapper.id();
    match node.submit(wrapper) {
        Ok(Admitted::Fresh) => accepted(&tx_id, "fresh"),
        Ok(Admitted::Known) => accepted(&tx_id, "known"),
        Err(reject) => rejected(reject),
    }
}

fn accepted(tx_id: &str, state: &str) -> Json {
    object(vec![
        ("verdict", Json::str("accepted")),
        ("state", Json::str(state)),
        ("tx_id", Json::str(tx_id)),
    ])
}

fn rejected(reject: Reject) -> Json {
    let mut fields = vec![
        ("verdict", Json::str("rejected")),
        ("reason", Json::str(reason_code(&reject))),
    ];
    if let Reject::BadNonce { expected, got } = reject {
        fields.push(("expected", Json::Int(expected)));
        fields.push(("got", Json::Int(got)));
    }
    object(fields)
}

fn reason_code(reject: &Reject) -> &'static str {
    match reject {
        Reject::UnknownSender => "unknown_sender",
        Reject::UnsupportedScheme => "unsupported_scheme",
        Reject::BadSignature => "bad_signature",
        Reject::BadNonce { .. } => "bad_nonce",
        Reject::BadCall => "bad_call",
        Reject::SelfTransfer => "self_transfer",
        Reject::MeterLimitTooLow => "meter_limit_too_low",
        Reject::FeeTooLow => "fee_too_low",
        Reject::InsufficientFunds => "insufficient_funds",
        Reject::WrongChain => "wrong_chain",
        Reject::PoolFull => "pool_full",
        Reject::SenderQueueFull => "sender_queue_full",
        Reject::RateLimited => "rate_limited",
    }
}

fn block(node: &DevNode, selector: BlockSelector) -> Result<Json, ClientError> {
    let found = match &selector {
        BlockSelector::Height(height) => node.block_at_height(*height),
        BlockSelector::Id(id) => node.block_by_id(id),
    };
    let block = found.ok_or_else(|| match selector {
        BlockSelector::Height(height) => {
            ClientError::not_found(format!("no finalised block at height {height}"))
        }
        BlockSelector::Id(id) => ClientError::not_found(format!("no finalised block {id}")),
    })?;

    let header = block.header();
    let tx_ids: Vec<Json> = block.body().iter().map(|w| Json::str(w.id())).collect();
    Ok(object(vec![
        ("height", Json::Int(header.height())),
        ("block", Json::str(block.id())),
        (
            "parent",
            Json::str(
                qtv_idfmt::render_block(header.parent_hash())
                    .expect("a parent hash is digest length"),
            ),
        ),
        (
            "q_root",
            Json::str(
                qtv_idfmt::render_state(header.q_root())
                    .expect("a state root is digest length"),
            ),
        ),
        (
            "transaction_root",
            Json::str(crate::json::to_hex(header.transaction_root())),
        ),
        (
            "event_root",
            Json::str(crate::json::to_hex(header.event_root())),
        ),
        ("proposer", Json::str(header.proposer())),
        ("time", Json::Int(header.time())),
        ("tx_count", Json::Int(block.body().len() as u64)),
        (
            "extra_data",
            Json::str(
                header
                    .extra_data()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            ),
        ),
        ("tx_ids", Json::Array(tx_ids)),
    ]))
}

#[cfg(test)]
mod storage_at_tests {
    use super::*;

    #[test]
    fn get_storage_at_parses_the_address_and_the_thirty_two_byte_keys() {
        let key = "11".repeat(32);
        let body = crate::json::parse(&format!("{{\"address\":\"q1abc\",\"keys\":[\"{key}\"]}}"))
            .expect("the body parses");
        let request = match build_request("get_storage_at", &body) {
            Ok(request) => request,
            Err(e) => panic!("the request parses: {}", e.message),
        };
        match request {
            Request::StorageAt { address, keys } => {
                assert_eq!(address, "q1abc", "the address is read");
                assert_eq!(keys, vec![[0x11u8; 32]], "the key decodes to thirty two bytes");
            }
            _ => panic!("get_storage_at parses to a StorageAt request"),
        }
    }

    #[test]
    fn get_storage_at_refuses_a_key_that_is_not_thirty_two_bytes() {
        let body = crate::json::parse("{\"address\":\"q1abc\",\"keys\":[\"1122\"]}")
            .expect("the body parses");
        assert!(
            build_request("get_storage_at", &body).is_err(),
            "a short key is refused rather than truncated or padded"
        );
    }

    #[test]
    fn get_storage_at_caps_the_number_of_keys() {
        let one = format!("\"{}\"", "11".repeat(32));
        let many = std::iter::repeat(one).take(MAX_STORAGE_KEYS + 1).collect::<Vec<_>>().join(",");
        let body = crate::json::parse(&format!("{{\"address\":\"q1abc\",\"keys\":[{many}]}}"))
            .expect("the body parses");
        assert!(
            build_request("get_storage_at", &body).is_err(),
            "a request over the key cap is refused"
        );
    }
}
