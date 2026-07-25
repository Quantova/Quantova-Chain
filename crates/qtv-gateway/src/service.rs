// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_devnet::wire::wrapper_from_bytes;
use qtv_devnet::DevNode;
use qtv_node::fee::FeeParams;
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
    Supply,
    Events(u64),
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
        "get_events" => {
            let height = body
                .get("height")
                .and_then(Json::as_u64)
                .ok_or_else(|| ClientError::bad("bad_request", "get_events needs a height"))?;
            Ok(Request::Events(height))
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
        Request::Events(height) => Ok(events(node, height)),
    }
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
                ("session_days", Json::Int(qtv_staking::SESSION_DAYS)),
                ("high_session_tx", Json::Int(qtv_staking::HIGH_SESSION_TX)),
                ("low_session_bps", Json::Int(qtv_staking::LOW_SESSION_BPS as u64)),
                ("high_session_bps", Json::Int(qtv_staking::HIGH_SESSION_BPS as u64)),
                (
                    "reward_cap_micro_usd_per_session",
                    Json::Int(qtv_staking::REWARD_CAP_MICRO_USD_PER_SESSION as u64),
                ),
                (
                    "mainnet_blackout_days",
                    Json::Int(qtv_staking::MAINNET_BLACKOUT_DAYS),
                ),
                ("bond_lock_days", Json::Int(qtv_staking::BOND_LOCK_DAYS)),
                ("unbonding_days", Json::Int(qtv_staking::UNBONDING_DAYS)),
                ("vest_cliff_days", Json::Int(qtv_staking::VEST_CLIFF_DAYS)),
                ("vest_tranche_days", Json::Int(qtv_staking::VEST_TRANCHE_DAYS)),
                ("vest_tranches", Json::Int(qtv_staking::VEST_TRANCHES)),
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
    let state_root = node.ledger().state_root_id();
    let block = if head_height >= qtv_bft::params::MIN_HEIGHT {
        Json::str(qtv_idfmt::render_block(&node.head_hash()).expect("a header hash is digest length"))
    } else {
        Json::Null
    };
    object(vec![
        ("height", Json::Int(head_height)),
        ("block", block),
        ("state_root", Json::str(state_root)),
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

fn tx_fields(wrapper: &Wrapper) -> Vec<(&'static str, Json)> {
    let body = wrapper.body();
    let amount = qtv_node::execution::transfer_amount(body.call()).unwrap_or(0);
    vec![
        ("from", Json::str(body.sender())),
        ("to", Json::str(body.call().target())),
        ("value", Json::str(amount.to_string())),
        ("fee", Json::str(body.fee().to_string())),
        ("nonce", Json::Int(body.nonce())),
        ("meter_limit", Json::Int(body.meter_limit())),
        ("scheme", Json::Int(u64::from(wrapper.scheme()))),
        ("signature", Json::str(crate::json::to_hex(wrapper.signature()))),
        ("raw", Json::str(crate::json::to_hex(&qtv_codec::to_bytes(wrapper)))),
    ]
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
                fields.extend(tx_fields(wrapper));
            }
        }
        object(fields)
    } else if node.is_pending(tx_id) {
        let mut fields = vec![
            ("tx_id", Json::str(tx_id)),
            ("status", Json::str("pending")),
        ];
        if let Some(wrapper) = node
            .pending_transactions()
            .iter()
            .find(|w| w.id() == tx_id)
        {
            fields.extend(tx_fields(wrapper));
        }
        object(fields)
    } else {
        object(vec![
            ("tx_id", Json::str(tx_id)),
            ("status", Json::str("unknown")),
        ])
    }
}

fn pending(node: &DevNode) -> Json {
    let items: Vec<Json> = node
        .pending_transactions()
        .iter()
        .map(|wrapper| {
            let mut fields = vec![("tx_id", Json::str(wrapper.id()))];
            fields.extend(tx_fields(wrapper));
            object(fields)
        })
        .collect();
    object(vec![
        ("count", Json::Int(items.len() as u64)),
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
    let slots: Vec<Json> = node
        .ledger()
        .contract_storage_at(address)
        .into_iter()
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
            "state_root",
            Json::str(
                qtv_idfmt::render_state(header.state_root())
                    .expect("a state root is digest length"),
            ),
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
