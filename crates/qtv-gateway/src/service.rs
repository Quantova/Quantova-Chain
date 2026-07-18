//! The seam between the wire and the node.
//!
//! A request names one of the six methods and carries its parameters. Handling a
//! request reads or writes the node and returns a JSON value, the body a client
//! receives. This is the whole of what the node exposes to the outside, and it is a
//! plain function of a request and the node, so the same handling serves a request
//! that arrived in process over a channel and would serve one that arrived over a
//! socket from a separate gateway. The gateway never holds the node, it asks it.

use qtv_devnet::wire::wrapper_from_bytes;
use qtv_devnet::DevNode;
use qtv_node::fee::FeeParams;
use qtv_node::mempool::{Admitted, Reject};
use qtv_tx::Wrapper;

use crate::json::{object, Json};

/// The static context a running node carries that the node itself does not hold, the
/// chain id and genesis hash the daemon read from the genesis file and the version of
/// the running binary. Node info reports these.
pub struct NodeContext {
    pub chain_id: String,
    pub genesis_hash_hex: String,
    pub fee_params: FeeParams,
    pub version: String,
}

/// A block named either by its height or by its id.
pub enum BlockSelector {
    Height(u64),
    Id(String),
}

/// One of the six methods, with its parameters.
pub enum Request {
    NodeInfo,
    Account(String),
    Submit(Vec<u8>),
    Transaction(String),
    Block(BlockSelector),
    Head,
}

/// A request the gateway could not carry out because the client sent it wrong, a
/// malformed parameter or a block that does not exist. It is distinct from a rejected
/// submission, which is a well formed request the node handled and answered.
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

    /// The error rendered as the JSON body a client receives on a 4xx.
    pub fn render(&self) -> String {
        object(vec![
            ("error", Json::str(&self.code)),
            ("message", Json::str(&self.message)),
        ])
        .render()
    }
}

/// Build a request from a method name and a parsed body, or refuse it as a client
/// error. This is where a path becomes a typed request, so the transport above stays
/// ignorant of the methods.
pub fn build_request(method: &str, body: &Json) -> Result<Request, ClientError> {
    match method {
        "node_info" => Ok(Request::NodeInfo),
        "head" => Ok(Request::Head),
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
        other => Err(ClientError {
            code: "unknown_method".to_string(),
            message: format!("no method named {other}"),
            http: 404,
        }),
    }
}

/// Read a required string field from a request body.
fn string_field(body: &Json, key: &str) -> Result<String, ClientError> {
    body.get(key)
        .and_then(Json::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| ClientError::bad("bad_request", format!("missing string field {key}")))
}

/// Handle a request against the node, returning the JSON body a client receives or a
/// client error. The node is borrowed mutably because a submission admits to the
/// mempool; every other method only reads.
pub fn handle(ctx: &NodeContext, node: &mut DevNode, request: Request) -> Result<Json, ClientError> {
    match request {
        Request::NodeInfo => Ok(node_info(ctx, node)),
        Request::Head => Ok(head(node)),
        Request::Account(address) => account(node, &address),
        Request::Transaction(tx_id) => Ok(transaction(node, &tx_id)),
        Request::Submit(bytes) => Ok(submit(node, bytes)),
        Request::Block(selector) => block(node, selector),
    }
}

fn node_info(ctx: &NodeContext, node: &DevNode) -> Json {
    let fee = &ctx.fee_params;
    object(vec![
        ("chain_id", Json::str(&ctx.chain_id)),
        ("genesis_hash", Json::str(&ctx.genesis_hash_hex)),
        ("head_height", Json::Int(node.height().saturating_sub(1))),
        ("denomination", Json::str("Qgas")),
        (
            "fee",
            object(vec![
                ("transfer_micro_usd", Json::str(fee.transfer_micro_usd.to_string())),
                (
                    "rate_micro_usd_per_qtov",
                    Json::str(fee.rate_micro_usd_per_qtov.to_string()),
                ),
                ("native_unit_qgas", Json::str(fee.native_unit.to_string())),
                ("transfer_qgas", Json::str(fee.transfer_fee().to_string())),
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

fn transaction(node: &DevNode, tx_id: &str) -> Json {
    if let Some(height) = node.finalized_height(tx_id) {
        let block = node
            .block_at_height(height)
            .map(|b| Json::str(b.id()))
            .unwrap_or(Json::Null);
        object(vec![
            ("tx_id", Json::str(tx_id)),
            ("status", Json::str("finalised")),
            ("height", Json::Int(height)),
            ("block", block),
        ])
    } else if node.is_pending(tx_id) {
        object(vec![
            ("tx_id", Json::str(tx_id)),
            ("status", Json::str("pending")),
        ])
    } else {
        object(vec![
            ("tx_id", Json::str(tx_id)),
            ("status", Json::str("unknown")),
        ])
    }
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

/// Map a reject to its wire verdict. The reason codes are the closed set the reject
/// enum fixes, in snake case, and a client branches on exactly these.
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
        // The header's arbitrary data note as hex, byte exact, empty string when none.
        // A reader recovers the bytes by decoding the hex.
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
