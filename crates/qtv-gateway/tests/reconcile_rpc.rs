// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use qtv_devnet::config::{DevnetConfig, NodeConfig, DEFAULT_SLOTS, FULL_FANOUT};
use qtv_devnet::DevNode;
use qtv_gateway::json::{object, Json};
use qtv_gateway::{build_request, handle, ClientError, NodeContext, Request};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

fn unique_base(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut base = std::env::temp_dir();
    base.push(format!("qtv-gateway-{}-{}-{}", std::process::id(), name, stamp));
    base
}

fn context() -> NodeContext {
    NodeContext {
        chain_id: "Qtest".to_string(),
        genesis_hash_hex: "00".to_string(),
        asset: "QTOV".to_string(),
        fee_params: FeeParams::devnet(),
        version: "test".to_string(),
    }
}

fn config_with_accounts(base: &Path, accounts: Vec<GenesisAccount>) -> DevnetConfig {
    let node = NodeConfig::online(1, 2_000, base.join("node-1"));
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts,
        nodes: vec![node],
        genesis_time: 1_700_000_000_000,
        fanout: FULL_FANOUT,
        slots: DEFAULT_SLOTS,
        published_roster: None,
    }
}

fn build(method: &str, body: Json) -> Request {
    match build_request(method, &body) {
        Ok(request) => request,
        Err(err) => panic!("build_request rejected {method}: {} {}", err.code, err.message),
    }
}

fn served(result: Result<Json, ClientError>) -> Json {
    match result {
        Ok(value) => value,
        Err(err) => panic!("expected a served view, got {} {}", err.code, err.message),
    }
}

fn hex16(byte: u8) -> String {
    (0..16).map(|_| format!("{byte:02x}")).collect()
}

fn hex32(byte: u8) -> String {
    (0..32).map(|_| format!("{byte:02x}")).collect()
}

#[test]
fn genesis_accounts_rpc_serves_the_configured_allocations_and_moves_no_root() {
    let base = unique_base("genesis-accounts");
    let first = qtv_idfmt::render_address(&[0x11u8; 32]).unwrap();
    let second = qtv_idfmt::render_address(&[0x22u8; 32]).unwrap();
    let accounts = vec![
        GenesisAccount {
            address: first.clone(),
            balance: 5_000,
            scheme: 1,
            public_key: Vec::new(),
        },
        GenesisAccount {
            address: second.clone(),
            balance: 7_000,
            scheme: 1,
            public_key: Vec::new(),
        },
    ];
    let cfg = config_with_accounts(&base, accounts);
    let ctx = context();
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let root_before = node.ledger().q_root();
    let out = served(handle(
        &ctx,
        &mut node,
        build("genesis_accounts", object(Vec::new())),
    ));

    assert_eq!(out.get("count").and_then(Json::as_u64), Some(2));
    assert_eq!(
        out.get("supply_quon").and_then(Json::as_str),
        Some(node.genesis_supply().to_string().as_str()),
        "the reported genesis supply matches the seeded baseline",
    );
    let rows = match out.get("accounts") {
        Some(Json::Array(items)) => items.clone(),
        other => panic!("accounts must be an array, got {other:?}"),
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get("address").and_then(Json::as_str), Some(first.as_str()));
    assert_eq!(rows[0].get("balance").and_then(Json::as_str), Some("5000"));
    assert_eq!(rows[1].get("address").and_then(Json::as_str), Some(second.as_str()));
    assert_eq!(rows[1].get("balance").and_then(Json::as_str), Some("7000"));

    // The genesis supply baseline must equal the sum of the funded balances the accounts carry
    // plus the pool and the validator bonds, which the reconstruction seeds at height zero.
    let sum_accounts: u64 = 5_000 + 7_000;
    assert!(node.genesis_supply() > sum_accounts, "supply also carries the pool and bonds");

    assert_eq!(
        root_before,
        node.ledger().q_root(),
        "serving the genesis accounts view moves no state root",
    );

    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn bridged_balance_rpc_is_wired_read_only_and_accepts_hex_and_q1_holders() {
    let base = unique_base("bridged-balance");
    let cfg = config_with_accounts(&base, Vec::new());
    let ctx = context();
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let root_before = node.ledger().q_root();

    let asset = hex16(0xAB);
    let holder_hex = hex32(0xCD);
    let out = served(handle(
        &ctx,
        &mut node,
        build(
            "get_bridged_balance",
            object(vec![
                ("asset_id", Json::str(&asset)),
                ("holder", Json::str(&holder_hex)),
            ]),
        ),
    ));
    assert_eq!(out.get("balance").and_then(Json::as_str), Some("0"));
    assert_eq!(out.get("supply").and_then(Json::as_str), Some("0"));
    assert_eq!(out.get("asset_id").and_then(Json::as_str), Some(asset.as_str()));

    // The same reader accepts a q1 holder address as well as raw 32-byte hex.
    let holder_q1 = qtv_idfmt::render_address(&[0xCDu8; 32]).unwrap();
    let out_q1 = served(handle(
        &ctx,
        &mut node,
        build(
            "get_bridged_balance",
            object(vec![
                ("asset_id", Json::str(&asset)),
                ("holder", Json::str(&holder_q1)),
            ]),
        ),
    ));
    assert_eq!(out_q1.get("holder").and_then(Json::as_str), Some(holder_hex.as_str()));

    let supply = served(handle(
        &ctx,
        &mut node,
        build("get_bridged_supply", object(vec![("asset_id", Json::str(&asset))])),
    ));
    assert_eq!(supply.get("registered"), Some(&Json::Bool(false)));
    assert_eq!(supply.get("supply").and_then(Json::as_str), Some("0"));

    assert_eq!(
        root_before,
        node.ledger().q_root(),
        "the bridged balance and supply readers move no state root",
    );

    std::fs::remove_dir_all(&base).ok();
}
