// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use qtv_devnet::config::{DevnetConfig, NodeConfig, DEFAULT_SLOTS, FULL_FANOUT};
use qtv_devnet::DevNode;
use qtv_gateway::json::{object, Json};
use qtv_gateway::{build_request, handle, ClientError, NodeContext, Request};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::SideEvent;

fn unique_base(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut base = std::env::temp_dir();
    base.push(format!("qtv-gateway-{}-{}-{}", std::process::id(), name, stamp));
    base
}

fn single_node(base: &Path) -> DevnetConfig {
    let node = NodeConfig::online(1, 2_000, base.join("node-1"));
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: Vec::new(),
        nodes: vec![node],
        genesis_time: 1_700_000_000_000,
        fanout: FULL_FANOUT,
        slots: DEFAULT_SLOTS,
        published_roster: None,
        bridge_dest_chain: None,
        guardians: qtv_devnet::GuardianSet::default(),
        bridge_operators: None,
        bridged_assets: vec![],
        bridge_era: None,
    }
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

fn field<'a>(event: &'a Json, key: &str) -> Option<&'a Json> {
    event.get(key)
}

#[test]
fn get_side_events_serialises_the_recorded_kinds_for_a_height() {
    let base = unique_base("side-events");
    let cfg = single_node(&base);
    let ctx = context();
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let validator = "q1validator".to_string();
    let target = "q1target".to_string();
    node.seed_side_events(
        5,
        vec![
            SideEvent::GovEnact {
                referendum: 3,
                action: "mint",
                proposal_hash: [0u8; 32],
            },
            SideEvent::Bond {
                validator: validator.clone(),
                amount: 1_000,
                fee: 5,
            },
            SideEvent::Freeze {
                target: target.clone(),
            },
        ],
    );

    let out = served(handle(
        &ctx,
        &mut node,
        build("get_side_events", object(vec![("height", Json::Int(5))])),
    ));
    assert_eq!(out.get("height").and_then(Json::as_u64), Some(5));
    assert_eq!(out.get("count").and_then(Json::as_u64), Some(3));

    let events = match out.get("events") {
        Some(Json::Array(items)) => items.clone(),
        other => panic!("events must be an array, got {other:?}"),
    };
    assert_eq!(events.len(), 3);

    assert_eq!(field(&events[0], "kind").and_then(Json::as_str), Some("gov_enact"));
    assert_eq!(field(&events[0], "index").and_then(Json::as_u64), Some(0));
    assert_eq!(field(&events[0], "ref").and_then(Json::as_u64), Some(3));
    assert_eq!(field(&events[0], "action").and_then(Json::as_str), Some("mint"));

    assert_eq!(field(&events[1], "kind").and_then(Json::as_str), Some("bond"));
    assert_eq!(field(&events[1], "index").and_then(Json::as_u64), Some(1));
    assert_eq!(field(&events[1], "actor").and_then(Json::as_str), Some(validator.as_str()));
    assert_eq!(field(&events[1], "amount").and_then(Json::as_str), Some("1000"));
    assert_eq!(field(&events[1], "fee").and_then(Json::as_str), Some("5"));

    assert_eq!(field(&events[2], "kind").and_then(Json::as_str), Some("freeze"));
    assert_eq!(field(&events[2], "target").and_then(Json::as_str), Some(target.as_str()));

    let empty = served(handle(
        &ctx,
        &mut node,
        build("get_side_events", object(vec![("height", Json::Int(6))])),
    ));
    assert_eq!(empty.get("count").and_then(Json::as_u64), Some(0));
    assert_eq!(empty.get("events"), Some(&Json::Array(Vec::new())));

    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn get_side_events_serialises_the_bridge_economic_kinds() {
    let base = unique_base("bridge-side-events");
    let cfg = single_node(&base);
    let ctx = context();
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let asset_id = [7u8; 16];
    let recipient = [9u8; 32];
    let holder = [4u8; 32];
    let beneficiary = [6u8; 32];
    let burn_ref = [3u8; 32];
    let destination = [1u8; 32];
    node.seed_side_events(
        8,
        vec![
            SideEvent::BridgeMint {
                asset_id,
                recipient,
                amount: 1_000,
            },
            SideEvent::BridgeBurn {
                asset_id,
                holder,
                amount: 400,
                destination,
                chain_id: 2,
                burn_ref,
            },
            SideEvent::BridgeSettle {
                asset_id,
                beneficiary,
                amount: 400,
                burn_ref,
            },
            SideEvent::BridgeSlash {
                asset_id,
                beneficiary,
                amount: 400,
                burn_ref,
            },
        ],
    );

    let out = served(handle(
        &ctx,
        &mut node,
        build("get_side_events", object(vec![("height", Json::Int(8))])),
    ));
    assert_eq!(out.get("count").and_then(Json::as_u64), Some(4));
    let events = match out.get("events") {
        Some(Json::Array(items)) => items.clone(),
        other => panic!("events must be an array, got {other:?}"),
    };
    assert_eq!(events.len(), 4);

    let asset_hex: String = asset_id.iter().map(|b| format!("{b:02x}")).collect();
    let burn_hex: String = burn_ref.iter().map(|b| format!("{b:02x}")).collect();

    assert_eq!(field(&events[0], "kind").and_then(Json::as_str), Some("bridge_mint"));
    assert_eq!(field(&events[0], "amount").and_then(Json::as_str), Some("1000"));
    assert_eq!(field(&events[0], "asset_id").and_then(Json::as_str), Some(asset_hex.as_str()));
    assert_eq!(
        field(&events[0], "target").and_then(Json::as_str),
        Some(qtv_idfmt::render_address(&recipient).unwrap().as_str()),
    );

    assert_eq!(field(&events[1], "kind").and_then(Json::as_str), Some("bridge_burn"));
    assert_eq!(field(&events[1], "amount").and_then(Json::as_str), Some("400"));
    assert_eq!(field(&events[1], "chain_id").and_then(Json::as_u64), Some(2));
    assert_eq!(field(&events[1], "burn_ref").and_then(Json::as_str), Some(burn_hex.as_str()));
    assert_eq!(
        field(&events[1], "actor").and_then(Json::as_str),
        Some(qtv_idfmt::render_address(&holder).unwrap().as_str()),
    );

    assert_eq!(field(&events[2], "kind").and_then(Json::as_str), Some("bridge_settle"));
    assert_eq!(field(&events[2], "burn_ref").and_then(Json::as_str), Some(burn_hex.as_str()));
    assert_eq!(field(&events[3], "kind").and_then(Json::as_str), Some("bridge_slash"));
    assert_eq!(
        field(&events[3], "target").and_then(Json::as_str),
        Some(qtv_idfmt::render_address(&beneficiary).unwrap().as_str()),
    );

    std::fs::remove_dir_all(&base).ok();
}
