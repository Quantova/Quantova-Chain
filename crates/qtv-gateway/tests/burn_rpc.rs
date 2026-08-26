// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use qtv_devnet::config::{DevnetConfig, NodeConfig, DEFAULT_SLOTS, FULL_FANOUT};
use qtv_devnet::DevNode;
use qtv_gateway::json::{object, to_hex, Json};
use qtv_gateway::{build_request, handle, ClientError, NodeContext, Request};
use qtv_node::fee::FeeParams;
use qtv_store::BurnArchiveEntry;

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

fn entry(height: u64, tag: u8) -> BurnArchiveEntry {
    BurnArchiveEntry {
        height,
        header_bytes: vec![tag; 24],
        certificate: vec![tag ^ 0x5a; 40],
        events: vec![vec![0x01, tag], vec![0x02, tag, tag, tag]],
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

#[test]
fn finalized_head_returns_the_node_head() {
    let base = unique_base("finalized-head");
    let cfg = single_node(&base);
    let ctx = context();
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let expected = node.finalized_head();
    let out = served(handle(&ctx, &mut node, build("finalized_head", Json::Object(Vec::new()))));
    assert_eq!(out.get("head").and_then(Json::as_u64), Some(expected));

    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn burn_block_returns_the_archived_entry_and_a_not_found_when_absent() {
    let base = unique_base("burn-block");
    let cfg = single_node(&base);
    let ctx = context();
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let seeded = entry(7, 0xab);
    node.seed_burn_archive(seeded.clone());

    let out = served(handle(&ctx, &mut node, build("burn_block", object(vec![("height", Json::Int(7))]))));
    assert_eq!(out.get("height").and_then(Json::as_u64), Some(7));
    assert_eq!(
        out.get("header_bytes").and_then(Json::as_str),
        Some(to_hex(&seeded.header_bytes).as_str())
    );
    assert_eq!(
        out.get("certificate").and_then(Json::as_str),
        Some(to_hex(&seeded.certificate).as_str())
    );
    let events = match out.get("events") {
        Some(Json::Array(items)) => items.clone(),
        other => panic!("events must be an array, got {other:?}"),
    };
    let expected_events: Vec<Json> = seeded
        .events
        .iter()
        .map(|leaf| Json::str(to_hex(leaf)))
        .collect();
    assert_eq!(events, expected_events);

    match handle(&ctx, &mut node, build("burn_block", object(vec![("height", Json::Int(8))]))) {
        Err(err) => {
            assert_eq!(err.http, 404);
            assert_eq!(err.code, "not_found");
        }
        Ok(value) => panic!("an unarchived height must be a not found, got {value:?}"),
    }

    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn burn_heights_after_lists_archived_heights_in_order_from_the_cursor() {
    let base = unique_base("heights-after");
    let cfg = single_node(&base);
    let ctx = context();
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    node.seed_burn_archive(entry(12, 0x11));
    node.seed_burn_archive(entry(7, 0x22));
    node.seed_burn_archive(entry(30, 0x33));

    let from_zero = served(handle(&ctx, &mut node, build("burn_heights_after", object(vec![("cursor", Json::Int(0))]))));
    assert_eq!(from_zero.get("count").and_then(Json::as_u64), Some(3));
    assert_eq!(
        from_zero.get("heights"),
        Some(&Json::Array(vec![Json::Int(7), Json::Int(12), Json::Int(30)]))
    );

    let from_twelve = served(handle(&ctx, &mut node, build("burn_heights_after", object(vec![("cursor", Json::Int(12))]))));
    assert_eq!(
        from_twelve.get("heights"),
        Some(&Json::Array(vec![Json::Int(30)]))
    );

    let from_top = served(handle(&ctx, &mut node, build("burn_heights_after", object(vec![("cursor", Json::Int(30))]))));
    assert_eq!(from_top.get("count").and_then(Json::as_u64), Some(0));
    assert_eq!(from_top.get("heights"), Some(&Json::Array(Vec::new())));

    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn a_zero_cursor_burn_heights_request_is_bounded_to_one_serve_page() {
    let base = unique_base("heights-after-flood");
    let cfg = single_node(&base);
    let ctx = context();
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let seeded = (qtv_store::MAX_HEIGHTS_AFTER + 64) as u64;
    for height in 1..=seeded {
        node.seed_burn_archive(entry(height, (height & 0xff) as u8));
    }

    let flood = served(handle(&ctx, &mut node, build("burn_heights_after", object(vec![("cursor", Json::Int(0))]))));
    let returned = match flood.get("heights") {
        Some(Json::Array(items)) => items.len(),
        other => panic!("heights must be an array, got {other:?}"),
    };
    assert!(
        returned <= qtv_store::MAX_HEIGHTS_AFTER,
        "a single burn_heights_after request served {returned} heights, past the {} page cap",
        qtv_store::MAX_HEIGHTS_AFTER
    );
    assert_eq!(
        flood.get("count").and_then(Json::as_u64),
        Some(returned as u64),
        "the reported count must match the bounded page"
    );

    std::fs::remove_dir_all(&base).ok();
}
