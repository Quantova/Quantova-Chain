// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_devnet::config::{DevnetConfig, NodeConfig};
use qtv_devnet::Devnet;
use qtv_node::fee::FeeParams;

use support::{header_chain, unique_base, GENESIS_TIME, VALIDATOR_STAKE};

fn config_with_slots(base: &std::path::Path, online: &[bool], slots: u64) -> DevnetConfig {
    let count = online.len();
    let nodes = online
        .iter()
        .enumerate()
        .map(|(i, &on)| {
            let id = i as u64 + 1;
            let bootstrap = if i == 0 {
                if count > 1 {
                    vec![2]
                } else {
                    Vec::new()
                }
            } else {
                vec![1]
            };
            NodeConfig {
                id,
                stake: VALIDATOR_STAKE,
                online: on,
                store_dir: base.join(format!("node-{id}")),
                bootstrap,
                address: format!("mem://{id}"),
                secret: qtv_node::keys::fixture_secret(id),
            }
        })
        .collect();
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: vec![],
        nodes,
        genesis_time: GENESIS_TIME,
        fanout: qtv_devnet::config::FULL_FANOUT,
        slots,
        published_roster: None,
        bridge_dest_chain: None,
        guardians: qtv_devnet::GuardianSet::default(),
        bridge_operators: None,
        bridged_assets: vec![],
        bridge_era: None,
    }
}

#[test]
fn the_running_devnet_rotates_keys_across_epochs_and_finalises_past_the_fixed_ceiling() {
    let base = unique_base("epoch-rotation");
    let slots = 4u64;
    let online = [true, true, true, true];
    let mut devnet = Devnet::over_duplex(config_with_slots(&base, &online, slots)).expect("devnet");

    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).epoch(), 0);
    }

    let target = slots * 3 + 2;
    for expected_height in 1..=target {
        devnet.step().expect("the committee finalised the height across the rotation");
        for i in 0..devnet.len() {
            assert_eq!(
                devnet.node(i).height(),
                expected_height + 1,
                "node {i} stalled at height {expected_height}",
            );
        }
    }

    assert!(
        target > slots,
        "the run did not pass the point a single fixed tree would have run out",
    );

    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len() as u64, target, "not every height finalised");
    for i in 0..devnet.len() {
        assert!(devnet.node(i).epoch() >= 2, "node {i} did not rotate across two epochs");
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "node {i} finalised a different chain than node zero across the rotation",
        );
    }
}
