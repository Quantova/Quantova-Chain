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
        bridge_exit_max_amount: None,
    }
}

#[test]
fn a_node_restarting_within_an_epoch_rebuilds_peers_rotated_roots_from_the_chain() {
    let base = unique_base("registration-persistence");
    let slots = 4u64;
    let online = [true, true, true, true];
    let mut devnet = Devnet::over_duplex(config_with_slots(&base, &online, slots)).expect("devnet");

    for _ in 0..6u64 {
        devnet
            .step()
            .expect("the committee finalises across the rotation");
    }
    let index = devnet.len() - 1;
    assert!(
        devnet.node(index).epoch() >= 1,
        "the node has crossed a boundary"
    );
    let epoch = devnet.node(index).epoch();
    let ids: Vec<u64> = (1..=devnet.len() as u64).collect();
    let before: Vec<_> = ids
        .iter()
        .map(|id| devnet.node(index).roster_root(*id))
        .collect();
    for (j, id) in ids.iter().enumerate() {
        assert_eq!(
            before[j],
            Some(devnet.node(j).own_rotated_root(epoch)),
            "validator {id} registered in time, so it sits at its rotated root"
        );
    }

    let head_before = devnet.node(index).head_hash();
    let height_before = devnet.node(index).height();

    devnet
        .restart_node(index)
        .expect("reopened across the boundary from the store");

    assert_eq!(
        devnet.node(index).head_hash(),
        head_before,
        "the head reloaded"
    );
    assert_eq!(
        devnet.node(index).height(),
        height_before,
        "the height reloaded"
    );
    for (j, id) in ids.iter().enumerate() {
        assert_eq!(
            devnet.node(index).roster_root(*id),
            before[j],
            "the restart rebuilt validator {id}'s rotated root from chain history"
        );
        assert_eq!(
            devnet.node(index).roster_root(*id),
            devnet.node(0).roster_root(*id),
            "the restarted node and a peer hold validator {id} at the same root"
        );
    }

    for _ in 0..3u64 {
        devnet
            .step()
            .expect("the restarted node keeps finalising within the epoch");
    }
    let restarted_tail = header_chain(devnet.node(index));
    let peer_tail: Vec<[u8; 32]> = devnet
        .node(0)
        .chain()
        .iter()
        .skip((height_before - 1) as usize)
        .map(|block| block.header_hash())
        .collect();
    assert_eq!(
        restarted_tail, peer_tail,
        "the restarted node finalised the identical blocks as a peer"
    );
    let head = devnet.node(0).head_hash();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).head_hash(), head, "node {i} head differs");
    }
}
