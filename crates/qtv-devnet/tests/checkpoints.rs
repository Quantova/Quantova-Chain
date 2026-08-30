// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_devnet::config::{DevnetConfig, NodeConfig};
use qtv_devnet::{Checkpoint, DevNode, Devnet, SyncError};
use qtv_node::consensus::header_value;
use qtv_node::fee::FeeParams;

use support::{config, unique_base, GENESIS_TIME, VALIDATOR_STAKE};

fn config_with_slots(base: &std::path::Path, online: &[bool], slots: u64) -> DevnetConfig {
    let nodes = online
        .iter()
        .enumerate()
        .map(|(i, &on)| {
            let id = i as u64 + 1;
            let bootstrap = if i == 0 { vec![2] } else { vec![1] };
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
fn a_fork_before_the_checkpoint_is_refused() {
    let online = [true, true, true, false];

    let base_a = unique_base("wscp-honest");
    let cfg_a = config(&base_a, &online, vec![]);
    let mut honest_net = Devnet::over_duplex(cfg_a.clone()).expect("honest devnet");
    honest_net
        .step()
        .expect("the honest committee finalises height one");
    let honest = honest_net
        .served_blocks(0, 1, 1)
        .into_iter()
        .next()
        .expect("the honest height one block");
    let honest_value = header_value(&honest.header_hash());

    let base_b = unique_base("wscp-fork");
    let mut cfg_b = config(&base_b, &online, vec![]);
    cfg_b.genesis_time = GENESIS_TIME + 1_000_000;
    let mut fork_net = Devnet::over_duplex(cfg_b).expect("fork devnet");
    fork_net
        .step()
        .expect("the fork committee finalises height one");
    let fork = fork_net
        .served_blocks(0, 1, 1)
        .into_iter()
        .next()
        .expect("the fork height one block");
    let fork_value = header_value(&fork.header_hash());
    assert_ne!(
        honest_value, fork_value,
        "the fork carries a different value at the checkpoint height"
    );

    let mut node = DevNode::open(&cfg_a.nodes[3], &cfg_a).expect("verifier node");
    node.set_checkpoint(Checkpoint {
        height: 1,
        value: honest_value,
    });
    assert_eq!(
        node.apply_synced_block(fork),
        Err(SyncError::CheckpointConflict),
        "the node synced across a fork that conflicts with its checkpoint"
    );
    assert_eq!(
        node.height(),
        1,
        "the refused fork did not advance the node"
    );
    node.apply_synced_block(honest)
        .expect("the honest block at the checkpoint value is accepted");
    assert_eq!(
        node.height(),
        2,
        "the node synced the honest chain past the checkpoint"
    );
}

#[test]
fn the_node_advances_its_checkpoint_each_epoch() {
    let base = unique_base("wscp-each-epoch");
    let epoch_len = 4u64;
    let mut devnet = Devnet::over_duplex(config_with_slots(
        &base,
        &[true, true, true, true],
        epoch_len,
    ))
    .expect("devnet");

    assert!(
        devnet.node(0).checkpoint().is_none(),
        "no checkpoint before the first epoch closes"
    );

    for _ in 0..(2 * epoch_len) {
        devnet.step().expect("finalised a height across the epochs");
    }

    let checkpoint = devnet
        .node(0)
        .checkpoint()
        .expect("a checkpoint was taken at an epoch boundary");
    assert_eq!(
        checkpoint.height,
        2 * epoch_len,
        "the checkpoint tracks the latest epoch boundary"
    );
    for i in 1..devnet.len() {
        assert_eq!(
            devnet.node(i).checkpoint(),
            Some(checkpoint),
            "node {i} holds a different epoch checkpoint",
        );
    }
}
