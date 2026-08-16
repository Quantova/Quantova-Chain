// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A node that restarts within an epoch rebuilds the peers rotated one time sortition roots
//! from the registration records carried in the chain, so it draws the committee at once
//! rather than waiting for the next boundary to re gossip.

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
    }
}

#[test]
fn a_node_restarting_within_an_epoch_rebuilds_peers_rotated_roots_from_the_chain() {
    let base = unique_base("registration-persistence");
    let slots = 4u64;
    let online = [true, true, true, true];
    let mut devnet = Devnet::over_duplex(config_with_slots(&base, &online, slots)).expect("devnet");

    // Drive past the first epoch boundary so the epoch one committee has rotated and the
    // block that starts the epoch carries every validator's re registration.
    for _ in 0..6u64 {
        devnet.step().expect("the committee finalises across the rotation");
    }
    let index = devnet.len() - 1;
    assert!(devnet.node(index).epoch() >= 1, "the node has crossed a boundary");
    assert!(
        !devnet.node(index).collected_registration_ids().is_empty(),
        "before the restart the node holds the peers rotated roots"
    );

    let head_before = devnet.node(index).head_hash();
    let height_before = devnet.node(index).height();

    // Restart the node from its store alone. The reload has to rebuild the rotated roots
    // from the chain, since the certificate at the head was formed over the rotated
    // committee and would not verify against the genesis roots.
    devnet.restart_node(index).expect("reopened across the boundary from the store");

    assert_eq!(devnet.node(index).head_hash(), head_before, "the head reloaded");
    assert_eq!(devnet.node(index).height(), height_before, "the height reloaded");
    let rebuilt = devnet.node(index).collected_registration_ids();
    assert!(
        !rebuilt.is_empty(),
        "the restarted node rebuilt the peers rotated roots from chain history"
    );
    for id in &rebuilt {
        assert_ne!(*id, devnet.node(index).id(), "a rebuilt root is a peer, not the node's own");
    }

    // It rejoins and keeps finalising the same chain as the peers that never restarted. The
    // reloaded node holds only the blocks it finalised after reopening, so compare that tail
    // against the matching span of a peer that never restarted.
    for _ in 0..3u64 {
        devnet.step().expect("the restarted node keeps finalising within the epoch");
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
