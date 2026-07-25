// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Peer discovery from bootstrap. A node that starts from a single bootstrap peer
//! discovers the whole network over authenticated qtv-net channels, learning peers
//! it never bootstrapped from through the exchange.

mod support;

use qtv_devnet::config::{DevnetConfig, NodeConfig};
use qtv_devnet::Devnet;

use qtv_node::fee::FeeParams;
use support::{unique_base, GENESIS_TIME, VALIDATOR_STAKE};

/// A chain bootstrap over `count` nodes: node `i` starts from node `i + 1` alone,
/// so every node has at most one bootstrap peer and the last has none, reached only
/// because its predecessor bootstraps from it. Discovery must cross the whole chain
/// for a node to learn the far end.
fn chain_config(base: &std::path::Path, count: usize) -> DevnetConfig {
    let nodes = (0..count)
        .map(|i| {
            let id = i as u64 + 1;
            let bootstrap = if i + 1 < count {
                vec![id + 1]
            } else {
                Vec::new()
            };
            NodeConfig::online(id, VALIDATOR_STAKE, base.join(format!("node-{id}")))
                .with_bootstrap(bootstrap)
        })
        .collect();
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: Vec::new(),
        nodes,
        genesis_time: GENESIS_TIME,
        // A ring overlay keeps discovery cheap; discovery is independent of the
        // fanout, so the peer tables converge the same whatever the overlay degree.
        fanout: 2,
        slots: qtv_devnet::config::DEFAULT_SLOTS,
        published_roster: None,
    }
}

#[test]
fn a_node_from_one_bootstrap_peer_discovers_the_whole_network() {
    let base = unique_base("discovery");
    let count = 5;
    let devnet = Devnet::over_duplex(chain_config(&base, count)).expect("devnet discovers");

    // The full set of identities every node should end up knowing.
    let mut expected: Vec<[u8; 32]> = (0..count).map(|i| devnet.identity_fingerprint(i)).collect();
    expected.sort_unstable();

    for i in 0..count {
        assert_eq!(
            devnet.known_peer_count(i),
            count,
            "node {i} did not discover the whole network"
        );
        assert_eq!(
            devnet.known_peer_fingerprints(i),
            expected,
            "node {i} discovered a different peer set"
        );
    }
}

#[test]
fn the_far_end_of_the_chain_is_discovered_transitively() {
    let base = unique_base("discovery-far");
    let count = 5;
    let devnet = Devnet::over_duplex(chain_config(&base, count)).expect("devnet discovers");

    // Node zero bootstraps only from node one, yet it learns the identity of the
    // last node in the chain, which it never bootstrapped from.
    let far = devnet.identity_fingerprint(count - 1);
    assert!(
        devnet.known_peer_fingerprints(0).contains(&far),
        "the origin never discovered the far end of the chain"
    );
}
