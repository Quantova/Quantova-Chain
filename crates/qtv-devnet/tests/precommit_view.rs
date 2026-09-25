// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::node::GenesisAccount;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};

use support::{config, unique_base, user};

fn open_nodes(config: &DevnetConfig) -> Vec<DevNode> {
    let mut nodes: Vec<DevNode> = config
        .nodes
        .iter()
        .map(|node| DevNode::open(node, config).expect("node opens"))
        .collect();
    let notes: Vec<_> = nodes
        .iter()
        .filter_map(|node| node.own_reveal_note())
        .collect();
    for node in &mut nodes {
        for note in &notes {
            node.collect_reveal(note.clone());
        }
    }
    nodes
}

fn index_of(config: &DevnetConfig, id: u64) -> usize {
    config
        .nodes
        .iter()
        .position(|node| node.id == id)
        .expect("a node holds the id")
}

#[test]
fn a_precommit_carries_the_view_that_authorised_the_stage() {
    let base = unique_base("precommit_view");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let leader0 = leader_for(&selection, 0);
    let leader0_idx = index_of(&config, leader0);
    let victim = (0..nodes.len())
        .find(|&i| i != leader0_idx)
        .expect("a follower that does not lead view zero");

    let proposal = nodes[leader0_idx]
        .build_proposal(&selection)
        .expect("the leader holds a credential for the slot it leads");
    let _ = nodes[victim].on_proposal(&selection, leader0, proposal);
    assert_eq!(
        nodes[victim].staged_view(),
        Some(0),
        "the victim staged the view zero proposal"
    );

    nodes[victim].jump_to(1);
    assert_eq!(nodes[victim].view(), 1, "the victim moved to view one");
    assert_eq!(
        nodes[victim].staged_view(),
        Some(0),
        "the stage still belongs to view zero"
    );

    let attestation = nodes[victim].attest().expect("a staged node attests");
    assert_eq!(
        attestation.view, 0,
        "a precommit signed at the current view turns a stale stage into a same view \
         double vote against anything the node commits at view one"
    );
}
