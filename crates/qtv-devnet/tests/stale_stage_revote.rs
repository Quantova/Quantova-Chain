// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


mod support;

use qtv_attest::Attestation;
use qtv_node::consensus::header_value;
use qtv_node::node::GenesisAccount;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};
use qtv_devnet::wire::Message;

use support::{config, unique_base, user};

fn open_nodes(config: &DevnetConfig) -> Vec<DevNode> {
    let mut nodes: Vec<DevNode> = config
        .nodes
        .iter()
        .map(|node| DevNode::open(node, config).expect("node opens"))
        .collect();
    let notes: Vec<_> = nodes.iter().filter_map(|node| node.own_reveal_note()).collect();
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

fn prevote_of(messages: &[Message]) -> Option<Attestation> {
    messages.iter().find_map(|message| match message {
        Message::Prevote(att) => Some((**att).clone()),
        _ => None,
    })
}

#[test]
fn a_stale_stage_is_not_reprevoted_at_a_new_view() {
    let base = unique_base("stale_revote");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    assert_eq!((selection.expected, selection.tau), (4, 3));
    let leader0 = leader_for(&selection, 0);
    let leader1 = leader_for(&selection, 1);
    let leader0_idx = index_of(&config, leader0);
    let leader1_idx = index_of(&config, leader1);
    let victim = (0..nodes.len())
        .find(|&i| i != leader0_idx && i != leader1_idx)
        .expect("a follower that leads neither driven view");

    let proposal_a = nodes[leader0_idx].build_proposal(&selection);
    let value_a = header_value(&proposal_a.header.hash());
    let out = nodes[victim].on_proposal(&selection, leader0, proposal_a);
    let prevote_a = prevote_of(&out).expect("the victim prevotes A at view zero");
    assert_eq!((prevote_a.view, prevote_a.block.cost), (0, u64::MAX), "a prevote is a control plane vote");
    assert_eq!(nodes[victim].staged_view(), Some(0));

    nodes[victim].jump_to(1);
    let entered = nodes[victim].enter_round(&selection, true);
    assert!(
        prevote_of(&entered).is_none(),
        "the victim re-prevoted the stale view zero stage at view one"
    );

    let drivers: Vec<usize> = (0..nodes.len()).filter(|&i| i != victim).collect();
    for driver in drivers {
        let record = nodes[driver].make_view_change(1);
        nodes[leader1_idx].collect_view_change(&selection, record);
    }
    let justified_b = nodes[leader1_idx]
        .build_justified_proposal(&selection, 1)
        .expect("a quorum of records with no polka justifies a fresh proposal");
    let value_b = header_value(&justified_b.header.hash());
    assert_ne!(value_a, value_b, "the fresh proposal competes with A");

    let out = nodes[victim].on_proposal(&selection, leader1, justified_b);
    let prevote_b = prevote_of(&out).expect("the unlocked victim prevotes the justified B");
    assert_eq!(prevote_b.view, 1);
    assert_eq!(nodes[victim].staged_value(), Some(value_b));
}
