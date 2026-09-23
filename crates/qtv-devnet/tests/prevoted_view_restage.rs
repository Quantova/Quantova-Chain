// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_attest::Attestation;
use qtv_node::consensus::header_value;
use qtv_node::node::GenesisAccount;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};
use qtv_devnet::wire::Message;

use support::{config, transfer, unique_base, user};

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

fn prevote_of(messages: &[Message]) -> Option<Attestation> {
    messages.iter().find_map(|message| match message {
        Message::Prevote(att) => Some((**att).clone()),
        _ => None,
    })
}

#[test]
fn a_leader_cannot_retract_a_view_the_node_has_already_prevoted() {
    let base = unique_base("prevoted_restage");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let leader0 = leader_for(&selection, 0);
    let leader0_idx = index_of(&config, leader0);
    let victim = (0..nodes.len())
        .find(|&i| i != leader0_idx)
        .expect("a follower that does not lead view zero");

    let first = nodes[leader0_idx].build_proposal(&selection);
    let value_a = header_value(&first.header.hash());
    let out = nodes[victim].on_proposal(&selection, leader0, first);
    let prevote = prevote_of(&out).expect("the victim prevotes the first proposal at view zero");
    assert_eq!(prevote.view, 0);
    assert_eq!(nodes[victim].staged_value(), Some(value_a));

    let params = nodes[leader0_idx].fee_params();
    let payment = transfer(&alice, &user(1).address(), 1_000, 0, &params);
    nodes[leader0_idx].submit(payment).expect("the fee is paid");

    for driver in 0..nodes.len() {
        if driver == leader0_idx {
            continue;
        }
        let record = nodes[driver].make_view_change(0);
        nodes[leader0_idx].collect_view_change(&selection, record);
    }
    let second = nodes[leader0_idx]
        .build_justified_proposal(&selection, 0)
        .expect("the leader of view zero justifies a second proposal at the same view");
    let value_b = header_value(&second.header.hash());
    assert_ne!(
        value_a, value_b,
        "the second proposal carries a different body, so it is a competing value"
    );

    let out = nodes[victim].on_proposal(&selection, leader0, second);
    assert!(
        prevote_of(&out).is_none(),
        "the victim does not prevote a second value at a view it already voted"
    );
    assert_eq!(
        nodes[victim].staged_value(),
        Some(value_a),
        "the stage the quorum prevoted still stands, so the round can still be precommitted"
    );
}
