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

fn prevote_of(messages: Vec<Message>) -> Option<Attestation> {
    messages.into_iter().find_map(|message| match message {
        Message::Prevote(att) => Some(*att),
        _ => None,
    })
}

fn is_precommit(messages: &[Message]) -> bool {
    messages.iter().any(|m| matches!(m, Message::Attest(_)))
}

#[test]
fn a_body_less_copy_does_not_hold_the_senders_view_change_slot() {
    let base = unique_base("stripped_view_change");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let l0 = leader_for(&selection, 0);
    let l0_idx = index_of(&config, l0);
    let l1 = leader_for(&selection, 1);
    let l1_idx = index_of(&config, l1);
    let holder = (0..nodes.len())
        .find(|&i| i != l0_idx && i != l1_idx)
        .expect("a member leading neither view");

    let proposal = nodes[l0_idx].build_proposal(&selection);
    let locked_value = header_value(&proposal.header.hash());
    let first = prevote_of(nodes[holder].on_proposal(&selection, l0, proposal.clone()))
        .expect("the holder prevotes");
    let mut polka = vec![first];
    for i in 0..nodes.len() {
        if i == holder {
            continue;
        }
        if let Some(p) = prevote_of(nodes[i].on_proposal(&selection, l0, proposal.clone())) {
            polka.push(p);
        }
        if polka.len() as u64 >= selection.tau {
            break;
        }
    }
    let mut precommitted = false;
    for prevote in &polka {
        if is_precommit(&nodes[holder].on_prevote(&selection, prevote.clone())) {
            precommitted = true;
        }
    }
    assert!(precommitted, "the holder locked on the view zero proposal");

    let genuine = nodes[holder].make_view_change(1);
    assert!(
        genuine
            .locked
            .as_ref()
            .is_some_and(|block| !block.body.is_empty()),
        "the holder's own record carries the locked body"
    );
    let mut stripped = genuine.clone();
    if let Some(block) = stripped.locked.as_mut() {
        block.body = Vec::new();
    }

    nodes[l1_idx].collect_view_change(&selection, stripped);
    nodes[l1_idx].collect_view_change(&selection, genuine);
    for i in 0..nodes.len() {
        if i == holder {
            continue;
        }
        let record = nodes[i].make_view_change(1);
        nodes[l1_idx].collect_view_change(&selection, record);
    }

    let proposal = nodes[l1_idx]
        .build_justified_proposal(&selection, 1)
        .expect("the genuine record still justifies the locked value");
    assert_eq!(
        header_value(&proposal.header.hash()),
        locked_value,
        "the leader re-proposes the value the quorum locked"
    );
}
