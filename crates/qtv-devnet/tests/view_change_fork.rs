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

fn idx(config: &DevnetConfig, id: u64) -> usize {
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
fn a_polka_locked_validator_refuses_to_prevote_a_conflict() {
    let base = unique_base("fork_refute");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    assert_eq!(selection.members.len(), 7, "committee draw is not 7");
    assert_eq!(selection.tau, 5, "tau is not 5");

    let l0 = leader_for(&selection, 0);
    let l0_idx = idx(&config, l0);
    let l2 = leader_for(&selection, 2);
    let l2_idx = idx(&config, l2);
    let victim = (0..nodes.len())
        .find(|&i| i != l0_idx && i != l2_idx)
        .expect("a member leading neither view zero nor view two");

    let proposal_x = nodes[l0_idx].build_proposal(&selection);
    let value_x = header_value(&proposal_x.header.hash());
    let victim_prevote = prevote_of(nodes[victim].on_proposal(&selection, l0, proposal_x.clone()))
        .expect("the victim prevotes X");

    let mut polka: Vec<Attestation> = vec![victim_prevote];
    for i in 0..nodes.len() {
        if i == victim {
            continue;
        }
        if let Some(prevote) = prevote_of(nodes[i].on_proposal(&selection, l0, proposal_x.clone())) {
            polka.push(prevote);
        }
        if polka.len() as u64 >= selection.tau {
            break;
        }
    }
    assert!(polka.len() as u64 >= selection.tau, "a quorum prevoted X");

    let mut precommitted = false;
    for prevote in &polka {
        if is_precommit(&nodes[victim].on_prevote(&selection, prevote.clone())) {
            precommitted = true;
        }
    }
    assert!(precommitted, "the victim formed the polka and precommitted X");

    let mut records = Vec::new();
    for i in 0..nodes.len() {
        if i == victim {
            continue;
        }
        records.push(nodes[i].make_view_change(2));
    }
    for record in &records {
        nodes[l2_idx].collect_view_change(&selection, record.clone());
    }
    let proposal_y = nodes[l2_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum of view changes justifies a proposal");
    let value_y = header_value(&proposal_y.header.hash());
    assert_ne!(value_x, value_y, "the leader proposes a conflicting Y");

    let out = nodes[victim].on_proposal(&selection, l2, proposal_y);
    assert!(
        prevote_of(out).is_none(),
        "the polka locked victim refuses to prevote the conflicting Y, so Y cannot gather a polka"
    );
}
