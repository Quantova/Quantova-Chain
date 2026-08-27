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

fn prevote_of(messages: Vec<Message>) -> Option<Attestation> {
    messages.into_iter().find_map(|message| match message {
        Message::Prevote(att) => Some(*att),
        _ => None,
    })
}

fn is_precommit(messages: &[Message]) -> bool {
    messages.iter().any(|m| matches!(m, Message::Attest(_)))
}

fn lock_victim_on_proposal(
    nodes: &mut [DevNode],
    selection: &qtv_node::consensus::Selection,
    leader: u64,
    victim: usize,
    proposal: &qtv_devnet::wire::Proposal,
) {
    let victim_prevote =
        prevote_of(nodes[victim].on_proposal(selection, leader, proposal.clone())).expect("victim prevotes");
    let mut polka = vec![victim_prevote];
    for i in 0..nodes.len() {
        if i == victim {
            continue;
        }
        if let Some(p) = prevote_of(nodes[i].on_proposal(selection, leader, proposal.clone())) {
            polka.push(p);
        }
        if polka.len() as u64 >= selection.tau {
            break;
        }
    }
    let mut precommitted = false;
    for prevote in &polka {
        if is_precommit(&nodes[victim].on_prevote(selection, prevote.clone())) {
            precommitted = true;
        }
    }
    assert!(precommitted, "the victim formed the polka and precommitted");
}

#[test]
fn a_polka_locked_validator_refuses_a_conflict() {
    let base = unique_base("polka_lock");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let l0 = leader_for(&selection, 0);
    let l0_idx = index_of(&config, l0);
    let l2 = leader_for(&selection, 2);
    let l2_idx = index_of(&config, l2);
    let victim = (0..nodes.len())
        .find(|&i| i != l0_idx && i != l2_idx)
        .expect("a member leading neither view");

    let proposal_a = nodes[l0_idx].build_proposal(&selection);
    let value_a = header_value(&proposal_a.header.hash());
    lock_victim_on_proposal(&mut nodes, &selection, l0, victim, &proposal_a);

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
    let proposal_b = nodes[l2_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum justifies a proposal");
    assert_ne!(header_value(&proposal_b.header.hash()), value_a, "B competes with A");

    let _ = records;
    let out = nodes[victim].on_proposal(&selection, l2, proposal_b);
    assert!(
        prevote_of(out).is_none(),
        "the locked victim refuses to prevote the conflicting B, so B cannot gather a polka"
    );
    assert_eq!(
        nodes[victim].staged_value(),
        Some(value_a),
        "the victim stays committed to A"
    );
}

#[test]
fn a_validator_without_a_lock_prevotes_a_justified_proposal() {
    let base = unique_base("no_lock");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let l2 = leader_for(&selection, 2);
    let l2_idx = index_of(&config, l2);
    let follower = (0..nodes.len()).find(|&i| i != l2_idx).expect("a follower");

    let mut records = Vec::new();
    for i in 0..nodes.len() {
        if i == follower {
            continue;
        }
        records.push(nodes[i].make_view_change(2));
    }
    for record in &records {
        nodes[l2_idx].collect_view_change(&selection, record.clone());
    }
    let justified = nodes[l2_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum justifies a proposal");
    let value = header_value(&justified.header.hash());

    let out = nodes[follower].on_proposal(&selection, l2, justified);
    assert!(prevote_of(out).is_some(), "the unlocked follower prevotes the justified proposal");
    assert_eq!(nodes[follower].staged_value(), Some(value));
}
