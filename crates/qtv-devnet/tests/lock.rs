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
    let victim_prevote = prevote_of(nodes[victim].on_proposal(selection, leader, proposal.clone()))
        .expect("victim prevotes");
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

    let proposal_a = nodes[l0_idx]
        .build_proposal(&selection)
        .expect("the leader holds a credential for the slot it leads");
    let value_a = header_value(&proposal_a.header.hash());
    lock_victim_on_proposal(&mut nodes, &selection, l0, victim, &proposal_a);

    let mut records = Vec::new();
    for i in 0..nodes.len() {
        if i == victim {
            continue;
        }
        records.push(
            nodes[i]
                .make_view_change(2)
                .expect("a committee member can vote to change view"),
        );
    }
    for record in &records {
        nodes[l2_idx].collect_view_change(&selection, record.clone());
    }
    let proposal_b = nodes[l2_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum justifies a proposal");
    assert_ne!(
        header_value(&proposal_b.header.hash()),
        value_a,
        "B competes with A"
    );

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
        records.push(
            nodes[i]
                .make_view_change(2)
                .expect("a committee member can vote to change view"),
        );
    }
    for record in &records {
        nodes[l2_idx].collect_view_change(&selection, record.clone());
    }
    let justified = nodes[l2_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum justifies a proposal");
    let value = header_value(&justified.header.hash());

    let out = nodes[follower].on_proposal(&selection, l2, justified);
    assert!(
        prevote_of(out).is_some(),
        "the unlocked follower prevotes the justified proposal"
    );
    assert_eq!(nodes[follower].staged_value(), Some(value));
}

#[test]
fn a_justified_proposal_carries_one_polka_and_no_locked_bodies_and_is_bound_by_it() {
    let base = unique_base("carried_lock");
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
    let follower = (0..nodes.len())
        .find(|&i| i != l0_idx && i != l2_idx && i != victim)
        .expect("a follower");

    let proposal_a = nodes[l0_idx]
        .build_proposal(&selection)
        .expect("the leader holds a credential for the slot it leads");
    let value_a = header_value(&proposal_a.header.hash());
    lock_victim_on_proposal(&mut nodes, &selection, l0, victim, &proposal_a);

    let records: Vec<_> = (0..nodes.len())
        .map(|i| {
            nodes[i]
                .make_view_change(2)
                .expect("a committee member can vote to change view")
        })
        .collect();
    for record in &records {
        nodes[l2_idx].collect_view_change(&selection, record.clone());
    }
    let justified = nodes[l2_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum justifies a proposal");
    assert_eq!(header_value(&justified.header.hash()), value_a);
    assert!(justified
        .justification
        .iter()
        .filter_map(|r| r.locked.as_ref())
        .all(|locked| locked.body.is_empty()));
    assert_eq!(
        justified
            .justification
            .iter()
            .filter(|r| r.polka.is_some())
            .count(),
        1,
        "the binding lock's polka is carried once"
    );
    assert_eq!(
        nodes[follower].justification_bound(&selection, &justified.justification),
        Some(Some(0))
    );

    let mut stripped = justified.justification.clone();
    for record in &mut stripped {
        record.polka = None;
    }
    assert_eq!(
        nodes[follower].justification_bound(&selection, &stripped),
        None,
        "a leader cannot drop the polka of the highest lock and propose free of it"
    );

    let out = nodes[follower].on_proposal(&selection, l2, justified);
    assert!(
        prevote_of(out).is_some(),
        "the carried justification is accepted"
    );
    assert_eq!(nodes[follower].staged_value(), Some(value_a));
}

#[test]
fn a_locked_validator_keeps_its_lock_across_a_restart() {
    let base = unique_base("lock_restart");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let l0 = leader_for(&selection, 0);
    let l0_idx = index_of(&config, l0);
    let victim = (0..nodes.len())
        .find(|&i| i != l0_idx)
        .expect("a member not leading view zero");

    let proposal_a = nodes[l0_idx]
        .build_proposal(&selection)
        .expect("the leader holds a credential for the slot it leads");
    let value_a = header_value(&proposal_a.header.hash());
    lock_victim_on_proposal(&mut nodes, &selection, l0, victim, &proposal_a);

    nodes[victim].stop_signing();
    nodes[victim] = DevNode::open(&config.nodes[victim], &config).expect("reopen");
    let record = nodes[victim]
        .make_view_change(2)
        .expect("a committee member can vote to change view");
    let locked = record
        .locked
        .expect("the restarted node still reports its lock");
    assert_eq!(header_value(&locked.header.hash()), value_a);
    assert!(record.polka.is_some(), "the polka behind the lock survives");
}

#[test]
fn a_view_change_whose_locked_body_misses_its_header_is_not_collected() {
    let base = unique_base("junk_locked_body");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let l0 = leader_for(&selection, 0);
    let l0_idx = index_of(&config, l0);
    let victim = (0..nodes.len())
        .find(|&i| i != l0_idx)
        .expect("a member not leading view zero");
    let observer = (0..nodes.len())
        .find(|&i| i != l0_idx && i != victim)
        .expect("an observer");

    let proposal_a = nodes[l0_idx]
        .build_proposal(&selection)
        .expect("the leader holds a credential for the slot it leads");
    lock_victim_on_proposal(&mut nodes, &selection, l0, victim, &proposal_a);

    let mut junk = nodes[victim]
        .make_view_change(2)
        .expect("a committee member can vote to change view");
    let params = qtv_node::fee::FeeParams::devnet();
    junk.locked
        .as_mut()
        .expect("the victim is locked")
        .body
        .push(transfer(&alice, &user(1).address(), 5, 0, &params));
    let before = nodes[observer].view_changes_len();
    nodes[observer].collect_view_change(&selection, junk);
    assert_eq!(nodes[observer].view_changes_len(), before);

    let genuine = nodes[victim]
        .make_view_change(2)
        .expect("a committee member can vote to change view");
    nodes[observer].collect_view_change(&selection, genuine);
    assert_eq!(nodes[observer].view_changes_len(), before + 1);
}

#[test]
fn a_restarted_locked_validator_refuses_an_unjustified_conflict_at_a_later_view() {
    let base = unique_base("lock_restart_conflict");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let l0 = leader_for(&selection, 0);
    let l0_idx = index_of(&config, l0);
    let l1 = leader_for(&selection, 1);
    let l1_idx = index_of(&config, l1);
    let victim = (0..nodes.len())
        .find(|&i| i != l0_idx && i != l1_idx)
        .expect("a member leading neither view");

    let proposal_a = nodes[l0_idx]
        .build_proposal(&selection)
        .expect("the leader holds a credential for the slot it leads");
    let value_a = header_value(&proposal_a.header.hash());
    lock_victim_on_proposal(&mut nodes, &selection, l0, victim, &proposal_a);

    let notes: Vec<_> = nodes
        .iter()
        .filter_map(|node| node.own_reveal_note())
        .collect();
    nodes[victim].stop_signing();
    nodes[victim] = DevNode::open(&config.nodes[victim], &config).expect("reopen");
    for note in &notes {
        nodes[victim].collect_reveal(note.clone());
    }
    assert_eq!(
        nodes[victim].staged_value(),
        Some(value_a),
        "the restart restores the stage behind the lock"
    );
    let view = nodes[victim].view();
    assert!(
        !nodes[victim].on_timeout(view),
        "a locked stage holds its view across a restart"
    );
    nodes[victim].jump_to(1);

    let mut rival_config = config.nodes[l1_idx].clone();
    rival_config.store_dir = unique_base("lock_restart_conflict_rival");
    let mut rival = DevNode::open(&rival_config, &config).expect("the view one leader opens");
    for note in &notes {
        rival.collect_reveal(note.clone());
    }
    assert!(rival.on_timeout(0), "the unstaged leader moves to view one");
    let proposal_b = rival
        .build_proposal(&selection)
        .expect("the leader holds a credential for the slot it leads");
    assert_eq!(proposal_b.view, 1);
    assert!(proposal_b.justification.is_empty());
    assert_ne!(header_value(&proposal_b.header.hash()), value_a);

    let out = nodes[victim].on_proposal(&selection, l1, proposal_b);
    assert!(
        prevote_of(out).is_none(),
        "a restarted validator locked on A never prevotes an unjustified B at a later view"
    );
    assert_eq!(nodes[victim].staged_value(), Some(value_a));
}
