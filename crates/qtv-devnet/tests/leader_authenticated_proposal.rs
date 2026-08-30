// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_attest::Attestation;
use qtv_node::consensus::header_value;
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};
use qtv_devnet::wire::{Message, Proposal};
use qtv_devnet::Devnet;

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

fn idx(config: &DevnetConfig, id: u64) -> usize {
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

fn leader_and_stranger(
    config: &DevnetConfig,
    nodes: &[DevNode],
    committee: usize,
) -> (u64, usize, usize) {
    let selection = nodes[0].select().expect("committee");
    assert_eq!(selection.members.len(), committee, "committee draw differs");
    let leader = leader_for(&selection, 0);
    let leader_idx = idx(config, leader);
    let stranger = (0..nodes.len())
        .find(|&i| i != leader_idx)
        .expect("a non leader member");
    (leader, leader_idx, stranger)
}

fn only_a_leader_signed_proposal_is_prevoted(committee: usize, online: &[bool]) {
    let base = unique_base(&format!("leader_auth_{committee}"));
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, online, accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let (leader, leader_idx, stranger_idx) = leader_and_stranger(&config, &nodes, committee);

    let genuine = nodes[leader_idx].build_proposal(&selection);
    let counterfeit = nodes[stranger_idx].build_proposal(&selection);

    assert_eq!(
        header_value(&genuine.header.hash()),
        header_value(&counterfeit.header.hash()),
        "the stranger reproduces the same block, so only the signature separates them"
    );
    assert_eq!(
        genuine.auth.from, leader,
        "the leader signs under its own identity"
    );
    assert_ne!(
        counterfeit.auth.from, leader,
        "the stranger cannot sign as the elected leader"
    );

    let victim = (0..nodes.len())
        .find(|&i| i != leader_idx && i != stranger_idx)
        .expect("a distinct victim");
    let refused = nodes[victim].on_proposal(&selection, leader, counterfeit.clone());
    assert!(
        prevote_of(&refused).is_none(),
        "a proposal not signed by the elected leader must not be prevoted"
    );
    assert_eq!(
        nodes[victim].staged_view(),
        None,
        "an unauthenticated proposal must not be staged"
    );

    let grafted = Proposal {
        auth: counterfeit.auth.clone(),
        ..genuine.clone()
    };
    let refused = nodes[victim].on_proposal(&selection, leader, grafted);
    assert!(
        prevote_of(&refused).is_none(),
        "a leader header re signed by another member must not be prevoted"
    );
    assert_eq!(nodes[victim].staged_view(), None);

    let accepted = nodes[victim].on_proposal(&selection, leader, genuine);
    assert!(
        prevote_of(&accepted).is_some(),
        "the genuine leader signed proposal is prevoted"
    );
    assert_eq!(nodes[victim].staged_view(), Some(0));
}

#[test]
fn a_non_leader_proposal_is_refused_at_a_four_node_committee() {
    only_a_leader_signed_proposal_is_prevoted(4, &[true, true, true, true]);
}

#[test]
fn a_non_leader_proposal_is_refused_at_a_seven_node_committee() {
    only_a_leader_signed_proposal_is_prevoted(7, &[true, true, true, true, true, true, true]);
}

#[test]
fn a_genuine_leader_signed_proposal_finalizes() {
    let base = unique_base("leader_auth_finalize");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let tx = transfer(&alice, &bob.address(), 1_000, 0, &params);
    devnet.submit(0, tx).expect("admitted");
    devnet
        .step()
        .expect("the committee finalized a leader signed height");

    for i in 0..devnet.len() {
        assert_eq!(
            devnet.node(i).chain().len(),
            1,
            "node {i} did not finalize the leader signed block"
        );
    }
    assert_eq!(devnet.node(0).ledger().balance(&bob.address()), 1_000);
}

#[test]
fn a_replayed_justification_flood_verifies_within_the_committee_bound() {
    let base = unique_base("justification_flood");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    assert_eq!(selection.members.len(), 7);
    let tau = selection.tau;

    let l0 = leader_for(&selection, 0);
    let l0_idx = idx(&config, l0);
    let l2 = leader_for(&selection, 2);
    let l2_idx = idx(&config, l2);

    let proposal_x = nodes[l0_idx].build_proposal(&selection);
    let mut prevotes: Vec<Attestation> = Vec::new();
    for i in 0..nodes.len() {
        if let Some(prevote) = prevote_of(&nodes[i].on_proposal(&selection, l0, proposal_x.clone()))
        {
            prevotes.push(prevote);
        }
    }
    for i in 0..nodes.len() {
        for prevote in &prevotes {
            let _ = nodes[i].on_prevote(&selection, prevote.clone());
        }
    }

    let mut records = Vec::new();
    for i in 0..nodes.len() {
        if i == l2_idx {
            continue;
        }
        let record = nodes[i].make_view_change(2);
        nodes[l2_idx].collect_view_change(&selection, record.clone());
        records.push(record);
    }
    let justified = nodes[l2_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum of view changes justifies a proposal");
    let genuine = justified.justification;
    let distinct = genuine.len();
    assert!(
        distinct as u64 >= tau,
        "the genuine justification carries at least a quorum"
    );
    let _ = records;

    let mut flood = genuine.clone();
    while flood.len() < selection.members.len() {
        flood.push(genuine[flood.len() % distinct].clone());
    }
    assert!(
        flood.len() > distinct,
        "the flood carries more records than there are distinct signers"
    );

    let observer = (0..nodes.len())
        .find(|&i| i != l2_idx)
        .expect("an observer that did not assemble the justification");

    let (valid, first) = nodes[observer].measure_justification(&selection, &flood, 2);
    assert!(valid, "the genuine higher polka is still accepted");
    assert_eq!(
        first, distinct as u64,
        "each distinct signer is verified once, the replayed copies add no verifications"
    );
    assert!(
        first < flood.len() as u64,
        "verification does not scale with the size of the flood"
    );
    assert!(
        first <= 4 * qtv_sampler::params::COMMITTEE_BUDGET,
        "verifications stay within the committee budget cap"
    );

    let mut later: u64 = 0;
    for _ in 0..64 {
        let (still_valid, count) = nodes[observer].measure_justification(&selection, &flood, 2);
        assert!(
            still_valid,
            "the cached justification stays valid on replay"
        );
        later += count;
    }
    assert_eq!(
        later, 0,
        "a replayed justification is not verified a second time"
    );
}
