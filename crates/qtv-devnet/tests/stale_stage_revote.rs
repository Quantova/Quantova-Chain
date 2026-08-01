// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_attest::Attestation;
use qtv_node::consensus::{
    equivocation_offenders, header_value, roster_of, ConsensusValidator, DEFAULT_SLOTS,
};
use qtv_node::node::GenesisAccount;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};
use qtv_devnet::wire::Message;

use support::{config, unique_base, user, VALIDATOR_STAKE};

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

fn attest_of(messages: &[Message]) -> Option<Attestation> {
    messages.iter().find_map(|message| match message {
        Message::Attest(att) => Some((**att).clone()),
        _ => None,
    })
}

#[test]
fn a_stale_stage_is_not_revoted_at_a_new_view() {
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
    let att_a_v0 = attest_of(&out).expect("the victim attests A at view zero");
    assert_eq!((att_a_v0.view, att_a_v0.block.val), (0, value_a));
    assert_eq!(nodes[victim].staged_view(), Some(0));

    nodes[victim].jump_to(1);
    let entered = nodes[victim].enter_round(&selection, true);
    let stale = attest_of(&entered);
    assert!(
        !matches!(&stale, Some(att) if att.view == 1 && att.block.val == value_a),
        "the victim re-cast a vote for the stale view zero block at view one"
    );

    let drivers: Vec<usize> = (0..nodes.len()).filter(|&i| i != victim).collect();
    assert_eq!(drivers.len() as u64, selection.tau, "the justification holds a quorum");
    for driver in drivers {
        let record = nodes[driver].make_view_change(1);
        nodes[leader1_idx].collect_view_change(&selection, record);
    }
    let justified_b = nodes[leader1_idx]
        .build_justified_proposal(&selection, 1)
        .expect("a quorum of records with no floor-clearing lock justifies a fresh proposal");
    let value_b = header_value(&justified_b.header.hash());
    assert_ne!(value_a, value_b, "the fresh proposal competes with A");

    let out = nodes[victim].on_proposal(&selection, leader1, justified_b);
    let att_b_v1 = attest_of(&out).expect("the victim attests the justified B at view one");
    assert_eq!((att_b_v1.view, att_b_v1.block.val), (1, value_b));

    if let Some(stale_a_v1) = stale {
        let validators: Vec<ConsensusValidator> = (1..=nodes.len() as u64)
            .map(|id| {
                ConsensusValidator::from_secret(
                    id,
                    VALIDATOR_STAKE,
                    true,
                    qtv_node::keys::fixture_secret(id),
                )
            })
            .collect();
        let roster = roster_of(&validators, DEFAULT_SLOTS);
        let chain_id = config.fee_params.chain_id;
        let flagged = equivocation_offenders(chain_id, &[stale_a_v1, att_b_v1], &roster);
        assert!(
            !flagged.contains(&nodes[victim].id()),
            "the honest victim is slashed for equivocation its own stale re-vote created"
        );
    }
}
