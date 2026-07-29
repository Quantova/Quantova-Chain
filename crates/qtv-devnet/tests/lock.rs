// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The lock and its justified unlock, driven directly over the node without the
//! round loop. A validator that has attested a block locks on it. It refuses a
//! conflicting later proposal that carries no justification, and it changes its
//! lock only under a proper justification: a quorum of view change records for a
//! higher view whose safe value the proposed block matches.

mod support;

use qtv_node::consensus::header_value;
use qtv_node::node::GenesisAccount;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};
use qtv_devnet::wire::Message;

use support::{config, unique_base, user};

/// Open every node standalone and exchange the height's reveals so each forms the
/// committee, the step the round loop does before a height.
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

/// The index of the node holding a committee id.
fn index_of(config: &DevnetConfig, id: u64) -> usize {
    config
        .nodes
        .iter()
        .position(|node| node.id == id)
        .expect("a node holds the id")
}

#[test]
fn a_locked_validator_changes_its_lock_only_under_a_justification() {
    let base = unique_base("lock");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let leader0 = leader_for(&selection, 0);
    let leader1 = leader_for(&selection, 1);
    let leader0_idx = index_of(&config, leader0);
    let leader1_idx = index_of(&config, leader1);
    // The two members that lead neither driven view: one is the victim we lock, the
    // other rounds out the view change quorum.
    let spares: Vec<usize> = (0..nodes.len())
        .filter(|&i| i != leader0_idx && i != leader1_idx)
        .collect();
    let victim = spares[0];
    let spare = spares[1];

    // The view zero leader proposes block A.
    let proposal_a = nodes[leader0_idx].build_proposal(&selection);
    let value_a = header_value(&proposal_a.header.hash());

    // The view one leader rotates and proposes a competing block B for the same
    // height, locking itself on B at view one.
    assert!(
        nodes[leader1_idx].on_timeout(0),
        "an unlocked leader rotates"
    );
    let proposal_b = nodes[leader1_idx].build_proposal(&selection);
    let value_b = header_value(&proposal_b.header.hash());
    assert_ne!(value_a, value_b, "A and B compete at one height");
    assert_eq!(nodes[leader1_idx].staged_value(), Some(value_b));

    // The spare also locks B at view one, so B clears the quorum-intersection floor.
    assert!(nodes[spare].on_timeout(0), "an unlocked member rotates");
    let out = nodes[spare].on_proposal(&selection, leader1, proposal_b.clone());
    assert!(
        matches!(out.as_slice(), [Message::Attest(_)]),
        "the spare attested and locked on B"
    );
    assert_eq!(nodes[spare].staged_value(), Some(value_b));

    // The victim attests A and thereby locks on A at view zero.
    let out = nodes[victim].on_proposal(&selection, leader0, proposal_a.clone());
    assert!(
        matches!(out.as_slice(), [Message::Attest(_)]),
        "the victim attested and locked on A"
    );
    assert_eq!(nodes[victim].staged_view(), Some(0));
    assert_eq!(nodes[victim].staged_value(), Some(value_a));

    // A bare conflicting proposal for a later view carries no justification. The
    // locked victim does not attest it and stays locked on A.
    let out = nodes[victim].on_proposal(&selection, leader1, proposal_b.clone());
    assert!(out.is_empty(), "the victim refused the bare conflicting B");
    assert_eq!(
        nodes[victim].staged_value(),
        Some(value_a),
        "the lock still holds the victim on A"
    );

    // A view two quorum: two records lock B at view one, one locks A at view zero. B clears the floor, A does not.
    let vc_b_leader = nodes[leader1_idx].make_view_change(2);
    let vc_b_spare = nodes[spare].make_view_change(2);
    let vc_a = nodes[victim].make_view_change(2);
    for record in [vc_b_leader, vc_b_spare, vc_a] {
        nodes[leader0_idx].collect_view_change(&selection, record);
    }
    let justified = nodes[leader0_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum of view change records justifies a proposal");
    assert_eq!(
        header_value(&justified.header.hash()),
        value_b,
        "the justification binds to B, the block that clears the floor"
    );

    // A justification that falls short of a quorum does not unlock the victim.
    let mut short = justified.clone();
    short.justification.truncate(2);
    let out = nodes[victim].on_proposal(&selection, leader1, short);
    assert!(out.is_empty(), "a sub quorum justification is refused");
    assert_eq!(nodes[victim].staged_value(), Some(value_a));

    // The full justification unlocks the victim: it abandons A, attests B, and locks
    // on B at view two.
    let out = nodes[victim].on_proposal(&selection, leader1, justified);
    assert!(
        matches!(out.as_slice(), [Message::Attest(_)]),
        "the victim attested B under the justification"
    );
    assert_eq!(nodes[victim].staged_value(), Some(value_b));
    assert_eq!(nodes[victim].staged_view(), Some(2));
}

/// With the safe-value gate on, a lone Byzantine higher lock cannot override an honestly-backed one.
#[test]
fn the_safe_value_rule_refuses_a_lone_higher_lock() {
    let base = unique_base("safe_value");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let leader0 = leader_for(&selection, 0);
    let leader1 = leader_for(&selection, 1);
    let leader0_idx = index_of(&config, leader0);
    let leader1_idx = index_of(&config, leader1);
    let spares: Vec<usize> = (0..nodes.len())
        .filter(|&i| i != leader0_idx && i != leader1_idx)
        .collect();
    let victim = spares[0];
    let spare = spares[1];

    // View zero leader proposes A and thereby locks on A at view zero.
    let proposal_a = nodes[leader0_idx].build_proposal(&selection);
    let value_a = header_value(&proposal_a.header.hash());

    // View one leader rotates and proposes a competing B, locking on B at view one.
    assert!(nodes[leader1_idx].on_timeout(0), "an unlocked leader rotates");
    let proposal_b = nodes[leader1_idx].build_proposal(&selection);
    let value_b = header_value(&proposal_b.header.hash());
    assert_ne!(value_a, value_b, "A and B compete at one height");

    // The victim attests A. Now two members hold a real lock on A at view zero (leader0
    // and the victim), while only leader1 holds B at the higher view one.
    let out = nodes[victim].on_proposal(&selection, leader0, proposal_a.clone());
    assert!(matches!(out.as_slice(), [Message::Attest(_)]), "the victim locked on A");
    assert_eq!(nodes[victim].staged_value(), Some(value_a));

    // A view-two quorum: two records carry the real A lock, one the lone B lock; A clears the floor, B does not.
    let vc_a_leader = nodes[leader0_idx].make_view_change(2);
    let vc_a_victim = nodes[victim].make_view_change(2);
    let vc_b_lone = nodes[leader1_idx].make_view_change(2);
    for record in [vc_a_leader, vc_a_victim, vc_b_lone] {
        nodes[spare].collect_view_change(&selection, record);
    }
    let justified = nodes[spare]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum of view change records justifies a proposal");
    assert_eq!(
        header_value(&justified.header.hash()),
        value_a,
        "the safe value binds the proposal to A, refusing the lone higher B lock"
    );

    // A Byzantine proposer offers B under the same justification. The victim computes the
    // safe value A, sees B does not match, refuses, and stays committed to A. No fork.
    let mut byzantine_b = proposal_b.clone();
    byzantine_b.justification = justified.justification.clone();
    let out = nodes[victim].on_proposal(&selection, leader1, byzantine_b);
    assert!(out.is_empty(), "the victim refuses B because the safe value is A");
    assert_eq!(
        nodes[victim].staged_value(),
        Some(value_a),
        "the victim stays committed to A, so A and B cannot both finalize"
    );
}
