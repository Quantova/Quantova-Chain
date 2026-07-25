// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The lock and its justified unlock, driven directly over the node without the
//! round loop. A validator that has attested a block locks on it. It refuses a
//! conflicting later proposal that carries no justification, and it changes its
//! lock only under a proper justification: a quorum of view change records for a
//! higher view whose highest lock the proposed block matches.

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

    // Build a genuine justification for view two: a quorum of view change records,
    // one reporting the lock on B at view one, one reporting the lock on A at view
    // zero, and one from an unlocked member. The highest lock in the quorum is B, so
    // the justified proposal re-offers B.
    let vc_b = nodes[leader1_idx].make_view_change(2);
    let vc_a = nodes[leader0_idx].make_view_change(2);
    let vc_none = nodes[spare].make_view_change(2);
    for record in [vc_b, vc_a, vc_none] {
        nodes[spare].collect_view_change(&selection, record);
    }
    let justified = nodes[spare]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum of view change records justifies a proposal");
    assert_eq!(
        header_value(&justified.header.hash()),
        value_b,
        "the justification selects B, the highest locked block"
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
