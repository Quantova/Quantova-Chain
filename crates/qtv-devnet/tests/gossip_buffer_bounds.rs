// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};

use support::{config, unique_base};

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

#[test]
fn a_flood_of_far_view_proposals_stays_bounded_in_the_future_buffer() {
    let base = unique_base("future-proposal-flood");
    let config = config(&base, &[true, true, true, true], vec![]);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let leader0 = leader_for(&selection, 0);
    let leader0_idx = index_of(&config, leader0);

    let base_proposal = nodes[leader0_idx].build_proposal(&selection);

    let victim = (0..nodes.len())
        .find(|&i| i != leader0_idx)
        .expect("a non leader victim");

    let flood: u64 = 4_000;
    for view in 1..=flood {
        let mut proposal = base_proposal.clone();
        proposal.view = view;
        let from = leader_for(&selection, view);
        let out = nodes[victim].on_proposal(&selection, from, proposal);
        assert!(out.is_empty(), "a far view proposal is buffered, not acted on");
    }

    let held = nodes[victim].future_proposals_len();
    assert!(
        held <= 256,
        "the future proposal buffer must stay bounded under a far view flood, held {held} of {flood}"
    );
}

#[test]
fn a_flood_of_distinct_target_views_stays_bounded_per_sender() {
    let base = unique_base("view-change-flood");
    let config = config(&base, &[true, true, true, true], vec![]);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");

    let flood: u64 = 1_000;
    let mut records = Vec::with_capacity(flood as usize);
    for view in 1..=flood {
        records.push(nodes[0].make_view_change(view));
    }

    let victim = 1usize;
    for record in records {
        nodes[victim].collect_view_change(&selection, record);
    }

    let held = nodes[victim].view_changes_len();
    assert!(
        held <= 64,
        "one signer must not occupy more than the per sender bound, held {held} of {flood}"
    );
}
