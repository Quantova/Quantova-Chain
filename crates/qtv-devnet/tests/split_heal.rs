// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A network split into two groups, neither a supermajority, finalizes nothing.
//! When the split heals the nodes converge on one branch and resume finalizing,
//! and no two nodes ever hold a different finalized block at one height.

mod support;

use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, encoded_chain, unique_base, user};

#[test]
fn a_split_finalizes_nothing_and_heals_to_one_branch() {
    let base = unique_base("split-heal");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    // Split the four nodes into two groups of two. The view zero leader and one
    // partner form one group; the other two form the other. Neither group is a
    // supermajority of three, so neither can finalize alone.
    let leader = devnet.peek_leader().expect("view zero leader");
    let leader_index = devnet.index_of(leader).expect("leader is a node");
    let partner = (0..devnet.len())
        .find(|&i| i != leader_index)
        .expect("a partner");
    let mut groups = vec![1usize; devnet.len()];
    groups[leader_index] = 0;
    groups[partner] = 0;
    devnet.set_partition(&groups);

    // Run the split for a bounded stretch: long enough for the leader's group to
    // lock its block and the other group to time out once, short enough that the
    // stalled group does not churn through every view.
    let deadline = devnet.view_timeout() + devnet.view_timeout() / 2;
    devnet.drive_window(2, deadline).expect("split window");

    // Neither group finalized: no node holds a block at height one.
    for i in 0..devnet.len() {
        assert!(
            devnet.node(i).chain().is_empty(),
            "node {i} finalized during the split"
        );
    }

    // Heal the split and let the round loop run. The nodes reconcile through a view
    // change and finalize one block.
    devnet.heal();
    let resumed = devnet.drive(2).expect("drive after heal");
    assert!(
        resumed,
        "the nodes did not resume finalizing after the split healed"
    );

    // Every node finalized exactly one block, and it is byte identical across nodes,
    // so no two nodes hold a different finalized block at height one.
    let reference = encoded_chain(devnet.node(0));
    assert_eq!(reference.len(), 1, "height one did not finalize once");
    for i in 1..devnet.len() {
        assert_eq!(
            encoded_chain(devnet.node(i)),
            reference,
            "node {i} converged on a different branch"
        );
    }

    // The block that finalized is the one the view zero leader proposed and its
    // group locked, not a fresh block from the later leader that drove the view
    // change. The justification forced that later leader to re-propose the locked
    // block, so the two competing proposals converged on exactly one and no node
    // ever finalized the other.
    let finalized = devnet.node(0).chain().last().expect("a finalized block");
    assert_eq!(
        finalized.header().proposer(),
        qtv_node::node::validator_address(leader).as_str(),
        "the finalized block was not the view zero leader's proposal"
    );

    // The state agrees across nodes and no node was slashed.
    let root = devnet.node(0).ledger().q_root();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).ledger().q_root(), root, "node {i} state");
        assert!(
            devnet.node(i).slashed().is_empty(),
            "node {i} slashed a peer"
        );
    }
}
