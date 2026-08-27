// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, header_chain, unique_base, user};

#[test]
fn a_split_finalizes_nothing_and_heals_to_one_branch() {
    let base = unique_base("split-heal");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let leader = devnet.peek_leader().expect("view zero leader");
    let leader_index = devnet.index_of(leader).expect("leader is a node");
    let partner = (0..devnet.len())
        .find(|&i| i != leader_index)
        .expect("a partner");
    let mut groups = vec![1usize; devnet.len()];
    groups[leader_index] = 0;
    groups[partner] = 0;
    devnet.set_partition(&groups);

    let deadline = devnet.view_timeout() + devnet.view_timeout() / 2;
    devnet.drive_window(2, deadline).expect("split window");

    for i in 0..devnet.len() {
        assert!(
            devnet.node(i).chain().is_empty(),
            "node {i} finalized during the split"
        );
    }

    devnet.heal();
    let resumed = devnet.drive(2).expect("drive after heal");
    assert!(
        resumed,
        "the nodes did not resume finalizing after the split healed"
    );

    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len(), 1, "height one did not finalize once");
    for i in 1..devnet.len() {
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "node {i} converged on a different branch"
        );
    }

    let finalized = devnet.node(0).chain().last().expect("a finalized block");
    assert_eq!(finalized.header().height(), 1, "height one finalized once");

    let root = devnet.node(0).ledger().q_root();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).ledger().q_root(), root, "node {i} state");
        assert!(
            devnet.node(i).slashed().is_empty(),
            "node {i} slashed a peer"
        );
    }
}
