// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Liveness bounds. The chain finalizes only while an honest supermajority is
//! online: it stalls when the online set drops below a supermajority and resumes
//! when it returns, and a node that was offline for the stall is never slashed.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

#[test]
fn the_chain_stalls_below_a_supermajority_and_resumes_above_it() {
    let base = unique_base("stall");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    // Four validators, a supermajority of three.
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    // Keep the elected leader and one peer online, and take the other two offline,
    // so only two of four are online, one short of the supermajority. The online
    // leader still proposes, so the two see a valid block and hold on it rather
    // than churning views.
    let leader = devnet.peek_leader().expect("leader");
    let leader_index = devnet.index_of(leader).expect("leader is a node");
    let others: Vec<usize> = (0..devnet.len()).filter(|&i| i != leader_index).collect();
    let helper = others[0];
    let recover = others[1];
    let absent = others[2];
    devnet.set_active(recover, false);
    devnet.set_active(absent, false);

    let tx = transfer(&alice, &bob.address(), 1_000, 0, &params);
    devnet.submit(leader_index, tx).expect("admitted");

    // Below the supermajority the height does not finalize; the online nodes hold.
    let progressed = devnet.drive(2).expect("drive");
    assert!(!progressed, "the chain finalized below a supermajority");
    assert_eq!(devnet.height(), 1, "the height advanced while stalled");
    assert!(devnet.node(leader_index).chain().is_empty());
    assert!(devnet.node(helper).chain().is_empty());

    // Bring one offline node back, restoring the supermajority. The held block now
    // finalizes.
    devnet.set_active(recover, true);
    let resumed = devnet.drive(2).expect("drive");
    assert!(
        resumed,
        "the chain did not resume once the supermajority returned"
    );
    for &i in &[leader_index, helper, recover] {
        assert_eq!(
            devnet.node(i).chain().len(),
            1,
            "node {i} did not finalize once online again"
        );
    }
    // The finalized block is the one the leader held all along.
    let finalized = devnet.node(leader_index).chain().last().expect("a block");
    assert_eq!(finalized.leader, leader);

    // The node still offline finalized nothing, and no node is ever slashed for
    // being offline through the stall.
    assert!(devnet.node(absent).chain().is_empty());
    for i in 0..devnet.len() {
        assert!(
            devnet.node(i).slashed().is_empty(),
            "node {i} slashed a peer"
        );
    }
}
