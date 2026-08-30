// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

#[test]
fn a_silent_first_leader_is_routed_around_by_a_view_change() {
    let base = unique_base("silent-leader");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let silent = devnet.peek_leader().expect("view zero leader");
    let next = devnet.leader_at(1).expect("view one leader");
    assert_ne!(silent, next, "the rotation moves to a different leader");

    let silent_index = devnet
        .index_of(silent)
        .expect("the silent leader is a node");
    devnet.set_silent(silent_index, true);

    let tx = transfer(&alice, &bob.address(), 1_000, 0, &params);
    devnet.submit(0, tx).expect("admitted");
    devnet
        .step()
        .expect("the timeout routed around the silent leader");

    for i in 0..devnet.len() {
        assert_eq!(
            devnet.node(i).chain().len(),
            1,
            "node {i} did not finalize the height"
        );
        let finalized = devnet.node(i).chain().last().expect("a finalized block");
        assert_eq!(
            finalized.leader, next,
            "the height was not proposed by the next leader in rotation"
        );
    }

    let reference = header_chain(devnet.node(0));
    for i in 1..devnet.len() {
        assert_eq!(header_chain(devnet.node(i)), reference, "node {i} diverged");
    }

    let finalized = devnet.node(0).chain().last().expect("a finalized block");
    assert!(
        finalized.attesters.contains(&silent),
        "the silent leader still attested the block the next leader proposed"
    );
    for i in 0..devnet.len() {
        assert!(
            devnet.node(i).slashed().is_empty(),
            "node {i} slashed a peer"
        );
    }

    assert_eq!(devnet.node(0).ledger().balance(&bob.address()), 1_000);
}
