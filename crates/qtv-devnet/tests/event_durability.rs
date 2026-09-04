// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

#[test]
fn events_survive_a_restart_instead_of_dying_with_the_process() {
    // Events used to live only in a map in the node. Nothing wrote them anywhere, so a
    // restart lost every event the chain had ever emitted, and the explorer was the one
    // surviving record of them purely because its indexer had captured them live. That
    // was proven against the running testnet: heights 1000, 50000 and 200000 all
    // answered with no events at all while a height near the head answered with five.
    let base = unique_base("event-durability");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    devnet
        .submit(0, transfer(&alice, &bob.address(), 1_000, 0, &params))
        .expect("admitted");
    devnet.step().expect("finalized");

    let height = devnet.node(0).height() - 1;
    let index = devnet.len() - 1;

    let before = devnet.node(index).events_at(height);
    assert!(
        !before.is_empty(),
        "a finalized transfer must emit at least one event to make this test mean anything"
    );

    devnet.restart_node(index).expect("reopened from the store");

    let after = devnet.node(index).events_at(height);
    assert_eq!(
        after, before,
        "the events for a finalized height did not survive a restart"
    );
}
