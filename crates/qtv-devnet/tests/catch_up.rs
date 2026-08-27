// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

#[test]
fn a_node_that_missed_a_stretch_catches_up_and_matches() {
    let base = unique_base("catch-up");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    for nonce in 0..2u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet.step().expect("finalized");
    }
    let lagging = devnet.len() - 1;
    let height_before = devnet.node(lagging).height();

    devnet.set_active(lagging, false);
    for nonce in 2..5u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet.step().expect("finalized without the lagging node");
    }
    let tip = devnet.node(0).height();
    assert!(
        devnet.node(lagging).height() < tip,
        "the lagging node should be behind the group"
    );
    assert_eq!(
        devnet.node(lagging).height(),
        height_before,
        "the lagging node advanced nothing while offline"
    );

    devnet.set_active(lagging, true);
    devnet.sync().expect("catch up sync");

    assert_eq!(devnet.node(lagging).height(), tip);
    let lagging_headers: Vec<[u8; 32]> =
        devnet.node(lagging).chain().iter().map(|b| b.header_hash()).collect();
    let leader_headers: Vec<[u8; 32]> =
        devnet.node(0).chain().iter().map(|b| b.header_hash()).collect();
    assert_eq!(
        lagging_headers, leader_headers,
        "the synced chain diverged from the peer that never left"
    );
    assert_eq!(devnet.node(lagging).head_hash(), devnet.node(0).head_hash());
    assert_eq!(
        devnet.node(lagging).stored_blocks(),
        devnet.node(0).stored_blocks(),
        "the synced node did not persist the whole chain"
    );
    assert!(devnet.node(lagging).slashed().is_empty());
}
