// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Determinism of catch up sync: the same schedule gives the same synced chain,
//! byte for byte, across independent runs.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, encoded_chain, transfer, unique_base, user};

/// Run one fixed catch up schedule: four nodes finalize two heights, the last
/// falls offline for a stretch, then rejoins and catches up by verified sync.
/// Return the synced node's chain and a peer's chain, byte encoded.
fn run(tag: &str) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let base = unique_base(tag);
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
    devnet.set_active(lagging, false);
    for nonce in 2..5u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet.step().expect("finalized without the lagging node");
    }
    devnet.set_active(lagging, true);
    devnet.sync().expect("catch up sync");

    (
        encoded_chain(devnet.node(lagging)),
        encoded_chain(devnet.node(0)),
    )
}

#[test]
fn the_same_schedule_gives_the_same_synced_chain() {
    let (synced_a, peer_a) = run("determinism-a");
    let (synced_b, peer_b) = run("determinism-b");

    // The synced node ends byte identical to the peer that never left, in both runs.
    assert_eq!(synced_a, peer_a);
    assert_eq!(synced_b, peer_b);
    // And the two independent runs produce the identical synced chain.
    assert_eq!(synced_a, synced_b, "the synced chain was not deterministic");
    assert!(!synced_a.is_empty(), "the synced chain should not be empty");
}
