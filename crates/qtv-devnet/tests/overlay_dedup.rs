// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! De duplication and loop freedom over the overlay. In a ring a message reaches a
//! far node by two paths, one from each side; the seen record counts it once and
//! never relays it back, so no attestation is double counted and no relay loop
//! forms. The run terminating at all is the loop freedom: an overlay that relayed a
//! seen message again would never fall idle.

mod support;

use std::collections::BTreeSet;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config_with_fanout, header_chain, transfer, unique_base, user};

const NODES: usize = 5;
const FANOUT: usize = 2;

#[test]
fn a_duplicate_is_counted_once_and_a_relay_cannot_loop() {
    let base = unique_base("overlay-dedup");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let online = vec![true; NODES];
    let mut devnet =
        Devnet::over_duplex(config_with_fanout(&base, &online, accounts, FANOUT)).expect("devnet");

    // A ring, so every node has exactly two neighbors and a far node hears each
    // message from both sides.
    assert_eq!(devnet.max_neighbor_count(), 2);
    assert!(devnet.max_neighbor_count() < NODES - 1);

    let heights = 2u64;
    for nonce in 0..heights {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet
            .submit((nonce as usize) % devnet.len(), tx)
            .expect("admitted");
        // If a seen message were relayed again the clock would never fall idle and
        // this call would not return.
        devnet.step().expect("finalized over the overlay");
    }

    // Every node holds the same finalized chain, so de duplication did not corrupt
    // the block a message arriving by two paths contributes to.
    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len(), heights as usize);
    for i in 0..devnet.len() {
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "node {i} finalized a different chain"
        );
        // No attester appears twice in any certificate: a message arriving by two
        // overlay paths is counted once.
        for block in devnet.node(i).chain() {
            let unique: BTreeSet<u64> = block.attesters.iter().copied().collect();
            assert_eq!(
                unique.len(),
                block.attesters.len(),
                "node {i} counted an attestation twice"
            );
        }
    }
}
