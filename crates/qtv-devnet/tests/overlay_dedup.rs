// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

    assert_eq!(devnet.max_neighbor_count(), 2);
    assert!(devnet.max_neighbor_count() < NODES - 1);

    let heights = 2u64;
    for nonce in 0..heights {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet
            .submit((nonce as usize) % devnet.len(), tx)
            .expect("admitted");
        devnet.step().expect("finalized over the overlay");
    }

    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len(), heights as usize);
    for i in 0..devnet.len() {
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "node {i} finalized a different chain"
        );
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
