// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Progress under reordered and delayed messages between honest nodes. Records
//! from different peers arrive at a receiver in a scrambled order, each edge still
//! in send order, and the nodes still finalize the same chain.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::Wrapper;

use qtv_devnet::{Devnet, Network};

use support::{config, header_chain, transfer, unique_base, user};

#[test]
fn honest_nodes_finalize_the_same_chain_under_reordering() {
    let base = unique_base("reorder");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    // Deliver records under a reordering schedule: attestations and proposals from
    // different peers land out of order, but within the view timeout, so the round
    // still finalizes without a view change.
    devnet.set_network(Network::reordering());

    let heights = 3u64;
    let mut ids = Vec::new();
    for nonce in 0..heights {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        ids.push(tx.id());
        // Submit to a rotating node, so a transaction reaches the leader over the
        // reordered wire.
        devnet
            .submit((nonce as usize) % devnet.len(), tx)
            .expect("admitted");
        devnet.step().expect("finalized under reordering");
    }

    // Every node holds the same finalized chain, byte for byte, over every height.
    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len(), heights as usize);
    for i in 1..devnet.len() {
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "node {i} finalized a different chain under reordering"
        );
    }

    // Every transaction was finalized, and the state agrees across nodes.
    let root = devnet.node(0).ledger().q_root();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).ledger().q_root(), root);
        let finalized: Vec<String> = devnet
            .node(i)
            .chain()
            .iter()
            .flat_map(|block| block.block.body().iter().map(Wrapper::id))
            .collect();
        for id in &ids {
            assert!(finalized.contains(id), "node {i} dropped a transaction");
        }
    }
    assert_eq!(
        devnet.node(0).ledger().balance(&bob.address()),
        heights * 1_000
    );
}
