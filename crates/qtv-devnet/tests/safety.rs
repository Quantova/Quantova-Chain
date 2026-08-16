// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Safety under asynchronous timing, message reordering, and a view change. No
//! two nodes finalize different blocks at one height: the finalized block and the
//! certificate are byte identical across nodes at every height.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::{Devnet, Network};

use support::{config, header_chain, transfer, unique_base, user};

#[test]
fn no_two_nodes_finalize_different_blocks_at_a_height() {
    let base = unique_base("safety");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    // Reorder the wire and force a view change at the first height by silencing its
    // elected leader, so the height finalizes only through the rotation while
    // records arrive out of order.
    devnet.set_network(Network::reordering());
    let silent = devnet.peek_leader().expect("view zero leader");
    let next = devnet.leader_at(1).expect("view one leader");
    let silent_index = devnet.index_of(silent).expect("silent leader is a node");
    devnet.set_silent(silent_index, true);

    let heights = 4u64;
    for nonce in 0..heights {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet
            .submit((nonce as usize) % devnet.len(), tx)
            .expect("admitted");
        devnet
            .step()
            .expect("finalized under reordering and a view change");
    }

    // The first height finalized through the view change, not the silent leader.
    let first = devnet.node(0).chain().first().expect("a first block");
    assert_eq!(
        first.leader, next,
        "the first height did not route around the silent leader"
    );

    // Safety: at every height, every node holds the identical finalized block and
    // certificate, so no two nodes finalized different blocks at one height.
    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len(), heights as usize);
    for i in 1..devnet.len() {
        let chain = header_chain(devnet.node(i));
        assert_eq!(chain.len(), reference.len());
        for (height, (block, expected)) in chain.iter().zip(&reference).enumerate() {
            assert_eq!(
                block,
                expected,
                "node {i} finalized a different block at height {}",
                height + 1
            );
        }
    }

    // The state root agrees across nodes and no node was slashed.
    let root = devnet.node(0).ledger().q_root();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).ledger().q_root(), root, "node {i} state");
        assert!(
            devnet.node(i).slashed().is_empty(),
            "node {i} slashed a peer"
        );
    }
}
