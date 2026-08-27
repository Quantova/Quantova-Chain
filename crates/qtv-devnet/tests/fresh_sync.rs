// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

#[test]
fn a_fresh_node_syncs_the_whole_chain_from_a_peer() {
    let base = unique_base("fresh-sync");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, false], accounts)).expect("devnet");
    let fresh = devnet.len() - 1;

    for nonce in 0..4u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet.step().expect("finalized");
    }

    assert_eq!(devnet.node(fresh).stored_blocks(), 0);
    assert!(devnet.node(fresh).chain().is_empty());
    let tip = devnet.node(0).height();
    assert!(tip > devnet.node(fresh).height());

    devnet.set_active(fresh, true);
    devnet.sync().expect("fresh sync");

    assert_eq!(devnet.node(fresh).height(), tip);
    assert_eq!(
        header_chain(devnet.node(fresh)),
        header_chain(devnet.node(0)),
        "the fresh node did not reproduce the peer chain"
    );
    assert_eq!(devnet.node(fresh).head_hash(), devnet.node(0).head_hash());
    assert_eq!(
        devnet.node(fresh).stored_blocks(),
        devnet.node(0).stored_blocks()
    );
    assert_eq!(
        devnet.node(fresh).ledger().balance(&bob.address()),
        devnet.node(0).ledger().balance(&bob.address())
    );
}
