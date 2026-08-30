// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

#[test]
fn nodes_reach_a_byte_identical_chain_at_each_height() {
    let base = unique_base("converge");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let heights = 2u64;
    for nonce in 0..heights {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted at the origin node");
        devnet.step().expect("the committee finalized the height");
    }

    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len(), heights as usize);
    for i in 1..devnet.len() {
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "node {i} finalized a different chain"
        );
    }

    let root = devnet.node(0).ledger().q_root();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).ledger().q_root(), root);
        for finalized in devnet.node(i).chain() {
            assert!(
                finalized.attesters.len() >= 3,
                "at least a two thirds quorum attested"
            );
            assert!(
                finalized
                    .attesters
                    .iter()
                    .all(|a| [1u64, 2, 3, 4].contains(a)),
                "every attester is a committee member"
            );
        }
    }

    assert_eq!(
        devnet.node(0).ledger().balance(&bob.address()),
        heights * 1_000
    );
}
