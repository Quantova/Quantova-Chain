// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

#[test]
fn a_restarted_node_reloads_its_chain_and_rejoins() {
    let base = unique_base("restart");
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

    let index = devnet.len() - 1;
    let head_before = devnet.node(index).head_hash();
    let height_before = devnet.node(index).height();

    devnet.restart_node(index).expect("reopened from the store");

    assert_eq!(devnet.node(index).head_hash(), head_before);
    assert_eq!(devnet.node(index).height(), height_before);
    assert_eq!(devnet.node(index).stored_blocks(), 2);

    for nonce in 2..4u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet
            .step()
            .expect("the restarted node rejoined and finalized");
    }

    let restarted_tail = header_chain(devnet.node(index));
    let peer_tail: Vec<[u8; 32]> = devnet
        .node(0)
        .chain()
        .iter()
        .skip(2)
        .map(|block| block.header_hash())
        .collect();
    assert_eq!(restarted_tail, peer_tail);

    let head = devnet.node(0).head_hash();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).head_hash(), head, "node {i} head differs");
    }
    assert_eq!(devnet.node(index).height(), height_before + 2);
}

#[test]
fn a_restarted_node_reloads_bonded_stake() {
    let base = unique_base("restart-stake");
    let params = FeeParams::devnet();
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 100_000 * 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let stake = qtv_node::ledger::stake_system_address();
    let bond = 5_000u64 * 1_000_000;
    devnet
        .submit(0, transfer(&alice, &stake, bond, 0, &params))
        .expect("admitted");
    let mut rounds = 0;
    while devnet.node(0).ledger().staked_weight(&alice.address()) == 0 {
        devnet.step().expect("the bond finalizes");
        rounds += 1;
        assert!(rounds < 12, "the bond should finalize within a few rounds");
    }
    let weight = devnet.node(0).ledger().staked_weight(&alice.address());
    assert!(weight > 0, "the bond registered");

    let index = devnet.len() - 1;
    devnet.restart_node(index).expect("reopened from the store");

    assert_eq!(
        devnet.node(index).ledger().staked_weight(&alice.address()),
        weight,
        "the bond survived the restart"
    );
    assert_eq!(
        devnet.node(index).head_hash(),
        devnet.node(0).head_hash(),
        "the restarted node's state matches a peer"
    );
}
