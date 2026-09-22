// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

#[test]
fn the_transaction_index_answers_after_finality_and_survives_a_restart() {
    let base = unique_base("tx-index");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let tx = transfer(&alice, &bob.address(), 1_000, 0, &params);
    let tx_id = tx.id();
    devnet.submit(0, tx).expect("admitted");
    devnet.step().expect("finalized");

    let height = devnet.node(0).height() - 1;

    assert_eq!(devnet.node(0).finalized_height(&tx_id), Some(height));
    assert_eq!(devnet.node(0).finalized_height("qtx1neverfinalised"), None);

    let index = devnet.len() - 1;
    assert_eq!(devnet.node(index).finalized_height(&tx_id), Some(height));
    devnet.restart_node(index).expect("reopened from the store");
    assert_eq!(
        devnet.node(index).finalized_height(&tx_id),
        Some(height),
        "the transaction index did not survive a restart"
    );
}

#[test]
fn the_index_names_where_in_its_block_a_transaction_sits() {
    let base = unique_base("tx-position");
    let params = FeeParams::devnet();
    let senders: Vec<_> = (0..3).map(user).collect();
    let bob = user(9);
    let accounts = senders
        .iter()
        .map(|s| GenesisAccount::from_account(s, 1_000_000))
        .collect();
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");
    let ids: Vec<String> = senders
        .iter()
        .map(|sender| {
            let tx = transfer(sender, &bob.address(), 1_000, 0, &params);
            let id = tx.id();
            devnet.submit(0, tx).expect("admitted");
            id
        })
        .collect();
    devnet.step().expect("finalized");

    for id in &ids {
        let (height, position) = devnet.node(0).finalized_location(id).expect("indexed");
        let position = position.expect("the position is recorded");
        let served = devnet
            .node(0)
            .served_block(height)
            .expect("the block is served");
        assert_eq!(&served.block.body()[position].id(), id);
        assert_eq!(&served.ids()[position], id);
    }
}
