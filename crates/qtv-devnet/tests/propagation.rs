// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A transaction submitted to one node propagates over the wire and is finalized
//! by the committee, even when the submitting node is not the leader.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::Wrapper;

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

#[test]
fn a_transaction_propagates_from_one_node_and_is_finalized() {
    let base = unique_base("propagate");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    // Submit to a node that does not lead this height, so finalization proves the
    // transaction reached the leader over the wire.
    let leader = devnet.peek_leader().expect("leader");
    let submitter = (0..devnet.len())
        .find(|&i| devnet.node(i).id() != leader)
        .expect("a non leader node");

    let tx = transfer(&alice, &bob.address(), 4_242, 0, &params);
    let tx_id = tx.id();
    devnet
        .submit(submitter, tx)
        .expect("admitted at the submitter");

    // Only the submitting node holds the transaction before the round.
    assert_eq!(devnet.node(submitter).mempool_len(), 1);
    for i in 0..devnet.len() {
        if i != submitter {
            assert_eq!(devnet.node(i).mempool_len(), 0);
        }
    }

    devnet.step().expect("the committee finalized the height");

    // The transaction is in the finalized body on every node, and the leader, not
    // the submitter, proposed it.
    for i in 0..devnet.len() {
        let finalized = devnet.node(i).chain().last().expect("a finalized block");
        let ids: Vec<String> = finalized.block.body().iter().map(Wrapper::id).collect();
        assert!(
            ids.contains(&tx_id),
            "node {i} did not finalize the propagated transaction"
        );
        assert_eq!(finalized.leader, leader);
    }
    assert_ne!(devnet.node(submitter).id(), leader);
    assert_eq!(devnet.node(0).ledger().balance(&bob.address()), 4_242);
}
