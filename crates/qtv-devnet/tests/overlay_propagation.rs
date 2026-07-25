// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A transaction, a proposal, and an attestation each propagate from one origin to
//! every node through the bounded overlay, reaching nodes that are not direct
//! neighbors of the origin, rather than over a direct link to each.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::Wrapper;

use qtv_devnet::Devnet;

use support::{config_with_fanout, encoded_chain, transfer, unique_base, user};

const NODES: usize = 5;
const FANOUT: usize = 2;

#[test]
fn a_transaction_a_proposal_and_an_attestation_reach_every_node_over_the_overlay() {
    let base = unique_base("overlay-propagate");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let online = vec![true; NODES];
    let mut devnet =
        Devnet::over_duplex(config_with_fanout(&base, &online, accounts, FANOUT)).expect("devnet");

    // The overlay is bounded: each node keeps at most a ring lattice of neighbors,
    // far below the six of a full mesh over seven nodes.
    assert!(devnet.max_neighbor_count() < NODES - 1);

    // Submit to a node that neither leads nor neighbors the leader, so the
    // transaction, the proposal, and the attestations all cross relayed hops.
    let leader = devnet.peek_leader().expect("leader");
    let leader_index = devnet.index_of(leader).expect("leader is a node");
    let submitter = (0..devnet.len())
        .find(|&i| i != leader_index && !devnet.neighbors(leader_index).contains(&i))
        .expect("a node off the leader's neighbor set");

    let tx = transfer(&alice, &bob.address(), 4_242, 0, &params);
    let tx_id = tx.id();
    devnet
        .submit(submitter, tx)
        .expect("admitted at the submitter");

    // Only the submitter holds the transaction before the round.
    for i in 0..devnet.len() {
        let expected = usize::from(i == submitter);
        assert_eq!(devnet.node(i).mempool_len(), expected);
    }

    devnet
        .step()
        .expect("the committee finalized over the overlay");

    // The transaction reached the leader and is in the finalized body on every node,
    // the proposal reached every node so the block is byte identical, and the
    // attestations reached every node so the certificate is byte identical.
    let reference = encoded_chain(devnet.node(0));
    assert_eq!(reference.len(), 1);
    let attesters = devnet.node(0).chain()[0].attesters.clone();
    for i in 0..devnet.len() {
        assert_eq!(
            encoded_chain(devnet.node(i)),
            reference,
            "node {i} did not finalize the same block over the overlay"
        );
        let finalized = devnet.node(i).chain().last().expect("a finalized block");
        let ids: Vec<String> = finalized.block.body().iter().map(Wrapper::id).collect();
        assert!(
            ids.contains(&tx_id),
            "node {i} did not finalize the propagated transaction"
        );
        assert_eq!(finalized.leader, leader);
        assert_eq!(
            finalized.attesters, attesters,
            "node {i} aggregated a different set"
        );
    }

    // The submitter is not a neighbor of the leader, so the transaction reached the
    // leader only by being relayed across the overlay, and the finalized block
    // reached the submitter the same way.
    assert!(!devnet.neighbors(leader_index).contains(&submitter));
    assert_eq!(devnet.node(0).ledger().balance(&bob.address()), 4_242);
}
