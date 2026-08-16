// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Consensus reaches finality over a bounded gossip overlay, not a full mesh, and
//! the finalized chain is byte identical to the one the same script produces over a
//! full mesh. A bounded neighbor count is enough: every proposal and attestation
//! still reaches every node through relayed hops.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config_with_fanout, header_chain, transfer, unique_base, user};

/// The number of nodes, large enough that a small fanout is below a full mesh.
const NODES: usize = 5;
/// The bounded overlay fanout, a ring lattice of this degree.
const FANOUT: usize = 2;

/// Run one fixed script over a fresh devnet at the given fanout and return the
/// finalized chain, the final state root, and the largest neighbor count.
fn run(name: &str, fanout: usize) -> (Vec<[u8; 32]>, [u8; 32], usize) {
    let base = unique_base(name);
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let online = vec![true; NODES];
    let mut devnet =
        Devnet::over_duplex(config_with_fanout(&base, &online, accounts, fanout)).expect("devnet");

    for nonce in 0..3u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        // Rotate the submitter, so the transaction reaches the leader over the
        // overlay rather than over a direct link.
        devnet
            .submit((nonce as usize) % devnet.len(), tx)
            .expect("admitted");
        devnet.step().expect("finalized over the overlay");
    }

    let chain = header_chain(devnet.node(0));
    // Every node holds the same finalized chain, byte for byte.
    for i in 1..devnet.len() {
        assert_eq!(
            header_chain(devnet.node(i)),
            chain,
            "node {i} finalized a different chain over the overlay"
        );
    }
    (
        chain,
        devnet.node(0).ledger().q_root(),
        devnet.max_neighbor_count(),
    )
}

#[test]
fn a_bounded_overlay_finalizes_the_same_chain_as_a_full_mesh() {
    let (bounded_chain, bounded_root, bounded_degree) = run("overlay-bounded", FANOUT);
    let (full_chain, full_root, full_degree) = run("overlay-full", qtv_devnet::config::FULL_FANOUT);

    // The bounded overlay keeps a small neighbor count, well below the full mesh.
    assert!(
        bounded_degree <= 2 * FANOUT,
        "the overlay degree {bounded_degree} exceeded the fanout"
    );
    assert!(
        bounded_degree < NODES - 1,
        "the overlay degree {bounded_degree} was not below a full mesh"
    );
    assert_eq!(full_degree, NODES - 1, "the full mesh links every pair");

    // Finality over the bounded overlay is byte identical to finality over the full
    // mesh: three heights finalized, the same blocks, the same state.
    assert_eq!(bounded_chain.len(), 3, "the overlay did not reach finality");
    assert_eq!(
        bounded_chain, full_chain,
        "the overlay finalized a different chain than the full mesh"
    );
    assert_eq!(
        bounded_root, full_root,
        "the overlay reached a different state"
    );
}
