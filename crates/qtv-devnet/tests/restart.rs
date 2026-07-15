//! A node restarted from its store reloads its finalized chain and rejoins.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, encoded_chain, transfer, unique_base, user};

#[test]
fn a_restarted_node_reloads_its_chain_and_rejoins() {
    let base = unique_base("restart");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    // Two heights, so every node persists blocks one and two.
    for nonce in 0..2u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet.step().expect("finalized");
    }

    let index = devnet.len() - 1;
    let head_before = devnet.node(index).head_hash();
    let height_before = devnet.node(index).height();

    // Restart the node from its store while the mesh stays up.
    devnet.restart_node(index).expect("reopened from the store");

    // It reloaded the exact head, height, and block count it had persisted.
    assert_eq!(devnet.node(index).head_hash(), head_before);
    assert_eq!(devnet.node(index).height(), height_before);
    assert_eq!(devnet.node(index).stored_blocks(), 2);

    // It rejoins and keeps finalizing the same chain as its peers.
    for nonce in 2..4u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet
            .step()
            .expect("the restarted node rejoined and finalized");
    }

    // The blocks the restarted node finalized after reopening match a peer that
    // never restarted, and the whole devnet agrees on the head.
    let restarted_tail = encoded_chain(devnet.node(index));
    let peer_tail: Vec<Vec<u8>> = devnet
        .node(0)
        .chain()
        .iter()
        .skip(2)
        .map(|block| block.encoded())
        .collect();
    assert_eq!(restarted_tail, peer_tail);

    let head = devnet.node(0).head_hash();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).head_hash(), head, "node {i} head differs");
    }
    assert_eq!(devnet.node(index).height(), height_before + 2);
}
