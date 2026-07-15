//! A node behind by several heights catches up by sync and then finalizes new
//! heights with the group, ending byte identical to the nodes that never left.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, encoded_chain, transfer, unique_base, user};

#[test]
fn a_lagging_node_catches_up_then_finalizes_with_the_group() {
    let base = unique_base("rejoin");
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

    // The last node falls several heights behind while offline.
    let lagging = devnet.len() - 1;
    devnet.set_active(lagging, false);
    for nonce in 2..6u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet.step().expect("finalized without the lagging node");
    }
    let behind = devnet.node(lagging).height();
    let tip = devnet.node(0).height();
    assert!(
        tip >= behind + 3,
        "the node should be several heights behind"
    );

    // It comes back online. A step catches it up over sync, then the whole group
    // finalizes a fresh height together.
    devnet.set_active(lagging, true);
    for nonce in 6..8u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet
            .step()
            .expect("the rejoined node caught up and finalized with the group");
    }

    // Every node advanced past the tip the group held, and the rejoined node's chain
    // is byte identical to a peer that never left.
    let head = devnet.node(0).head_hash();
    let final_height = devnet.node(0).height();
    assert!(final_height > tip, "the group did not finalize new heights");
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).height(), final_height, "node {i} lagged");
        assert_eq!(devnet.node(i).head_hash(), head, "node {i} head differs");
    }
    assert_eq!(
        encoded_chain(devnet.node(lagging)),
        encoded_chain(devnet.node(0)),
        "the rejoined chain diverged"
    );
    // The rejoined node finalized the fresh heights itself, from live consensus.
    let attesters = &devnet
        .node(lagging)
        .chain()
        .last()
        .expect("a finalized block")
        .attesters;
    assert!(
        attesters.contains(&devnet.node(lagging).id()),
        "the rejoined node attested the newest block it finalized live"
    );
}
