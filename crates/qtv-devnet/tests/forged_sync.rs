//! Trustless sync refuses a forged chain. A block whose certificate does not
//! verify, whose parent link is wrong, or whose state root is wrong is rejected
//! and does not advance the syncing node, while the genuine block is accepted.

mod support;

use qtv_block::{Block as ChainBlock, Header};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

#[test]
fn a_forged_block_is_rejected_and_does_not_advance_the_node() {
    let base = unique_base("forged-sync");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    // Finalize a stretch so the peers hold a chain to serve.
    for nonce in 0..2u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet.step().expect("finalized");
    }

    // One node drops offline for a single height, so it needs exactly that block.
    let victim = devnet.len() - 1;
    devnet.set_active(victim, false);
    let tx = transfer(&alice, &bob.address(), 1_000, 2, &params);
    devnet.submit(0, tx).expect("admitted");
    devnet.step().expect("finalized without the victim");
    devnet.set_active(victim, true);

    let need = devnet.node(victim).height();
    let genuine = devnet.served_blocks(0, need, need).remove(0);
    assert_eq!(genuine.header().height(), need);
    assert!(
        !genuine.body().is_empty(),
        "the served block should carry the transfer, so a tampered body moves the state root"
    );
    let header = genuine.header();

    // A wrong parent link: the same block re-linked to a head it does not follow.
    let mut wrong_parent_hash = *header.parent_hash();
    wrong_parent_hash[0] ^= 255;
    let forged_parent = ChainBlock::new(
        Header::new(
            header.height(),
            wrong_parent_hash,
            *header.state_root(),
            *header.transaction_root(),
            *header.event_root(),
            *header.beacon_seed(),
            header.proposer().to_string(),
            header.time(),
        ),
        genuine.certificate().to_vec(),
        genuine.body().to_vec(),
    );
    assert!(devnet.apply_synced(victim, forged_parent).is_err());
    assert_eq!(
        devnet.node(victim).height(),
        need,
        "a bad parent advanced it"
    );

    // A wrong state root: the genuine header over an emptied body no longer
    // reproduces the committed state root.
    let forged_state = ChainBlock::new(header.clone(), genuine.certificate().to_vec(), Vec::new());
    assert!(devnet.apply_synced(victim, forged_state).is_err());
    assert_eq!(
        devnet.node(victim).height(),
        need,
        "a bad state root advanced it"
    );

    // A certificate that does not verify: one signature byte flipped, so the
    // aggregate no longer proves an entitled supermajority.
    let mut cert = genuine.certificate().to_vec();
    let last = cert.len() - 1;
    cert[last] ^= 1;
    let forged_cert = ChainBlock::new(header.clone(), cert, genuine.body().to_vec());
    assert!(devnet.apply_synced(victim, forged_cert).is_err());
    assert_eq!(
        devnet.node(victim).height(),
        need,
        "a bad certificate advanced it"
    );

    // The genuine block still verifies and advances the node one height.
    devnet
        .apply_synced(victim, genuine)
        .expect("the verified block is accepted");
    assert_eq!(devnet.node(victim).height(), need + 1);
    assert_eq!(devnet.node(victim).head_hash(), devnet.node(0).head_hash());
}
