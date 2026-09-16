// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_block::{Block as ChainBlock, Header};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::node::SyncError;
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

    for nonce in 0..2u64 {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet.step().expect("finalized");
    }

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

    let mut wrong_parent_hash = *header.parent_hash();
    wrong_parent_hash[0] ^= 255;
    let forged_parent = ChainBlock::new(
        Header::new(
            header.height(),
            wrong_parent_hash,
            *header.q_root(),
            *header.transaction_root(),
            *header.event_root(),
            *header.beacon_seed(),
            header.proposer().to_string(),
            header.time(),
        ),
        genuine.certificate().to_vec(),
        genuine.body().to_vec(),
    );
    assert_eq!(
        devnet.apply_synced(victim, forged_parent),
        Err(SyncError::WrongParent),
        "a block naming another parent must be refused for that reason, not incidentally"
    );
    assert_eq!(
        devnet.node(victim).height(),
        need,
        "a bad parent advanced it"
    );

    let forged_state = ChainBlock::new(header.clone(), genuine.certificate().to_vec(), Vec::new());
    assert_eq!(
        devnet.apply_synced(victim, forged_state),
        Err(SyncError::WrongStateRoot),
        "a body that does not reproduce the committed roots must be refused for that reason"
    );
    assert_eq!(
        devnet.node(victim).height(),
        need,
        "a bad state root advanced it"
    );

    let mut cert = genuine.certificate().to_vec();
    let last = cert.len() - 1;
    cert[last] ^= 1;
    let forged_cert = ChainBlock::new(header.clone(), cert, genuine.body().to_vec());
    assert_eq!(
        devnet.apply_synced(victim, forged_cert),
        Err(SyncError::NoCommittee),
        "tampering with the certificate breaks the committee it commits to, so the block is \
         refused before any signature is even checked"
    );

    let mut decoded = qtv_devnet::wire::certificate_from_bytes(genuine.certificate())
        .expect("the genuine certificate decodes");
    let last = decoded.attestations[0].sig.len() - 1;
    decoded.attestations[0].sig[last] ^= 1;
    let forged_sig = ChainBlock::new(
        header.clone(),
        qtv_devnet::wire::certificate_to_bytes(&decoded),
        genuine.body().to_vec(),
    );
    assert_eq!(
        devnet.apply_synced(victim, forged_sig),
        Err(SyncError::UnverifiedCertificate),
        "a certificate that still names the right committee but carries a forged signature must \
         be refused at signature verification"
    );
    assert_eq!(
        devnet.node(victim).height(),
        need,
        "a forged signature advanced it"
    );
    assert_eq!(
        devnet.node(victim).height(),
        need,
        "a bad certificate advanced it"
    );

    devnet
        .apply_synced(victim, genuine)
        .expect("the verified block is accepted");
    assert_eq!(devnet.node(victim).height(), need + 1);
    assert_eq!(devnet.node(victim).head_hash(), devnet.node(0).head_hash());
}

#[test]
fn every_header_field_the_sync_path_checks_is_refused_on_its_own() {
    let base = unique_base("sync-header-fields");
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
    let victim = devnet.len() - 1;
    devnet.set_active(victim, false);
    let tx = transfer(&alice, &bob.address(), 1_000, 2, &params);
    devnet.submit(0, tx).expect("admitted");
    devnet.step().expect("finalized without the victim");
    devnet.set_active(victim, true);

    let need = devnet.node(victim).height();
    let genuine = devnet.served_blocks(0, need, need).remove(0);
    let header = genuine.header().clone();

    let rebuild = |h: Header| {
        ChainBlock::new(h, genuine.certificate().to_vec(), genuine.body().to_vec())
    };
    let header_with = |height: u64, seed: [u8; 32], time: u64| {
        Header::new(
            height,
            *header.parent_hash(),
            *header.q_root(),
            *header.transaction_root(),
            *header.event_root(),
            seed,
            header.proposer().to_string(),
            time,
        )
    };

    assert_eq!(
        devnet.apply_synced(victim, rebuild(header_with(header.height() + 1, *header.beacon_seed(), header.time()))),
        Err(SyncError::WrongHeight),
        "a block for another height must not be applied at this one"
    );

    let mut seed = *header.beacon_seed();
    seed[0] ^= 0xff;
    assert_eq!(
        devnet.apply_synced(victim, rebuild(header_with(header.height(), seed, header.time()))),
        Err(SyncError::WrongBeacon),
        "a block carrying a beacon the node did not derive must be refused, or a proposer could \
         name the draw it wanted"
    );

    assert_eq!(
        devnet.apply_synced(victim, rebuild(header_with(header.height(), *header.beacon_seed(), 0))),
        Err(SyncError::WrongTime),
        "a block timed before its parent must be refused"
    );

    assert_eq!(
        devnet.node(victim).height(),
        need,
        "no refused header advanced the node"
    );
    devnet
        .apply_synced(victim, genuine)
        .expect("the genuine block is still accepted after every refusal");
    assert_eq!(devnet.node(victim).height(), need + 1);
}
