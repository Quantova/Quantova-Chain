// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The three gossip messages round trip through the canonical codec, and a
//! message that does not parse is refused at the edge.

mod support;

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Beacon, Block, CommitteeCommitment, Parent};
use qtv_block::{empty_transaction_root, Header};
use qtv_node::fee::FeeParams;

use qtv_devnet::discovery::PeerEntry;
use qtv_devnet::node::node_identity;
use qtv_devnet::coded::code_proposal;
use qtv_devnet::wire::{certificate_from_bytes, certificate_to_bytes, Message, Proposal};

use support::{transfer, user};

// A fixed chain id for the self contained round trips. The sign, aggregate and verify sides
// all rebuild the preimage under the same id, so the certificate that is signed here is the
// one that verifies here.
const CHAIN_ID: u64 = 1;

#[test]
fn a_transaction_message_round_trips() {
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let tx = transfer(&alice, &bob.address(), 700, 0, &params);
    let bytes = Message::Tx(tx.clone()).encode();
    match Message::decode(&bytes).expect("decodes") {
        Message::Tx(decoded) => {
            assert_eq!(decoded.id(), tx.id());
            assert_eq!(decoded.body().sender(), tx.body().sender());
            assert_eq!(decoded.signature(), tx.signature());
        }
        _ => panic!("decoded a different message"),
    }
}

#[test]
fn a_proposal_message_round_trips() {
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let body = vec![transfer(&alice, &bob.address(), 500, 0, &params)];
    let header = Header::new(
        1,
        [0u8; 32],
        [7u8; 32],
        qtv_block::transaction_root(&body),
        empty_transaction_root(),
        [9u8; 32],
        "q1proposer".to_string(),
        1_700_000_000_150,
    );
    let bytes = Message::Proposal(Proposal {
        view: 2,
        header: header.clone(),
        body: body.clone(),
        justification: Vec::new(),
    })
    .encode();
    match Message::decode(&bytes).expect("decodes") {
        Message::Proposal(decoded) => {
            assert_eq!(decoded.view, 2);
            assert_eq!(decoded.header, header);
            assert_eq!(decoded.body.len(), 1);
            assert_eq!(decoded.body[0].id(), body[0].id());
        }
        _ => panic!("decoded a different message"),
    }
}

#[test]
fn a_coded_proposal_shard_round_trips_and_still_verifies() {
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let body = vec![
        transfer(&alice, &bob.address(), 500, 0, &params),
        transfer(&alice, &bob.address(), 501, 1, &params),
    ];
    let header = Header::new(
        3,
        [0u8; 32],
        [7u8; 32],
        qtv_block::transaction_root(&body),
        empty_transaction_root(),
        [9u8; 32],
        "q1proposer".to_string(),
        1_700_000_000_150,
    );
    let proposal = Proposal {
        view: 4,
        header: header.clone(),
        body,
        justification: Vec::new(),
    };
    // Code the proposal into its shards and round trip one shard message.
    let shards = code_proposal(&proposal).expect("code the proposal");
    let shard = shards[1].clone();
    let bytes = Message::CodedProposal(Box::new(shard.clone())).encode();
    match Message::decode(&bytes).expect("decodes") {
        Message::CodedProposal(decoded) => {
            assert_eq!(decoded.view, 4);
            assert_eq!(decoded.header, header);
            assert_eq!(decoded.commitment, shard.commitment);
            assert_eq!(decoded.shard, shard.shard);
            assert_eq!(decoded.proof, shard.proof);
            assert!(decoded.justification.is_empty());
            // The shard still authenticates against its commitment after the wire.
            assert!(decoded.commitment.verify_shard(&decoded.shard, &decoded.proof));
        }
        _ => panic!("decoded a different message"),
    }
}

#[test]
fn an_attestation_message_round_trips_and_still_verifies() {
    let attester = Attester::from_secret(1, &[1u8; 32], 2_000);
    let beacon = Beacon::genesis();
    let block = Block::new(1, [5u8; 32], Parent::Genesis);
    let attestation = attester.attest(CHAIN_ID, 1, 1, 0, block, &beacon);

    let bytes = Message::Attest(Box::new(attestation.clone())).encode();
    match Message::decode(&bytes).expect("decodes") {
        Message::Attest(decoded) => {
            assert_eq!(decoded.from, attestation.from);
            assert_eq!(decoded.height, attestation.height);
            assert_eq!(decoded.slot, attestation.slot);
            assert_eq!(decoded.view, attestation.view);
            assert_eq!(decoded.block, attestation.block);
            assert_eq!(decoded.membership.position, attestation.membership.position);
            assert_eq!(decoded.membership.preimage, attestation.membership.preimage);
            assert_eq!(decoded.membership.path, attestation.membership.path);
            assert_eq!(decoded.sig, attestation.sig);
            // The signature survives the wire and still verifies under the key.
            assert!(decoded.signature_verifies(CHAIN_ID, attester.attest_public_key()));
        }
        _ => panic!("decoded a different message"),
    }
}

#[test]
fn a_peer_list_message_round_trips() {
    let one = node_identity(1);
    let two = node_identity(2);
    let peers = vec![
        PeerEntry::from_identity(&one, "mem://1"),
        PeerEntry::from_identity(&two, "mem://2"),
    ];
    let bytes = Message::Peers(peers.clone()).encode();
    match Message::decode(&bytes).expect("decodes") {
        Message::Peers(decoded) => {
            assert_eq!(decoded.len(), 2);
            assert_eq!(decoded[0].peer_id(), one.peer_id());
            assert_eq!(decoded[0].address(), "mem://1");
            assert_eq!(decoded[1].peer_id(), two.peer_id());
        }
        _ => panic!("decoded a different message"),
    }
}

#[test]
fn a_status_and_a_block_request_round_trip() {
    match Message::decode(&Message::Status(7).encode()).expect("decodes") {
        Message::Status(height) => assert_eq!(height, 7),
        _ => panic!("decoded a different message"),
    }
    let bytes = Message::GetBlocks { from: 3, to: 9 }.encode();
    match Message::decode(&bytes).expect("decodes") {
        Message::GetBlocks { from, to } => {
            assert_eq!(from, 3);
            assert_eq!(to, 9);
        }
        _ => panic!("decoded a different message"),
    }
}

#[test]
fn a_certificate_carrying_block_round_trips_and_still_verifies() {
    // Build a real stage one certificate, saturating each member share so a valid
    // draw is entitled, exactly as the aggregation layer is exercised.
    let a = Attester::from_secret(1, &[1u8; 32], 100);
    let b = Attester::from_secret(2, &[2u8; 32], 100);
    let c = Attester::from_secret(3, &[3u8; 32], 100);
    let d = Attester::from_secret(4, &[4u8; 32], 100);
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters_with_budget(0, &[&a, &b, &c, &d], 4);
    let atts = vec![
        a.attest(CHAIN_ID, 1, 0, 0, block, &beacon),
        b.attest(CHAIN_ID, 1, 0, 0, block, &beacon),
        c.attest(CHAIN_ID, 1, 0, 0, block, &beacon),
    ];
    let cert = aggregate(CHAIN_ID, 1, 0, block, &commitment, &beacon, &atts, 3).expect("quorum");

    // The certificate slot round trips to the same certificate, and it still
    // verifies from public inputs alone, the check a syncing node runs.
    let cert_bytes = certificate_to_bytes(&cert);
    let decoded = certificate_from_bytes(&cert_bytes).expect("cert decodes");
    assert_eq!(decoded.digest(), cert.digest());
    assert!(decoded.verify(CHAIN_ID, &commitment, &beacon, 3).is_verified());

    // A finalized block carrying the certificate round trips through the sync
    // response, header, slot, and body preserved.
    let header = Header::new(
        1,
        [0u8; 32],
        [7u8; 32],
        empty_transaction_root(),
        empty_transaction_root(),
        [9u8; 32],
        "q1proposer".to_string(),
        1_700_000_000_150,
    );
    let chain_block = qtv_block::Block::new(header.clone(), cert_bytes.clone(), Vec::new());
    let bytes = Message::Blocks(vec![chain_block]).encode();
    match Message::decode(&bytes).expect("decodes") {
        Message::Blocks(blocks) => {
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0].header(), &header);
            assert_eq!(blocks[0].certificate(), cert_bytes.as_slice());
        }
        _ => panic!("decoded a different message"),
    }
}

#[test]
fn the_content_id_is_stable_and_separates_messages() {
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let one = transfer(&alice, &bob.address(), 1, 0, &params);
    let two = transfer(&alice, &bob.address(), 2, 1, &params);
    // The same message hashes to the same id, distinct messages to distinct ids.
    assert_eq!(Message::Tx(one.clone()).id(), Message::Tx(one.clone()).id());
    assert_ne!(Message::Tx(one).id(), Message::Tx(two).id());
}

#[test]
fn a_malformed_message_is_refused() {
    // An unknown tag, a truncated body, and empty input all fail to parse and are
    // dropped rather than admitted.
    assert!(Message::decode(&[]).is_err());
    assert!(Message::decode(&[9u8]).is_err());
    assert!(Message::decode(&[1u8, 0, 0]).is_err());
}
