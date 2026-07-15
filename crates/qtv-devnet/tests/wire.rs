//! The three gossip messages round trip through the canonical codec, and a
//! message that does not parse is refused at the edge.

mod support;

use qtv_attest::{Attester, Beacon, Block, Parent};
use qtv_block::{empty_transaction_root, Header};
use qtv_node::fee::FeeParams;

use qtv_devnet::discovery::PeerEntry;
use qtv_devnet::node::net_identity;
use qtv_devnet::wire::{Message, Proposal};

use support::{transfer, user};

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
fn an_attestation_message_round_trips_and_still_verifies() {
    let attester = Attester::new(1, 2_000);
    let beacon = Beacon::genesis();
    let block = Block::new(1, 5, Parent::Genesis);
    let attestation = attester.attest(1, 1, block, &beacon);

    let bytes = Message::Attest(Box::new(attestation.clone())).encode();
    match Message::decode(&bytes).expect("decodes") {
        Message::Attest(decoded) => {
            assert_eq!(decoded.from, attestation.from);
            assert_eq!(decoded.height, attestation.height);
            assert_eq!(decoded.slot, attestation.slot);
            assert_eq!(decoded.block, attestation.block);
            assert_eq!(decoded.membership.output, attestation.membership.output);
            assert_eq!(decoded.membership.proof, attestation.membership.proof);
            assert_eq!(decoded.sig, attestation.sig);
            // The signature survives the wire and still verifies under the key.
            assert!(decoded.signature_verifies(attester.attest_public_key()));
        }
        _ => panic!("decoded a different message"),
    }
}

#[test]
fn a_peer_list_message_round_trips() {
    let one = net_identity(1);
    let two = net_identity(2);
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
