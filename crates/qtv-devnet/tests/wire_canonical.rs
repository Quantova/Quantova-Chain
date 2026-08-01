// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_attest::{Attester, Beacon, Block, Parent};
use qtv_devnet::wire::{gossip_id, Message};

const CHAIN_ID: u64 = 1;

#[test]
fn a_genesis_parent_with_a_nonzero_value_is_refused() {
    let attester = Attester::from_secret(1, &[1u8; 32], 2_000);
    let beacon = Beacon::genesis();
    let block = Block::new(1, [5u8; 32], Parent::Genesis);
    let attestation = attester.attest(CHAIN_ID, 1, 1, 0, block, &beacon);
    let bytes = Message::Attest(Box::new(attestation)).encode();

    // The block sits at: tag(1) from(8) height(8) slot(8) view(8) then
    // block.height(8) block.val(32) parent_tag(1), so the genesis parent value that
    // the encoder wrote as zeros starts here.
    let pv_start = 1 + 8 + 8 + 8 + 8 + 8 + 32 + 1;
    assert_eq!(bytes[pv_start - 1], 0, "the encoder wrote the genesis parent tag");

    let mut mutated = bytes.clone();
    for slot in mutated[pv_start..pv_start + 32].iter_mut() {
        *slot ^= 0xFF;
    }
    assert_ne!(mutated, bytes, "the mutation changed the raw bytes");
    assert_eq!(
        gossip_id(&bytes),
        gossip_id(&bytes),
        "the canonical frame still hashes to itself"
    );

    // The canonical frame decodes; the malleated copy no longer decodes, so a single
    // valid message can no longer be re-spun into unbounded distinct gossip frames.
    assert!(Message::decode(&bytes).is_ok(), "the canonical frame decodes");
    assert!(
        Message::decode(&mutated).is_err(),
        "a genesis parent carrying a nonzero value is refused"
    );
}

#[test]
fn message_decode_never_panics_on_arbitrary_bytes() {
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..100_000 {
        let len = (next() % 512) as usize;
        let mut bytes = vec![0u8; len];
        for b in bytes.iter_mut() {
            *b = (next() & 0xFF) as u8;
        }
        if !bytes.is_empty() {
            bytes[0] = (next() % 16) as u8;
        }
        let _ = Message::decode(&bytes);
    }
}

#[test]
fn well_formed_frames_round_trip_to_themselves() {
    use qtv_node::fee::FeeParams;
    use support::{transfer, user};
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let tx = transfer(&alice, &bob.address(), 700, 0, &params);
    let frames = [
        Message::Tx(tx).encode(),
        Message::Status(42).encode(),
        Message::GetBlocks { from: 1, to: 9 }.encode(),
    ];
    for frame in &frames {
        let decoded = Message::decode(frame).expect("the frame decodes");
        assert_eq!(&decoded.encode(), frame, "the frame re-encodes to itself");
    }
}
