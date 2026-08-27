// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A running node feeds the attestations it sees into an evidence pool and attributes an
//! equivocation from two conflicting attestations, ready for a block to carry.

mod support;

use qtv_attest::Attester;
use qtv_devnet::config::DEFAULT_SLOTS;
use qtv_devnet::DevNode;
use qtv_node::consensus::{genesis_beacon, Block, Parent};

use support::{config, unique_base, VALIDATOR_STAKE};

#[test]
fn a_running_node_attributes_an_equivocation_from_conflicting_attestations() {
    let base = unique_base("evidence-pool");
    let cfg = config(&base, &[true, true, true, true], vec![]);
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    // The offender is a registered validator the node holds in its roster. The pool
    // attributes an equivocation from any roster member's attestations, drawn or not.
    let offender_id = 2u64;

    // Reproduce the offender's attester from its fixture secret and sign two conflicting
    // attestations at the node's height and slot.
    let secret = qtv_node::keys::fixture_secret(offender_id);
    let offender =
        Attester::from_secret_with_slots(offender_id, &secret, VALIDATOR_STAKE, DEFAULT_SLOTS);
    // Sign under the chain the node runs on, the same id the on chain verifier rebuilds the
    // attestation preimage with, so a genuine double vote authenticates.
    let chain_id = cfg.fee_params.chain_id;
    let beacon = genesis_beacon();
    let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
    let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
    let att_a = offender.attest(chain_id, 1, 1, 0, [0u8; 32], block_a, &beacon);
    let att_b = offender.attest(chain_id, 1, 1, 0, [0u8; 32], block_b, &beacon);

    node.on_attestation(att_a);
    let evidence = node.pending_evidence();
    assert!(evidence.is_empty(), "one attestation is not yet an equivocation");

    node.on_attestation(att_b);
    let evidence = node.pending_evidence();
    assert_eq!(evidence.len(), 1, "the second conflicting attestation is attributed");
    assert!(
        evidence[0].attributes(chain_id, offender.attest_public_key()),
        "the attributed evidence authenticates to the offender's key"
    );

    // Drained once, the evidence is not re emitted.
    assert!(node.pending_evidence().is_empty());
}

#[test]
fn a_running_node_does_not_attribute_an_honest_cross_view_re_vote() {
    let base = unique_base("evidence-cross-view");
    let cfg = config(&base, &[true, true, true, true], vec![]);
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let offender_id = 2u64;
    let secret = qtv_node::keys::fixture_secret(offender_id);
    let offender =
        Attester::from_secret_with_slots(offender_id, &secret, VALIDATOR_STAKE, DEFAULT_SLOTS);
    let chain_id = cfg.fee_params.chain_id;
    let beacon = genesis_beacon();
    let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
    let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
    let att_a = offender.attest(chain_id, 1, 1, 0, [0u8; 32], block_a, &beacon);
    let att_b = offender.attest(chain_id, 1, 1, 1, [0u8; 32], block_b, &beacon);

    node.on_attestation(att_a);
    assert!(node.pending_evidence().is_empty());

    node.on_attestation(att_b);
    assert!(
        node.pending_evidence().is_empty(),
        "a conflicting block signed in a higher view is a justified vote change, not a double vote"
    );
}

#[test]
fn both_halves_of_a_same_view_double_sign_relay_and_a_duplicate_does_not() {
    let base = unique_base("evidence-relay");
    let cfg = config(&base, &[true, true, true, true], vec![]);
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let offender_id = 2u64;
    let secret = qtv_node::keys::fixture_secret(offender_id);
    let offender =
        Attester::from_secret_with_slots(offender_id, &secret, VALIDATOR_STAKE, DEFAULT_SLOTS);
    let chain_id = cfg.fee_params.chain_id;
    let beacon = genesis_beacon();
    let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
    let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
    let att_a = offender.attest(chain_id, 1, 1, 0, [0u8; 32], block_a, &beacon);
    let att_b = offender.attest(chain_id, 1, 1, 0, [0u8; 32], block_b, &beacon);

    assert!(node.on_attestation(att_a.clone()));
    assert!(!node.on_attestation(att_a));
    assert!(node.on_attestation(att_b));
    assert_eq!(node.pending_evidence().len(), 1);
}

#[test]
fn a_third_block_at_one_view_slot_is_not_relayed() {
    let base = unique_base("evidence-relay-cap");
    let cfg = config(&base, &[true, true, true, true], vec![]);
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let secret = qtv_node::keys::fixture_secret(2);
    let offender = Attester::from_secret_with_slots(2, &secret, VALIDATOR_STAKE, DEFAULT_SLOTS);
    let chain_id = cfg.fee_params.chain_id;
    let beacon = genesis_beacon();
    let a = offender.attest(chain_id, 1, 1, 0, [0u8; 32], Block::new(1, [1u8; 32], Parent::Genesis), &beacon);
    let b = offender.attest(chain_id, 1, 1, 0, [0u8; 32], Block::new(1, [2u8; 32], Parent::Genesis), &beacon);
    let c = offender.attest(chain_id, 1, 1, 0, [0u8; 32], Block::new(1, [3u8; 32], Parent::Genesis), &beacon);

    assert!(node.on_attestation(a));
    assert!(node.on_attestation(b));
    assert!(!node.on_attestation(c));
}

#[test]
fn flooding_other_view_slots_does_not_suppress_an_equivocation_relay() {
    let base = unique_base("evidence-relay-isolation");
    let cfg = config(&base, &[true, true, true, true], vec![]);
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");
    let chain_id = cfg.fee_params.chain_id;
    let beacon = genesis_beacon();

    let flood_secret = qtv_node::keys::fixture_secret(3);
    let flooder = Attester::from_secret_with_slots(3, &flood_secret, VALIDATOR_STAKE, DEFAULT_SLOTS);
    for v in 0..250u64 {
        let blk = Block::new(1, [(v % 251) as u8 + 4; 32], Parent::Genesis);
        node.on_attestation(flooder.attest(chain_id, 1, 1, v, [0u8; 32], blk, &beacon));
    }

    let secret = qtv_node::keys::fixture_secret(2);
    let offender = Attester::from_secret_with_slots(2, &secret, VALIDATOR_STAKE, DEFAULT_SLOTS);
    let a = offender.attest(chain_id, 1, 1, 0, [0u8; 32], Block::new(1, [1u8; 32], Parent::Genesis), &beacon);
    let b = offender.attest(chain_id, 1, 1, 0, [0u8; 32], Block::new(1, [2u8; 32], Parent::Genesis), &beacon);
    assert!(node.on_attestation(a));
    assert!(node.on_attestation(b));
    assert_eq!(node.pending_evidence().len(), 1);
}
