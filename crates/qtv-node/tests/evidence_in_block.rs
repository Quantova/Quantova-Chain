// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Equivocation evidence carried in a block slashes the offender as a deterministic in
//! block state transition, verified against the attestation key held in state, so every
//! node that executes the block reaches the same slash.

use qtv_account::{derive, Account as KeyAccount};
use qtv_attest::{Attester, Beacon, Block, Parent};
use qtv_node::evidence::Equivocation;
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{evidence_address, registration_address, Account, Ledger};
use qtv_node::node::execute_ordered;
use qtv_node::parallel::execute_parallel;
use qtv_tx::{sign, Body, Call, Wrapper};

const NATIVE_UNIT: u64 = 1_000_000;

// The evidence executes under the local chain id, so the offender's attestations are signed
// under the same id the on chain verifier rebuilds the preimage with. A mismatch would mean a
// genuine double vote failed to authenticate on chain, which is exactly what the chain id
// binding is meant to prevent, so the fixture signs under the chain it is executed on.
const CHAIN_ID: u64 = qtv_tx::LOCAL_CHAIN_ID;

fn reporter() -> KeyAccount {
    derive(&[3u8; 32], 0)
}

fn offender_secret() -> [u8; 32] {
    [9u8; 32]
}

fn innocent_secret() -> [u8; 32] {
    [10u8; 32]
}

/// A real equivocation, the two conflicting attestations the offender secret signs at one
/// height for two different blocks.
fn equivocation(offender_address: &str) -> Equivocation {
    let attester = Attester::from_secret(1, &offender_secret(), 2_000);
    let beacon = Beacon::genesis();
    let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
    let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
    let a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
    let b = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_b, &beacon);
    Equivocation {
        offender: offender_address.to_string(),
        height: 1,
        view_a: 0,
        view_b: 0,
        slot_a: 1,
        slot_b: 1,
        committee_a: [0u8; 32],
        committee_b: [0u8; 32],
        block_a: block_a.to_bytes(),
        sig_a: a.sig.to_vec(),
        block_b: block_b.to_bytes(),
        sig_b: b.sig.to_vec(),
    }
}

/// A cross view re vote by the offender secret, block A signed in view 0 and block B signed
/// in view 1 at the same height. The signatures are genuine but the views differ, so the
/// evidence is a justified vote change rather than a double vote.
fn cross_view_re_vote(offender_address: &str) -> Equivocation {
    let attester = Attester::from_secret(1, &offender_secret(), 2_000);
    let beacon = Beacon::genesis();
    let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
    let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
    let a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
    let b = attester.attest(CHAIN_ID, 1, 1, 1, [0u8; 32], block_b, &beacon);
    Equivocation {
        offender: offender_address.to_string(),
        height: 1,
        view_a: 0,
        view_b: 1,
        slot_a: 1,
        slot_b: 1,
        committee_a: [0u8; 32],
        committee_b: [0u8; 32],
        block_a: block_a.to_bytes(),
        sig_a: a.sig.to_vec(),
        block_b: block_b.to_bytes(),
        sig_b: b.sig.to_vec(),
    }
}

fn evidence_tx(evidence: &Equivocation, fee: &FeeParams) -> Wrapper {
    let call = Call::new(evidence_address(), evidence.encode());
    let body = Body::new(
        reporter().address(),
        0,
        TRANSFER_METER,
        u128::from(fee.transfer_fee()),
        call,
    );
    sign(&reporter(), &body)
}

fn seeded_ledger(offender_address: &str, offender_pk: &[u8]) -> Ledger {
    let mut ledger = Ledger::new();
    ledger.seed_supply(1_000_000_000);
    let r = reporter();
    ledger.set_account(
        &r.address(),
        &Account::funded(1_000_000, r.scheme(), r.public_key().to_vec()),
    );
    ledger.seed_validator_bond(offender_address, 2_000 * NATIVE_UNIT);
    ledger.set_validator_attest_key(offender_address, offender_pk);
    ledger
}

#[test]
fn a_block_of_valid_evidence_slashes_the_offender_identically_on_every_node() {
    let fee = FeeParams::devnet();
    let offender = qtv_node::keys::validator_address(&offender_secret());
    let offender_pk = Attester::from_secret(1, &offender_secret(), 2_000)
        .attest_public_key()
        .to_vec();
    let tx = evidence_tx(&equivocation(&offender), &fee);

    // Two independent nodes each execute the same evidence block.
    let mut node_one = seeded_ledger(&offender, &offender_pk);
    let mut node_two = seeded_ledger(&offender, &offender_pk);
    assert!(!node_one.is_validator_banned(&offender));

    assert_eq!(execute_ordered(&mut node_one, &[tx.clone()], &fee, 0).len(), 1);
    assert_eq!(execute_ordered(&mut node_two, &[tx.clone()], &fee, 0).len(), 1);

    assert!(node_one.is_validator_banned(&offender), "node one slashed the offender");
    assert!(node_two.is_validator_banned(&offender), "node two slashed the offender");
    assert_eq!(node_one.staked_weight(&offender), 0, "the offender's stake is slashed");
    assert_eq!(
        node_one.q_root(),
        node_two.q_root(),
        "both nodes reach the identical post slash state from the block alone"
    );
}

#[test]
fn forged_evidence_naming_an_innocent_validator_slashes_no_one() {
    let fee = FeeParams::devnet();
    let offender = qtv_node::keys::validator_address(&offender_secret());
    let innocent = qtv_node::keys::validator_address(&innocent_secret());
    let innocent_pk = Attester::from_secret(2, &innocent_secret(), 2_000)
        .attest_public_key()
        .to_vec();

    // The offender's genuine conflicting signatures, but the evidence names the innocent
    // validator, so it must authenticate against the innocent key and fail.
    let mut forged = equivocation(&offender);
    forged.offender = innocent.clone();
    let tx = evidence_tx(&forged, &fee);

    let mut ledger = Ledger::new();
    ledger.seed_supply(1_000_000_000);
    let r = reporter();
    ledger.set_account(
        &r.address(),
        &Account::funded(1_000_000, r.scheme(), r.public_key().to_vec()),
    );
    ledger.seed_validator_bond(&innocent, 2_000 * NATIVE_UNIT);
    ledger.set_validator_attest_key(&innocent, &innocent_pk);

    execute_ordered(&mut ledger, &[tx], &fee, 0);
    assert!(
        !ledger.is_validator_banned(&innocent),
        "unauthenticated evidence never slashes the named validator"
    );
    assert_eq!(
        ledger.staked_weight(&innocent),
        2_000,
        "the innocent validator keeps its whole stake"
    );
}

#[test]
fn an_evidence_and_registration_block_matches_across_the_parallel_and_ordered_paths() {
    let fee = FeeParams::devnet();
    let offender = qtv_node::keys::validator_address(&offender_secret());
    let offender_pk = Attester::from_secret(1, &offender_secret(), 2_000)
        .attest_public_key()
        .to_vec();

    let registrar = derive(&[7u8; 32], 0);
    let payer = derive(&[8u8; 32], 0);
    let payee = derive(&[11u8; 32], 0);

    let mut ledger = seeded_ledger(&offender, &offender_pk);
    for who in [&registrar, &payer, &payee] {
        ledger.set_account(
            &who.address(),
            &Account::funded(1_000_000, who.scheme(), who.public_key().to_vec()),
        );
    }

    let evidence = evidence_tx(&equivocation(&offender), &fee);
    let registration = {
        let call = Call::new(registration_address(), vec![1, 2, 3, 4]);
        let body = Body::new(
            registrar.address(),
            0,
            TRANSFER_METER,
            u128::from(fee.transfer_fee()),
            call,
        );
        sign(&registrar, &body)
    };
    let payment = {
        let call = transfer_call(&payee.address(), 1_000);
        let body = Body::new(
            payer.address(),
            0,
            TRANSFER_METER,
            u128::from(fee.transfer_fee()),
            call,
        );
        sign(&payer, &body)
    };
    let block = vec![evidence, registration, payment];

    let mut ordered = ledger.clone();
    let ordered_included = execute_ordered(&mut ordered, &block, &fee, 0);

    let mut parallel = ledger.clone();
    let parallel_included = execute_parallel(&mut parallel, &block, &fee, 8, 0);

    assert!(
        ordered.is_validator_banned(&offender),
        "the ordered path slashes the offender named in the evidence"
    );
    assert!(
        parallel.is_validator_banned(&offender),
        "the parallel path degrades to ordered and applies the same slash"
    );
    assert_eq!(
        ordered.q_root(),
        parallel.q_root(),
        "an evidence and registration block degrades so both paths reach the identical state root"
    );
    assert_eq!(
        ordered_included.len(),
        parallel_included.len(),
        "both paths carry the same transactions in the block"
    );
}

#[test]
fn a_cross_view_re_vote_carried_in_a_block_slashes_no_one() {
    let fee = FeeParams::devnet();
    let offender = qtv_node::keys::validator_address(&offender_secret());
    let offender_pk = Attester::from_secret(1, &offender_secret(), 2_000)
        .attest_public_key()
        .to_vec();
    let tx = evidence_tx(&cross_view_re_vote(&offender), &fee);

    let mut ledger = seeded_ledger(&offender, &offender_pk);
    assert!(!ledger.is_validator_banned(&offender));

    execute_ordered(&mut ledger, &[tx], &fee, 0);

    assert!(
        !ledger.is_validator_banned(&offender),
        "an honest cross view re vote is never slashed as a double vote"
    );
    assert_eq!(
        ledger.staked_weight(&offender),
        2_000,
        "the validator keeps its whole stake across a view change"
    );
}
