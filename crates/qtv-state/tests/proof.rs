// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Coverage for the trie get, the deterministic root, and the proofs of
//! presence and absence.

use qtv_codec::{from_bytes, to_bytes};
use qtv_state::{verify, Key, Proof, Trie};

/// A deterministic thirty two byte key seeded by a single byte.
fn key(seed: u8) -> Key {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(seed).wrapping_add(seed);
    }
    out
}

#[test]
fn insert_then_get_returns_the_value() {
    let mut trie = Trie::new();
    trie.insert(key(1), b"first".to_vec());
    trie.insert(key(2), b"second".to_vec());
    assert_eq!(trie.get(&key(1)), Some(&b"first"[..]));
    assert_eq!(trie.get(&key(2)), Some(&b"second"[..]));
    assert_eq!(trie.get(&key(3)), None);
}

#[test]
fn root_does_not_depend_on_insertion_order() {
    let mut forward = Trie::new();
    forward.insert(key(1), b"a".to_vec());
    forward.insert(key(2), b"b".to_vec());
    forward.insert(key(3), b"c".to_vec());

    let mut backward = Trie::new();
    backward.insert(key(3), b"c".to_vec());
    backward.insert(key(1), b"a".to_vec());
    backward.insert(key(2), b"b".to_vec());

    assert_eq!(forward.root(), backward.root());
    assert_eq!(forward.root(), forward.root());
}

#[test]
fn inclusion_proof_verifies_against_the_root() {
    let mut trie = Trie::new();
    trie.insert(key(10), b"ten".to_vec());
    trie.insert(key(20), b"twenty".to_vec());
    let root = trie.root();
    let proof = trie.prove(&key(10));
    assert!(proof.is_present());
    assert_eq!(proof.value(), Some(&b"ten"[..]));
    assert!(verify(&key(10), &proof, &root));
}

#[test]
fn exclusion_proof_verifies_against_the_root() {
    let mut trie = Trie::new();
    trie.insert(key(10), b"ten".to_vec());
    trie.insert(key(20), b"twenty".to_vec());
    let root = trie.root();
    let proof = trie.prove(&key(99));
    assert!(!proof.is_present());
    assert_eq!(proof.value(), None);
    assert!(verify(&key(99), &proof, &root));
}

#[test]
fn exclusion_proof_verifies_on_an_empty_trie() {
    let trie = Trie::new();
    let root = trie.root();
    let proof = trie.prove(&key(7));
    assert!(!proof.is_present());
    assert!(verify(&key(7), &proof, &root));
}

#[test]
fn a_tampered_sibling_is_rejected() {
    let mut trie = Trie::new();
    trie.insert(key(10), b"ten".to_vec());
    trie.insert(key(20), b"twenty".to_vec());
    let root = trie.root();
    let proof = trie.prove(&key(10));

    let mut siblings = proof.siblings().to_vec();
    let last = siblings.len() - 1;
    siblings[last][0] ^= 1;
    let tampered = Proof::new(proof.value().map(|value| value.to_vec()), siblings);

    assert!(!verify(&key(10), &tampered, &root));
}

#[test]
fn a_tampered_value_is_rejected() {
    let mut trie = Trie::new();
    trie.insert(key(10), b"ten".to_vec());
    trie.insert(key(20), b"twenty".to_vec());
    let root = trie.root();
    let proof = trie.prove(&key(10));

    let tampered = Proof::new(Some(b"eleven".to_vec()), proof.siblings().to_vec());
    assert!(!verify(&key(10), &tampered, &root));
}

#[test]
fn claiming_absence_for_a_present_key_is_rejected() {
    let mut trie = Trie::new();
    trie.insert(key(10), b"ten".to_vec());
    let root = trie.root();
    let proof = trie.prove(&key(10));

    let tampered = Proof::new(None, proof.siblings().to_vec());
    assert!(!verify(&key(10), &tampered, &root));
}

#[test]
fn changing_a_value_changes_the_root() {
    let mut before = Trie::new();
    before.insert(key(10), b"ten".to_vec());
    before.insert(key(20), b"twenty".to_vec());
    let root_before = before.root();

    let mut after = Trie::new();
    after.insert(key(10), b"ten".to_vec());
    after.insert(key(20), b"changed".to_vec());
    let root_after = after.root();

    assert_ne!(root_before, root_after);
}

#[test]
fn proof_round_trips_through_the_codec() {
    let mut trie = Trie::new();
    trie.insert(key(10), b"ten".to_vec());
    trie.insert(key(20), b"twenty".to_vec());
    let root = trie.root();
    let proof = trie.prove(&key(10));

    let bytes = to_bytes(&proof);
    let back = from_bytes::<Proof>(&bytes).unwrap();
    assert_eq!(proof, back);
    assert!(verify(&key(10), &back, &root));
}
