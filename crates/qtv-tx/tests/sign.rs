//! Coverage for transaction signing, verification, and the transaction id.

use qtv_account::{derive, derive_with_scheme};
use qtv_tx::{sign, verify, Body, Call, Wrapper, SCHEME_FALCON, SCHEME_HASH, SCHEME_LATTICE};

/// A deterministic master seed pattern.
fn master() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    seed
}

/// A sample body whose sender is index zero and whose target is index one.
fn sample_body() -> Body {
    let seed = master();
    let sender = derive(&seed, 0);
    let target = derive(&seed, 1);
    let call = Call::new(target.address(), vec![1, 2, 3, 4, 5]);
    Body::new(sender.address(), 7, 21_000, 1_000_000, call)
}

/// Rebuild a body while replacing a single field so the digest moves.
fn rebuild(body: &Body, nonce: u64, args: Vec<u8>) -> Body {
    let call = Call::new(body.call().target().to_string(), args);
    Body::new(
        body.sender().to_string(),
        nonce,
        body.meter_limit(),
        body.fee(),
        call,
    )
}

#[test]
fn signed_transaction_verifies() {
    let account = derive(&master(), 0);
    let wrapper = sign(&account, &sample_body());
    assert!(verify(&wrapper, account.public_key()));
    assert_eq!(wrapper.scheme(), SCHEME_LATTICE);
}

#[test]
fn tampered_body_is_rejected() {
    let account = derive(&master(), 0);
    let body = sample_body();
    let wrapper = sign(&account, &body);
    let tampered = rebuild(&body, body.nonce(), vec![9, 9, 9]);
    let forged = Wrapper::new(tampered, wrapper.scheme(), wrapper.signature().to_vec());
    assert!(!verify(&forged, account.public_key()));
}

#[test]
fn tampered_nonce_is_rejected() {
    let account = derive(&master(), 0);
    let body = sample_body();
    let wrapper = sign(&account, &body);
    let tampered = rebuild(&body, body.nonce() + 1, body.call().args().to_vec());
    let forged = Wrapper::new(tampered, wrapper.scheme(), wrapper.signature().to_vec());
    assert!(!verify(&forged, account.public_key()));
}

#[test]
fn tampered_signature_is_rejected() {
    let account = derive(&master(), 0);
    let wrapper = sign(&account, &sample_body());
    let mut signature = wrapper.signature().to_vec();
    signature[0] ^= 0xFF;
    let forged = Wrapper::new(wrapper.body().clone(), wrapper.scheme(), signature);
    assert!(!verify(&forged, account.public_key()));
}

#[test]
fn a_different_public_key_is_rejected() {
    let seed = master();
    let account = derive(&seed, 0);
    let other = derive(&seed, 1);
    let wrapper = sign(&account, &sample_body());
    assert!(!verify(&wrapper, other.public_key()));
}

#[test]
fn an_unknown_scheme_is_rejected() {
    let account = derive(&master(), 0);
    let wrapper = sign(&account, &sample_body());
    let forged = Wrapper::new(
        wrapper.body().clone(),
        SCHEME_FALCON + 1,
        wrapper.signature().to_vec(),
    );
    assert!(!verify(&forged, account.public_key()));
}

// Hash based signing is slow, so this keeps to one derive, one sign, and two
// verifies. Run the suite in release if the debug run drags.
#[test]
fn hash_scheme_signs_and_verifies() {
    let seed = master();
    let account = derive_with_scheme(&seed, SCHEME_HASH, 0);
    let target = derive_with_scheme(&seed, SCHEME_HASH, 1);
    let call = Call::new(target.address(), vec![1, 2, 3, 4, 5]);
    let body = Body::new(account.address(), 7, 21_000, 1_000_000, call);
    let wrapper = sign(&account, &body);
    assert_eq!(wrapper.scheme(), SCHEME_HASH);
    assert!(verify(&wrapper, account.public_key()));
    assert!(!verify(&wrapper, target.public_key()));
}

#[test]
fn body_encoding_is_byte_identical() {
    let body = sample_body();
    let first = qtv_codec::to_bytes(&body);
    let second = qtv_codec::to_bytes(&body);
    assert_eq!(first, second);
}

#[test]
fn transaction_id_round_trips_through_the_format() {
    let account = derive(&master(), 0);
    let wrapper = sign(&account, &sample_body());
    let id = wrapper.id();
    let payload = qtv_idfmt::parse_tx(&id).unwrap();
    let again = qtv_idfmt::render_tx(&payload).unwrap();
    assert_eq!(id, again);
    assert!(id.starts_with("qtx1"));
}
