// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
    signature[0] ^= 255;
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
fn the_chain_id_is_bound_into_the_signature() {
    let account = derive(&master(), 0);
    let target = derive(&master(), 1);
    let call = Call::new(target.address(), vec![1, 2, 3]);
    let mainnet = Body::with_context(
        account.address(),
        7,
        21_000,
        1_000_000,
        call.clone(),
        0,
        qtv_tx::MAINNET_CHAIN_ID,
    );
    let wrapper = sign(&account, &mainnet);
    assert!(verify(&wrapper, account.public_key()));

    let testnet = Body::with_context(
        account.address(),
        7,
        21_000,
        1_000_000,
        call,
        0,
        qtv_tx::TESTNET_CHAIN_ID,
    );
    let replayed = Wrapper::new(testnet, wrapper.scheme(), wrapper.signature().to_vec());
    assert!(
        !verify(&replayed, account.public_key()),
        "a mainnet signature does not authenticate the same body on another network"
    );
}

#[test]
fn a_carried_asset_is_bound_into_the_signature() {
    let account = derive(&master(), 0);
    let target = derive(&master(), 1);
    let issuer = derive(&master(), 2);
    let mut issuer32 = [0u8; 32];
    issuer32.copy_from_slice(&qtv_idfmt::parse_address(&issuer.address()).unwrap());
    let call = Call::new(target.address(), vec![1, 2, 3, 4]);
    let body = Body::with_context(
        account.address(),
        7,
        21_000,
        1_000_000,
        call.clone(),
        500,
        qtv_tx::LOCAL_CHAIN_ID,
    )
    .carrying(issuer32);
    let wrapper = sign(&account, &body);
    assert!(verify(&wrapper, account.public_key()));
    assert_eq!(wrapper.body().in_asset(), Some(issuer32));

    let plain = Body::with_context(
        account.address(),
        7,
        21_000,
        1_000_000,
        call,
        500,
        qtv_tx::LOCAL_CHAIN_ID,
    );
    let forged = Wrapper::new(plain, wrapper.scheme(), wrapper.signature().to_vec());
    assert!(
        !verify(&forged, account.public_key()),
        "dropping the carried asset does not authenticate the same body"
    );
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
    assert!(id.starts_with("QTX1"));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The seed the cross language conformance vectors share.
fn shared_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = i as u8;
    }
    seed
}

#[test]
fn the_body_binds_the_decoded_payload_not_the_rendered_string() {
    let body = sample_body();
    let encoded = qtv_codec::to_bytes(&body);
    let payload = qtv_idfmt::parse_address(body.sender()).unwrap();
    assert_eq!(payload.len(), 32, "an address payload is thirty two bytes");
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    prefix.extend_from_slice(&payload);
    assert!(
        encoded.starts_with(&prefix),
        "the leading field is the raw payload"
    );
    assert!(
        !encoded.starts_with(body.sender().as_bytes()),
        "the leading field is not the rendered string"
    );
}

#[test]
fn address_case_can_never_change_the_signature() {
    let account = derive(&master(), 0);
    let target = derive(&master(), 1);
    let upper = target.address();
    let lower = upper.to_ascii_lowercase();
    assert_ne!(upper, lower, "the two casings differ");

    let call_upper = Call::new(upper.clone(), vec![4, 2]);
    let call_lower = Call::new(lower.clone(), vec![4, 2]);
    let sender_upper = account.address();
    let sender_lower = sender_upper.to_ascii_lowercase();

    let body_upper = Body::new(sender_upper, 9, 21_000, 1_000_000, call_upper);
    let body_lower = Body::new(sender_lower, 9, 21_000, 1_000_000, call_lower);

    assert_eq!(
        qtv_codec::to_bytes(&body_upper),
        qtv_codec::to_bytes(&body_lower),
        "casing the sender or the target does not move the signed bytes"
    );

    let signed_upper = sign(&account, &body_upper);
    let signed_lower = sign(&account, &body_lower);
    assert_eq!(signed_upper.signature(), signed_lower.signature());
    assert_eq!(signed_upper.id(), signed_lower.id());
}

#[test]
fn a_raw_byte_signed_transaction_verifies() {
    let account = derive(&master(), 0);
    let target = derive(&master(), 1);
    let call = Call::new(target.address().to_ascii_lowercase(), vec![1, 2, 3]);
    let body = Body::new(account.address().to_ascii_lowercase(), 7, 21_000, 1_000_000, call);
    let wrapper = sign(&account, &body);
    assert!(
        verify(&wrapper, account.public_key()),
        "the verifier recomputes the digest over the decoded payload"
    );
}

#[test]
fn the_chain_id_follows_the_display_string_hash() {
    assert_eq!(
        qtv_tx::chain_id_from_name(qtv_tx::LOCAL_CHAIN_NAME),
        qtv_tx::LOCAL_CHAIN_ID
    );
    assert_eq!(
        qtv_tx::chain_id_from_name(qtv_tx::TESTNET_CHAIN_NAME),
        qtv_tx::TESTNET_CHAIN_ID
    );
    assert_eq!(
        qtv_tx::chain_id_from_name(qtv_tx::MAINNET_CHAIN_NAME),
        qtv_tx::MAINNET_CHAIN_ID
    );
    assert_eq!(qtv_tx::LOCAL_CHAIN_NAME, "Q-dev-net-1");
    assert_eq!(qtv_tx::TESTNET_CHAIN_NAME, "Q-test-net-1");
    assert_eq!(qtv_tx::MAINNET_CHAIN_NAME, "Q-main-net-1");
}

#[test]
fn the_body_reproduces_the_qcore_js_transfer_vector() {
    let seed = shared_seed();
    let sender = derive(&seed, 7);
    let target = derive(&seed, 8);
    assert_eq!(
        sender.address(),
        "Q133C9CYVYZNQ7X25H0JJWUDHU8U5G3DN7CQC4J64LFTRSUH66ZNCQWDRA8R"
    );
    assert_eq!(
        target.address(),
        "Q1H2PLGDKK73HPS8PM4EQT5NL7MV8K9ENUMCDQC4V0GKDEJC3FTYAS70UVL8"
    );
    let call = Call::new(target.address(), vec![0xde, 0xad, 0xbe, 0xef]);
    let body = Body::with_context(
        sender.address(),
        3,
        21_000,
        1_000_000,
        call,
        0,
        qtv_tx::LOCAL_CHAIN_ID,
    );
    let want = "20000000000000008c705c118414c1e32a977ca4ee36fc3f2888b67ec031596abf4ac70e5f5a14f00300000000000000085200000000000040420f000000000000000000000000002000000000000000ba83f436d6f46e181c3bae40ba4ffedb0f62e67cde1a0c558f459b996229593b0400000000000000deadbeef000000000000000098ba0ce08f27d0be0000000000000000";
    assert_eq!(hex(&qtv_codec::to_bytes(&body)), want);
}

#[test]
fn the_signed_transaction_reproduces_the_qcore_js_payable_vector() {
    let seed = shared_seed();
    let sender = derive(&seed, 7);
    let target = derive(&seed, 8);
    let call = Call::new(target.address(), vec![0xde, 0xad, 0xbe, 0xef]);
    let body = Body::with_context(
        sender.address(),
        3,
        21_000,
        1_000_000,
        call,
        250_000,
        qtv_tx::TESTNET_CHAIN_ID,
    );
    let wrapper = sign(&sender, &body);
    assert!(verify(&wrapper, sender.public_key()));
    assert_eq!(
        wrapper.id(),
        "QTX1TLFZ7EQNKADUQ6LSFTQUFU7E7ZSQQCX6RY46VNQ8T07DUZGANX7QK0Z0MD"
    );
}
