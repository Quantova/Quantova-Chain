//! Coverage for the header round trip, the transaction root, and the block id.

use qtv_block::{empty_transaction_root, header_from_bytes, transaction_root, Block, Header};
use qtv_codec::to_bytes;
use qtv_crypto::ml_dsa;
use qtv_tx::{Body, Call, Wrapper, SCHEME_LATTICE};

/// A deterministic thirty two byte pattern seeded by a single byte.
fn pattern(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(seed).wrapping_add(seed);
    }
    out
}

/// A module lattice signature over a fixed message. The transaction root hashes
/// the wrapper encodings and never verifies the signature, so one signature is
/// enough to assemble the sample wrappers.
fn sample_signature() -> Vec<u8> {
    let (_public, secret) = ml_dsa::keygen(&[7u8; 32]);
    ml_dsa::sign(&secret, &[0u8; 32], &[], &[0u8; 32])
        .expect("an empty context stays within the length bound")
        .to_vec()
}

/// A wrapper whose body carries the given nonce.
fn wrapper_with_nonce(nonce: u64) -> Wrapper {
    let call = Call::new("q1target".to_string(), vec![1, 2, 3]);
    let body = Body::new("q1sender".to_string(), nonce, 21_000, 1_000_000, call);
    Wrapper::new(body, SCHEME_LATTICE, sample_signature())
}

/// A sample header whose transaction root covers the given body.
fn sample_header(body: &[Wrapper]) -> Header {
    Header::new(
        42,
        pattern(3),
        pattern(5),
        transaction_root(body),
        pattern(7),
        pattern(11),
        "q1proposer".to_string(),
        1_700_000_000,
    )
}

#[test]
fn header_round_trips_through_the_codec() {
    let header = sample_header(&[wrapper_with_nonce(1)]);
    let bytes = to_bytes(&header);
    let back = header_from_bytes(&bytes).unwrap();
    assert_eq!(header, back);
}

#[test]
fn header_decode_rejects_trailing_bytes() {
    let header = sample_header(&[]);
    let mut bytes = to_bytes(&header);
    bytes.push(0x00);
    assert!(header_from_bytes(&bytes).is_err());
}

#[test]
fn transaction_root_is_deterministic() {
    let body = vec![
        wrapper_with_nonce(1),
        wrapper_with_nonce(2),
        wrapper_with_nonce(3),
    ];
    assert_eq!(transaction_root(&body), transaction_root(&body));
}

#[test]
fn transaction_root_changes_when_a_transaction_changes() {
    let first = vec![wrapper_with_nonce(1), wrapper_with_nonce(2)];
    let second = vec![wrapper_with_nonce(1), wrapper_with_nonce(9)];
    assert_ne!(transaction_root(&first), transaction_root(&second));
}

#[test]
fn empty_body_has_a_defined_transaction_root() {
    let empty = transaction_root(&[]);
    assert_eq!(empty, empty_transaction_root());
    assert_eq!(transaction_root(&[]), empty);
    assert_ne!(empty, transaction_root(&[wrapper_with_nonce(1)]));
}

#[test]
fn block_id_round_trips_through_the_format() {
    let body = vec![wrapper_with_nonce(1), wrapper_with_nonce(2)];
    let header = sample_header(&body);
    let block = Block::new(header, vec![0xAA, 0xBB, 0xCC], body);
    let id = block.id();
    let payload = qtv_idfmt::parse_block(&id).unwrap();
    let again = qtv_idfmt::render_block(&payload).unwrap();
    assert_eq!(id, again);
    assert!(id.starts_with("qbk1"));
    assert_eq!(payload, block.header_hash().to_vec());
}
