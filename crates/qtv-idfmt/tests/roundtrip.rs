// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Round trip and rejection coverage for every identifier family.

use qtv_idfmt::{
    parse_address, parse_block, parse_cid, parse_proof, parse_secret, parse_state, parse_tx,
    render_address, render_block, render_cid, render_proof, render_secret, render_state, render_tx,
    Error,
};

/// A deterministic byte pattern of the requested length.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
        .collect()
}

#[test]
fn round_trip_address_at_floor() {
    let raw = pattern(32);
    let text = render_address(&raw).unwrap();
    assert_eq!(parse_address(&text).unwrap(), raw);
}

#[test]
fn round_trip_address_full_width() {
    let raw = pattern(32);
    let text = render_address(&raw).unwrap();
    assert_eq!(parse_address(&text).unwrap(), raw);
}

#[test]
fn round_trip_secret() {
    let raw = pattern(32);
    let text = render_secret(&raw).unwrap();
    assert_eq!(parse_secret(&text).unwrap(), raw);
}

#[test]
fn round_trip_tx() {
    let raw = pattern(32);
    let text = render_tx(&raw).unwrap();
    assert_eq!(parse_tx(&text).unwrap(), raw);
}

#[test]
fn round_trip_block() {
    let raw = pattern(32);
    let text = render_block(&raw).unwrap();
    assert_eq!(parse_block(&text).unwrap(), raw);
}

#[test]
fn round_trip_state() {
    let raw = pattern(32);
    let text = render_state(&raw).unwrap();
    assert_eq!(parse_state(&text).unwrap(), raw);
}

#[test]
fn round_trip_cid() {
    let raw = pattern(32);
    let text = render_cid(&raw).unwrap();
    assert_eq!(parse_cid(&text).unwrap(), raw);
}

#[test]
fn round_trip_proof() {
    let raw = pattern(32);
    let text = render_proof(&raw).unwrap();
    assert_eq!(parse_proof(&text).unwrap(), raw);
}

#[test]
fn reject_corrupted_checksum() {
    let raw = pattern(32);
    let text = render_tx(&raw).unwrap();
    let mut symbols: Vec<char> = text.chars().collect();
    let last = symbols.len() - 1;
    symbols[last] = if symbols[last] == 'Q' { 'P' } else { 'Q' };
    let corrupted: String = symbols.into_iter().collect();
    assert_eq!(parse_tx(&corrupted), Err(Error::BadChecksum));
}

#[test]
fn reject_wrong_prefix() {
    let raw = pattern(32);
    let text = render_tx(&raw).unwrap();
    assert_eq!(parse_block(&text), Err(Error::WrongPrefix));
}

#[test]
fn reject_non_thirty_two_address_payload() {
    assert_eq!(
        render_address(&pattern(31)),
        Err(Error::BadLength { expected: 32, got: 31 })
    );
    assert_eq!(
        render_address(&pattern(33)),
        Err(Error::BadLength { expected: 32, got: 33 })
    );
}

#[test]
fn reject_wrong_digest_length() {
    let raw = pattern(31);
    assert_eq!(
        render_tx(&raw),
        Err(Error::BadLength {
            expected: 32,
            got: 31
        })
    );
}

#[test]
fn address_string_begins_with_q1() {
    let raw = pattern(32);
    let text = render_address(&raw).unwrap();
    assert!(text.starts_with("Q1"));
}
