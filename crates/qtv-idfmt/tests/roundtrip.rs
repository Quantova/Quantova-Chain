// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_idfmt::{
    parse_address, parse_block, parse_cid, parse_proof, parse_secret, parse_state, parse_tx,
    render_address, render_block, render_cid, render_proof, render_secret, render_state, render_tx,
    Error,
};

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
        Err(Error::BadLength {
            expected: 32,
            got: 31
        })
    );
    assert_eq!(
        render_address(&pattern(33)),
        Err(Error::BadLength {
            expected: 32,
            got: 33
        })
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

// An address is a key into the ledger and it appears in transactions, blocks and the
// explorer. If one account can be written two ways, the two spellings index apart while
// spending the same balance, so these pin the rules that keep the encoding unique.

#[test]
fn a_mixed_case_address_is_refused() {
    let raw = pattern(32);
    let text = render_address(&raw).unwrap();
    assert_eq!(parse_address(&text).unwrap(), raw, "the honest form parses");

    let lower = text.to_ascii_lowercase();
    assert_eq!(
        parse_address(&lower).unwrap(),
        raw,
        "an all lowercase spelling is the same address"
    );

    let mut mixed: String = text.clone();
    if let Some(pos) = mixed.char_indices().rev().find_map(|(i, c)| {
        if c.is_ascii_alphabetic() {
            Some(i)
        } else {
            None
        }
    }) {
        let flipped = mixed[pos..pos + 1].to_ascii_lowercase();
        mixed.replace_range(pos..pos + 1, &flipped);
    }
    assert_ne!(mixed, text, "the sample really is mixed case");
    assert_eq!(
        parse_address(&mixed),
        Err(Error::MixedCase),
        "a mixed case spelling must be refused, accepting it gives one account two forms"
    );
}

#[test]
fn a_bech32_checksum_does_not_pass_as_bech32m() {
    // Flipping the final data symbol moves the residue off the bech32m constant. A decoder
    // that accepted the older bech32 constant as well would let a second checksum verify.
    let raw = pattern(32);
    let text = render_address(&raw).unwrap();
    let mut bytes: Vec<char> = text.chars().collect();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == 'Q' { 'P' } else { 'Q' };
    let altered: String = bytes.into_iter().collect();
    assert_eq!(
        parse_address(&altered),
        Err(Error::BadChecksum),
        "only the bech32m residue may verify"
    );
}

#[test]
fn a_truncated_or_extended_address_is_refused() {
    let raw = pattern(32);
    let text = render_address(&raw).unwrap();

    let short = &text[..text.len() - 1];
    assert!(
        parse_address(short).is_err(),
        "dropping a symbol must not still parse"
    );

    let long = format!("{text}Q");
    assert!(
        parse_address(&long).is_err(),
        "appending a symbol must not still parse, a padded form is a second encoding"
    );
}

#[test]
fn every_rendered_kind_refuses_every_other_kind() {
    let raw = pattern(32);
    let renders: [(&str, String); 4] = [
        ("address", render_address(&raw).unwrap()),
        ("tx", render_tx(&raw).unwrap()),
        ("block", render_block(&raw).unwrap()),
        ("state", render_state(&raw).unwrap()),
    ];
    for (name, text) in &renders {
        if *name != "address" {
            assert!(
                parse_address(text).is_err(),
                "a {name} identifier parsed as an address, the prefixes must keep the kinds apart"
            );
        }
        if *name != "tx" {
            assert!(
                parse_tx(text).is_err(),
                "a {name} identifier parsed as a tx"
            );
        }
        if *name != "block" {
            assert!(
                parse_block(text).is_err(),
                "a {name} identifier parsed as a block"
            );
        }
    }
}
