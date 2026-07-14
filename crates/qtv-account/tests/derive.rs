//! Coverage for the account derivation pipeline and the address tiers.

use qtv_account::{address_for_key, derive, rotate, Tier, SCHEME_LATTICE};
use qtv_idfmt::{parse_address, parse_secret, KEY_FLOOR};

/// A deterministic master seed pattern.
fn master() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    seed
}

#[test]
fn derive_is_deterministic() {
    let seed = master();
    let first = derive(&seed, 0);
    let second = derive(&seed, 0);
    assert_eq!(first.address(), second.address());
    assert_eq!(first.seed(), second.seed());
    assert_eq!(first.public_key(), second.public_key());
    assert_eq!(first.secret_export(), second.secret_export());
}

#[test]
fn address_round_trips_through_the_format() {
    let account = derive(&master(), 0);
    let text = account.address();
    let payload = parse_address(&text).unwrap();
    let again = qtv_idfmt::render_address(&payload).unwrap();
    assert_eq!(text, again);
    assert!(text.starts_with("q1"));
}

#[test]
fn secret_export_round_trips_through_the_format() {
    let account = derive(&master(), 0);
    let export = account.secret_export();
    let payload = parse_secret(&export).unwrap();
    assert_eq!(payload.as_slice(), account.seed());
}

#[test]
fn changing_the_index_changes_the_address() {
    let seed = master();
    assert_ne!(derive(&seed, 0).address(), derive(&seed, 1).address());
}

#[test]
fn changing_the_scheme_changes_the_address() {
    let account = derive(&master(), 0);
    let key = account.public_key();
    let lattice = address_for_key(SCHEME_LATTICE, key, Tier::Canonical);
    let other = address_for_key(SCHEME_LATTICE + 1, key, Tier::Canonical);
    assert_ne!(lattice, other);
}

#[test]
fn compact_tier_is_shorter_and_both_hold_the_floor() {
    let account = derive(&master(), 7);
    let canonical = parse_address(&account.address_at(Tier::Canonical)).unwrap();
    let compact = parse_address(&account.address_at(Tier::Compact)).unwrap();
    assert!(compact.len() < canonical.len());
    assert!(compact.len() >= KEY_FLOOR);
    assert!(canonical.len() >= KEY_FLOOR);
}

#[test]
fn rotation_binds_the_old_address_to_the_new() {
    let seed = master();
    let current = derive(&seed, 0);
    let rotation = rotate(&seed, &current, 1);
    let next = derive(&seed, 1);
    assert_eq!(rotation.binding().from(), current.address());
    assert_eq!(rotation.binding().to(), next.address());
    assert_eq!(rotation.next().address(), next.address());
    assert_ne!(rotation.binding().from(), rotation.binding().to());
}
