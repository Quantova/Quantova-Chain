//! Coverage for the account derivation pipeline and the address format.

use qtv_account::{
    address_for_key, derive, derive_with_scheme, rotate, SCHEME_HASH, SCHEME_LATTICE,
};
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
    let lattice = address_for_key(SCHEME_LATTICE, key);
    let other = address_for_key(SCHEME_LATTICE + 1, key);
    assert_ne!(lattice, other);
}

#[test]
fn an_address_is_the_full_width_and_holds_the_floor() {
    let account = derive(&master(), 7);
    let payload = parse_address(&account.address()).unwrap();
    assert_eq!(payload.len(), 32);
    assert!(payload.len() >= KEY_FLOOR);
}

#[test]
fn two_schemes_differ_only_in_scheme_yet_hide_it() {
    let seed = master();
    let lattice = derive_with_scheme(&seed, SCHEME_LATTICE, 0);
    let hash = derive_with_scheme(&seed, SCHEME_HASH, 0);
    assert_eq!(lattice.scheme(), SCHEME_LATTICE);
    assert_eq!(hash.scheme(), SCHEME_HASH);
    assert_ne!(lattice.address(), hash.address());
    let lattice_payload = parse_address(&lattice.address()).unwrap();
    let hash_payload = parse_address(&hash.address()).unwrap();
    assert_eq!(lattice_payload.len(), hash_payload.len());
    assert_ne!(lattice_payload, hash_payload);
    assert!(lattice.address().starts_with("q1"));
    assert!(hash.address().starts_with("q1"));
}

#[test]
fn the_default_derive_takes_the_lattice_scheme() {
    let seed = master();
    assert_eq!(
        derive(&seed, 0).address(),
        derive_with_scheme(&seed, SCHEME_LATTICE, 0).address()
    );
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
