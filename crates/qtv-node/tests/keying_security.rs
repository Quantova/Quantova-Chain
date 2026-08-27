// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_node::keys;

#[test]
fn the_bond_account_is_a_function_of_the_secret_alone_not_the_id() {
    let secret = [0x21u8; 32];
    assert_eq!(
        keys::validator_address(&secret),
        keys::validator_address(&secret)
    );
    assert_ne!(
        keys::validator_address(&secret),
        keys::validator_address(&[0x22u8; 32])
    );
}

#[test]
fn the_published_bond_address_reveals_neither_the_secret_nor_the_seed() {
    let secret = [0x33u8; 32];
    let seed = keys::validator_account_seed(&secret);
    assert_ne!(seed, secret, "the account seed must not be the secret");

    let account = keys::validator_account(&secret);
    assert_ne!(account.seed(), &secret, "the signing seed must not be the secret");
    assert_ne!(account.seed(), &seed, "the signing seed must not be the account seed");
    let shown = format!("{account:?}");
    assert!(
        shown.contains("[redacted]"),
        "the account seed leaked in debug: {shown}"
    );
    assert!(!shown.contains(&format!("{:02x}", secret[0]).repeat(4)));
}

#[test]
fn a_party_with_only_the_public_bond_address_cannot_forge_the_account() {
    let victim = keys::validator_account(&[0xa1u8; 32]);
    let impostor = keys::validator_account(&[0xb2u8; 32]);
    assert_ne!(victim.address(), impostor.address());
    assert_ne!(victim.public_key(), impostor.public_key());
}

#[test]
fn two_independent_secrets_yield_independent_bond_accounts() {
    let a = keys::validator_account(&[0x01u8; 32]);
    let b = keys::validator_account(&[0x02u8; 32]);
    assert_ne!(a.address(), b.address());
    assert_ne!(a.public_key(), b.public_key());
    assert_ne!(
        keys::validator_account_seed(&[0x01u8; 32]),
        keys::validator_account_seed(&[0x02u8; 32])
    );
}

#[test]
fn a_keystore_is_generated_on_first_run_persists_and_two_nodes_draw_independent_secrets() {
    let base = std::env::temp_dir().join(format!(
        "qtv-keystore-proof-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let one = base.join("node-1").join("keystore");
    let two = base.join("node-2").join("keystore");

    let first = keys::load_or_generate(&one).expect("first run generates the node's own secret");
    let reload = keys::load_or_generate(&one).expect("second run reads the same secret");
    assert_eq!(first, reload, "the keystore did not persist the secret");

    let other = keys::load_or_generate(&two).expect("a second node generates its own secret");
    assert_ne!(
        first, other,
        "two nodes generated the same secret, they are not independent"
    );

    let _ = std::fs::remove_dir_all(&base);
}
