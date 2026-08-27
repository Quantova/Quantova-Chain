// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn every_git_dependency_is_a_quantova_repository() {
    for line in MANIFEST.lines() {
        if line.contains("git =") {
            assert!(
                line.contains("github.com/Quantova/"),
                "a git dependency points outside the Quantova organization: {line}"
            );
        }
    }
}

#[test]
fn no_classical_or_elliptic_curve_crate_is_present() {
    assert!(
        MANIFEST.contains("qtv-crypto"),
        "qtv-crypto must be the cryptographic dependency"
    );
    let manifest = MANIFEST.to_ascii_lowercase();
    let banned = [
        "x25519",
        "ed25519",
        "curve25519",
        "dalek",
        "k256",
        "p256",
        "secp256k1",
        "rsa =",
        "bls12",
        "ark-",
        "pairing",
        "openssl",
        "ring =",
        "rustls",
    ];
    for token in banned {
        assert!(
            !manifest.contains(token),
            "a forbidden classical crate token is present: {token}"
        );
    }
}
