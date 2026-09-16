// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

const MANIFEST: &str = include_str!("../Cargo.toml");
const LOCKFILE: &str = include_str!("../../../Cargo.lock");

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

#[test]
fn no_classical_or_elliptic_curve_crate_reaches_the_lockfile() {
    let lock = LOCKFILE.to_ascii_lowercase();
    let banned = [
        "x25519",
        "ed25519",
        "curve25519",
        "dalek",
        "k256",
        "p256",
        "secp256k1",
        "ark-",
        "openssl",
        "rustls",
        "name = \"ring\"",
    ];
    for token in banned {
        assert!(
            !lock.contains(token),
            "a classical crate reaches the build through a transitive dependency: {token}"
        );
    }
}

#[test]
fn blst_is_the_only_classical_curve_and_only_q_bls_may_reach_it() {
    assert!(
        LOCKFILE.contains("name = \"blst\""),
        "blst left the graph, so this bound no longer describes the build and must be retired"
    );
    let mut dependents = Vec::new();
    for block in LOCKFILE.split("[[package]]") {
        let name = block
            .lines()
            .find_map(|line| line.strip_prefix("name = "))
            .map(|name| name.trim_matches('"'));
        let (Some(name), true) = (name, block.contains("\"blst\"")) else {
            continue;
        };
        if name != "blst" {
            dependents.push(name.to_string());
        }
    }
    assert_eq!(
        dependents,
        vec!["q-bls".to_string()],
        "blst is admitted only to verify foreign Ethereum consensus proofs through q-bls, it \
         must never sign or verify anything the Q chain itself relies on, so any other crate \
         reaching it is a widening of the classical crypto surface"
    );
}
