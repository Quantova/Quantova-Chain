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

fn normal_dependents_of(crate_name: &str) -> Vec<String> {
    let mut dependents = Vec::new();
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).expect("crates dir")
    {
        let dir = entry.expect("entry").path();
        let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        let normal = text
            .split("\n[dependencies]")
            .nth(1)
            .and_then(|rest| rest.split("\n[").next())
            .unwrap_or_default();
        if normal
            .lines()
            .any(|line| line.trim_start().starts_with(crate_name))
        {
            dependents.push(
                dir.file_name()
                    .expect("crate dir")
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }
    dependents.sort();
    dependents
}

#[test]
fn no_classical_curve_reaches_the_chain_at_all() {
    for curve in [
        "blst",
        "bls12_381",
        "secp256k1",
        "k256",
        "ed25519",
        "ed25519-dalek",
        "curve25519-dalek",
        "p256",
        "ring",
    ] {
        assert!(
            !LOCKFILE.contains(&format!("name = \"{curve}\"")),
            "{curve} is in the chain graph; a classical curve belongs in Q-Oracle, never here"
        );
        assert!(
            normal_dependents_of(curve).is_empty(),
            "{curve} is reachable as a normal dependency of the chain"
        );
    }
}
