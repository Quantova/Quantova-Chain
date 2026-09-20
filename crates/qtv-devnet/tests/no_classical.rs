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
fn only_q_bls_carries_blst_into_a_production_build() {
    assert!(
        LOCKFILE.contains("name = \"blst\""),
        "blst left the graph, so this bound no longer describes the build and must be retired"
    );
    assert_eq!(
        normal_dependents_of("blst"),
        vec!["q-bls".to_string()],
        "blst is admitted only to verify foreign Ethereum consensus proofs through q-bls. A test \
         may reach it under dev-dependencies, but a normal dependency anywhere else ships the \
         signing half of a classical curve into the running node"
    );
}
