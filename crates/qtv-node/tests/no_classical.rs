// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The node crate holds the bridge, so the whole resolved dependency graph must link no classical
//! cryptography and no oracle side crate. This guard scans the committed workspace lockfile, the
//! transitive graph deny.toml also guards, and fails if any banned crate or oracle source appears.

const LOCKFILE: &str = include_str!("../../../Cargo.lock");

const BANNED_CRATES: &[&str] = &[
    "k256",
    "ed25519",
    "ed25519-dalek",
    "ed25519-compact",
    "curve25519-dalek",
    "x25519-dalek",
    "p256",
    "secp256k1",
    "rsa",
    "bls12_381",
    "blst",
    "ark-ec",
    "ark-bls12-381",
    "ark-groth16",
    "pairing",
    "openssl",
    "openssl-sys",
    "ring",
    "rustls",
    "q-oracle",
    "qtv-oracle",
    "q-prover-bridge",
    "qtv-prover",
];

const BANNED_SOURCES: &[&str] = &["q-oracle", "q-prover", "prover-bridge", "oracle"];

#[test]
fn the_lockfile_links_no_classical_or_oracle_crate() {
    for line in LOCKFILE.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name = \"") {
            let name = rest.trim_end_matches('"');
            assert!(
                !BANNED_CRATES.contains(&name),
                "the lockfile links a banned crate: {name}"
            );
        }
        if trimmed.starts_with("source = ") {
            let lower = trimmed.to_ascii_lowercase();
            for token in BANNED_SOURCES {
                assert!(
                    !lower.contains(token),
                    "the lockfile links an oracle side source: {token} in {trimmed}"
                );
            }
        }
    }
}
