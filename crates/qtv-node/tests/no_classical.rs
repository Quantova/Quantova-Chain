// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{BTreeMap, BTreeSet, VecDeque};

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

const BRIDGE_VERIFIER_CRATES: &[&str] = &["blst"];

const BRIDGE_VERIFIER_WRAPPERS: &[&str] = &["q-bls"];

const NODE_ROOTS: &[&str] = &["qtv-node", "qtv-daemon"];

struct Package {
    deps: Vec<String>,
    source: String,
}

fn packages() -> BTreeMap<String, Package> {
    let mut graph: BTreeMap<String, Package> = BTreeMap::new();
    let mut name: Option<String> = None;
    let mut deps: Vec<String> = Vec::new();
    let mut source = String::new();
    let mut in_deps = false;
    let flush = |graph: &mut BTreeMap<String, Package>,
                 name: &mut Option<String>,
                 deps: &mut Vec<String>,
                 source: &mut String| {
        if let Some(n) = name.take() {
            graph.insert(
                n,
                Package {
                    deps: std::mem::take(deps),
                    source: std::mem::take(source),
                },
            );
        }
    };
    for line in LOCKFILE.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            flush(&mut graph, &mut name, &mut deps, &mut source);
            in_deps = false;
        } else if let Some(rest) = trimmed.strip_prefix("name = \"") {
            name = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = trimmed.strip_prefix("source = \"") {
            source = rest.trim_end_matches('"').to_string();
        } else if trimmed.starts_with("dependencies = [") {
            in_deps = true;
        } else if in_deps {
            if trimmed.starts_with(']') {
                in_deps = false;
            } else {
                let entry = trimmed.trim_matches(|c| c == '"' || c == ',');
                if let Some(crate_name) = entry.split_whitespace().next() {
                    if !crate_name.is_empty() {
                        deps.push(crate_name.to_string());
                    }
                }
            }
        }
    }
    flush(&mut graph, &mut name, &mut deps, &mut source);
    graph
}

fn linked_closure(graph: &BTreeMap<String, Package>, roots: &[&str]) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = roots.iter().map(|r| r.to_string()).collect();
    while let Some(node) = queue.pop_front() {
        if !seen.insert(node.clone()) {
            continue;
        }
        if let Some(pkg) = graph.get(&node) {
            for dep in &pkg.deps {
                if !seen.contains(dep) {
                    queue.push_back(dep.clone());
                }
            }
        }
    }
    seen
}

#[test]
fn the_node_links_no_classical_or_oracle_crate() {
    let graph = packages();
    for root in NODE_ROOTS {
        assert!(
            graph.contains_key(*root),
            "the lockfile is missing the node crate {root}"
        );
    }
    let linked = linked_closure(&graph, NODE_ROOTS);
    for name in &linked {
        assert!(
            !BANNED_CRATES.contains(&name.as_str()),
            "the node dependency closure links a banned crate: {name}"
        );
        if let Some(pkg) = graph.get(name) {
            let lower = pkg.source.to_ascii_lowercase();
            for token in BANNED_SOURCES {
                assert!(
                    !lower.contains(token),
                    "the node dependency closure links an oracle side source: {token} in {name}"
                );
            }
            for dep in &pkg.deps {
                if BRIDGE_VERIFIER_CRATES.contains(&dep.as_str()) {
                    assert!(
                        BRIDGE_VERIFIER_WRAPPERS.contains(&name.as_str()),
                        "a foreign proof verifier {dep} enters the node through {name}, outside the audited bridge wrapper set"
                    );
                }
            }
        }
    }
}
