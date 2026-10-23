// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const WORKSPACE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

const SIMULATION_CRATES: &[&str] = &["qtv-live", "qtv-loopback", "qtv-widearea"];

fn normal_section(manifest: &str) -> String {
    manifest
        .split("\n[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .unwrap_or_default()
        .to_string()
}

fn crates_enabling_fixtures_normally() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let dir = Path::new(WORKSPACE).join("crates");
    for entry in fs::read_dir(&dir).expect("the crates directory is readable") {
        let path = entry.expect("a crate directory").path();
        let Ok(manifest) = fs::read_to_string(path.join("Cargo.toml")) else {
            continue;
        };
        if normal_section(&manifest)
            .lines()
            .any(|line| line.contains("test-fixtures") || line.contains("test-util"))
        {
            found.insert(
                path.file_name()
                    .expect("a name")
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }
    found
}

#[test]
fn no_workspace_crate_turns_on_the_test_fixtures() {
    assert_eq!(
        crates_enabling_fixtures_normally(),
        BTreeSet::new(),
        "a crate outside the simulation harnesses enables the deterministic id derived secrets \
         as a normal dependency. Cargo unifies features within a build graph, so that is how a \
         test only signing key reaches a shipped node binary"
    );
}

#[test]
fn the_simulation_harnesses_live_in_their_own_workspace() {
    let manifest = fs::read_to_string(Path::new(WORKSPACE).join("Cargo.toml"))
        .expect("the workspace manifest is readable");
    assert!(
        manifest.contains("exclude = [\"harness\"]"),
        "the harness workspace must stay excluded, or a workspace build unifies the fixture \
         feature into the graph that produces the node"
    );
    for name in SIMULATION_CRATES {
        assert!(
            !manifest.contains(&format!("\"crates/{name}\"")),
            "{name} enables the test fixtures and must not be a member of the node workspace"
        );
        assert!(
            Path::new(WORKSPACE)
                .join("harness")
                .join(name)
                .join("Cargo.toml")
                .exists(),
            "{name} belongs in the separate harness workspace"
        );
    }
}

#[test]
fn the_node_and_daemon_never_enable_the_fixtures_normally() {
    for name in ["qtv-node", "qtv-daemon", "qtv-devnet", "qtv-gateway"] {
        let manifest = fs::read_to_string(
            Path::new(WORKSPACE)
                .join("crates")
                .join(name)
                .join("Cargo.toml"),
        )
        .expect("the crate manifest is readable");
        let normal = normal_section(&manifest);
        assert!(
            !normal.contains("test-fixtures") && !normal.contains("test-util"),
            "{name} enables a test only feature as a normal dependency, which puts it in every \
             build that links {name}"
        );
    }
}
