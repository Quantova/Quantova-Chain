// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use std::path::{Path, PathBuf};

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::node::RoundError;
use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

fn store_dir(base: &Path, id: u64) -> PathBuf {
    base.join(format!("node-{id}"))
}

fn chop(path: &Path, bytes: u64) {
    let len = std::fs::metadata(path).expect("the log exists").len();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open the log");
    file.set_len(len - bytes).expect("truncate the log");
    file.sync_all().ok();
}

#[test]
fn a_torn_state_commit_recovers_to_the_last_complete_height() {
    let base = unique_base("crash-torn-commit");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");
    let victim = devnet.len() - 1;

    for nonce in 0..2u64 {
        devnet
            .submit(0, transfer(&alice, &bob.address(), 1_000, nonce, &params))
            .expect("admitted");
        devnet.step().expect("finalized");
    }
    let head_at_two = devnet.node(victim).head_hash();
    let height_at_two = devnet.node(victim).height();
    assert_eq!(devnet.node(victim).stored_blocks(), 2);

    devnet
        .submit(0, transfer(&alice, &bob.address(), 1_000, 2, &params))
        .expect("admitted");
    devnet.step().expect("finalized");
    assert_eq!(devnet.node(victim).stored_blocks(), 3);

    let dir = store_dir(&base, victim as u64 + 1);
    chop(&dir.join("state.log"), 6);

    devnet
        .restart_node(victim)
        .expect("the node recovers from the torn commit");

    assert_eq!(devnet.node(victim).stored_blocks(), 2);
    assert_eq!(devnet.node(victim).height(), height_at_two);
    assert_eq!(devnet.node(victim).head_hash(), head_at_two);

    for nonce in 3..6u64 {
        devnet
            .submit(0, transfer(&alice, &bob.address(), 1_000, nonce, &params))
            .expect("admitted");
        devnet.step().expect("the recovered node finalizes on");
    }
    let head = devnet.node(0).head_hash();
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).head_hash(), head, "node {i} head differs");
    }
}

#[test]
fn a_committed_state_without_its_head_block_refuses_to_resume() {
    let base = unique_base("crash-missing-block");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");
    let victim = devnet.len() - 1;

    for nonce in 0..3u64 {
        devnet
            .submit(0, transfer(&alice, &bob.address(), 1_000, nonce, &params))
            .expect("admitted");
        devnet.step().expect("finalized");
    }
    assert_eq!(devnet.node(victim).stored_blocks(), 3);

    let dir = store_dir(&base, victim as u64 + 1);
    chop(&dir.join("blocks.log"), 6);

    match devnet.restart_node(victim) {
        Err(RoundError::StateRootMismatch { height, .. }) => {
            assert_eq!(height, 2, "it reports the head it could still prove");
        }
        other => panic!("a mismatched resume must be refused, got {other:?}"),
    }
}
