// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use std::path::{Path, PathBuf};

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::node::{DevNode, RoundError};
use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

fn store_dir(base: &Path, id: u64) -> PathBuf {
    base.join(format!("node-{id}"))
}

#[test]
fn a_lost_block_log_does_not_reseed_genesis_over_the_state_that_survived() {
    let base = unique_base("genesis-over-state");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut devnet = Devnet::over_duplex(config.clone()).expect("devnet");
    let victim = devnet.len() - 1;

    devnet
        .submit(0, transfer(&alice, &bob.address(), 1_000, 0, &params))
        .expect("admitted");
    devnet.step().expect("finalized");
    assert_eq!(devnet.node(victim).stored_blocks(), 1);
    drop(devnet);

    let dir = store_dir(&base, victim as u64 + 1);
    let holder = dir.join("state.log.holder");
    let _ = std::fs::remove_file(&holder);
    std::fs::remove_file(dir.join("blocks.log")).expect("the block log is lost");

    let reopened = DevNode::open(&config.nodes[victim], &config);
    match reopened {
        Err(RoundError::StateRootMismatch { state_root, .. }) => {
            assert!(
                state_root.is_some(),
                "the surviving state root is named in the refusal"
            );
        }
        Err(other) => panic!("the node refused for the wrong reason: {other:?}"),
        Ok(_) => panic!("genesis was written over state the node had already committed"),
    }
}
