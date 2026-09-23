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
fn a_validator_restored_without_its_watermark_refuses_to_sign_again() {
    let base = unique_base("watermark-required");
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
    drop(devnet);

    let dir = store_dir(&base, victim as u64 + 1);
    let _ = std::fs::remove_file(dir.join("state.log.holder"));
    DevNode::open(&config.nodes[victim], &config).expect("the node reopens with its watermark");

    std::fs::remove_file(dir.join("sign.watermark"))
        .expect("the watermark is left out of a backup");
    let _ = std::fs::remove_file(dir.join("state.log.holder"));
    match DevNode::open(&config.nodes[victim], &config) {
        Err(RoundError::WatermarkBehindBlocks { head }) => {
            assert!(head >= 1, "the chain it holds is named in the refusal");
        }
        Err(other) => panic!("the node refused for the wrong reason: {other:?}"),
        Ok(_) => panic!("a validator holding a chain but no watermark was allowed to sign again"),
    }
}
