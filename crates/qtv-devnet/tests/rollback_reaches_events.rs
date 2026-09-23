// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use std::path::{Path, PathBuf};

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::node::DevNode;
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
fn a_rolled_back_block_takes_its_events_and_its_index_entry_with_it() {
    let base = unique_base("rollback-events");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut devnet = Devnet::over_duplex(config.clone()).expect("devnet");
    let victim = devnet.len() - 1;

    let mut last_id = String::new();
    for nonce in 0..2u64 {
        let payment = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        last_id = payment.id();
        devnet.submit(0, payment).expect("admitted");
        devnet.step().expect("finalized");
    }
    let torn_height = devnet.node(victim).height() - 1;
    assert!(
        !devnet.node(victim).events_at(torn_height).is_empty(),
        "the block that is about to be torn off did record events"
    );
    assert_eq!(
        devnet.node(victim).finalized_height(&last_id),
        Some(torn_height),
        "and its transaction is indexed at that height"
    );
    drop(devnet);

    let dir = store_dir(&base, victim as u64 + 1);
    let _ = std::fs::remove_file(dir.join("state.log.holder"));
    chop(&dir.join("state.log"), 6);

    let node = DevNode::open(&config.nodes[victim], &config).expect("the node reopens");
    assert!(
        node.events_at(torn_height).is_empty(),
        "the events of a rolled back block are rolled back with it"
    );
    assert_eq!(
        node.finalized_height(&last_id),
        None,
        "and its transaction no longer reports a height whose block was dropped"
    );
}
