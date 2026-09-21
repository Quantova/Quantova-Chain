// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_devnet::config::{DevnetConfig, NodeConfig, DEFAULT_SLOTS, FULL_FANOUT};
use qtv_devnet::Devnet;
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use support::{unique_base, user, GENESIS_TIME, VALIDATOR_STAKE};

fn devnet_with_ceiling(tag: &str, ceiling: Option<u128>) -> Devnet<qtv_net::DuplexStream> {
    let base = unique_base(tag);
    let alice = user(0);
    let nodes: Vec<NodeConfig> = (1..=2u64)
        .map(|id| NodeConfig {
            id,
            stake: VALIDATOR_STAKE,
            online: true,
            store_dir: base.join(format!("node-{id}")),
            bootstrap: if id == 1 { vec![2] } else { vec![1] },
            address: format!("mem://{id}"),
            secret: [id as u8; 32],
        })
        .collect();
    let config = DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: vec![GenesisAccount::from_account(&alice, 1_000_000)],
        nodes,
        genesis_time: GENESIS_TIME,
        fanout: FULL_FANOUT,
        slots: DEFAULT_SLOTS,
        published_roster: None,
        bridge_dest_chain: None,
        guardians: qtv_devnet::GuardianSet::default(),
        bridge_operators: None,
        bridged_assets: vec![],
        bridge_era: None,
        bridge_exit_max_amount: ceiling,
    };
    Devnet::over_duplex(config).expect("the devnet stands up")
}

#[test]
fn a_genesis_declared_exit_ceiling_reaches_the_ledger() {
    let devnet = devnet_with_ceiling("exit-ceiling-set", Some(25_000));
    assert_eq!(
        devnet.node(0).ledger().bridge_exit_max_amount(),
        25_000,
        "the ceiling the genesis declared is the ceiling the exit checks read"
    );
}

#[test]
fn an_undeclared_ceiling_reads_as_zero_which_both_exit_checks_treat_as_open() {
    let devnet = devnet_with_ceiling("exit-ceiling-unset", None);
    assert_eq!(devnet.node(0).ledger().bridge_exit_max_amount(), 0);
}
