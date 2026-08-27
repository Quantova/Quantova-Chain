// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_devnet::config::{DevnetConfig, NodeConfig, DEFAULT_SLOTS, FULL_FANOUT};
use qtv_devnet::Devnet;
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use support::{transfer, unique_base, user, GENESIS_TIME, VALIDATOR_STAKE};

#[test]
fn a_devnet_of_keystore_backed_nodes_stands_up_and_finalizes() {
    let base = unique_base("keystore-custody");
    let n = 4u64;

    let nodes: Vec<NodeConfig> = (1..=n)
        .map(|id| {
            let store_dir = base.join(format!("node-{id}"));
            let secret = qtv_node::keys::load_or_generate(&store_dir.join("keystore"))
                .expect("the node generates and holds its own secret");
            let bootstrap = if id == 1 { vec![2] } else { vec![1] };
            NodeConfig {
                id,
                stake: VALIDATOR_STAKE,
                online: true,
                store_dir,
                bootstrap,
                address: format!("mem://{id}"),
                secret,
            }
        })
        .collect();

    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            assert_ne!(
                nodes[i].secret, nodes[j].secret,
                "two nodes drew the same secret"
            );
        }
    }

    let alice = user(0);
    let bob = user(1);
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
    };

    let mut devnet =
        Devnet::over_duplex(config).expect("the devnet stands up on independent keystore secrets");

    let params = FeeParams::devnet();
    devnet
        .submit(0, transfer(&alice, &bob.address(), 3_000, 0, &params))
        .expect("admitted");
    devnet.step().expect("the committee finalized a height");

    for i in 0..devnet.len() {
        let chain = devnet.node(i).chain();
        assert_eq!(chain.len(), 1, "node {i} did not finalize");
        assert_eq!(chain[0].header().height(), 1);
    }
    let root = devnet.node(0).ledger().q_root();
    for i in 1..devnet.len() {
        assert_eq!(
            devnet.node(i).ledger().q_root(),
            root,
            "node {i} finalized a different state"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
}
