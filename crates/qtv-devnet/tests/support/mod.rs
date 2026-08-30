// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use qtv_account::{derive, Account};
use qtv_devnet::config::{DevnetConfig, NodeConfig};
use qtv_devnet::DevNode;
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::{sign, Body, Wrapper};

pub const USER_SEED: [u8; 32] = [11u8; 32];
pub const GENESIS_TIME: u64 = 1_700_000_000_000;
pub const VALIDATOR_STAKE: u64 = 2_000;

pub fn user(index: u64) -> Account {
    derive(&USER_SEED, index)
}

pub fn unique_base(name: &str) -> PathBuf {
    let mut base = std::env::temp_dir();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    base.push(format!(
        "qtv-devnet-{}-{}-{}",
        std::process::id(),
        name,
        stamp
    ));
    base
}

pub fn config(base: &Path, online: &[bool], accounts: Vec<GenesisAccount>) -> DevnetConfig {
    config_with_fanout(base, online, accounts, qtv_devnet::config::FULL_FANOUT)
}

pub fn config_with_fanout(
    base: &Path,
    online: &[bool],
    accounts: Vec<GenesisAccount>,
    fanout: usize,
) -> DevnetConfig {
    let count = online.len();
    let nodes = online
        .iter()
        .enumerate()
        .map(|(i, &on)| {
            let id = i as u64 + 1;
            let bootstrap = if i == 0 {
                if count > 1 {
                    vec![2]
                } else {
                    Vec::new()
                }
            } else {
                vec![1]
            };
            NodeConfig {
                id,
                stake: VALIDATOR_STAKE,
                online: on,
                store_dir: base.join(format!("node-{id}")),
                bootstrap,
                address: format!("mem://{id}"),
                secret: qtv_node::keys::fixture_secret(id),
            }
        })
        .collect();
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts,
        nodes,
        genesis_time: GENESIS_TIME,
        fanout,
        slots: qtv_devnet::config::DEFAULT_SLOTS,
        published_roster: None,
        bridge_dest_chain: None,
        guardians: qtv_governance::GuardianSet::default(),
        bridge_operators: None,
        bridged_assets: vec![],
        bridge_era: None,
    }
}

pub fn transfer(from: &Account, to: &str, amount: u64, nonce: u64, params: &FeeParams) -> Wrapper {
    let call = transfer_call(to, amount);
    let body = Body::new(
        from.address(),
        nonce,
        TRANSFER_METER,
        u128::from(params.transfer_fee()),
        call,
    );
    sign(from, &body)
}

pub fn encoded_chain(node: &DevNode) -> Vec<Vec<u8>> {
    node.chain().iter().map(|block| block.encoded()).collect()
}

pub fn header_chain(node: &DevNode) -> Vec<[u8; 32]> {
    node.chain()
        .iter()
        .map(|block| block.header_hash())
        .collect()
}

pub fn dummy_auth() -> qtv_attest::Attestation {
    use qtv_attest::{Attester, Beacon, Block, Parent};
    Attester::from_secret(1, &[1u8; 32], 100).attest(
        1,
        1,
        0,
        0,
        [0u8; 32],
        Block::new(1, [0u8; 32], Parent::Genesis),
        &Beacon::genesis(),
    )
}
