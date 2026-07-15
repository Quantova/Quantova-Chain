//! Shared setup for the devnet integration tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use qtv_account::{derive, Account};
use qtv_devnet::config::{DevnetConfig, NodeConfig};
use qtv_devnet::DevNode;
use qtv_node::execution::{transfer_call, TRANSFER_GAS};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::{sign, Body, Wrapper};

/// The seed the funded user accounts derive from.
pub const USER_SEED: [u8; 32] = [11u8; 32];
/// The genesis time the devnet starts from.
pub const GENESIS_TIME: u64 = 1_700_000_000_000;
/// The native stake each validator holds, the in application validator stake.
pub const VALIDATOR_STAKE: u64 = 2_000;

/// A funded user account for an index.
pub fn user(index: u64) -> Account {
    derive(&USER_SEED, index)
}

/// A per run unique temporary base directory, so tests never share store files.
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

/// A devnet configuration over a base directory, one node per online flag, all at
/// the same stake, funding the given genesis accounts.
pub fn config(base: &Path, online: &[bool], accounts: Vec<GenesisAccount>) -> DevnetConfig {
    let nodes = online
        .iter()
        .enumerate()
        .map(|(i, &on)| {
            let id = i as u64 + 1;
            NodeConfig {
                id,
                stake: VALIDATOR_STAKE,
                online: on,
                store_dir: base.join(format!("node-{id}")),
            }
        })
        .collect();
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts,
        nodes,
        genesis_time: GENESIS_TIME,
    }
}

/// A signed transfer at the protocol fee.
pub fn transfer(from: &Account, to: &str, amount: u64, nonce: u64, params: &FeeParams) -> Wrapper {
    let call = transfer_call(to, amount);
    let body = Body::new(
        from.address(),
        nonce,
        TRANSFER_GAS,
        u128::from(params.transfer_fee()),
        call,
    );
    sign(from, &body)
}

/// The canonical encodings of a node finalized chain, the bytes two nodes compare
/// to prove their chains are identical.
pub fn encoded_chain(node: &DevNode) -> Vec<Vec<u8>> {
    node.chain().iter().map(|block| block.encoded()).collect()
}
