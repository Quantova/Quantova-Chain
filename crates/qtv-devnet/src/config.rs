// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::PathBuf;

use qtv_node::consensus::ValidatorRegistration;
use qtv_node::fee::FeeParams;
use qtv_governance::GuardianSet;
use qtv_node::bridge::OperatorSet;
use qtv_node::node::{Genesis, GenesisAccount, GenesisBridgedAsset, ValidatorSpec};

#[derive(Clone)]
pub struct NodeConfig {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    pub store_dir: PathBuf,
    pub bootstrap: Vec<u64>,
    pub address: String,
    pub secret: [u8; 32],
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("id", &self.id)
            .field("stake", &self.stake)
            .field("online", &self.online)
            .field("store_dir", &self.store_dir)
            .field("bootstrap", &self.bootstrap)
            .field("address", &self.address)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl NodeConfig {
    pub fn with_bootstrap(mut self, bootstrap: Vec<u64>) -> Self {
        self.bootstrap = bootstrap;
        self
    }

    pub fn bond_address(&self) -> String {
        qtv_node::keys::validator_address(&self.secret)
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl NodeConfig {
    pub fn online(id: u64, stake: u64, store_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            id,
            stake,
            online: true,
            store_dir: store_dir.into(),
            bootstrap: Vec::new(),
            address: format!("mem://{id}"),
            secret: qtv_node::keys::fixture_secret(id),
        }
    }

    pub fn offline(id: u64, stake: u64, store_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            id,
            stake,
            online: false,
            store_dir: store_dir.into(),
            bootstrap: Vec::new(),
            address: format!("mem://{id}"),
            secret: qtv_node::keys::fixture_secret(id),
        }
    }
}

pub const FULL_FANOUT: usize = usize::MAX;

pub const DEFAULT_SLOTS: u64 = qtv_sampler::validator::DEFAULT_SLOTS;

#[derive(Clone, Debug)]
pub struct DevnetConfig {
    pub fee_params: FeeParams,
    pub accounts: Vec<GenesisAccount>,
    pub nodes: Vec<NodeConfig>,
    pub genesis_time: u64,
    pub fanout: usize,
    pub slots: u64,
    pub published_roster: Option<Vec<ValidatorRegistration>>,
    pub bridge_dest_chain: Option<u32>,
    pub guardians: GuardianSet,
    pub bridge_operators: Option<OperatorSet>,
    pub bridged_assets: Vec<GenesisBridgedAsset>,
    pub bridge_era: Option<[u8; 32]>,
}

impl DevnetConfig {
    pub fn validator_specs(&self) -> Vec<ValidatorSpec> {
        self.nodes
            .iter()
            .map(|node| {
                ValidatorSpec::from_secret(
                    node.id,
                    node.stake,
                    node.online,
                    &node.secret,
                    self.slots,
                )
            })
            .collect()
    }

    pub fn roster(&self) -> Vec<ValidatorRegistration> {
        if let Some(roster) = &self.published_roster {
            return roster.clone();
        }
        self.nodes
            .iter()
            .map(|node| {
                ValidatorRegistration::from_secret(
                    node.id,
                    node.stake,
                    node.online,
                    &node.secret,
                    self.slots,
                )
            })
            .collect()
    }

    pub fn genesis(&self) -> Genesis {
        Genesis {
            fee_params: self.fee_params,
            accounts: self.accounts.clone(),
            validators: self.validator_specs(),
            genesis_time: self.genesis_time,
            guardians: self.guardians.clone(),
            bridge_dest_chain: self.bridge_dest_chain,
            bridge_operators: self.bridge_operators.clone(),
            bridged_assets: self.bridged_assets.clone(),
            bridge_era: self.bridge_era,
            bridge_bitcoin_anchor: None,
        }
    }
}
