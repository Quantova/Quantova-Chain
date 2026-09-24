// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::PathBuf;

use qtv_governance::GuardianSet;
use qtv_node::bridge::OperatorSet;
use qtv_node::consensus::ValidatorRegistration;
use qtv_node::fee::FeeParams;
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
    pub bridge_exit_max_amount: Option<u128>,
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
            bridge_exit_max_amount: self.bridge_exit_max_amount,
        }
    }
}

#[cfg(test)]
mod secret_redaction_tests {
    use super::*;

    #[test]
    fn a_node_config_never_prints_its_secret() {
        let secret = [0xABu8; 32];
        let config = NodeConfig {
            id: 1,
            stake: 100,
            online: true,
            store_dir: std::path::PathBuf::from("/tmp/redaction-probe"),
            bootstrap: vec![2],
            address: "mem://1".to_string(),
            secret,
        };

        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("[redacted]"),
            "the secret field must render as redacted, got {rendered}"
        );
        assert!(
            !rendered.contains("171") && !rendered.to_lowercase().contains("ab, ab"),
            "the raw secret bytes appear in the debug rendering: {rendered}"
        );
        for byte in secret.iter().take(4) {
            assert!(
                !rendered.contains(&format!("{byte}, {byte}, {byte}")),
                "a run of secret bytes leaked into the debug rendering"
            );
        }
    }

    #[test]
    fn a_devnet_config_never_prints_a_node_secret() {
        let config = DevnetConfig {
            fee_params: qtv_node::fee::FeeParams::devnet(),
            accounts: Vec::new(),
            nodes: vec![NodeConfig {
                id: 1,
                stake: 100,
                online: true,
                store_dir: std::path::PathBuf::from("/tmp/redaction-probe"),
                bootstrap: Vec::new(),
                address: "mem://1".to_string(),
                secret: [0xCDu8; 32],
            }],
            genesis_time: 0,
            fanout: crate::config::FULL_FANOUT,
            slots: DEFAULT_SLOTS,
            published_roster: None,
            bridge_dest_chain: None,
            guardians: GuardianSet::default(),
            bridge_operators: None,
            bridged_assets: Vec::new(),
            bridge_era: None,
            bridge_exit_max_amount: None,
        };

        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("[redacted]"),
            "a config printed through the whole devnet must still redact the node secret"
        );
        assert!(
            !rendered.contains("205, 205"),
            "the node secret leaked when the enclosing config was formatted: {rendered}"
        );
    }
}
