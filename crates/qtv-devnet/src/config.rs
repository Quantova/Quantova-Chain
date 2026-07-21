
use std::path::PathBuf;

use qtv_node::fee::FeeParams;
use qtv_node::node::{Genesis, GenesisAccount, ValidatorSpec};

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    pub store_dir: PathBuf,
    pub bootstrap: Vec<u64>,
    pub address: String,
}

impl NodeConfig {
    pub fn online(id: u64, stake: u64, store_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            id,
            stake,
            online: true,
            store_dir: store_dir.into(),
            bootstrap: Vec::new(),
            address: format!("mem://{id}"),
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
        }
    }

    pub fn with_bootstrap(mut self, bootstrap: Vec<u64>) -> Self {
        self.bootstrap = bootstrap;
        self
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
}

impl DevnetConfig {
    pub fn validator_specs(&self) -> Vec<ValidatorSpec> {
        self.nodes
            .iter()
            .map(|node| ValidatorSpec {
                id: node.id,
                stake: node.stake,
                online: node.online,
            })
            .collect()
    }

    pub fn genesis(&self) -> Genesis {
        Genesis {
            fee_params: self.fee_params,
            accounts: self.accounts.clone(),
            validators: self.validator_specs(),
            genesis_time: self.genesis_time,
        }
    }
}
