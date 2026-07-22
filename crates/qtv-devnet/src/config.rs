
use std::path::PathBuf;

use qtv_node::consensus::ConsensusValidator;
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
    /// The node's own 32 byte operator secret. In a running node it is loaded from a
    /// keystore file the operator owns; the single process simulation holds one per
    /// node so it can stand up the whole set. It is never derived from the id and never
    /// published; only the commitments it derives to are.
    pub secret: [u8; 32],
}

impl NodeConfig {
    pub fn with_bootstrap(mut self, bootstrap: Vec<u64>) -> Self {
        self.bootstrap = bootstrap;
        self
    }

    /// The node's published bond and reward address, the commitment its secret derives
    /// to.
    pub fn bond_address(&self) -> String {
        qtv_node::keys::validator_address(&self.secret)
    }
}

// Per id node constructors for tests and the single process simulation, sourcing the
// secret from the gated fixture. A running node builds its config with a secret read
// from its keystore; these are absent from a default build.
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
}

impl DevnetConfig {
    pub fn validator_specs(&self) -> Vec<ValidatorSpec> {
        self.nodes
            .iter()
            .map(|node| ValidatorSpec {
                id: node.id,
                stake: node.stake,
                online: node.online,
                bond_address: node.bond_address(),
            })
            .collect()
    }

    /// The consensus roster for the single process simulation: one entry per node
    /// carrying its stake, its committed bond address, and the secret this process
    /// holds on its behalf. The secret is present only because one process stands up
    /// the whole committee; it is never serialized into genesis or the roster.
    pub fn consensus_validators(&self) -> Vec<ConsensusValidator> {
        self.nodes
            .iter()
            .map(|node| {
                ConsensusValidator::from_secret(node.id, node.stake, node.online, node.secret)
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
