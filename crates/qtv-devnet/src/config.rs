//! The genesis and node configuration a devnet is stood up from.
//!
//! One devnet configuration fixes the shared genesis, the fee parameters, the
//! funded accounts, and the validator set, and it lists the nodes. Each node
//! carries its consensus id, its native stake, whether it is online this run, and
//! the directory its two stores live in. Every node derives the same genesis from
//! the shared fields, so the nodes start from an identical state and an identical
//! committee.

use std::path::PathBuf;

use qtv_node::fee::FeeParams;
use qtv_node::node::{Genesis, GenesisAccount, ValidatorSpec};

/// The configuration of one node: its consensus identity, its native stake,
/// whether it is online this run, and where its stores live on disk.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    pub store_dir: PathBuf,
}

impl NodeConfig {
    /// An online node with the given id, stake, and store directory.
    pub fn online(id: u64, stake: u64, store_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            id,
            stake,
            online: true,
            store_dir: store_dir.into(),
        }
    }

    /// An offline node. It keeps its stake and its committee candidacy but does
    /// not participate this run, and is never slashed.
    pub fn offline(id: u64, stake: u64, store_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            id,
            stake,
            online: false,
            store_dir: store_dir.into(),
        }
    }
}

/// The configuration of a whole devnet: the shared genesis fields and the nodes.
#[derive(Clone, Debug)]
pub struct DevnetConfig {
    pub fee_params: FeeParams,
    pub accounts: Vec<GenesisAccount>,
    pub nodes: Vec<NodeConfig>,
    pub genesis_time: u64,
}

impl DevnetConfig {
    /// The validator specs of the whole set, in the node order. Every node builds
    /// its committee driver over this same set, so all nodes select the same
    /// committee and elect the same leader.
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

    /// The shared genesis every node starts from.
    pub fn genesis(&self) -> Genesis {
        Genesis {
            fee_params: self.fee_params,
            accounts: self.accounts.clone(),
            validators: self.validator_specs(),
            genesis_time: self.genesis_time,
        }
    }
}
