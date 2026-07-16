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
/// whether it is online this run, where its stores live on disk, the bootstrap
/// peers it starts discovery from, and the address other nodes dial to reach it.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    pub store_dir: PathBuf,
    /// The consensus ids of the bootstrap peers this node starts from. The node
    /// discovers the rest of the network by exchanging its known peer set with
    /// these. An empty list leaves the node reachable only through peers that
    /// bootstrap from it.
    pub bootstrap: Vec<u64>,
    /// The address other nodes dial to reach this node. On the in memory devnet it
    /// is a symbolic handle; over a real transport it is a socket address.
    pub address: String,
}

impl NodeConfig {
    /// An online node with the given id, stake, and store directory, with no
    /// bootstrap peers set yet.
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

    /// An offline node. It keeps its stake and its committee candidacy but does
    /// not participate this run, and is never slashed.
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

    /// The same node reachable through the given bootstrap peers.
    pub fn with_bootstrap(mut self, bootstrap: Vec<u64>) -> Self {
        self.bootstrap = bootstrap;
        self
    }
}

/// The default overlay fanout, a full mesh. A small devnet keeps every pair
/// connected unless a larger network sets a bound, so the existing behavior is
/// preserved while a bounded overlay is opt in through a smaller fanout.
pub const FULL_FANOUT: usize = usize::MAX;

/// The one time slot count a devnet sizes each validator tree to unless a run asks
/// for more. It is the consensus sampler default. One slot is spent per finalised
/// height, so this bounds a run to that many heights, and a driver that must sustain
/// more heights raises the count through the DevnetConfig slots field rather than
/// changing this default.
pub const DEFAULT_SLOTS: u64 = qtv_sampler::validator::DEFAULT_SLOTS;

/// The configuration of a whole devnet: the shared genesis fields, the nodes, and
/// the overlay fanout each node keeps neighbors up to.
#[derive(Clone, Debug)]
pub struct DevnetConfig {
    pub fee_params: FeeParams,
    pub accounts: Vec<GenesisAccount>,
    pub nodes: Vec<NodeConfig>,
    pub genesis_time: u64,
    /// The most neighbors a node keeps in the gossip overlay. `FULL_FANOUT` keeps
    /// every pair connected; a smaller bound draws a ring lattice of that degree.
    pub fanout: usize,
    /// The one time slot count every validator tree is sized to for this devnet.
    /// `DEFAULT_SLOTS` keeps the consensus default; a harness that must finalise more
    /// heights than the default serves sets a larger count here, which flows into the
    /// committee sampler and the attester so the whole draw and verify path serves the
    /// larger count.
    pub slots: u64,
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
