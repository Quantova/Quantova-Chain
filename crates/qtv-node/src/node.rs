//! The node state transition and finalization loop.
//!
//! A node holds chain state, a mempool, a committee driver, and the chain of
//! finalized blocks. For a height it selects the committee, produces a block from
//! the mempool, executes each transaction through the virtual machine so the
//! block carries a real post execution state root, drives the committee through
//! attestation and aggregation into a finality certificate over the real header,
//! and on finalization commits the block and advances to the next height. The
//! whole loop runs in one process over direct calls.

use std::collections::BTreeMap;

use qtv_block::{Block as ChainBlock, Header};
use qtv_tx::Wrapper;

use crate::consensus::{header_value, Beacon, Consensus, ConsensusValidator, Parent};
use crate::execution::execute_transfer;
use crate::fee::FeeParams;
use crate::ledger::{Account, Ledger};
use crate::mempool::{validate, Mempool, Reject};
use crate::parallel::execute_parallel;

use qtv_attest::Certificate;

/// A validator in the genesis committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorSpec {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
}

impl ValidatorSpec {
    /// An online validator with the given native stake.
    pub fn online(id: u64, stake: u64) -> Self {
        ValidatorSpec {
            id,
            stake,
            online: true,
        }
    }

    /// An offline validator with the given native stake. It is still selected and
    /// is simply skipped when it would attest, and is never slashed.
    pub fn offline(id: u64, stake: u64) -> Self {
        ValidatorSpec {
            id,
            stake,
            online: false,
        }
    }
}

/// A funded genesis account, its balance and the public key a signature is
/// verified against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisAccount {
    pub address: String,
    pub balance: u64,
    pub scheme: u8,
    pub public_key: Vec<u8>,
}

impl GenesisAccount {
    /// A genesis account for a derived key account funded with a balance.
    pub fn from_account(account: &qtv_account::Account, balance: u64) -> Self {
        GenesisAccount {
            address: account.address(),
            balance,
            scheme: account.scheme(),
            public_key: account.public_key().to_vec(),
        }
    }
}

/// The genesis configuration of a node: the fee parameters, the funded accounts,
/// the validator committee, and the genesis time.
#[derive(Clone, Debug)]
pub struct Genesis {
    pub fee_params: FeeParams,
    pub accounts: Vec<GenesisAccount>,
    pub validators: Vec<ValidatorSpec>,
    pub genesis_time: u64,
}

/// A finalized block: the chain block, its finality certificate, and the record
/// of the leader, the committee size, and the attesters that finalized it.
pub struct Finalized {
    pub block: ChainBlock,
    pub certificate: Certificate,
    pub leader: u64,
    pub committee_size: usize,
    pub attesters: Vec<u64>,
}

impl Finalized {
    /// The finalized header.
    pub fn header(&self) -> &Header {
        self.block.header()
    }

    /// The header hash the certificate is bound to.
    pub fn header_hash(&self) -> [u8; 32] {
        self.block.header_hash()
    }

    /// The block id under the block family.
    pub fn id(&self) -> String {
        self.block.id()
    }

    /// The transaction ids in the finalized body, in order.
    pub fn transaction_ids(&self) -> Vec<String> {
        self.block.body().iter().map(Wrapper::id).collect()
    }

    /// Whether the finality certificate reconciles with the real header: the
    /// header hash folded to a word equals the value the certificate carries.
    pub fn reconciles(&self) -> bool {
        header_value(&self.header_hash()) == self.certificate.envelope.block.val
    }
}

/// The reason a height failed to produce a finalized block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProduceError {
    /// The sortition admitted no committee for the height.
    NoCommittee,
    /// No entitled supermajority formed, so the block did not finalize.
    NotFinalized,
}

/// Fold a validator id into a deterministic key seed for its genesis account,
/// separated from any other key use by a domain tag.
fn validator_seed(id: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8..15].copy_from_slice(b"QTVNODE");
    seed
}

/// The proposer address a validator signs blocks under, derived deterministically
/// from its consensus id. Every node computes the same address for a leader, so a
/// header built by one node hashes the same on every other.
pub fn validator_address(id: u64) -> String {
    qtv_account::derive(&validator_seed(id), 0).address()
}

/// Execute an ordered list of candidate transactions against the ledger. Each
/// candidate that validates and executes through the virtual machine has its post
/// execution balances and bumped nonce written back, and a candidate that no
/// longer validates or that faults is skipped. The included transactions are
/// returned in the order they applied. The leader runs this over its mempool
/// candidates to build a block, and every other node runs it over the proposed
/// body to reach the same post execution state root.
pub fn execute_ordered(
    ledger: &mut Ledger,
    candidates: &[Wrapper],
    fee_params: &FeeParams,
) -> Vec<Wrapper> {
    let mut included = Vec::new();
    for wrapper in candidates {
        let plan = match validate(wrapper, ledger, fee_params) {
            Ok(plan) => plan,
            Err(_) => continue,
        };
        let mut sender = ledger.account(&plan.sender);
        let mut recipient = ledger.account(&plan.recipient);
        let transferred = match execute_transfer(
            sender.balance,
            recipient.balance,
            plan.amount,
            plan.fee,
            wrapper.body().gas_limit(),
        ) {
            Ok(transferred) => transferred,
            Err(_) => continue,
        };
        sender.balance = transferred.sender_balance;
        sender.nonce += 1;
        recipient.balance = transferred.recipient_balance;
        ledger.set_account(&plan.sender, &sender);
        ledger.set_account(&plan.recipient, &recipient);
        included.push(wrapper.clone());
    }
    included
}

/// The node: the state transition and finalization loop over a fixed committee.
pub struct Node {
    ledger: Ledger,
    mempool: Mempool,
    consensus: Consensus,
    fee_params: FeeParams,
    validator_addresses: BTreeMap<u64, String>,
    beacon: Beacon,
    height: u64,
    parent_header_hash: [u8; 32],
    parent_val: Parent,
    genesis_time: u64,
    chain: Vec<Finalized>,
    slashed: Vec<u64>,
    exec_threads: usize,
}

impl Node {
    /// Build a node from its genesis configuration. Accounts are funded, the
    /// committee driver is built, and each validator is given a deterministic
    /// address for the proposer field.
    pub fn new(genesis: Genesis) -> Self {
        let mut ledger = Ledger::new();
        for account in &genesis.accounts {
            ledger.set_account(
                &account.address,
                &Account::funded(account.balance, account.scheme, account.public_key.clone()),
            );
        }

        let validators: Vec<ConsensusValidator> = genesis
            .validators
            .iter()
            .map(|v| ConsensusValidator {
                id: v.id,
                stake: v.stake,
                online: v.online,
            })
            .collect();
        let validator_addresses = genesis
            .validators
            .iter()
            .map(|v| (v.id, validator_address(v.id)))
            .collect();

        Node {
            ledger,
            mempool: Mempool::new(),
            consensus: Consensus::new(&validators),
            fee_params: genesis.fee_params,
            validator_addresses,
            beacon: crate::consensus::genesis_beacon(),
            height: qtv_bft::params::MIN_HEIGHT,
            parent_header_hash: [0u8; 32],
            parent_val: Parent::Genesis,
            genesis_time: genesis.genesis_time,
            chain: Vec::new(),
            slashed: Vec::new(),
            exec_threads: 1,
        }
    }

    /// Set how many cores the node executes a block across. One core is the
    /// sequential path. More than one runs transactions with disjoint state
    /// concurrently and serialises conflicting ones in block order, for the
    /// identical post state and root. A server class validator sets this to its
    /// core count to lift execution off the wall clock.
    pub fn set_parallelism(&mut self, threads: usize) {
        self.exec_threads = threads.max(1);
    }

    /// The node with its block execution set to run across the given cores. The
    /// builder form of `set_parallelism`.
    pub fn with_parallelism(mut self, threads: usize) -> Self {
        self.set_parallelism(threads);
        self
    }

    /// Submit a signed transaction to the mempool. It is admitted only when valid.
    pub fn submit(&mut self, transaction: Wrapper) -> Result<(), Reject> {
        self.mempool
            .admit(transaction, &self.ledger, &self.fee_params)
    }

    /// Produce and finalize the block at the current height. Transactions are
    /// executed through the virtual machine, the resulting state root is committed
    /// in the header, the committee finalizes over that header, and the node
    /// advances to the next height.
    pub fn produce(&mut self) -> Result<&Finalized, ProduceError> {
        let height = self.height;
        let slot = height;

        let selection = self
            .consensus
            .select(&self.beacon, slot)
            .ok_or(ProduceError::NoCommittee)?;
        let proposer = self
            .validator_addresses
            .get(&selection.leader)
            .cloned()
            .unwrap_or_default();

        let included = self.execute_block();
        let included_ids: Vec<String> = included.iter().map(Wrapper::id).collect();

        let state_root = self.ledger.state_root();
        let transaction_root = qtv_block::transaction_root(&included);
        let event_root = qtv_block::empty_transaction_root();
        let time = self.genesis_time + height * qtv_bft::params::SLOT_MS;

        let header = Header::new(
            height,
            self.parent_header_hash,
            state_root,
            transaction_root,
            event_root,
            *self.beacon.seed(),
            proposer,
            time,
        );
        let header_hash = header.hash();

        let value = header_value(&header_hash);
        let block = crate::consensus::Block::new(height, value, self.parent_val);

        let certificate = self
            .consensus
            .finalize(&selection, height, slot, block, &self.beacon)
            .ok_or(ProduceError::NotFinalized)?;
        debug_assert!(self
            .consensus
            .verify(&certificate, &selection, &self.beacon));

        let cert_digest = certificate.digest();
        let attesters = certificate.attesters();
        let chain_block = ChainBlock::new(header, cert_digest.to_vec(), included);

        let finalized = Finalized {
            block: chain_block,
            certificate,
            leader: selection.leader,
            committee_size: selection.commitment.len(),
            attesters,
        };

        self.beacon = self.beacon.advance(&cert_digest, height);
        self.parent_header_hash = header_hash;
        self.parent_val = Parent::Value(value);
        self.height += 1;
        self.mempool.remove_included(&included_ids);
        self.chain.push(finalized);

        Ok(self.chain.last().expect("a block was just finalized"))
    }

    /// Execute the mempool candidates against state in build order. With one core
    /// this is the sequential path; with more it is the parallel executor, which
    /// produces the identical post state and root while running transactions with
    /// disjoint state concurrently.
    fn execute_block(&mut self) -> Vec<Wrapper> {
        let candidates = self.mempool.candidates();
        if self.exec_threads > 1 {
            execute_parallel(
                &mut self.ledger,
                &candidates,
                &self.fee_params,
                self.exec_threads,
            )
        } else {
            execute_ordered(&mut self.ledger, &candidates, &self.fee_params)
        }
    }

    /// Produce a run of heights in order, stopping at the first that does not
    /// finalize.
    pub fn run(&mut self, heights: u64) -> Result<(), ProduceError> {
        for _ in 0..heights {
            self.produce()?;
        }
        Ok(())
    }

    /// The account state.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The next height the node will produce.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// The finalized chain in order.
    pub fn chain(&self) -> &[Finalized] {
        &self.chain
    }

    /// The number of transactions waiting in the mempool.
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// The validators slashed by the node. Only equivocation is slashable and none
    /// occurs in this in process slice, so this is always empty. An offline
    /// validator is never slashed.
    pub fn slashed(&self) -> &[u64] {
        &self.slashed
    }
}
