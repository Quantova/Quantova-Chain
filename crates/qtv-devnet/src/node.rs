//! One node of the devnet: its identity, its state and store, and its share of
//! the round.
//!
//! A node reuses the chain crates rather than forking them. It holds account
//! state in a qtv-state trie through the qtv-node ledger, admits transactions
//! through the qtv-node mempool, executes a block through the shared ordered
//! execution, selects the committee through the qtv-node consensus driver over
//! qtv-sampler, attests with its own module lattice key through qtv-attest, and
//! aggregates the entitled supermajority into a qtv-attest certificate. Every
//! finalized block and the account state behind it are persisted through
//! qtv-store, so a node reopened from disk rebuilds the exact chain it committed.
//!
//! The node exposes its round as event handlers the driver dispatches: enter the
//! current view, take a proposal, take an attestation, fire a view timeout, and
//! try to finalize. It runs its own round on the logical clock over its own view.
//! Staging a block is the lock: while locked the node does not attest a conflicting
//! block at a later view unless a proposal carries a higher view justification, a
//! quorum of view change records whose highest lock the block matches. Any two
//! quorums intersect, so a lock change never lets two conflicting blocks reach a
//! supermajority and no two nodes finalize different blocks at one height. The
//! driver moves each sealed record between the channels; the node never touches a
//! channel itself.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attestation, Attester};
use qtv_block::{empty_transaction_root, transaction_root, Block as ChainBlock, Header};
use qtv_codec::{to_bytes, Decoder};
use qtv_net::{Identity, PeerId};
use qtv_node::consensus::{
    genesis_beacon, header_value, Beacon, Block as ConsensusBlock, Consensus, ConsensusValidator,
    Parent, Selection,
};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{account_key, Account, Ledger};
use qtv_node::mempool::{Admitted, Mempool, Reject};
use qtv_node::node::{
    committee_weights, day_of_height, execute_ordered, validator_address, Genesis,
};
use qtv_store::{BlockStore, StateStore};
use qtv_tx::Wrapper;

use crate::config::{DevnetConfig, NodeConfig};
use crate::wire::{LockedBlock, Message, Proposal, ViewChange};

/// A chain height, the block number a node produces.
pub type Height = u64;

/// A view within a height. View zero holds the sampler elected leader; each
/// timeout advances the view and rotates the leader to the next committee member.
pub type View = u64;

/// The domain tag folded into a node network identity seed, separating the
/// transport identity key from any other key derived from the same id.
const NET_ID_DOMAIN: &[u8; 8] = b"QTVNETID";

/// The post-quantum network identity of a node, derived deterministically from
/// its consensus id so a peer can pin it across restarts.
pub fn net_identity(id: u64) -> Identity {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8..16].copy_from_slice(NET_ID_DOMAIN);
    Identity::from_seed(&seed)
}

/// The leader of a view, rotating the committee past the view-zero leader. View
/// zero is the sampler elected leader; each later view rotates to the next
/// committee member in id order, so a timeout routes around a silent or offline
/// leader to a fresh one. This mirrors the view indexed leader rotation of the
/// qtv-bft core, with the sampler election as the view-zero base.
pub fn leader_for(selection: &Selection, view: View) -> u64 {
    let members = &selection.members;
    let base = members
        .iter()
        .position(|&id| id == selection.leader)
        .unwrap_or(0);
    members[(base + view as usize) % members.len()]
}

/// A reason a round step failed.
#[derive(Debug)]
pub enum RoundError {
    /// A store read or write failed.
    Io(io::Error),
    /// A channel handshake or a record send or receive failed.
    Net(qtv_net::Error),
    /// The sortition admitted no committee for the height.
    NoCommittee,
    /// No entitled supermajority formed, so the block did not finalize.
    NotFinalized,
    /// A proposal did not reconcile with the node view of the height.
    ProposalRejected,
    /// A round step ran without a staged block.
    NotStaged,
    /// A stored block could not be decoded on reload.
    Decode,
    /// Erasure coding a proposal for dissemination refused it, which only a coding
    /// parameter out of range reaches and the parameters are derived in range.
    Coding(crate::coded::CodedError),
}

impl From<io::Error> for RoundError {
    fn from(error: io::Error) -> Self {
        RoundError::Io(error)
    }
}

impl From<qtv_net::Error> for RoundError {
    fn from(error: qtv_net::Error) -> Self {
        RoundError::Net(error)
    }
}

impl From<crate::coded::CodedError> for RoundError {
    fn from(error: crate::coded::CodedError) -> Self {
        RoundError::Coding(error)
    }
}

/// A reason a synced block was refused. A refused block never advances the
/// syncing node and the serving peer is not trusted for it, so a forged or
/// altered chain cannot be synced.
#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    /// The block is not the exact next height the node needs.
    WrongHeight,
    /// The block does not link to the node head by parent hash.
    WrongParent,
    /// The block carries a beacon seed other than the one the node holds for the
    /// height.
    WrongBeacon,
    /// The committee could not be selected for the height.
    NoCommittee,
    /// The certificate slot did not decode.
    BadCertificate,
    /// The certificate names a different subject than this exact block.
    WrongSubject,
    /// The certificate did not verify as an entitled supermajority under the
    /// committee commitment and the beacon.
    UnverifiedCertificate,
    /// Re-executing the body did not reproduce the header roots.
    WrongStateRoot,
    /// Persisting the accepted block failed.
    Io,
}

/// A finalized block a node holds: the chain block, the leader that proposed it,
/// and the attesters that finalized it.
pub struct FinalizedBlock {
    pub block: ChainBlock,
    pub leader: u64,
    pub attesters: Vec<u64>,
}

impl FinalizedBlock {
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

    /// The canonical encoding of the finalized block, the bytes two nodes compare
    /// to prove their chains are byte identical.
    pub fn encoded(&self) -> Vec<u8> {
        to_bytes(&self.block)
    }
}

/// The block a node has proposed or accepted for the current height, waiting for
/// the attestations that finalize it. Staging a block is the lock: the node holds
/// this block and the view it locked in, and it will not attest a conflicting
/// block at a later view without a justification. The resulting ledger is kept
/// here rather than committed to the node, so the node stays on its confirmed
/// state and a lock change re-executes the new block from that state cleanly.
struct Staged {
    view: View,
    header: Header,
    body: Vec<Wrapper>,
    block: ConsensusBlock,
    included_ids: Vec<String>,
    ledger: Ledger,
    /// The justification the block was accepted under, an empty set for a view
    /// zero block, re-offered so a late peer sees why the lock changed.
    justification: Vec<ViewChange>,
}

/// One devnet node.
pub struct DevNode {
    id: u64,
    identity: Identity,
    ledger: Ledger,
    mempool: Mempool,
    consensus: Consensus,
    base_validators: Vec<ConsensusValidator>,
    attester: Attester,
    fee_params: FeeParams,
    beacon: Beacon,
    height: Height,
    view: View,
    parent_header_hash: [u8; 32],
    parent_val: Parent,
    genesis_time: u64,
    block_store: BlockStore,
    state_store: StateStore,
    outbox: Vec<Wrapper>,
    staged: Option<Staged>,
    round_atts: Vec<Attestation>,
    future_props: Vec<Proposal>,
    view_changes: Vec<ViewChange>,
    silent: bool,
    selection_cache: RefCell<Option<Selection>>,
    chain: Vec<FinalizedBlock>,
    slashed: Vec<u64>,
    /// The finalised height of each transaction by its id, the index that lets the
    /// node answer whether a transaction landed and where without scanning the chain.
    /// It is grown as blocks finalise and rebuilt from the block store on reload.
    tx_index: HashMap<String, Height>,
    /// Arbitrary header notes to stamp by height, empty unless the operator sets
    /// them. When this node proposes a height that has an entry, the bytes go into
    /// the header's arbitrary data field exactly as given, a coinbase style note.
    block_messages: HashMap<u64, Vec<u8>>,
}

impl DevNode {
    /// Open a node from its configuration and the shared devnet genesis. An empty
    /// store is initialized from genesis; a store with finalized blocks reloads the
    /// ledger, the beacon, and the parent link from the last block, so a restarted
    /// node rejoins at the next height.
    pub fn open(node: &NodeConfig, devnet: &DevnetConfig) -> Result<DevNode, RoundError> {
        std::fs::create_dir_all(&node.store_dir)?;
        let block_store = BlockStore::open(node.store_dir.join("blocks.log"))?;
        let state_store = StateStore::open(node.store_dir.join("state.log"))?;

        let validators: Vec<ConsensusValidator> = devnet
            .validator_specs()
            .iter()
            .map(|v| ConsensusValidator {
                id: v.id,
                stake: v.stake,
                online: v.online,
            })
            .collect();

        let mut dev = DevNode {
            id: node.id,
            identity: net_identity(node.id),
            ledger: Ledger::new(),
            mempool: Mempool::new(),
            consensus: Consensus::with_slots(&validators, devnet.slots),
            base_validators: validators.clone(),
            attester: Attester::with_slots(node.id, node.stake, devnet.slots),
            fee_params: devnet.fee_params,
            beacon: genesis_beacon(),
            height: qtv_bft::params::MIN_HEIGHT,
            view: 0,
            parent_header_hash: [0u8; 32],
            parent_val: Parent::Genesis,
            genesis_time: devnet.genesis_time,
            block_store,
            state_store,
            outbox: Vec::new(),
            staged: None,
            round_atts: Vec::new(),
            future_props: Vec::new(),
            view_changes: Vec::new(),
            silent: false,
            selection_cache: RefCell::new(None),
            chain: Vec::new(),
            slashed: Vec::new(),
            tx_index: HashMap::new(),
            block_messages: HashMap::new(),
        };

        if dev.block_store.is_empty() {
            dev.init_genesis(&devnet.genesis())?;
        } else {
            dev.reload()?;
        }
        Ok(dev)
    }

    /// Fund the genesis accounts and persist them under the genesis state root.
    fn init_genesis(&mut self, genesis: &Genesis) -> Result<(), RoundError> {
        for account in &genesis.accounts {
            let funded =
                Account::funded(account.balance, account.scheme, account.public_key.clone());
            self.ledger.set_account(&account.address, &funded);
            self.state_store
                .put_account(account_key(&account.address), to_bytes(&funded))?;
        }
        let (pool_key, pool_value) = self.ledger.seed_stake_pool(qtv_staking::STAKING_POOL);
        self.state_store.put_account(pool_key, pool_value)?;
        for v in &self.base_validators {
            if let Some((bond_key, bond_value)) = self.ledger.seed_validator_bond(
                &validator_address(v.id),
                v.stake.saturating_mul(qtv_staking::NATIVE_UNIT as u64),
            ) {
                self.state_store.put_account(bond_key, bond_value)?;
            }
        }
        self.state_store.commit(self.ledger.state_root())?;
        self.refresh_committee();
        Ok(())
    }

    /// Rebuild the committee weight set from committed state. Each validator's
    /// weight is its live bonded stake on the ledger, so a bond, a slash, or an exit
    /// moves the committee weight with it at the next height. It is a pure function
    /// of committed state, so every node that has applied the same blocks rebuilds
    /// the identical set and draws the identical committee. It runs at genesis, on
    /// reload, and whenever the height advances, always over the state that is final
    /// for the parent height, and it holds the one time slot count fixed so the
    /// sortition keys stay valid across the rebuild.
    fn refresh_committee(&mut self) {
        self.consensus
            .reweight(&committee_weights(&self.ledger, &self.base_validators));
    }

    /// Rebuild the ledger, the beacon, and the parent link from the last finalized
    /// block on disk.
    fn reload(&mut self) -> Result<(), RoundError> {
        self.ledger = Ledger::from_trie(self.state_store.load_trie());
        let head = self.block_store.head_height().ok_or(RoundError::Decode)?;
        let bytes = self
            .block_store
            .block_by_height(head)
            .ok_or(RoundError::Decode)?
            .to_vec();
        let (header, cert_digest) = decode_head(&bytes)?;
        self.parent_header_hash = header.hash();
        self.parent_val = Parent::Value(header_value(&self.parent_header_hash));
        self.beacon = Beacon::from_seed(*header.beacon_seed()).advance(&cert_digest, head);
        self.height = head + 1;
        *self.selection_cache.borrow_mut() = None;
        self.refresh_committee();
        self.rebuild_tx_index(head);
        Ok(())
    }

    /// Rebuild the transaction index from the stored blocks up to the head height, so a
    /// restarted node answers for its whole persisted chain and not only for the blocks
    /// it finalises after reopening. The index is held in memory and this scan runs once
    /// at startup, which is fine for a bounded chain. A persistent index is the change
    /// to make when a chain outgrows a startup scan.
    fn rebuild_tx_index(&mut self, head: Height) {
        self.tx_index.clear();
        for height in qtv_bft::params::MIN_HEIGHT..=head {
            let decoded = self
                .block_store
                .block_by_height(height)
                .and_then(|bytes| crate::wire::chain_block_from_bytes(bytes).ok());
            if let Some(block) = decoded {
                for wrapper in block.body() {
                    self.tx_index.insert(wrapper.id(), height);
                }
            }
        }
    }

    /// Submit a transaction to this node. It is admitted only when valid. A fresh
    /// admission is queued to gossip to the peers; an idempotent resubmit of a
    /// transaction already held is reported as known and not gossiped a second time.
    pub fn submit(&mut self, transaction: Wrapper) -> Result<Admitted, Reject> {
        let admitted =
            self.mempool
                .admit(transaction.clone(), &self.ledger, &self.fee_params)?;
        if admitted == Admitted::Fresh {
            self.outbox.push(transaction);
        }
        Ok(admitted)
    }

    /// Submit a batch of transactions to this node in one parallel signature pre pass.
    /// The batch is admitted through the mempool's batched path, which verifies every
    /// signature across the cores and then admits the same transactions per transaction
    /// `admit` would, and the admitted transactions are queued to gossip in the order
    /// they were admitted, exactly the outbox bookkeeping `submit` does one at a time. So
    /// a batched submit leaves the same pool and the same gossip queue as submitting each
    /// transaction in turn, with the signatures verified in parallel.
    pub fn submit_batch(&mut self, batch: Vec<Wrapper>) {
        let admitted = self
            .mempool
            .admit_batch(batch, &self.ledger, &self.fee_params);
        self.outbox.extend(admitted);
    }

    /// Take the transactions queued to gossip since the last round.
    pub fn take_outbox(&mut self) -> Vec<Wrapper> {
        std::mem::take(&mut self.outbox)
    }

    /// Admit a transaction that arrived over the wire. A duplicate or an invalid
    /// transaction is dropped, and a gossiped transaction is not requeued, so it
    /// does not loop back around the mesh.
    pub fn admit_gossiped(&mut self, transaction: Wrapper) {
        let _ = self
            .mempool
            .admit(transaction, &self.ledger, &self.fee_params);
    }

    /// Admit a batch of transactions that arrived over the wire in one parallel signature
    /// pre pass. Duplicates and invalid transactions are dropped, and gossiped
    /// transactions are not requeued, so they do not loop back around the mesh. This is
    /// `admit_gossiped` over a whole batch: the mempool's batched path admits exactly the
    /// transactions the per transaction path would, with the signatures verified across
    /// the cores instead of one at a time.
    pub fn admit_gossiped_batch(&mut self, batch: Vec<Wrapper>) {
        let _ = self
            .mempool
            .admit_batch(batch, &self.ledger, &self.fee_params);
    }

    /// Select the committee and elect the leader for the current height. The
    /// selection is a pure function of the beacon and height, both fixed within a
    /// height, so it is cached and the sortition runs once per height rather than
    /// once per event. The cache is cleared when the height advances.
    pub fn select(&self) -> Result<Selection, RoundError> {
        if let Some(selection) = self.selection_cache.borrow().as_ref() {
            return Ok(selection.clone());
        }
        let selection = self
            .consensus
            .select(&self.beacon, self.height)
            .ok_or(RoundError::NoCommittee)?;
        *self.selection_cache.borrow_mut() = Some(selection.clone());
        Ok(selection)
    }

    /// Set the arbitrary header notes to stamp by height. When this node proposes a
    /// height that has an entry, the bytes go into the header's arbitrary data field
    /// exactly as given. Only heights present are stamped; every other height is left
    /// with an empty field. Entries longer than the header allows are dropped rather
    /// than stamped, so a note that would be refused never silently truncates.
    pub fn set_block_messages(&mut self, messages: HashMap<u64, Vec<u8>>) {
        self.block_messages = messages
            .into_iter()
            .filter(|(_, bytes)| bytes.len() <= qtv_block::MAX_EXTRA_DATA)
            .collect();
    }

    /// Build the block for the current height from the mempool and stage it. The
    /// leader runs this, then gossips the returned proposal.
    pub fn build_proposal(&mut self, selection: &Selection) -> Proposal {
        self.build_proposal_at(selection, self.view)
    }

    /// Build a fresh block for a given view and stage it. The body executes
    /// against a copy of the confirmed state, so the node's own ledger stays on
    /// the confirmed state until the block finalizes.
    fn build_proposal_at(&mut self, selection: &Selection, view: View) -> Proposal {
        let height = self.height;
        let proposer = validator_address(leader_for(selection, view));
        let candidates = self.mempool.candidates();
        let mut ledger = self.ledger.clone();
        let included = execute_ordered(&mut ledger, &candidates, &self.fee_params, day_of_height(height));
        let mut header = Header::new(
            height,
            self.parent_header_hash,
            ledger.state_root(),
            transaction_root(&included),
            empty_transaction_root(),
            *self.beacon.seed(),
            proposer,
            self.genesis_time + height * qtv_bft::params::SLOT_MS,
        );
        // Stamp the operator's note for this height, if any, into the header's
        // arbitrary data field. The set was filtered to the size limit, so this
        // never refuses; the bytes commit into the header hash and so into the block
        // id, retrievable from chain data unchanged.
        if let Some(note) = self.block_messages.get(&height) {
            let _ = header.set_extra_data(note.clone());
        }
        let block = ConsensusBlock::new(height, header_value(&header.hash()), self.parent_val);
        let included_ids = included.iter().map(Wrapper::id).collect();
        self.staged = Some(Staged {
            view,
            header: header.clone(),
            body: included.clone(),
            block,
            included_ids,
            ledger,
            justification: Vec::new(),
        });
        Proposal {
            view,
            header,
            body: included,
            justification: Vec::new(),
        }
    }

    /// Accept a gossiped proposal for the current view. The node checks the
    /// proposal came from the leader of its view, then stages the block. A
    /// justified later-view proposal takes a separate path.
    pub fn accept_proposal(
        &mut self,
        selection: &Selection,
        proposal: &Proposal,
    ) -> Result<(), RoundError> {
        let header = &proposal.header;
        if proposal.view != self.view
            || header.proposer() != validator_address(leader_for(selection, proposal.view))
        {
            return Err(RoundError::ProposalRejected);
        }
        self.stage_from(header, &proposal.body, proposal.view)
    }

    /// Execute a header and body against a copy of the confirmed state and stage
    /// the block when the whole body applies and the resulting roots and the
    /// parent link match the header. The confirmed ledger is untouched, so a lock
    /// change re-executes the new block from the same base without a rollback.
    fn stage_from(
        &mut self,
        header: &Header,
        body: &[Wrapper],
        view: View,
    ) -> Result<(), RoundError> {
        if header.height() != self.height
            || *header.parent_hash() != self.parent_header_hash
            || header.beacon_seed() != self.beacon.seed()
        {
            return Err(RoundError::ProposalRejected);
        }
        let mut ledger = self.ledger.clone();
        let included = execute_ordered(&mut ledger, body, &self.fee_params, day_of_height(header.height()));
        if included.len() != body.len()
            || ledger.state_root() != *header.state_root()
            || transaction_root(&included) != *header.transaction_root()
        {
            return Err(RoundError::ProposalRejected);
        }
        let block = ConsensusBlock::new(self.height, header_value(&header.hash()), self.parent_val);
        let included_ids = included.iter().map(Wrapper::id).collect();
        self.staged = Some(Staged {
            view,
            header: header.clone(),
            body: body.to_vec(),
            block,
            included_ids,
            ledger,
            justification: Vec::new(),
        });
        Ok(())
    }

    /// Attest the staged block with this node module lattice key. Only an online
    /// committee member calls this; it returns the attestation to gossip.
    pub fn attest(&self) -> Result<Attestation, RoundError> {
        let staged = self.staged.as_ref().ok_or(RoundError::NotStaged)?;
        Ok(self
            .attester
            .attest(self.height, self.height, staged.block, &self.beacon))
    }

    /// Aggregate the collected attestations into a certificate, commit the
    /// finalized block, persist it and the account state, and advance to the next
    /// height. The beacon advances from the certificate digest, so every node that
    /// aggregated the same attestations advances alike.
    pub fn finalize(
        &mut self,
        selection: &Selection,
        attestations: &[Attestation],
    ) -> Result<(), RoundError> {
        let block = self.staged.as_ref().ok_or(RoundError::NotStaged)?.block;
        let certificate = aggregate(
            self.height,
            self.height,
            block,
            &selection.commitment,
            &self.beacon,
            attestations,
        )
        .ok_or(RoundError::NotFinalized)?;
        // Aggregation admits only entitled attestations whose module lattice
        // signature verifies, so the certificate is verified by construction. The
        // staged block is taken only once a quorum aggregates, so a speculative
        // finalize that falls short leaves the stage intact for the next attestation.
        let staged = self.staged.take().expect("the staged block is present");

        // Adopt the state the staged block executed to as the confirmed state.
        self.ledger = staged.ledger;
        let cert_digest = certificate.digest();
        let attesters = certificate.attesters();
        let cert_slot = crate::wire::certificate_to_bytes(&certificate);
        let chain_block = ChainBlock::new(staged.header, cert_slot, staged.body);
        self.persist(&chain_block)?;

        self.beacon = self.beacon.advance(&cert_digest, self.height);
        self.parent_header_hash = chain_block.header_hash();
        self.parent_val = Parent::Value(header_value(&self.parent_header_hash));
        self.height += 1;
        self.view = 0;
        self.round_atts.clear();
        self.future_props.clear();
        self.view_changes.clear();
        *self.selection_cache.borrow_mut() = None;
        self.refresh_committee();
        self.mempool.remove_included(&staged.included_ids);
        self.chain.push(FinalizedBlock {
            block: chain_block,
            leader: leader_for(selection, staged.view),
            attesters,
        });
        Ok(())
    }

    /// Enter the current view of the current height. An online leader offers its
    /// proposal for the view, building it the first time and re-offering the same
    /// one on a later entry, so a peer that came online late still receives it. Any
    /// node that has staged a block re-offers its attestation, so the late peer
    /// collects the full set. A silent leader withholds its proposal but still
    /// attests, and an offline node offers nothing, so the view times out and
    /// rotates. Returns the messages to gossip.
    pub fn enter_round(&mut self, selection: &Selection, online: bool) -> Vec<Message> {
        if !online {
            return Vec::new();
        }
        let mut messages = Vec::new();
        let leads = leader_for(selection, self.view) == self.id;
        // A leader offers a fresh proposal at view zero, or re-offers its current
        // staged block. A later view offers a proposal only through the view change
        // justification, which the driver builds once the leader holds a quorum of
        // view change records, so a bare later proposal never splits a locked node.
        let current_stage = matches!(&self.staged, Some(staged) if staged.view == self.view);
        if leads && !self.silent && (self.view == 0 || current_stage) {
            let proposal = if current_stage {
                let staged = self.staged.as_ref().expect("a current stage is present");
                Proposal {
                    view: staged.view,
                    header: staged.header.clone(),
                    body: staged.body.clone(),
                    justification: staged.justification.clone(),
                }
            } else {
                self.build_proposal(selection)
            };
            messages.push(Message::Proposal(proposal));
        }
        if self.staged.is_some() {
            let attestation = self.attest().expect("the staged block attests");
            self.record_attestation(&attestation);
            messages.push(Message::Attest(Box::new(attestation)));
        }
        messages
    }

    /// Handle a proposal that arrived over the wire. A proposal for a later view is
    /// buffered until the node reaches that view; a stale, misrouted, or invalid
    /// proposal is dropped; a valid proposal for the current view is accepted,
    /// attested once, and the attestation is returned to gossip. The node stages at
    /// most one block per height, so it never attests a second block and safety
    /// holds under reordering and view changes.
    pub fn on_proposal(
        &mut self,
        selection: &Selection,
        from: u64,
        proposal: Proposal,
    ) -> Vec<Message> {
        if proposal.header.height() != self.height {
            return Vec::new();
        }
        // A proposal that carries a justification takes the lock change path: a
        // locked node may unlock and attest a conflicting block, but only under a
        // valid quorum for a higher view.
        if !proposal.justification.is_empty() {
            return self.on_justified_proposal(selection, proposal);
        }
        // A bare proposal follows the plain rule. A later view is buffered until the
        // node reaches it; a stale or misrouted one is dropped; and once locked the
        // node holds, so it never attests a second block on a bare proposal.
        if leader_for(selection, proposal.view) != from || proposal.view < self.view {
            return Vec::new();
        }
        if proposal.view > self.view {
            self.buffer_proposal(proposal);
            return Vec::new();
        }
        if self.staged.is_some() {
            return Vec::new();
        }
        if self.accept_proposal(selection, &proposal).is_err() {
            return Vec::new();
        }
        let attestation = self.attest().expect("the accepted block attests");
        self.record_attestation(&attestation);
        vec![Message::Attest(Box::new(attestation))]
    }

    /// Handle a justified proposal, the lock change path. The node accepts and
    /// attests the block, unlocking from any conflicting block it held, only when
    /// the proposal carries a valid justification: a quorum of view change records
    /// for the proposal's view, that view is not behind the node, and the proposed
    /// block is the one the justification selects, the locked block of the highest
    /// lock view, or a fresh block from the view's leader when no record is locked.
    /// This is the exact rule that unlocks a validator: a valid proposal that
    /// carries a higher view justification for the same height.
    fn on_justified_proposal(&mut self, selection: &Selection, proposal: Proposal) -> Vec<Message> {
        let view = proposal.view;
        if view < self.view {
            return Vec::new();
        }
        let Some(records) = self.valid_justification(selection, &proposal.justification, view)
        else {
            return Vec::new();
        };
        let proposed_value = header_value(&proposal.header.hash());
        match justified_choice(&records) {
            Some(locked) => {
                // The justification selects a locked block: the proposal must
                // re-propose exactly it, whatever view first proposed it.
                if header_value(&locked.header.hash()) != proposed_value {
                    return Vec::new();
                }
            }
            None => {
                // No record is locked: the leader of this view may offer a fresh
                // block, so it must be shaped by that leader.
                if *proposal.header.proposer() != validator_address(leader_for(selection, view)) {
                    return Vec::new();
                }
            }
        }
        if self
            .stage_from(&proposal.header, &proposal.body, view)
            .is_err()
        {
            return Vec::new();
        }
        if let Some(staged) = self.staged.as_mut() {
            staged.justification = proposal.justification;
        }
        self.view = view;
        self.future_props.clear();
        let attestation = self.attest().expect("the justified block attests");
        self.record_attestation(&attestation);
        vec![Message::Attest(Box::new(attestation))]
    }

    /// This node's view change record for a target view, reporting the block it is
    /// currently locked on so the leader that collects the quorum can re-propose it.
    /// The record is a module lattice attestation over a canonical view change
    /// subject, so it is entitlement checked and unforgeable exactly like a finality
    /// attestation.
    pub fn make_view_change(&self, target_view: View) -> ViewChange {
        let (lock_view, locked_value, has_lock, locked) = match &self.staged {
            Some(staged) => {
                let value = header_value(&staged.header.hash());
                let block = LockedBlock {
                    header: staged.header.clone(),
                    body: staged.body.clone(),
                };
                (staged.view, value, true, Some(block))
            }
            None => (0, [0u8; 32], false, None),
        };
        let subject =
            view_change_subject(self.height, target_view, lock_view, locked_value, has_lock);
        let att = self
            .attester
            .attest(self.height, self.height, subject, &self.beacon);
        ViewChange {
            height: self.height,
            target_view,
            lock_view,
            locked,
            att,
        }
    }

    /// Collect a view change record for the current height, once per signer and
    /// target view, keeping only records that verify as an entitled committee
    /// member's signed move to that view.
    pub fn collect_view_change(&mut self, selection: &Selection, record: ViewChange) {
        if record.height != self.height || !self.verify_view_change(selection, &record) {
            return;
        }
        let seen = self
            .view_changes
            .iter()
            .any(|r| r.att.from == record.att.from && r.target_view == record.target_view);
        if !seen {
            self.view_changes.push(record);
        }
    }

    /// Whether a view change record verifies: it is signed by an entitled committee
    /// member, and the signature binds the exact height, target view, lock view, and
    /// locked value the record carries, so neither the move nor the reported lock can
    /// be forged.
    fn verify_view_change(&self, selection: &Selection, record: &ViewChange) -> bool {
        let Some(member) = selection.commitment.member(record.att.from) else {
            return false;
        };
        let (has_lock, locked_value, lock_view) = match &record.locked {
            Some(block) => (true, header_value(&block.header.hash()), record.lock_view),
            None => (false, [0u8; 32], 0),
        };
        let subject = view_change_subject(
            record.height,
            record.target_view,
            lock_view,
            locked_value,
            has_lock,
        );
        if record.att.height != record.height
            || record.att.slot != record.height
            || record.att.block != subject
        {
            return false;
        }
        if !record.att.signature_verifies(&member.attest_pk) {
            return false;
        }
        record.att.is_entitled(
            &member.root,
            &self.beacon,
            member.weight,
            selection.commitment.total_weight,
            selection.commitment.budget,
        )
    }

    /// The verified quorum of view change records for a target view, or None when
    /// the collected records do not form a supermajority of distinct members. This
    /// is the justification: any two quorums of the committee intersect, so a
    /// justification for a view always overlaps the attesters of any block that
    /// finalized at a lower view, which is what keeps a lock change safe.
    fn valid_justification(
        &self,
        selection: &Selection,
        records: &[ViewChange],
        view: View,
    ) -> Option<Vec<ViewChange>> {
        let mut seen: Vec<u64> = Vec::new();
        let mut valid: Vec<ViewChange> = Vec::new();
        for record in records {
            if record.target_view != view || record.height != self.height {
                continue;
            }
            if !self.verify_view_change(selection, record) {
                continue;
            }
            if seen.contains(&record.att.from) {
                continue;
            }
            seen.push(record.att.from);
            valid.push(record.clone());
        }
        if qtv_bft::params::is_quorum(seen.len(), selection.commitment.len()) {
            Some(valid)
        } else {
            None
        }
    }

    /// Build the leader's justified proposal for a view once it holds a quorum of
    /// view change records, staging the block it proposes. The proposed block is the
    /// locked block of the highest lock view in the quorum, the fork choice over the
    /// non finalized frontier, or a fresh block when no member is locked. None when
    /// no quorum has formed yet.
    pub fn build_justified_proposal(
        &mut self,
        selection: &Selection,
        view: View,
    ) -> Option<Proposal> {
        let records = self.justified_records(selection, view)?;
        let proposal = match justified_choice(&records) {
            Some(locked) => {
                self.stage_from(&locked.header, &locked.body, view).ok()?;
                Proposal {
                    view,
                    header: locked.header,
                    body: locked.body,
                    justification: records.clone(),
                }
            }
            None => {
                let mut proposal = self.build_proposal_at(selection, view);
                proposal.justification = records.clone();
                proposal
            }
        };
        if let Some(staged) = self.staged.as_mut() {
            staged.justification = records;
        }
        Some(proposal)
    }

    /// The quorum of collected view change records for a view, if one has formed.
    /// The collected records were verified as they arrived, so this counts distinct
    /// members without re-verifying each signature.
    fn justified_records(&self, selection: &Selection, view: View) -> Option<Vec<ViewChange>> {
        let mut seen: Vec<u64> = Vec::new();
        let mut records: Vec<ViewChange> = Vec::new();
        for record in &self.view_changes {
            if record.target_view != view {
                continue;
            }
            if seen.contains(&record.att.from) {
                continue;
            }
            seen.push(record.att.from);
            records.push(record.clone());
        }
        if qtv_bft::params::is_quorum(seen.len(), selection.commitment.len()) {
            Some(records)
        } else {
            None
        }
    }

    /// Attest the staged block and record the attestation, returning it to gossip.
    /// The leader uses this to attest the block it just justified and proposed.
    pub fn attest_staged(&mut self) -> Option<Attestation> {
        let attestation = self.attest().ok()?;
        self.record_attestation(&attestation);
        Some(attestation)
    }

    /// The highest view for which the node has collected view change records from a
    /// blocking set of distinct members, `n - quorum + 1`, which guarantees at least
    /// one honest member genuinely reached that view. A node that sees this jumps to
    /// the view and adds its own record, so the committee converges on one view after
    /// a split, the view synchronization that restores liveness.
    pub fn view_sync_target(&self, selection: &Selection) -> Option<View> {
        let n = selection.commitment.len();
        let blocking = n - qtv_bft::params::supermajority(n) + 1;
        let mut views: Vec<View> = self.view_changes.iter().map(|r| r.target_view).collect();
        views.sort_unstable();
        views.dedup();
        views
            .into_iter()
            .rev()
            .find(|&view| self.distinct_view_changes(view) >= blocking)
    }

    /// The number of distinct members whose view change record for a view the node
    /// has collected. The records were verified on arrival, so this only counts.
    fn distinct_view_changes(&self, view: View) -> usize {
        let mut seen: Vec<u64> = Vec::new();
        for record in &self.view_changes {
            if record.target_view == view && !seen.contains(&record.att.from) {
                seen.push(record.att.from);
            }
        }
        seen.len()
    }

    /// Jump to a later view, keeping any lock. A node does this on seeing a blocking
    /// set of view change records for the view, so it joins the view change without
    /// abandoning the block it is locked on.
    pub fn jump_to(&mut self, view: View) {
        if view > self.view {
            self.view = view;
        }
    }

    /// The view of the currently staged block, if any.
    pub fn staged_view(&self) -> Option<View> {
        self.staged.as_ref().map(|staged| staged.view)
    }

    /// The consensus value of the currently staged block, the value the lock holds,
    /// if any. Two competing blocks at one height carry different values.
    pub fn staged_value(&self) -> Option<[u8; 32]> {
        self.staged
            .as_ref()
            .map(|staged| header_value(&staged.header.hash()))
    }

    /// Collect an attestation that arrived over the wire. It is kept for the current
    /// height regardless of the block it names; the finalize path aggregates only
    /// the ones over the staged block, so attestations may arrive reordered or ahead
    /// of the proposal.
    pub fn on_attestation(&mut self, attestation: Attestation) {
        if attestation.height == self.height {
            self.record_attestation(&attestation);
        }
    }

    /// Fire the view timeout. The view advances only when the node is still at that
    /// view and has seen no valid proposal to lock onto; a node that already staged a
    /// block waits for it to finalize rather than rotating, and a stale timer is
    /// ignored. Returns whether the view advanced.
    pub fn on_timeout(&mut self, view: View) -> bool {
        if self.view != view || self.staged.is_some() {
            return false;
        }
        self.view += 1;
        true
    }

    /// Take a buffered proposal for the current view, if one arrived ahead of the
    /// view change that reaches it.
    pub fn take_buffered_proposal(&mut self) -> Option<Proposal> {
        let pos = self.future_props.iter().position(|p| p.view == self.view)?;
        Some(self.future_props.remove(pos))
    }

    /// Whether the node has collected an attestation over its staged block from
    /// every listed signer. The driver passes the online committee, so a node
    /// finalizes only once every online member has attested. The certificate then
    /// carries the same set of attestations on every node and is byte identical,
    /// rather than the first quorum each node happened to see.
    pub fn has_attestations_from(&self, signers: &[u64]) -> bool {
        let Some(staged) = &self.staged else {
            return false;
        };
        signers.iter().all(|signer| {
            self.round_atts
                .iter()
                .any(|a| a.from == *signer && a.block == staged.block)
        })
    }

    /// Try to finalize the staged block from the attestations collected so far.
    /// Returns whether it finalized; a shortfall leaves the stage in place for more
    /// attestations, so this is safe to call after every message.
    pub fn try_finalize(&mut self, selection: &Selection) -> Result<bool, RoundError> {
        if self.staged.is_none() {
            return Ok(false);
        }
        let attestations = self.round_atts.clone();
        match self.finalize(selection, &attestations) {
            Ok(()) => Ok(true),
            Err(RoundError::NotFinalized) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Record an attestation for the current height, once per signer and block.
    fn record_attestation(&mut self, attestation: &Attestation) {
        let seen = self
            .round_atts
            .iter()
            .any(|a| a.from == attestation.from && a.block == attestation.block);
        if !seen {
            self.round_atts.push(attestation.clone());
        }
    }

    /// Buffer a proposal for a later view of the current height, once per view.
    fn buffer_proposal(&mut self, proposal: Proposal) {
        if !self.future_props.iter().any(|p| p.view == proposal.view) {
            self.future_props.push(proposal);
        }
    }

    /// The current view of the current height.
    pub fn view(&self) -> View {
        self.view
    }

    /// Make this node a silent leader: it withholds its proposal when it leads,
    /// modelling a present but unproductive leader that a timeout routes around. It
    /// still attests other leaders' blocks and is never slashed.
    pub fn set_silent(&mut self, silent: bool) {
        self.silent = silent;
    }

    /// Whether this node withholds its proposal when it leads.
    pub fn is_silent(&self) -> bool {
        self.silent
    }

    /// Persist a finalized block and the accounts it touched, then commit the new
    /// state root as the store head.
    fn persist(&mut self, block: &ChainBlock) -> Result<(), RoundError> {
        self.block_store.put_block(block)?;
        let height = block.header().height();
        let mut touched: Vec<String> = Vec::new();
        for wrapper in block.body() {
            // Index the transaction at the height it finalised, so the node can answer
            // whether it landed and where without scanning the chain.
            self.tx_index.insert(wrapper.id(), height);
            let sender = wrapper.body().sender().to_string();
            let recipient = wrapper.body().call().target().to_string();
            if !touched.contains(&sender) {
                touched.push(sender);
            }
            if !touched.contains(&recipient) {
                touched.push(recipient);
            }
        }
        for address in &touched {
            self.state_store.put_account(
                account_key(address),
                to_bytes(&self.ledger.account(address)),
            )?;
        }
        self.state_store.commit(self.ledger.state_root())?;
        Ok(())
    }

    /// The consensus id of the node.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The next height the node will produce.
    pub fn height(&self) -> Height {
        self.height
    }

    /// The network identity of the node.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The peer identity other nodes pin this node by.
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// The finalized blocks this node holds since it opened, in order.
    pub fn chain(&self) -> &[FinalizedBlock] {
        &self.chain
    }

    /// The hash of the last finalized header, the head the next block builds on.
    pub fn head_hash(&self) -> [u8; 32] {
        self.parent_header_hash
    }

    /// The account state.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The number of transactions waiting in the mempool.
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// The number of finalized blocks on disk.
    pub fn stored_blocks(&self) -> usize {
        self.block_store.len()
    }

    /// The finalised height of a transaction by its id, if this node holds it in its
    /// chain, or None if the node has never finalised it. This is the honest answer to
    /// whether a transaction landed and where. Because finality is a certificate, the
    /// height is absolute, not a confirmation count creeping toward certainty.
    pub fn finalized_height(&self, tx_id: &str) -> Option<Height> {
        self.tx_index.get(tx_id).copied()
    }

    /// Whether a transaction with this id is waiting in the mempool, the state between
    /// a submission being accepted and the block that finalises it.
    pub fn is_pending(&self, tx_id: &str) -> bool {
        self.mempool.contains(tx_id)
    }

    /// The finalised block at a height, if the node holds it.
    pub fn block_at_height(&self, height: Height) -> Option<ChainBlock> {
        self.serve_blocks(height, height).into_iter().next()
    }

    /// The finalised block with a given block id, if the node holds it. The id decodes
    /// to the header hash the block is stored under.
    pub fn block_by_id(&self, id: &str) -> Option<ChainBlock> {
        let payload = qtv_idfmt::parse_block(id).ok()?;
        let hash: [u8; 32] = payload.try_into().ok()?;
        let bytes = self.block_store.block_by_hash(&hash)?;
        crate::wire::chain_block_from_bytes(bytes).ok()
    }

    /// The validators this node slashed. Only equivocation is slashable and none
    /// occurs here, so this is always empty and an offline node is never slashed.
    pub fn slashed(&self) -> &[u64] {
        &self.slashed
    }

    /// The node finalized status, the next height it will produce. A peer learns
    /// this node is ahead when it names a greater height than the peer holds.
    pub fn sync_height(&self) -> Height {
        self.height
    }

    /// Serve the finalized blocks in the inclusive height range from the block
    /// store, each carrying its finality certificate in its certificate slot. A
    /// height the node has not finalized ends the range, so a peer never serves a
    /// gap it cannot fill.
    pub fn serve_blocks(&self, from: Height, to: Height) -> Vec<ChainBlock> {
        let mut blocks = Vec::new();
        let mut height = from;
        while height <= to {
            let Some(bytes) = self.block_store.block_by_height(height) else {
                break;
            };
            match crate::wire::chain_block_from_bytes(bytes) {
                Ok(block) => blocks.push(block),
                Err(_) => break,
            }
            height += 1;
        }
        blocks
    }

    /// Verify a finalized block received from a peer and, only if it fully checks
    /// out, commit it and advance to the next height. Nothing about the serving
    /// peer is trusted: the block is accepted only when its certificate verifies
    /// as an entitled supermajority of module lattice attestations over this exact
    /// block under the committee commitment and the beacon, its header links to the
    /// node head by parent hash, and re-executing its body against the node own
    /// state reproduces the header roots. A block that fails any check leaves the
    /// node untouched, so a forged or altered chain cannot advance it.
    pub fn apply_synced_block(&mut self, block: ChainBlock) -> Result<(), SyncError> {
        let header = block.header().clone();
        if header.height() != self.height {
            return Err(SyncError::WrongHeight);
        }
        if *header.parent_hash() != self.parent_header_hash {
            return Err(SyncError::WrongParent);
        }
        if header.beacon_seed() != self.beacon.seed() {
            return Err(SyncError::WrongBeacon);
        }
        let selection = self.select().map_err(|_| SyncError::NoCommittee)?;
        let certificate = crate::wire::certificate_from_bytes(block.certificate())
            .map_err(|_| SyncError::BadCertificate)?;
        let subject =
            ConsensusBlock::new(self.height, header_value(&header.hash()), self.parent_val);
        if certificate.envelope.height != self.height
            || certificate.envelope.slot != self.height
            || certificate.envelope.block != subject
        {
            return Err(SyncError::WrongSubject);
        }
        if !certificate
            .verify(&selection.commitment, &self.beacon)
            .is_verified()
        {
            return Err(SyncError::UnverifiedCertificate);
        }
        // Re-execute the body against a copy of the state, so a block that fails
        // the root check leaves the committed ledger untouched.
        let mut ledger = self.ledger.clone();
        let included = execute_ordered(&mut ledger, block.body(), &self.fee_params, day_of_height(header.height()));
        if included.len() != block.body().len()
            || ledger.state_root() != *header.state_root()
            || transaction_root(&included) != *header.transaction_root()
        {
            return Err(SyncError::WrongStateRoot);
        }

        // Every check passed: adopt the verified state and commit the block.
        self.ledger = ledger;
        self.persist(&block).map_err(|_| SyncError::Io)?;
        let cert_digest = certificate.digest();
        let leader = selection
            .members
            .iter()
            .copied()
            .find(|&id| validator_address(id) == *header.proposer())
            .unwrap_or(selection.leader);
        let attesters = certificate.attesters();
        let included_ids: Vec<String> = block.body().iter().map(Wrapper::id).collect();
        self.beacon = self.beacon.advance(&cert_digest, self.height);
        self.parent_header_hash = block.header_hash();
        self.parent_val = Parent::Value(header_value(&self.parent_header_hash));
        self.height += 1;
        self.view = 0;
        self.staged = None;
        self.round_atts.clear();
        self.future_props.clear();
        self.view_changes.clear();
        *self.selection_cache.borrow_mut() = None;
        self.refresh_committee();
        self.mempool.remove_included(&included_ids);
        self.chain.push(FinalizedBlock {
            block,
            leader,
            attesters,
        });
        Ok(())
    }
}

/// The canonical subject a view change record signs: a consensus block whose value
/// commits to the height, the target view, the lock view, and the locked value, all
/// under a domain tag that separates it from any finality block. Signing this with
/// the module lattice key binds the whole move and its reported lock, so a forged
/// record does not verify.
fn view_change_subject(
    height: Height,
    target_view: View,
    lock_view: View,
    locked_value: [u8; 32],
    has_lock: bool,
) -> ConsensusBlock {
    let mut buf = Vec::with_capacity(21 + 8 * 3 + 32 + 1);
    buf.extend_from_slice(b"QTV-DEVNET-VIEWCHANGE");
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(&target_view.to_le_bytes());
    buf.extend_from_slice(&lock_view.to_le_bytes());
    buf.extend_from_slice(&locked_value);
    buf.push(has_lock as u8);
    let commitment = qtv_bft::hash::digest_256(&buf);
    ConsensusBlock::new(height, commitment, Parent::Genesis)
}

/// The block a justification selects: the locked block of the highest lock view
/// among the quorum, ties broken by the smaller consensus value so every node picks
/// the same one. None when no member in the quorum is locked, in which case the
/// leader is free to offer a fresh block. This is the fork choice tie break.
fn justified_choice(records: &[ViewChange]) -> Option<LockedBlock> {
    records
        .iter()
        .filter_map(|record| {
            record
                .locked
                .as_ref()
                .map(|block| (record.lock_view, header_value(&block.header.hash()), block))
        })
        .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
        .map(|(_, _, block)| block.clone())
}

/// Decode the header and the certificate digest from a stored block, the two
/// values a node needs to reconstruct its consensus state on reload. The
/// certificate slot carries the whole finality certificate; its digest is what
/// the beacon advances over. The body is left unread since the ledger is rebuilt
/// from the state store.
fn decode_head(bytes: &[u8]) -> Result<(Header, [u8; 32]), RoundError> {
    let mut decoder = Decoder::new(bytes);
    let header = Header::decode(&mut decoder).map_err(|_| RoundError::Decode)?;
    let cert_slot = decoder.get_bytes().map_err(|_| RoundError::Decode)?;
    let certificate =
        crate::wire::certificate_from_bytes(cert_slot).map_err(|_| RoundError::Decode)?;
    Ok((header, certificate.digest()))
}
