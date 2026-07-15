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
//! try to finalize. It runs its own round on the logical clock over its own view,
//! and it stages at most one block per height, so it never attests a second and no
//! two nodes finalize different blocks at one height. The driver moves each sealed
//! record between the channels; the node never touches a channel itself.

use std::cell::RefCell;
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
use qtv_node::mempool::{Mempool, Reject};
use qtv_node::node::{execute_ordered, validator_address, Genesis};
use qtv_store::{BlockStore, StateStore};
use qtv_tx::Wrapper;

use crate::config::{DevnetConfig, NodeConfig};
use crate::wire::{Message, Proposal};

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
/// the attestations that finalize it.
struct Staged {
    view: View,
    header: Header,
    body: Vec<Wrapper>,
    block: ConsensusBlock,
    included_ids: Vec<String>,
}

/// One devnet node.
pub struct DevNode {
    id: u64,
    identity: Identity,
    ledger: Ledger,
    mempool: Mempool,
    consensus: Consensus,
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
    silent: bool,
    selection_cache: RefCell<Option<Selection>>,
    chain: Vec<FinalizedBlock>,
    slashed: Vec<u64>,
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
            consensus: Consensus::new(&validators),
            attester: Attester::new(node.id, node.stake),
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
            silent: false,
            selection_cache: RefCell::new(None),
            chain: Vec::new(),
            slashed: Vec::new(),
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
        self.state_store.commit(self.ledger.state_root())?;
        Ok(())
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
        Ok(())
    }

    /// Submit a transaction to this node. It is admitted only when valid, and an
    /// admitted transaction is queued to gossip to the peers.
    pub fn submit(&mut self, transaction: Wrapper) -> Result<(), Reject> {
        self.mempool
            .admit(transaction.clone(), &self.ledger, &self.fee_params)?;
        self.outbox.push(transaction);
        Ok(())
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

    /// Build the block for the current height from the mempool and stage it. The
    /// leader runs this, then gossips the returned proposal.
    pub fn build_proposal(&mut self, selection: &Selection) -> Proposal {
        let height = self.height;
        let proposer = validator_address(leader_for(selection, self.view));
        let candidates = self.mempool.candidates();
        let included = execute_ordered(&mut self.ledger, &candidates, &self.fee_params);
        let header = Header::new(
            height,
            self.parent_header_hash,
            self.ledger.state_root(),
            transaction_root(&included),
            empty_transaction_root(),
            *self.beacon.seed(),
            proposer,
            self.genesis_time + height * qtv_bft::params::SLOT_MS,
        );
        let block = ConsensusBlock::new(height, header_value(&header.hash()), self.parent_val);
        let included_ids = included.iter().map(Wrapper::id).collect();
        self.staged = Some(Staged {
            view: self.view,
            header: header.clone(),
            body: included.clone(),
            block,
            included_ids,
        });
        Proposal {
            view: self.view,
            header,
            body: included,
        }
    }

    /// Accept a gossiped proposal. The node executes the proposed body against its
    /// own state and rejects the proposal unless the whole body applies and the
    /// resulting roots and the parent link match the header. On acceptance the
    /// block is staged for attestation.
    pub fn accept_proposal(
        &mut self,
        selection: &Selection,
        proposal: &Proposal,
    ) -> Result<(), RoundError> {
        let header = &proposal.header;
        if proposal.view != self.view
            || header.height() != self.height
            || *header.parent_hash() != self.parent_header_hash
            || header.beacon_seed() != self.beacon.seed()
            || header.proposer() != validator_address(leader_for(selection, proposal.view))
        {
            return Err(RoundError::ProposalRejected);
        }
        let included = execute_ordered(&mut self.ledger, &proposal.body, &self.fee_params);
        if included.len() != proposal.body.len()
            || self.ledger.state_root() != *header.state_root()
            || transaction_root(&included) != *header.transaction_root()
        {
            return Err(RoundError::ProposalRejected);
        }
        let block = ConsensusBlock::new(self.height, header_value(&header.hash()), self.parent_val);
        let included_ids = included.iter().map(Wrapper::id).collect();
        self.staged = Some(Staged {
            view: proposal.view,
            header: header.clone(),
            body: proposal.body.clone(),
            block,
            included_ids,
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

        let cert_digest = certificate.digest();
        let attesters = certificate.attesters();
        let chain_block = ChainBlock::new(staged.header, cert_digest.to_vec(), staged.body);
        self.persist(&chain_block)?;

        self.beacon = self.beacon.advance(&cert_digest, self.height);
        self.parent_header_hash = chain_block.header_hash();
        self.parent_val = Parent::Value(header_value(&self.parent_header_hash));
        self.height += 1;
        self.view = 0;
        self.round_atts.clear();
        self.future_props.clear();
        *self.selection_cache.borrow_mut() = None;
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
        if leads && !self.silent {
            let current_stage = matches!(&self.staged, Some(staged) if staged.view == self.view);
            let proposal = if current_stage {
                let staged = self.staged.as_ref().expect("a current stage is present");
                Proposal {
                    view: staged.view,
                    header: staged.header.clone(),
                    body: staged.body.clone(),
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
        if proposal.header.height() != self.height
            || leader_for(selection, proposal.view) != from
            || proposal.view < self.view
        {
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
        let mut touched: Vec<String> = Vec::new();
        for wrapper in block.body() {
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

    /// The validators this node slashed. Only equivocation is slashable and none
    /// occurs here, so this is always empty and an offline node is never slashed.
    pub fn slashed(&self) -> &[u64] {
        &self.slashed
    }
}

/// Decode the header and the certificate digest from a stored block, the two
/// values a node needs to reconstruct its consensus state on reload. The body is
/// left unread since the ledger is rebuilt from the state store.
fn decode_head(bytes: &[u8]) -> Result<(Header, [u8; 32]), RoundError> {
    let mut decoder = Decoder::new(bytes);
    let header = Header::decode(&mut decoder).map_err(|_| RoundError::Decode)?;
    let certificate = decoder.get_bytes().map_err(|_| RoundError::Decode)?;
    let digest: [u8; 32] = certificate.try_into().map_err(|_| RoundError::Decode)?;
    Ok((header, digest))
}
