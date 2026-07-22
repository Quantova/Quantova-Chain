
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;

use qtv_attest::Attestation;
use qtv_block::{event_root, transaction_root, Block as ChainBlock, Header};
use qtv_codec::{to_bytes, Decoder};
use qtv_net::{Identity, PeerId};
use qtv_node::consensus::{
    genesis_beacon, header_value, Beacon, Block as ConsensusBlock, Consensus, Parent, Selection,
    ValidatorRegistration,
};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{account_key, Account, BlockEvent, Ledger};
use qtv_node::mempool::{Admitted, Mempool, Reject};
use qtv_node::node::{day_of_height, execute_ordered, reweigh_roster, Genesis};
use qtv_sampler::committee::PublishedReveal;
use qtv_store::{BlockStore, StateStore};
use qtv_tx::Wrapper;

use crate::config::{DevnetConfig, NodeConfig};
use crate::wire::{LockedBlock, Message, Proposal, RevealNote, ViewChange};

pub type Height = u64;

pub type View = u64;

/// A node's peer to peer identity, derived from the one secret the node holds. Only
/// the public peer id is ever published; the secret half never leaves the node and is
/// not recomputable from the public id.
pub fn p2p_identity(secret: &[u8; 32]) -> Identity {
    Identity::from_seed(&qtv_node::keys::p2p_identity_seed(secret))
}

/// The peer id of a published peer to peer identity public key. This is how a running
/// node pins a peer read from the genesis roster, never by recomputing it from an id.
pub fn peer_id_of(public: &qtv_crypto::ml_dsa::PublicKey) -> PeerId {
    PeerId::from_public(public)
}

/// The published public peer id of the node holding `secret`. This is the commitment
/// a peer pins against; it carries no secret and cannot be turned back into one.
pub fn p2p_peer_id(secret: &[u8; 32]) -> PeerId {
    p2p_identity(secret).peer_id()
}

/// The peer to peer identity of validator `id` under the gated fixture secret, for the
/// single process simulation and the local load test binaries only. A running node
/// builds its own identity from the secret in its keystore through `p2p_identity`, and
/// pins a peer by the peer id published in the roster, never by recomputing it from an
/// id. This convenience is absent from a default node build.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn node_identity(id: u64) -> Identity {
    p2p_identity(&qtv_node::keys::fixture_secret(id))
}

/// The published peer id of validator `id` under the gated fixture secret, for the
/// single process simulation and the local load test binaries only. Absent from a
/// default node build.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn node_peer_id(id: u64) -> PeerId {
    p2p_peer_id(&qtv_node::keys::fixture_secret(id))
}

pub fn leader_for(selection: &Selection, view: View) -> u64 {
    let members = &selection.members;
    let base = members
        .iter()
        .position(|&id| id == selection.leader)
        .unwrap_or(0);
    members[(base + view as usize) % members.len()]
}

#[derive(Debug)]
pub enum RoundError {
    Io(io::Error),
    Net(qtv_net::Error),
    NoCommittee,
    NotFinalized,
    ProposalRejected,
    NotStaged,
    Decode,
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

#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    WrongHeight,
    WrongParent,
    WrongBeacon,
    NoCommittee,
    BadCertificate,
    WrongSubject,
    UnverifiedCertificate,
    WrongStateRoot,
    Io,
}

pub struct FinalizedBlock {
    pub block: ChainBlock,
    pub leader: u64,
    pub attesters: Vec<u64>,
}

impl FinalizedBlock {
    pub fn header(&self) -> &Header {
        self.block.header()
    }

    pub fn header_hash(&self) -> [u8; 32] {
        self.block.header_hash()
    }

    pub fn id(&self) -> String {
        self.block.id()
    }

    pub fn encoded(&self) -> Vec<u8> {
        to_bytes(&self.block)
    }
}

struct Staged {
    view: View,
    header: Header,
    body: Vec<Wrapper>,
    block: ConsensusBlock,
    included_ids: Vec<String>,
    ledger: Ledger,
    justification: Vec<ViewChange>,
}

pub struct DevNode {
    id: u64,
    identity: Identity,
    ledger: Ledger,
    mempool: Mempool,
    consensus: Consensus,
    base_roster: Vec<ValidatorRegistration>,
    reveals: Vec<PublishedReveal>,
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
    tx_index: HashMap<String, Height>,
    events_by_height: HashMap<Height, Vec<BlockEvent>>,
    block_messages: HashMap<u64, Vec<u8>>,
}

impl DevNode {
    pub fn open(node: &NodeConfig, devnet: &DevnetConfig) -> Result<DevNode, RoundError> {
        std::fs::create_dir_all(&node.store_dir)?;
        let block_store = BlockStore::open(node.store_dir.join("blocks.log"))?;
        let state_store = StateStore::open(node.store_dir.join("state.log"))?;

        let roster: Vec<ValidatorRegistration> = devnet.roster();

        let secret = node.secret;
        let mut dev = DevNode {
            id: node.id,
            identity: p2p_identity(&secret),
            ledger: Ledger::new(),
            mempool: Mempool::new(),
            consensus: Consensus::with_slots(node.id, &secret, roster.clone(), devnet.slots),
            base_roster: roster,
            reveals: Vec::new(),
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
            events_by_height: HashMap::new(),
            block_messages: HashMap::new(),
        };

        if dev.block_store.is_empty() {
            dev.init_genesis(&devnet.genesis())?;
        } else {
            dev.reload()?;
        }
        Ok(dev)
    }

    fn init_genesis(&mut self, genesis: &Genesis) -> Result<(), RoundError> {
        let mut supply: u64 = 0;
        for account in &genesis.accounts {
            let funded =
                Account::funded(account.balance, account.scheme, account.public_key.clone());
            self.ledger.set_account(&account.address, &funded);
            self.state_store
                .put_account(account_key(&account.address), to_bytes(&funded))?;
            supply = supply.saturating_add(account.balance);
        }
        for (key, value) in self.ledger.seed_grants_account() {
            self.state_store.put_account(key, value)?;
        }
        let (pool_key, pool_value) = self.ledger.seed_stake_pool(qtv_staking::STAKING_POOL);
        self.state_store.put_account(pool_key, pool_value)?;
        supply = supply.saturating_add(qtv_staking::STAKING_POOL);
        let mut validator_ids: Vec<[u8; 32]> = Vec::new();
        for v in &self.base_roster {
            let address = &v.bond_address;
            let bond = v.stake.saturating_mul(qtv_staking::NATIVE_UNIT as u64);
            if let Some((bond_key, bond_value)) = self.ledger.seed_validator_bond(address, bond) {
                self.state_store.put_account(bond_key, bond_value)?;
                supply = supply.saturating_add(bond);
            }
            if let Ok(payload) = qtv_idfmt::parse_address(address) {
                if let Ok(id) = <[u8; 32]>::try_from(payload) {
                    validator_ids.push(id);
                }
            }
        }
        let (validators_key, validators_value) = self.ledger.seed_validator_set(&validator_ids);
        self.state_store.put_account(validators_key, validators_value)?;
        let (supply_key, supply_value) = self.ledger.seed_supply(supply);
        self.state_store.put_account(supply_key, supply_value)?;
        for (key, value) in self.ledger.take_dirty_entries() {
            self.state_store.put_account(key, value)?;
        }
        self.state_store.commit(self.ledger.state_root())?;
        self.ledger.clear_dirty();
        self.refresh_committee();
        Ok(())
    }

    fn refresh_committee(&mut self) {
        self.consensus
            .reweight(reweigh_roster(&self.ledger, &self.base_roster));
        self.reveals.clear();
        *self.selection_cache.borrow_mut() = None;
        self.record_own_reveal();
    }

    /// Record this node's own reveal for the current height when it is selected.
    fn record_own_reveal(&mut self) {
        if let Some(reveal) = self.consensus.published_self(&self.beacon, self.height) {
            if !self.reveals.iter().any(|r| r.id == reveal.id) {
                self.reveals.push(reveal);
                *self.selection_cache.borrow_mut() = None;
            }
        }
    }

    /// The ids of the validators whose reveal this node has collected for the height.
    pub fn collected_reveal_ids(&self) -> Vec<u64> {
        self.reveals.iter().map(|r| r.id).collect()
    }

    /// This node's own reveal for the current height, as a note to publish, when selected.
    pub fn own_reveal_note(&self) -> Option<RevealNote> {
        self.consensus
            .published_self(&self.beacon, self.height)
            .map(|reveal| RevealNote {
                height: self.height,
                id: reveal.id,
                credential: reveal.credential,
            })
    }

    /// Admit a peer reveal for the current height, verified against the peer's committed
    /// root. Reveals for another height, that do not authenticate, or duplicates are
    /// dropped.
    pub fn collect_reveal(&mut self, note: RevealNote) {
        if note.height != self.height {
            return;
        }
        let reveal = PublishedReveal::new(note.id, note.credential);
        if self.reveals.iter().any(|r| r.id == reveal.id) {
            return;
        }
        if !self.consensus.verify_published(&self.beacon, self.height, &reveal) {
            return;
        }
        self.reveals.push(reveal);
        *self.selection_cache.borrow_mut() = None;
    }

    fn reload(&mut self) -> Result<(), RoundError> {
        self.ledger = Ledger::from_trie(self.state_store.load_trie());
        let head = self.block_store.head_height().ok_or(RoundError::Decode)?;
        let bytes = self
            .block_store
            .block_by_height(head)
            .ok_or(RoundError::Decode)?
            .to_vec();
        let (header, certificate) = decode_head(&bytes)?;
        self.parent_header_hash = header.hash();
        self.parent_val = Parent::Value(header_value(&self.parent_header_hash));
        self.beacon = Beacon::from_seed(*header.beacon_seed());
        let selection = self
            .committee_for_certificate(head, &certificate)
            .ok_or(RoundError::Decode)?;
        self.beacon = self.beacon.advance_from_reveals(head, &selection.reveals);
        self.height = head + 1;
        *self.selection_cache.borrow_mut() = None;
        self.refresh_committee();
        self.rebuild_tx_index(head);
        Ok(())
    }

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

    pub fn submit(&mut self, transaction: Wrapper) -> Result<Admitted, Reject> {
        let admitted =
            self.mempool
                .admit(transaction.clone(), &self.ledger, &self.fee_params)?;
        if admitted == Admitted::Fresh {
            self.outbox.push(transaction);
        }
        Ok(admitted)
    }

    pub fn submit_batch(&mut self, batch: Vec<Wrapper>) {
        let admitted = self
            .mempool
            .admit_batch(batch, &self.ledger, &self.fee_params);
        self.outbox.extend(admitted);
    }

    pub fn take_outbox(&mut self) -> Vec<Wrapper> {
        std::mem::take(&mut self.outbox)
    }

    pub fn admit_gossiped(&mut self, transaction: Wrapper) {
        let _ = self
            .mempool
            .admit(transaction, &self.ledger, &self.fee_params);
    }

    pub fn admit_gossiped_batch(&mut self, batch: Vec<Wrapper>) {
        let _ = self
            .mempool
            .admit_batch(batch, &self.ledger, &self.fee_params);
    }

    /// The committee for the current height, assembled from the reveals collected so far
    /// and cached until a new reveal is admitted or the height advances.
    pub fn select(&self) -> Result<Selection, RoundError> {
        if let Some(selection) = self.selection_cache.borrow().as_ref() {
            return Ok(selection.clone());
        }
        let selection = self
            .consensus
            .select(&self.beacon, self.height, &self.reveals)
            .ok_or(RoundError::NoCommittee)?;
        *self.selection_cache.borrow_mut() = Some(selection.clone());
        Ok(selection)
    }

    pub fn set_block_messages(&mut self, messages: HashMap<u64, Vec<u8>>) {
        self.block_messages = messages
            .into_iter()
            .filter(|(_, bytes)| bytes.len() <= qtv_block::MAX_EXTRA_DATA)
            .collect();
    }

    pub fn build_proposal(&mut self, selection: &Selection) -> Proposal {
        self.build_proposal_at(selection, self.view)
    }

    fn build_proposal_at(&mut self, selection: &Selection, view: View) -> Proposal {
        let height = self.height;
        let proposer = self.validator_address(leader_for(selection, view));
        let candidates = self.mempool.candidates();
        let mut ledger = self.ledger.clone();
        ledger.clear_block_events();
        ledger.set_round_proposer(&proposer);
        let included = execute_ordered(&mut ledger, &candidates, &self.fee_params, day_of_height(height));
        let event_leaves: Vec<Vec<u8>> = ledger.block_events().iter().map(BlockEvent::encode).collect();
        let mut header = Header::new(
            height,
            self.parent_header_hash,
            ledger.state_root(),
            transaction_root(&included),
            event_root(&event_leaves),
            *self.beacon.seed(),
            proposer,
            self.genesis_time + height * qtv_bft::params::SLOT_MS,
        );
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

    pub fn accept_proposal(
        &mut self,
        selection: &Selection,
        proposal: &Proposal,
    ) -> Result<(), RoundError> {
        let header = &proposal.header;
        if proposal.view != self.view
            || *header.proposer() != self.validator_address(leader_for(selection, proposal.view))
        {
            return Err(RoundError::ProposalRejected);
        }
        self.stage_from(header, &proposal.body, proposal.view)
    }

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
        ledger.clear_block_events();
        ledger.set_round_proposer(header.proposer());
        let included = execute_ordered(&mut ledger, body, &self.fee_params, day_of_height(header.height()));
        let event_leaves: Vec<Vec<u8>> = ledger.block_events().iter().map(BlockEvent::encode).collect();
        if included.len() != body.len()
            || ledger.state_root() != *header.state_root()
            || transaction_root(&included) != *header.transaction_root()
            || event_root(&event_leaves) != *header.event_root()
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

    pub fn attest(&self) -> Result<Attestation, RoundError> {
        let staged = self.staged.as_ref().ok_or(RoundError::NotStaged)?;
        Ok(self
            .consensus
            .own_attestation(self.height, self.height, staged.block, &self.beacon))
    }

    pub fn finalize(
        &mut self,
        selection: &Selection,
        attestations: &[Attestation],
    ) -> Result<(), RoundError> {
        let block = self.staged.as_ref().ok_or(RoundError::NotStaged)?.block;
        let certificate = self
            .consensus
            .finalize(
                selection,
                self.height,
                self.height,
                block,
                &self.beacon,
                attestations,
            )
            .ok_or(RoundError::NotFinalized)?;
        let staged = self.staged.take().expect("the staged block is present");

        self.ledger = staged.ledger;
        let block_events = self.ledger.block_events().to_vec();
        if !block_events.is_empty() {
            self.events_by_height.insert(self.height, block_events);
        }
        let attesters = certificate.attesters();
        let cert_slot = crate::wire::certificate_to_bytes(&certificate);
        let chain_block = ChainBlock::new(staged.header, cert_slot, staged.body);
        self.persist(&chain_block)?;

        self.beacon = self
            .beacon
            .advance_from_reveals(self.height, &selection.reveals);
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

    pub fn enter_round(&mut self, selection: &Selection, online: bool) -> Vec<Message> {
        if !online {
            return Vec::new();
        }
        let mut messages = Vec::new();
        let leads = leader_for(selection, self.view) == self.id;
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

    pub fn on_proposal(
        &mut self,
        selection: &Selection,
        from: u64,
        proposal: Proposal,
    ) -> Vec<Message> {
        if proposal.header.height() != self.height {
            return Vec::new();
        }
        if !proposal.justification.is_empty() {
            return self.on_justified_proposal(selection, proposal);
        }
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
                if header_value(&locked.header.hash()) != proposed_value {
                    return Vec::new();
                }
            }
            None => {
                if *proposal.header.proposer() != self.validator_address(leader_for(selection, view)) {
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
            .consensus
            .own_attestation(self.height, self.height, subject, &self.beacon);
        ViewChange {
            height: self.height,
            target_view,
            lock_view,
            locked,
            att,
        }
    }

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
        if seen.len() as u64 >= selection.tau {
            Some(valid)
        } else {
            None
        }
    }

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
        if seen.len() as u64 >= selection.tau {
            Some(records)
        } else {
            None
        }
    }

    pub fn attest_staged(&mut self) -> Option<Attestation> {
        let attestation = self.attest().ok()?;
        self.record_attestation(&attestation);
        Some(attestation)
    }

    pub fn view_sync_target(&self, selection: &Selection) -> Option<View> {
        let blocking = (selection.expected - selection.tau + 1) as usize;
        let mut views: Vec<View> = self.view_changes.iter().map(|r| r.target_view).collect();
        views.sort_unstable();
        views.dedup();
        views
            .into_iter()
            .rev()
            .find(|&view| self.distinct_view_changes(view) >= blocking)
    }

    fn distinct_view_changes(&self, view: View) -> usize {
        let mut seen: Vec<u64> = Vec::new();
        for record in &self.view_changes {
            if record.target_view == view && !seen.contains(&record.att.from) {
                seen.push(record.att.from);
            }
        }
        seen.len()
    }

    pub fn jump_to(&mut self, view: View) {
        if view > self.view {
            self.view = view;
        }
    }

    pub fn staged_view(&self) -> Option<View> {
        self.staged.as_ref().map(|staged| staged.view)
    }

    pub fn staged_value(&self) -> Option<[u8; 32]> {
        self.staged
            .as_ref()
            .map(|staged| header_value(&staged.header.hash()))
    }

    pub fn on_attestation(&mut self, attestation: Attestation) {
        if attestation.height == self.height {
            self.record_attestation(&attestation);
        }
    }

    pub fn on_timeout(&mut self, view: View) -> bool {
        if self.view != view || self.staged.is_some() {
            return false;
        }
        self.view += 1;
        true
    }

    pub fn take_buffered_proposal(&mut self) -> Option<Proposal> {
        let pos = self.future_props.iter().position(|p| p.view == self.view)?;
        Some(self.future_props.remove(pos))
    }

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

    fn record_attestation(&mut self, attestation: &Attestation) {
        let seen = self
            .round_atts
            .iter()
            .any(|a| a.from == attestation.from && a.block == attestation.block);
        if !seen {
            self.round_atts.push(attestation.clone());
        }
    }

    fn buffer_proposal(&mut self, proposal: Proposal) {
        if !self.future_props.iter().any(|p| p.view == proposal.view) {
            self.future_props.push(proposal);
        }
    }

    pub fn view(&self) -> View {
        self.view
    }

    pub fn set_silent(&mut self, silent: bool) {
        self.silent = silent;
    }

    pub fn is_silent(&self) -> bool {
        self.silent
    }

    fn persist(&mut self, block: &ChainBlock) -> Result<(), RoundError> {
        self.block_store.put_block(block)?;
        let height = block.header().height();
        for wrapper in block.body() {
            self.tx_index.insert(wrapper.id(), height);
        }
        for (key, value) in self.ledger.take_dirty_entries() {
            self.state_store.put_account(key, value)?;
        }
        self.state_store.commit(self.ledger.state_root())?;
        Ok(())
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// The committed bond and reward address of validator `id`, read from the roster
    /// this node holds. The address is a commitment; it is never recomputed from the
    /// id.
    fn validator_address(&self, id: u64) -> String {
        self.base_roster
            .iter()
            .find(|v| v.id == id)
            .map(|v| v.bond_address.clone())
            .unwrap_or_default()
    }

    /// Reconstruct the committee a finalized block was formed over from the reveals its
    /// certificate carries, adding this node's own reveal when needed, and accept it only
    /// when its committee digest matches the one the certificate commits to.
    fn committee_for_certificate(
        &self,
        height: u64,
        certificate: &qtv_attest::Certificate,
    ) -> Option<Selection> {
        let target = certificate.envelope.committee;
        let mut reveals: Vec<PublishedReveal> = certificate
            .attestations
            .iter()
            .map(|att| PublishedReveal::new(att.from, att.membership.clone()))
            .collect();
        if let Some(selection) = self.consensus.select(&self.beacon, height, &reveals) {
            if selection.commitment.digest() == target {
                return Some(selection);
            }
        }
        if let Some(mine) = self.consensus.published_self(&self.beacon, height) {
            if !reveals.iter().any(|r| r.id == mine.id) {
                reveals.push(mine);
            }
        }
        let selection = self.consensus.select(&self.beacon, height, &reveals)?;
        (selection.commitment.digest() == target).then_some(selection)
    }

    pub fn height(&self) -> Height {
        self.height
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    pub fn chain(&self) -> &[FinalizedBlock] {
        &self.chain
    }

    pub fn head_hash(&self) -> [u8; 32] {
        self.parent_header_hash
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    pub fn stored_blocks(&self) -> usize {
        self.block_store.len()
    }

    pub fn finalized_height(&self, tx_id: &str) -> Option<Height> {
        self.tx_index.get(tx_id).copied()
    }

    pub fn is_pending(&self, tx_id: &str) -> bool {
        self.mempool.contains(tx_id)
    }

    pub fn pending_transactions(&self) -> Vec<Wrapper> {
        self.mempool.candidates()
    }

    pub fn events_at(&self, height: Height) -> Vec<BlockEvent> {
        self.events_by_height.get(&height).cloned().unwrap_or_default()
    }

    pub fn block_at_height(&self, height: Height) -> Option<ChainBlock> {
        self.serve_blocks(height, height).into_iter().next()
    }

    pub fn block_by_id(&self, id: &str) -> Option<ChainBlock> {
        let payload = qtv_idfmt::parse_block(id).ok()?;
        let hash: [u8; 32] = payload.try_into().ok()?;
        let bytes = self.block_store.block_by_hash(&hash)?;
        crate::wire::chain_block_from_bytes(bytes).ok()
    }

    pub fn slashed(&self) -> &[u64] {
        &self.slashed
    }

    pub fn sync_height(&self) -> Height {
        self.height
    }

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
        let selection = self
            .committee_for_certificate(self.height, &certificate)
            .ok_or(SyncError::NoCommittee)?;
        if !certificate
            .verify(&selection.commitment, &self.beacon, selection.tau)
            .is_verified()
        {
            return Err(SyncError::UnverifiedCertificate);
        }
        let mut ledger = self.ledger.clone();
        ledger.clear_block_events();
        ledger.set_round_proposer(header.proposer());
        let included = execute_ordered(&mut ledger, block.body(), &self.fee_params, day_of_height(header.height()));
        let event_leaves: Vec<Vec<u8>> = ledger.block_events().iter().map(BlockEvent::encode).collect();
        if included.len() != block.body().len()
            || ledger.state_root() != *header.state_root()
            || transaction_root(&included) != *header.transaction_root()
            || event_root(&event_leaves) != *header.event_root()
        {
            return Err(SyncError::WrongStateRoot);
        }

        self.ledger = ledger;
        let block_events = self.ledger.block_events().to_vec();
        if !block_events.is_empty() {
            self.events_by_height.insert(self.height, block_events);
        }
        self.persist(&block).map_err(|_| SyncError::Io)?;
        let leader = selection
            .members
            .iter()
            .copied()
            .find(|&id| self.validator_address(id) == *header.proposer())
            .unwrap_or(selection.leader);
        let attesters = certificate.attesters();
        let included_ids: Vec<String> = block.body().iter().map(Wrapper::id).collect();
        self.beacon = self
            .beacon
            .advance_from_reveals(self.height, &selection.reveals);
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

fn decode_head(bytes: &[u8]) -> Result<(Header, qtv_attest::Certificate), RoundError> {
    let mut decoder = Decoder::new(bytes);
    let header = Header::decode(&mut decoder).map_err(|_| RoundError::Decode)?;
    let cert_slot = decoder.get_bytes().map_err(|_| RoundError::Decode)?;
    let certificate =
        crate::wire::certificate_from_bytes(cert_slot).map_err(|_| RoundError::Decode)?;
    Ok((header, certificate))
}
