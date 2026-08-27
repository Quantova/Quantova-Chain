// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;

use qtv_attest::committee::CommitteeDigest;
use qtv_attest::{Attestation, Certificate};
use qtv_block::{event_root, transaction_root, Block as ChainBlock, Header};
use qtv_codec::{to_bytes, Decoder};
use qtv_net::{Identity, PeerId};
use qtv_node::consensus::{
    genesis_beacon, header_value, Beacon, Block as ConsensusBlock, Consensus, FinalityLedger,
    FinalityStatus, Parent, Selection, ValidatorRegistration,
};
use qtv_node::evidence::{Equivocation, EvidencePool};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{
    account_key, evidence_address, registration_address, Account, BlockEvent, Ledger, SideEvent,
    EVENT_BRIDGE_BURN, NATIVE_EVENT_SOURCE,
};
use qtv_node::mempool::{Admitted, Mempool, Reject};
use qtv_node::node::{day_of_height, execute_ordered, reweigh_roster, Genesis, GenesisAccount};
use qtv_node::watermark::SignGuard;
use qtv_sampler::committee::PublishedReveal;
use qtv_store::{BlockStore, BurnArchive, BurnArchiveEntry, StateStore};
use qtv_tx::{Body, Call, Wrapper};

use crate::config::{DevnetConfig, NodeConfig};
use crate::wire::{
    decode_register_note, encode_register_note, LockedBlock, Message, Proposal, RegisterNote,
    RevealNote, ViewChange,
};
use qtv_sampler::onetime::Root;

pub type Height = u64;

pub type View = u64;

pub fn p2p_identity(secret: &[u8; 32]) -> Identity {
    Identity::from_seed(&qtv_node::keys::p2p_identity_seed(secret))
}

pub fn peer_id_of(public: &qtv_crypto::ml_dsa::PublicKey) -> PeerId {
    PeerId::from_public(public)
}

pub fn p2p_peer_id(secret: &[u8; 32]) -> PeerId {
    p2p_identity(secret).peer_id()
}

#[cfg(any(test, feature = "test-fixtures"))]
pub fn node_identity(id: u64) -> Identity {
    p2p_identity(&qtv_node::keys::fixture_secret(id))
}

#[cfg(any(test, feature = "test-fixtures"))]
pub fn node_peer_id(id: u64) -> PeerId {
    p2p_peer_id(&qtv_node::keys::fixture_secret(id))
}

pub fn leader_for(selection: &Selection, view: View) -> u64 {
    let members = &selection.members;
    if members.is_empty() {
        return selection.leader;
    }
    let base = members
        .iter()
        .position(|&id| id == selection.leader)
        .unwrap_or(0);
    let offset = (view % members.len() as u64) as usize;
    members[(base + offset) % members.len()]
}

const GENESIS_COMMIT_HEIGHT: Height = 0;

const MAX_ROUND_ATTESTATIONS: usize = 8192;
const MAX_RELAY_BLOCKS_PER_VIEW: usize = 2;
const MAX_RELAY_BUCKETS: usize = 1 << 16;

const MAX_ATTESTATIONS_PER_SENDER: usize = 64;

const MAX_FUTURE_PROPOSALS: usize = 256;

const MAX_VIEW_CHANGES_PER_SENDER: usize = 64;

const MAX_SERVE_BLOCKS: u64 = 256;

#[derive(Debug)]
pub enum RoundError {
    Io(io::Error),
    Net(qtv_net::Error),
    NoCommittee,
    NotFinalized,
    ProposalRejected,
    NotStaged,
    Decode,
    StateRootMismatch {
        height: Height,
        block_root: [u8; 32],
        state_root: Option<[u8; 32]>,
    },
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
    CheckpointConflict,
    FinalityViolation,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: Height,
    pub value: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fatal {
    DoubleSignRefused {
        height: Height,
        view: View,
    },
    FinalityViolation {
        height: Height,
        finalized: [u8; 32],
        conflicting: [u8; 32],
    },
    PersistFailed {
        height: Height,
    },
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

struct Lock {
    view: View,
    value: [u8; 32],
    block: LockedBlock,
    polka: Certificate,
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
    burn_archive: BurnArchive,
    outbox: Vec<Wrapper>,
    staged: Option<Staged>,
    lock: Option<Lock>,
    round_atts: Vec<Attestation>,
    attest_relayed: std::collections::HashMap<(u64, u64), std::collections::HashSet<Vec<u8>>>,
    prevotes: Vec<Attestation>,
    future_props: Vec<Proposal>,
    view_changes: Vec<ViewChange>,
    silent: bool,
    selection_cache: RefCell<Option<Selection>>,
    chain: Vec<FinalizedBlock>,
    slashed: Vec<u64>,
    tx_index: HashMap<String, Height>,
    events_by_height: HashMap<Height, Vec<BlockEvent>>,
    side_events_by_height: HashMap<Height, Vec<SideEvent>>,
    block_messages: HashMap<u64, Vec<u8>>,
    epoch_roots: HashMap<u64, Root>,
    epoch_notes: HashMap<u64, RegisterNote>,
    epoch_conflicted: HashSet<u64>,
    epoch_conflict_notes: Vec<RegisterNote>,
    sign_guard: SignGuard,
    finality: FinalityLedger,
    guarded_height: Option<Height>,
    fatal: Option<Fatal>,
    checkpoint: Option<Checkpoint>,
    evidence_pool: EvidencePool,
    genesis_accounts: Vec<GenesisAccount>,
    genesis_supply: u64,
}

fn genesis_supply_value(genesis: &Genesis, roster: &[ValidatorRegistration]) -> u64 {
    let mut supply: u64 = 0;
    for account in &genesis.accounts {
        supply = supply.saturating_add(account.balance);
    }
    supply = supply.saturating_add(qtv_staking::STAKING_POOL);
    for v in roster {
        let bond = v.stake.saturating_mul(qtv_staking::NATIVE_UNIT as u64);
        supply = supply.saturating_add(bond);
    }
    supply
}

impl DevNode {
    pub fn open(node: &NodeConfig, devnet: &DevnetConfig) -> Result<DevNode, RoundError> {
        std::fs::create_dir_all(&node.store_dir)?;
        let block_store = BlockStore::open(node.store_dir.join("blocks.log"))?;
        let state_store = StateStore::open(node.store_dir.join("state.log"))?;
        let burn_archive = BurnArchive::open(node.store_dir.join("burns.log"))?;
        let sign_guard = SignGuard::open(node.store_dir.join("sign.watermark"))?;

        let roster: Vec<ValidatorRegistration> = devnet.roster();

        let genesis = devnet.genesis();
        let genesis_accounts = genesis.accounts.clone();
        let genesis_supply = genesis_supply_value(&genesis, &roster);

        let secret = node.secret;
        let mut dev = DevNode {
            id: node.id,
            identity: p2p_identity(&secret),
            ledger: Ledger::new(),
            mempool: Mempool::new(),
            consensus: Consensus::with_slots(
                devnet.fee_params.chain_id,
                node.id,
                &secret,
                roster.clone(),
                devnet.slots,
            ),
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
            burn_archive,
            outbox: Vec::new(),
            staged: None,
            lock: None,
            round_atts: Vec::new(),
            attest_relayed: std::collections::HashMap::new(),
            prevotes: Vec::new(),
            future_props: Vec::new(),
            view_changes: Vec::new(),
            silent: false,
            selection_cache: RefCell::new(None),
            chain: Vec::new(),
            slashed: Vec::new(),
            tx_index: HashMap::new(),
            events_by_height: HashMap::new(),
            side_events_by_height: HashMap::new(),
            block_messages: HashMap::new(),
            epoch_roots: HashMap::new(),
            epoch_notes: HashMap::new(),
            epoch_conflicted: HashSet::new(),
            epoch_conflict_notes: Vec::new(),
            sign_guard,
            finality: FinalityLedger::new(),
            guarded_height: None,
            fatal: None,
            checkpoint: None,
            evidence_pool: EvidencePool::new(),
            genesis_accounts,
            genesis_supply,
        };

        if let Some(committed) = dev.state_store.committed_height() {
            dev.block_store.truncate_to_height(committed)?;
        }

        if dev.block_store.is_empty() {
            dev.init_genesis(&genesis)?;
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
            if let Some((attest_key, attest_value)) =
                self.ledger.seed_validator_attest_key(address, &v.attest_pk)
            {
                self.state_store.put_account(attest_key, attest_value)?;
            }
            if let Ok(payload) = qtv_idfmt::parse_address(address) {
                if let Ok(id) = <[u8; 32]>::try_from(payload) {
                    validator_ids.push(id);
                }
            }
        }
        let (validators_key, validators_value) = self.ledger.seed_validator_set(&validator_ids);
        self.state_store
            .put_account(validators_key, validators_value)?;
        if let Some(dest_chain) = genesis.bridge_dest_chain {
            let (dest_key, dest_value) = self.ledger.seed_bridge_dest_chain(dest_chain);
            self.state_store.put_account(dest_key, dest_value)?;
        }
        if let Some(era) = genesis.bridge_era {
            let (era_key, era_value) = self.ledger.seed_bridge_era(&era);
            self.state_store.put_account(era_key, era_value)?;
        }
        if let Some(ref operators) = genesis.bridge_operators {
            if let Some((op_key, op_value)) = self.ledger.seed_bridge_operator_set(operators) {
                self.state_store.put_account(op_key, op_value)?;
            }
        }
        for asset in &genesis.bridged_assets {
            let (asset_key, asset_value) = self.ledger.register_bridged_asset(
                &asset.asset_id,
                asset.cap,
                asset.epoch_cap,
                asset.requires_stark,
            );
            self.state_store.put_account(asset_key, asset_value)?;
        }
        if !genesis.guardians.members.is_empty() {
            let (guardian_key, guardian_value) = self.ledger.seed_guardian_set(&genesis.guardians);
            self.state_store.put_account(guardian_key, guardian_value)?;
        }
        let (supply_key, supply_value) = self.ledger.seed_supply(supply);
        self.state_store.put_account(supply_key, supply_value)?;
        for (key, value) in self.ledger.take_dirty_entries() {
            match value {
                Some(value) => self.state_store.put_account(key, value)?,
                None => self.state_store.delete_account(key)?,
            }
        }
        self.state_store
            .commit(GENESIS_COMMIT_HEIGHT, self.ledger.q_root())?;
        self.ledger.clear_dirty();
        self.refresh_committee();
        Ok(())
    }

    fn slot(&self) -> u64 {
        self.consensus.slot_for(self.height)
    }

    fn epoch_roster(&self) -> Vec<ValidatorRegistration> {
        self.epoch_roster_for(self.consensus.epoch_for(self.height))
    }

    fn epoch_roster_for(&self, epoch: u64) -> Vec<ValidatorRegistration> {
        let own_id = self.consensus.own_id();
        let own_root = self.consensus.own_epoch_root(epoch);
        reweigh_roster(&self.ledger, &self.base_roster)
            .into_iter()
            .map(|mut r| {
                if r.id == own_id {
                    r.root = own_root;
                } else if let Some(root) = self.epoch_roots.get(&r.id) {
                    r.root = *root;
                }
                r
            })
            .collect()
    }

    fn refresh_committee(&mut self) {
        let epoch = self.consensus.epoch_for(self.height);
        if epoch != self.consensus.epoch() {
            self.epoch_roots.clear();
            self.epoch_notes.clear();
            self.epoch_conflicted.clear();
            self.epoch_conflict_notes.clear();
        }
        let roster = self.epoch_roster();
        self.consensus.rotate_to_epoch(epoch, roster);
        self.reveals.clear();
        *self.selection_cache.borrow_mut() = None;
        self.record_own_reveal();
    }

    pub fn own_registration_note(&self) -> Option<RegisterNote> {
        let epoch = self.consensus.epoch_for(self.height);
        if epoch == 0 {
            return None;
        }
        let (root, sig) = self.consensus.own_epoch_registration(epoch);
        Some(RegisterNote {
            height: self.height,
            id: self.id,
            epoch,
            root,
            sig,
        })
    }

    pub fn collect_registration(&mut self, note: RegisterNote) -> bool {
        let epoch = self.consensus.epoch_for(self.height);
        if note.epoch != epoch || note.id == self.id {
            return false;
        }
        let Some(reg) = self.base_roster.iter().find(|r| r.id == note.id) else {
            return false;
        };
        if !qtv_attest::epoch_registration_verifies(
            &reg.attest_pk,
            note.id,
            note.epoch,
            &note.root,
            &note.sig,
        ) {
            return false;
        }
        if self.epoch_conflicted.contains(&note.id) {
            return false;
        }
        match self.epoch_roots.get(&note.id) {
            Some(existing) if *existing == note.root => false,
            Some(_) => {
                self.epoch_conflicted.insert(note.id);
                self.epoch_roots.remove(&note.id);
                self.epoch_notes.remove(&note.id);
                true
            }
            None => {
                self.epoch_notes.insert(note.id, note.clone());
                self.epoch_roots.insert(note.id, note.root);
                true
            }
        }
    }

    pub fn apply_registrations(&mut self) {
        let epoch = self.consensus.epoch_for(self.height);
        let roster = self.epoch_roster();
        self.consensus.rotate_to_epoch(epoch, roster);
        *self.selection_cache.borrow_mut() = None;
        self.record_own_reveal();
    }

    fn record_own_reveal(&mut self) {
        if let Some(reveal) = self.consensus.published_self(&self.beacon, self.slot()) {
            if !self.reveals.iter().any(|r| r.id == reveal.id) {
                self.reveals.push(reveal);
                *self.selection_cache.borrow_mut() = None;
            }
        }
    }

    pub fn collected_reveal_ids(&self) -> Vec<u64> {
        self.reveals.iter().map(|r| r.id).collect()
    }

    pub fn collected_registration_ids(&self) -> Vec<u64> {
        self.epoch_roots.keys().copied().collect()
    }

    fn epoch_registration_notes(&self) -> Vec<RegisterNote> {
        let mut notes: Vec<RegisterNote> = Vec::new();
        if let Some(own) = self.own_registration_note() {
            notes.push(own);
        }
        let mut ids: Vec<u64> = self.epoch_notes.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            if let Some(note) = self.epoch_notes.get(&id) {
                notes.push(note.clone());
            }
        }
        notes.extend(self.epoch_conflict_notes.iter().cloned());
        notes
    }

    fn rebuild_epoch_registrations(&mut self, head: Height) {
        let epoch = self.consensus.epoch_for(head);
        if epoch == 0 {
            return;
        }
        for height in qtv_bft::params::MIN_HEIGHT..=head {
            let Some(block) = self
                .block_store
                .block_by_height(height)
                .and_then(|bytes| crate::wire::chain_block_from_bytes(bytes).ok())
            else {
                continue;
            };
            for wrapper in block.body() {
                if wrapper.body().call().target() != registration_address() {
                    continue;
                }
                let Ok(note) = decode_register_note(wrapper.body().call().args()) else {
                    continue;
                };
                if note.epoch != epoch || note.id == self.id {
                    continue;
                }
                let Some(reg) = self.base_roster.iter().find(|r| r.id == note.id) else {
                    continue;
                };
                if qtv_attest::epoch_registration_verifies(
                    &reg.attest_pk,
                    note.id,
                    note.epoch,
                    &note.root,
                    &note.sig,
                ) {
                    if self.epoch_conflicted.contains(&note.id) {
                        continue;
                    }
                    match self.epoch_roots.get(&note.id) {
                        Some(existing) if *existing == note.root => {}
                        Some(_) => {
                            self.epoch_conflicted.insert(note.id);
                            self.epoch_roots.remove(&note.id);
                            self.epoch_notes.remove(&note.id);
                        }
                        None => {
                            self.epoch_notes.insert(note.id, note.clone());
                            self.epoch_roots.insert(note.id, note.root);
                        }
                    }
                }
            }
        }
    }

    pub fn own_reveal_note(&self) -> Option<RevealNote> {
        self.consensus
            .published_self(&self.beacon, self.slot())
            .map(|reveal| RevealNote {
                height: self.height,
                id: reveal.id,
                credential: reveal.credential,
            })
    }

    pub fn collect_reveal(&mut self, note: RevealNote) -> bool {
        if note.height != self.height {
            return false;
        }
        let reveal = PublishedReveal::new(note.id, note.credential);
        if self.reveals.iter().any(|r| r.id == reveal.id) {
            return false;
        }
        if !self
            .consensus
            .verify_published(&self.beacon, self.slot(), &reveal)
        {
            return false;
        }
        self.reveals.push(reveal);
        *self.selection_cache.borrow_mut() = None;
        true
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
        let block_root = *header.q_root();
        if self.state_store.head() != Some(block_root)
            || self.state_store.committed_height() != Some(head)
            || self.ledger.q_root() != block_root
        {
            return Err(RoundError::StateRootMismatch {
                height: head,
                block_root,
                state_root: Some(self.ledger.q_root()),
            });
        }
        self.parent_header_hash = header.hash();
        self.parent_val = Parent::Value(header_value(&self.parent_header_hash));
        self.beacon = Beacon::from_seed(*header.beacon_seed());
        let head_epoch = self.consensus.epoch_for(head);
        if head_epoch != 0 {
            self.rebuild_epoch_registrations(head);
            let roster = self.epoch_roster_for(head_epoch);
            self.consensus.rotate_to_epoch(head_epoch, roster);
            *self.selection_cache.borrow_mut() = None;
        }
        let reveals = match self.committee_for_certificate(head, &certificate) {
            Some(selection) => {
                debug_assert!(
                    certificate.committee_reveals.is_empty() || {
                        let mut carried = certificate.committee_reveals.clone();
                        carried.sort_by_key(|r| r.id);
                        let rebuilt: Vec<_> =
                            carried.iter().map(|r| r.credential.preimage).collect();
                        rebuilt == selection.reveals
                    },
                    "the certificate reveal reconstruction must match the selected committee"
                );
                selection.reveals
            }
            None if !certificate.committee_reveals.is_empty() => {
                let mut carried = certificate.committee_reveals.clone();
                carried.sort_by_key(|r| r.id);
                carried.iter().map(|r| r.credential.preimage).collect()
            }
            None => return Err(RoundError::Decode),
        };
        self.beacon = self
            .beacon
            .advance_from_reveals(self.consensus.slot_for(head), &reveals);
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
        let admitted = self
            .mempool
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

    pub fn select(&self) -> Result<Selection, RoundError> {
        if let Some(selection) = self.selection_cache.borrow().as_ref() {
            return Ok(selection.clone());
        }
        let selection = self
            .consensus
            .select(&self.beacon, self.slot(), &self.reveals)
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
        let chain_id = self.fee_params.chain_id;
        let mut candidates: Vec<Wrapper> = self
            .pending_evidence()
            .iter()
            .map(|evidence| evidence_transaction(evidence, chain_id))
            .collect();
        let epoch = self.consensus.epoch_for(height);
        if epoch != 0 && qtv_sampler::epoch::is_epoch_start(height, self.consensus.epoch_len()) {
            for note in self.epoch_registration_notes() {
                candidates.push(registration_transaction(&note, chain_id));
            }
        }
        candidates.extend(self.mempool.candidates());
        let mut ledger = self.ledger.clone();
        ledger.clear_block_events();
        ledger.set_round_proposer(&proposer);
        ledger.set_execution_height(height);
        let included = execute_ordered(
            &mut ledger,
            &candidates,
            &self.fee_params,
            day_of_height(height),
        );
        let event_leaves: Vec<Vec<u8>> = ledger
            .block_events()
            .iter()
            .map(BlockEvent::encode)
            .collect();
        let mut header = Header::new(
            height,
            self.parent_header_hash,
            ledger.q_root(),
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
            || header.time() != self.genesis_time + header.height() * qtv_bft::params::SLOT_MS
        {
            return Err(RoundError::ProposalRejected);
        }
        let mut ledger = self.ledger.clone();
        ledger.clear_block_events();
        ledger.set_round_proposer(header.proposer());
        ledger.set_execution_height(header.height());
        let included = execute_ordered(
            &mut ledger,
            body,
            &self.fee_params,
            day_of_height(header.height()),
        );
        let event_leaves: Vec<Vec<u8>> = ledger
            .block_events()
            .iter()
            .map(BlockEvent::encode)
            .collect();
        if included.len() != body.len()
            || ledger.q_root() != *header.q_root()
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

    fn guard_height(&mut self) -> bool {
        if self.fatal.is_some() {
            return false;
        }
        if self.guarded_height == Some(self.height) {
            return true;
        }
        match self.sign_guard.try_sign(self.height, 0) {
            Ok(true) => {
                self.guarded_height = Some(self.height);
                true
            }
            Ok(false) | Err(_) => {
                self.fatal = Some(Fatal::DoubleSignRefused {
                    height: self.height,
                    view: self.view,
                });
                false
            }
        }
    }

    fn observe_finality(&mut self, height: Height, value: [u8; 32]) {
        if let FinalityStatus::Violation {
            height,
            finalized,
            conflicting,
        } = self.finality.observe(height, value)
        {
            self.fatal = Some(Fatal::FinalityViolation {
                height,
                finalized,
                conflicting,
            });
        }
    }

    pub fn fatal(&self) -> Option<Fatal> {
        self.fatal
    }

    pub fn observe_certificate(&mut self, height: Height, value: [u8; 32]) -> Option<Fatal> {
        self.observe_finality(height, value);
        self.fatal
    }

    fn current_committee_digest(&self) -> CommitteeDigest {
        self.select()
            .map(|s| s.commitment.digest())
            .unwrap_or([0u8; 32])
    }

    pub fn attest(&self) -> Result<Attestation, RoundError> {
        let staged = self.staged.as_ref().ok_or(RoundError::NotStaged)?;
        Ok(self.consensus.own_attestation(
            self.height,
            self.slot(),
            self.view,
            self.current_committee_digest(),
            staged.block,
            &self.beacon,
        ))
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
                self.slot(),
                block,
                &self.beacon,
                attestations,
            )
            .ok_or(RoundError::NotFinalized)?;
        let member_ids: std::collections::HashSet<_> =
            selection.commitment.members.iter().map(|m| m.id).collect();
        let committee_reveals: Vec<_> = self
            .reveals
            .iter()
            .filter(|r| member_ids.contains(&r.id))
            .cloned()
            .collect();
        let certificate = certificate.with_committee_reveals(committee_reveals);
        let staged = self.staged.take().expect("the staged block is present");
        self.observe_finality(self.height, block.val);
        if self.fatal.is_some() {
            return Err(RoundError::NotFinalized);
        }

        self.ledger = staged.ledger;
        let block_events = self.ledger.block_events().to_vec();
        if !block_events.is_empty() {
            self.events_by_height.insert(self.height, block_events);
        }
        let side_events = self.ledger.side_events().to_vec();
        if !side_events.is_empty() {
            self.side_events_by_height.insert(self.height, side_events);
        }
        let attesters = certificate.attesters();
        let cert_slot = crate::wire::certificate_to_bytes(&certificate);
        let chain_block = ChainBlock::new(staged.header, cert_slot, staged.body);
        if let Err(err) = self.persist(&chain_block) {
            self.fatal = Some(Fatal::PersistFailed {
                height: self.height,
            });
            return Err(err);
        }
        self.archive_burn_block(&chain_block);

        self.beacon = self
            .beacon
            .advance_from_reveals(self.slot(), &selection.reveals);
        self.parent_header_hash = chain_block.header_hash();
        self.parent_val = Parent::Value(header_value(&self.parent_header_hash));
        let finalised_height = self.height;
        if qtv_sampler::epoch::is_epoch_start(finalised_height, self.consensus.epoch_len()) {
            self.checkpoint = Some(Checkpoint {
                height: finalised_height,
                value: block.val,
            });
        }
        self.height += 1;
        self.view = 0;
        self.lock = None;
        self.round_atts.clear();
        self.attest_relayed.clear();
        self.prevotes.clear();
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
        let stage_is_current = matches!(&self.staged, Some(staged) if staged.view == self.view);
        if stage_is_current {
            messages.extend(self.prevote_staged());
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
        self.prevote_staged()
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
        let high = self.justified_lock(selection, &records);
        match &high {
            Some((_, locked)) => {
                if header_value(&locked.header.hash()) != proposed_value {
                    return Vec::new();
                }
            }
            None => {
                if *proposal.header.proposer()
                    != self.validator_address(leader_for(selection, view))
                {
                    return Vec::new();
                }
            }
        }
        if let Some(lock) = &self.lock {
            if lock.value != proposed_value
                && !matches!(&high, Some((polka_view, _)) if *polka_view >= lock.view)
            {
                return Vec::new();
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
        self.prevote_staged()
    }

    fn justified_lock(
        &self,
        selection: &Selection,
        records: &[ViewChange],
    ) -> Option<(View, LockedBlock)> {
        let mut best: Option<(View, LockedBlock)> = None;
        for record in records {
            if let (Some(block), Some(polka)) = (&record.locked, &record.polka) {
                if self.polka_backs(selection, record.lock_view, block, polka)
                    && best
                        .as_ref()
                        .map_or(true, |(view, _)| record.lock_view > *view)
                {
                    best = Some((record.lock_view, block.clone()));
                }
            }
        }
        best
    }

    fn polka_backs(
        &self,
        selection: &Selection,
        lock_view: View,
        block: &LockedBlock,
        polka: &Certificate,
    ) -> bool {
        let value = header_value(&block.header.hash());
        let subject = prevote_subject(self.height, lock_view, value);
        polka.envelope.block == subject
            && polka.attestations.iter().all(|att| att.view == lock_view)
            && self.consensus.verify(polka, selection, &self.beacon)
    }

    pub fn prevote_staged(&mut self) -> Vec<Message> {
        if self.fatal.is_some() {
            return Vec::new();
        }
        let Some(staged) = self.staged.as_ref() else {
            return Vec::new();
        };
        let value = header_value(&staged.header.hash());
        let committee = self.current_committee_digest();
        let subject = prevote_subject(self.height, staged.view, value);
        let prevote = self.consensus.own_attestation(
            self.height,
            self.slot(),
            staged.view,
            committee,
            subject,
            &self.beacon,
        );
        self.record_prevote(&prevote);
        let mut out = vec![Message::Prevote(Box::new(prevote))];
        if let Ok(selection) = self.select() {
            out.extend(self.form_polka_and_precommit(&selection));
        }
        out
    }

    pub fn on_prevote(&mut self, selection: &Selection, prevote: Attestation) -> Vec<Message> {
        if prevote.height != self.height {
            return Vec::new();
        }
        if self.verify_attestation(selection, &prevote) {
            self.record_prevote(&prevote);
        }
        self.form_polka_and_precommit(selection)
    }

    fn form_polka_and_precommit(&mut self, selection: &Selection) -> Vec<Message> {
        let (view, value, block) = match self.staged.as_ref() {
            Some(staged) => (
                staged.view,
                header_value(&staged.header.hash()),
                LockedBlock {
                    header: staged.header.clone(),
                    body: staged.body.clone(),
                },
            ),
            None => return Vec::new(),
        };
        if matches!(&self.lock, Some(lock) if lock.view >= view) {
            return Vec::new();
        }
        let subject = prevote_subject(self.height, view, value);
        let prevotes: Vec<Attestation> = self
            .prevotes
            .iter()
            .filter(|p| p.view == view && p.block == subject)
            .cloned()
            .collect();
        if (prevotes.len() as u64) < selection.tau {
            return Vec::new();
        }
        let Some(polka) = self.consensus.finalize(
            selection,
            self.height,
            self.slot(),
            subject,
            &self.beacon,
            &prevotes,
        ) else {
            return Vec::new();
        };
        self.lock = Some(Lock {
            view,
            value,
            block,
            polka,
        });
        self.precommit_staged()
    }

    fn precommit_staged(&mut self) -> Vec<Message> {
        if !self.guard_height() {
            return Vec::new();
        }
        let Ok(attestation) = self.attest() else {
            return Vec::new();
        };
        self.record_attestation(&attestation);
        vec![Message::Attest(Box::new(attestation))]
    }

    fn record_prevote(&mut self, prevote: &Attestation) {
        let seen = self
            .prevotes
            .iter()
            .any(|p| p.from == prevote.from && p.view == prevote.view && p.block == prevote.block);
        if seen {
            return;
        }
        let from_count = self
            .prevotes
            .iter()
            .filter(|p| p.from == prevote.from)
            .count();
        if from_count >= MAX_ATTESTATIONS_PER_SENDER {
            return;
        }
        if self.prevotes.len() >= MAX_ROUND_ATTESTATIONS {
            self.prevotes.remove(0);
        }
        self.prevotes.push(prevote.clone());
    }

    pub fn make_view_change(&mut self, target_view: View) -> ViewChange {
        let _ = self.guard_height();
        let (lock_view, locked_value, has_lock, locked, polka) = match &self.lock {
            Some(lock) => (
                lock.view,
                lock.value,
                true,
                Some(lock.block.clone()),
                Some(lock.polka.clone()),
            ),
            None => (0, [0u8; 32], false, None, None),
        };
        let subject =
            view_change_subject(self.height, target_view, lock_view, locked_value, has_lock);
        let committee = self.current_committee_digest();
        let att = self.consensus.own_attestation(
            self.height,
            self.slot(),
            self.view,
            committee,
            subject,
            &self.beacon,
        );
        ViewChange {
            height: self.height,
            target_view,
            lock_view,
            locked,
            att,
            polka,
        }
    }

    pub fn collect_view_change(&mut self, selection: &Selection, record: ViewChange) {
        if record.height != self.height || !self.verify_view_change_att(selection, &record) {
            return;
        }
        let seen = self
            .view_changes
            .iter()
            .any(|r| r.att.from == record.att.from && r.target_view == record.target_view);
        if seen {
            return;
        }
        let from_count = self
            .view_changes
            .iter()
            .filter(|r| r.att.from == record.att.from)
            .count();
        if from_count >= MAX_VIEW_CHANGES_PER_SENDER {
            return;
        }
        if !self.verify_view_change_polka(selection, &record) {
            return;
        }
        self.view_changes.push(record);
    }

    fn verify_attestation(&self, selection: &Selection, att: &Attestation) -> bool {
        let Some(member) = selection.commitment.member(att.from) else {
            return false;
        };
        if att.height != self.height || att.slot != self.consensus.slot_for(self.height) {
            return false;
        }
        if !att.signature_verifies(self.consensus.chain_id(), &member.attest_pk) {
            return false;
        }
        att.is_entitled(
            &member.root,
            &self.beacon,
            member.weight,
            selection.commitment.total_weight,
            selection.commitment.budget,
        )
    }

    fn verify_view_change(&self, selection: &Selection, record: &ViewChange) -> bool {
        self.verify_view_change_att(selection, record)
            && self.verify_view_change_polka(selection, record)
    }

    fn verify_view_change_att(&self, selection: &Selection, record: &ViewChange) -> bool {
        let Some(member) = selection.commitment.member(record.att.from) else {
            return false;
        };
        let (has_lock, locked_value, lock_view) = match &record.locked {
            Some(block) => (true, header_value(&block.header.hash()), record.lock_view),
            None => (false, [0u8; 32], 0),
        };
        if has_lock && record.lock_view > record.target_view {
            return false;
        }
        let subject = view_change_subject(
            record.height,
            record.target_view,
            lock_view,
            locked_value,
            has_lock,
        );
        if record.att.height != record.height
            || record.att.slot != self.consensus.slot_for(record.height)
            || record.att.block != subject
        {
            return false;
        }
        if !record
            .att
            .signature_verifies(self.consensus.chain_id(), &member.attest_pk)
        {
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

    fn verify_view_change_polka(&self, selection: &Selection, record: &ViewChange) -> bool {
        match (&record.locked, &record.polka) {
            (None, None) => true,
            (Some(block), Some(polka)) => {
                self.polka_backs(selection, record.lock_view, block, polka)
            }
            _ => false,
        }
    }

    fn valid_justification(
        &self,
        selection: &Selection,
        records: &[ViewChange],
        view: View,
    ) -> Option<Vec<ViewChange>> {
        if records.len() > selection.commitment.len() {
            return None;
        }
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
        let bound = self.justified_lock(selection, &records).or_else(|| {
            self.lock
                .as_ref()
                .map(|lock| (lock.view, lock.block.clone()))
        });
        let proposal = match bound {
            Some((_, locked)) => {
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

    pub fn view_sync_target(&self, selection: &Selection) -> Option<View> {
        let blocking =
            view_sync_blocking(selection.expected, selection.members.len(), selection.tau);
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

    pub fn on_attestation(&mut self, attestation: Attestation) -> bool {
        if attestation.height != self.height {
            return false;
        }
        if attestation.view >= qtv_node::evidence::MAX_HEIGHT_VIEW {
            return false;
        }
        if !self.watch_for_equivocation(&attestation) {
            return false;
        }
        if let Ok(selection) = self.select() {
            if let Some(member) = selection.commitment.member(attestation.from) {
                if attestation.slot == self.consensus.slot_for(self.height)
                    && attestation.is_entitled(
                        &member.root,
                        &self.beacon,
                        member.weight,
                        selection.commitment.total_weight,
                        selection.commitment.budget,
                    )
                {
                    self.record_attestation(&attestation);
                }
            }
        }
        if attestation.block.cost == qtv_node::consensus::VIEW_CHANGE_SUBJECT_COST {
            return false;
        }
        let slot = (attestation.from, attestation.view);
        if !self.attest_relayed.contains_key(&slot)
            && self.attest_relayed.len() >= MAX_RELAY_BUCKETS
        {
            return false;
        }
        let bucket = self.attest_relayed.entry(slot).or_default();
        if bucket.len() >= MAX_RELAY_BLOCKS_PER_VIEW {
            return false;
        }
        bucket.insert(attestation.block.to_bytes())
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

    pub fn has_finality_threshold(&self, tau: u64) -> bool {
        let Some(staged) = &self.staged else {
            return false;
        };
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for attestation in &self.round_atts {
            if attestation.block == staged.block {
                seen.insert(attestation.from);
            }
        }
        seen.len() as u64 >= tau
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
        if seen {
            return;
        }
        let from_count = self
            .round_atts
            .iter()
            .filter(|a| a.from == attestation.from)
            .count();
        if from_count >= MAX_ATTESTATIONS_PER_SENDER {
            return;
        }
        if self.round_atts.len() >= MAX_ROUND_ATTESTATIONS {
            self.round_atts.remove(0);
        }
        self.round_atts.push(attestation.clone());
    }

    fn watch_for_equivocation(&mut self, attestation: &Attestation) -> bool {
        let chain_id = self.consensus.chain_id();
        let Some(offender) = self.base_roster.iter().find_map(|r| {
            if r.id == attestation.from && attestation.signature_verifies(chain_id, &r.attest_pk) {
                Some(r.bond_address.clone())
            } else {
                None
            }
        }) else {
            return false;
        };
        self.evidence_pool.observe(
            &offender,
            attestation.height,
            attestation.slot,
            attestation.view,
            attestation.committee,
            attestation.block.to_bytes(),
            attestation.sig.to_vec(),
        );
        true
    }

    pub fn pending_evidence(&mut self) -> Vec<Equivocation> {
        self.evidence_pool.drain()
    }

    fn buffer_proposal(&mut self, proposal: Proposal) {
        if self.future_props.iter().any(|p| p.view == proposal.view) {
            return;
        }
        if self.future_props.len() >= MAX_FUTURE_PROPOSALS {
            let Some((index, highest)) = self
                .future_props
                .iter()
                .enumerate()
                .map(|(i, p)| (i, p.view))
                .max_by_key(|(_, view)| *view)
            else {
                return;
            };
            if proposal.view >= highest {
                return;
            }
            self.future_props.remove(index);
        }
        self.future_props.push(proposal);
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
        let height = block.header().height();
        for wrapper in block.body() {
            self.tx_index.insert(wrapper.id(), height);
        }
        for (key, value) in self.ledger.take_dirty_entries() {
            match value {
                Some(value) => self.state_store.put_account(key, value)?,
                None => self.state_store.delete_account(key)?,
            }
        }
        self.block_store.put_block(block)?;
        self.block_store.sync()?;
        self.state_store.commit(height, self.ledger.q_root())?;
        Ok(())
    }

    fn archive_burn_block(&mut self, block: &ChainBlock) {
        let events = self.ledger.block_events();
        let carries_burn = events.iter().any(|event| {
            event.selector == EVENT_BRIDGE_BURN && event.contract == NATIVE_EVENT_SOURCE
        });
        if !carries_burn {
            return;
        }
        let leaves: Vec<Vec<u8>> = events.iter().map(BlockEvent::encode).collect();
        let entry = BurnArchiveEntry {
            height: block.header().height(),
            header_bytes: to_bytes(block.header()),
            certificate: block.certificate().to_vec(),
            events: leaves,
        };
        let _ = self.burn_archive.append(entry);
    }

    pub fn finalized_head(&self) -> Height {
        self.block_store.head_height().unwrap_or(0)
    }

    pub fn burn_block(&self, height: Height) -> Option<&BurnArchiveEntry> {
        self.burn_archive.entry(height)
    }

    pub fn burn_heights_after(&self, cursor: Height) -> Vec<Height> {
        self.burn_archive.heights_after(cursor)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn seed_burn_archive(&mut self, entry: BurnArchiveEntry) {
        let _ = self.burn_archive.append(entry);
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn future_proposals_len(&self) -> usize {
        self.future_props.len()
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn view_changes_len(&self) -> usize {
        self.view_changes.len()
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn seed_side_events(&mut self, height: Height, events: Vec<SideEvent>) {
        self.side_events_by_height.insert(height, events);
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    fn validator_address(&self, id: u64) -> String {
        self.base_roster
            .iter()
            .find(|v| v.id == id)
            .map(|v| v.bond_address.clone())
            .unwrap_or_default()
    }

    fn committee_for_certificate(
        &self,
        height: u64,
        certificate: &qtv_attest::Certificate,
    ) -> Option<Selection> {
        let target = certificate.envelope.committee;
        let slot = self.consensus.slot_for(height);
        let mut reveals: Vec<PublishedReveal> = if certificate.committee_reveals.is_empty() {
            certificate
                .attestations
                .iter()
                .map(|att| PublishedReveal::new(att.from, att.membership.clone()))
                .collect()
        } else {
            certificate.committee_reveals.clone()
        };
        if let Some(selection) = self.consensus.select(&self.beacon, slot, &reveals) {
            if selection.commitment.digest() == target {
                return Some(selection);
            }
        }
        if let Some(mine) = self.consensus.published_self(&self.beacon, slot) {
            if !reveals.iter().any(|r| r.id == mine.id) {
                reveals.push(mine);
            }
        }
        let selection = self.consensus.select(&self.beacon, slot, &reveals)?;
        (selection.commitment.digest() == target).then_some(selection)
    }

    pub fn height(&self) -> Height {
        self.height
    }

    pub fn epoch(&self) -> u64 {
        self.consensus.epoch_for(self.height)
    }

    pub fn checkpoint(&self) -> Option<Checkpoint> {
        self.checkpoint
    }

    pub fn set_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.checkpoint = Some(checkpoint);
    }

    pub fn conflicts_with_checkpoint(&self, height: Height, value: [u8; 32]) -> bool {
        matches!(self.checkpoint, Some(cp) if cp.height == height && cp.value != value)
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

    pub fn genesis_accounts(&self) -> &[GenesisAccount] {
        &self.genesis_accounts
    }

    pub fn genesis_supply(&self) -> u64 {
        self.genesis_supply
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

    pub fn pending_count(&self) -> usize {
        self.mempool.pending_len()
    }

    pub fn pending_transaction(&self, tx_id: &str) -> Option<Wrapper> {
        self.mempool.find_pending(tx_id)
    }

    pub fn pending_snapshot(&self, limit: usize) -> Vec<Wrapper> {
        self.mempool.top_candidates(limit)
    }

    pub fn events_at(&self, height: Height) -> Vec<BlockEvent> {
        self.events_by_height
            .get(&height)
            .cloned()
            .unwrap_or_default()
    }

    pub fn side_events_at(&self, height: Height) -> Vec<SideEvent> {
        self.side_events_by_height
            .get(&height)
            .cloned()
            .unwrap_or_default()
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
        let ceiling = serve_ceiling(from, to);
        let mut blocks = Vec::new();
        let mut height = from;
        while height <= ceiling {
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
        if self.conflicts_with_checkpoint(header.height(), header_value(&header.hash())) {
            return Err(SyncError::CheckpointConflict);
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
            || certificate.envelope.slot != self.slot()
            || certificate.envelope.block != subject
        {
            return Err(SyncError::WrongSubject);
        }
        let selection = self
            .committee_for_certificate(self.height, &certificate)
            .ok_or(SyncError::NoCommittee)?;
        if !certificate
            .verify(
                self.consensus.chain_id(),
                &selection.commitment,
                &self.beacon,
                selection.tau,
            )
            .is_verified()
        {
            return Err(SyncError::UnverifiedCertificate);
        }
        self.observe_finality(self.height, subject.val);
        if self.fatal.is_some() {
            return Err(SyncError::FinalityViolation);
        }
        let mut ledger = self.ledger.clone();
        ledger.clear_block_events();
        ledger.set_round_proposer(header.proposer());
        ledger.set_execution_height(header.height());
        let included = execute_ordered(
            &mut ledger,
            block.body(),
            &self.fee_params,
            day_of_height(header.height()),
        );
        let event_leaves: Vec<Vec<u8>> = ledger
            .block_events()
            .iter()
            .map(BlockEvent::encode)
            .collect();
        if included.len() != block.body().len()
            || ledger.q_root() != *header.q_root()
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
        let side_events = self.ledger.side_events().to_vec();
        if !side_events.is_empty() {
            self.side_events_by_height.insert(self.height, side_events);
        }
        self.persist(&block).map_err(|_| SyncError::Io)?;
        self.archive_burn_block(&block);
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
            .advance_from_reveals(self.slot(), &selection.reveals);
        self.parent_header_hash = block.header_hash();
        self.parent_val = Parent::Value(header_value(&self.parent_header_hash));
        self.height += 1;
        self.view = 0;
        self.staged = None;
        self.lock = None;
        self.round_atts.clear();
        self.attest_relayed.clear();
        self.prevotes.clear();
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

fn evidence_transaction(evidence: &Equivocation, chain_id: u64) -> Wrapper {
    let target = evidence_address();
    let call = Call::new(target.clone(), evidence.encode());
    let body = Body::with_context(target, 0, 0, 0, call, 0, chain_id);
    Wrapper::new(body, qtv_tx::SCHEME_LATTICE, Vec::new())
}

fn registration_transaction(note: &RegisterNote, chain_id: u64) -> Wrapper {
    let target = registration_address();
    let call = Call::new(target.clone(), encode_register_note(note));
    let body = Body::with_context(target, 0, 0, 0, call, 0, chain_id);
    Wrapper::new(body, qtv_tx::SCHEME_LATTICE, Vec::new())
}

fn view_sync_blocking(expected: u64, members: usize, tau: u64) -> usize {
    let committee = expected.max(members as u64);
    (committee.saturating_sub(tau) + 1) as usize
}

fn prevote_subject(height: Height, view: View, value: [u8; 32]) -> ConsensusBlock {
    let mut buf = Vec::with_capacity(18 + 8 * 2 + 32);
    buf.extend_from_slice(b"QTV-DEVNET-PREVOTE");
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    buf.extend_from_slice(&value);
    let commitment = qtv_bft::hash::digest_256(&buf);
    ConsensusBlock::with_cost(
        height,
        commitment,
        Parent::Genesis,
        qtv_node::consensus::VIEW_CHANGE_SUBJECT_COST,
    )
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
    ConsensusBlock::with_cost(
        height,
        commitment,
        Parent::Genesis,
        qtv_node::consensus::VIEW_CHANGE_SUBJECT_COST,
    )
}

fn decode_head(bytes: &[u8]) -> Result<(Header, qtv_attest::Certificate), RoundError> {
    let mut decoder = Decoder::new(bytes);
    let header = Header::decode(&mut decoder).map_err(|_| RoundError::Decode)?;
    let cert_slot = decoder.get_bytes().map_err(|_| RoundError::Decode)?;
    let certificate =
        crate::wire::certificate_from_bytes(cert_slot).map_err(|_| RoundError::Decode)?;
    Ok((header, certificate))
}

fn serve_ceiling(from: Height, to: Height) -> Height {
    to.min(from.saturating_add(MAX_SERVE_BLOCKS.saturating_sub(1)))
}

#[cfg(test)]
mod tests {
    use super::{serve_ceiling, view_sync_blocking, Height, MAX_SERVE_BLOCKS};

    fn span(from: Height, ceiling: Height) -> u64 {
        ceiling - from + 1
    }

    #[test]
    fn a_hostile_upper_height_is_clamped_to_the_serve_window() {
        let ceiling = serve_ceiling(0, u64::MAX);
        assert_eq!(
            ceiling,
            MAX_SERVE_BLOCKS - 1,
            "the window did not clamp a u64::MAX request"
        );
        assert_eq!(
            span(0, ceiling),
            MAX_SERVE_BLOCKS,
            "the served span exceeded the window"
        );
    }

    #[test]
    fn the_window_never_overflows_for_a_high_lower_bound() {
        let from = u64::MAX - 3;
        let ceiling = serve_ceiling(from, u64::MAX);
        assert_eq!(
            ceiling,
            u64::MAX,
            "a near ceiling from must saturate, not wrap"
        );
        assert!(
            span(from, ceiling) <= MAX_SERVE_BLOCKS,
            "the span breached the window near u64::MAX"
        );
    }

    #[test]
    fn a_request_within_the_window_is_served_whole() {
        let ceiling = serve_ceiling(10, 12);
        assert_eq!(ceiling, 12, "an in window request was clamped");
        assert_eq!(span(10, ceiling), 3);
    }

    #[test]
    fn a_request_exactly_at_the_window_edge_is_served_whole() {
        let to = MAX_SERVE_BLOCKS - 1;
        let ceiling = serve_ceiling(0, to);
        assert_eq!(ceiling, to, "a request at the window edge was clamped");
        assert_eq!(span(0, ceiling), MAX_SERVE_BLOCKS);
    }

    #[test]
    fn view_sync_blocking_is_underflow_safe_when_tau_exceeds_expected() {
        assert_eq!(
            view_sync_blocking(500, 500, 334),
            167,
            "no over draw measures the blocking set against the expected size"
        );
        assert_eq!(
            view_sync_blocking(500, 650, 434),
            217,
            "an over draw measures the blocking set against the realized committee"
        );
        assert_eq!(
            view_sync_blocking(500, 750, 501),
            250,
            "a threshold above the expected size must not underflow"
        );
        assert_eq!(
            view_sync_blocking(10, 10, 100),
            1,
            "a threshold above the whole committee saturates to one"
        );
    }
}
