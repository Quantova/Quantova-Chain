// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::aggregate::aggregate;
use qtv_attest::committee::MemberKey;
use qtv_attest::{Attestation, Attester, Certificate, CommitteeCommitment, CommitteeDigest};
use qtv_crypto::ml_dsa::PublicKey;
use qtv_sampler::committee::{CommitteeView, PublishedReveal};
use qtv_sampler::onetime::Root;
use qtv_sampler::sortition::Credential;
use qtv_sampler::validator::Registration;

pub use qtv_attest::{Beacon, Block, Parent};
pub use qtv_sampler::validator::DEFAULT_SLOTS;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusValidator {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    pub secret: [u8; 32],
    pub bond_address: String,
}

impl ConsensusValidator {
    pub fn from_secret(id: u64, stake: u64, online: bool, secret: [u8; 32]) -> Self {
        let bond_address = crate::keys::validator_address(&secret);
        ConsensusValidator {
            id,
            stake,
            online,
            secret,
            bond_address,
        }
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl ConsensusValidator {
    pub fn online(id: u64, stake: u64) -> Self {
        Self::from_secret(id, stake, true, crate::keys::fixture_secret(id))
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorRegistration {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    pub bond_address: String,
    pub root: Root,
    pub attest_pk: PublicKey,
}

impl ValidatorRegistration {
    pub fn from_secret(id: u64, stake: u64, online: bool, secret: &[u8; 32], slots: u64) -> Self {
        let attester = Attester::from_secret_with_slots(id, secret, stake, slots);
        ValidatorRegistration {
            id,
            stake,
            online,
            bond_address: crate::keys::validator_address(secret),
            root: attester.root(),
            attest_pk: *attester.attest_public_key(),
        }
    }

    pub fn of(validator: &ConsensusValidator, slots: u64) -> Self {
        Self::from_secret(
            validator.id,
            validator.stake,
            validator.online,
            &validator.secret,
            slots,
        )
    }

    pub fn from_spec(spec: &crate::node::ValidatorSpec) -> Self {
        ValidatorRegistration {
            id: spec.id,
            stake: spec.stake,
            online: spec.online,
            bond_address: spec.bond_address.clone(),
            root: spec.root,
            attest_pk: spec.attest_pk,
        }
    }

    fn member_key(&self) -> MemberKey {
        MemberKey {
            id: self.id,
            weight: self.stake,
            root: self.root,
            attest_pk: self.attest_pk,
        }
    }

    fn registration(&self) -> Registration {
        Registration {
            id: self.id,
            root: self.root,
            weight: self.stake,
        }
    }
}

pub fn roster_of(validators: &[ConsensusValidator], slots: u64) -> Vec<ValidatorRegistration> {
    validators
        .iter()
        .map(|v| ValidatorRegistration::of(v, slots))
        .collect()
}

#[derive(Clone)]
pub struct Selection {
    pub commitment: CommitteeCommitment,
    pub members: Vec<u64>,
    pub leader: u64,
    pub tau: u64,
    pub expected: u64,
    pub reveals: Vec<[u8; qtv_sampler::onetime::PREIMAGE_BYTES]>,
}

pub fn genesis_beacon() -> Beacon {
    Beacon::genesis()
}

pub const VIEW_CHANGE_SUBJECT_COST: u64 = u64::MAX;

pub fn equivocation_offenders(
    chain_id: u64,
    attestations: &[Attestation],
    roster: &[ValidatorRegistration],
) -> Vec<u64> {
    let mut flagged: Vec<u64> = Vec::new();
    for (index, first) in attestations.iter().enumerate() {
        for second in &attestations[index + 1..] {
            if first.from == second.from
                && first.height == second.height
                && first.view == second.view
                && first.block != second.block
                && first.block.cost != VIEW_CHANGE_SUBJECT_COST
                && second.block.cost != VIEW_CHANGE_SUBJECT_COST
                && !flagged.contains(&first.from)
            {
                if let Some(registration) = roster.iter().find(|r| r.id == first.from) {
                    if first.signature_verifies(chain_id, &registration.attest_pk)
                        && second.signature_verifies(chain_id, &registration.attest_pk)
                    {
                        flagged.push(first.from);
                    }
                }
            }
        }
    }
    flagged.sort_unstable();
    flagged
}

pub fn double_finalize_offenders(
    chain_id: u64,
    attestations: &[Attestation],
    roster: &[ValidatorRegistration],
    tau: u64,
) -> Vec<u64> {
    let mut quorums: Vec<(u64, [u8; 32], Vec<u64>)> = Vec::new();
    for att in attestations {
        if att.block.cost == VIEW_CHANGE_SUBJECT_COST {
            continue;
        }
        let Some(registration) = roster.iter().find(|r| r.id == att.from) else {
            continue;
        };
        if !att.signature_verifies(chain_id, &registration.attest_pk) {
            continue;
        }
        match quorums
            .iter_mut()
            .find(|(height, value, _)| *height == att.height && *value == att.block.val)
        {
            Some(entry) => {
                if !entry.2.contains(&att.from) {
                    entry.2.push(att.from);
                }
            }
            None => quorums.push((att.height, att.block.val, vec![att.from])),
        }
    }
    let finalized: Vec<&(u64, [u8; 32], Vec<u64>)> = quorums
        .iter()
        .filter(|(_, _, signers)| signers.len() as u64 >= tau)
        .collect();
    let mut flagged: Vec<u64> = Vec::new();
    for (index, first) in finalized.iter().enumerate() {
        for second in &finalized[index + 1..] {
            if first.0 == second.0 && first.1 != second.1 {
                for id in &first.2 {
                    if second.2.contains(id) && !flagged.contains(id) {
                        flagged.push(*id);
                    }
                }
            }
        }
    }
    flagged.sort_unstable();
    flagged
}

pub fn header_value(header_hash: &[u8; 32]) -> [u8; 32] {
    *header_hash
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityStatus {
    Extends,
    Confirms,
    Violation {
        height: u64,
        finalized: [u8; 32],
        conflicting: [u8; 32],
    },
}

/// How many epochs of finalized heights the violation check keeps.
///
/// This map is a local safety alarm. It catches THIS node finalizing two different
/// values at one height. It is not the slashing record, which lives in the evidence
/// pool and is keyed by offender rather than by height. Conflicting certificates for a
/// single height arrive within a round of each other, so sixty four epochs is already
/// far wider than the case it exists to catch, and at a 150ms block it covers about ten
/// minutes for a couple of hundred kilobytes.
///
/// The limit this accepts, stated here rather than only in a report: a conflicting
/// finalization for a height older than this window is NOT detected. That is bounded
/// harm, because a certificate that old cannot be applied to a chain that has already
/// finalized past it, and the offender remains slashable through the evidence pool.
/// Before this the map was never pruned at all and grew by one entry per finalized
/// height for the life of the process, which at a 150ms block is over half a million
/// entries a day on a node that already needs swap to restart.
const FINALITY_RETAINED_EPOCHS: u64 = 64;
const FINALITY_RETAINED_HEIGHTS: u64 = FINALITY_RETAINED_EPOCHS * DEFAULT_SLOTS;

#[derive(Debug, Default)]
pub struct FinalityLedger {
    finalized: std::collections::BTreeMap<u64, [u8; 32]>,
    highest: u64,
}

impl FinalityLedger {
    pub fn new() -> Self {
        FinalityLedger {
            finalized: std::collections::BTreeMap::new(),
            highest: 0,
        }
    }

    pub fn finalized_value(&self, height: u64) -> Option<[u8; 32]> {
        self.finalized.get(&height).copied()
    }

    pub fn observe(&mut self, height: u64, value: [u8; 32]) -> FinalityStatus {
        match self.finalized.get(&height) {
            Some(seen) if *seen == value => FinalityStatus::Confirms,
            Some(seen) => FinalityStatus::Violation {
                height,
                finalized: *seen,
                conflicting: value,
            },
            None => {
                // Older than the window, so it was already dropped and cannot be
                // judged either way. Recording it would let the map grow backwards
                // without bound, which is the leak this window exists to close.
                if height.saturating_add(FINALITY_RETAINED_HEIGHTS) < self.highest {
                    return FinalityStatus::Confirms;
                }
                self.finalized.insert(height, value);
                self.highest = self.highest.max(height);
                let floor = self.highest.saturating_sub(FINALITY_RETAINED_HEIGHTS);
                if self.finalized.keys().next().is_some_and(|&low| low < floor) {
                    self.finalized = self.finalized.split_off(&floor);
                }
                FinalityStatus::Extends
            }
        }
    }
}

pub struct Consensus {
    chain_id: u64,
    own: Attester,
    own_id: u64,
    roster: Vec<ValidatorRegistration>,
    budget: u64,
    slots: u64,
    epoch: u64,
    epoch_len: u64,
}

impl Consensus {
    pub fn new(
        chain_id: u64,
        own_id: u64,
        own_secret: &[u8; 32],
        roster: Vec<ValidatorRegistration>,
    ) -> Self {
        Self::with_slots(chain_id, own_id, own_secret, roster, DEFAULT_SLOTS)
    }

    pub fn with_slots(
        chain_id: u64,
        own_id: u64,
        own_secret: &[u8; 32],
        mut roster: Vec<ValidatorRegistration>,
        slots: u64,
    ) -> Self {
        roster.sort_by_key(|r| r.id);
        let own_stake = roster
            .iter()
            .find(|r| r.id == own_id)
            .map(|r| r.stake)
            .unwrap_or(0);
        let own = Attester::from_secret_with_slots(own_id, own_secret, own_stake, slots);
        Consensus {
            chain_id,
            own,
            own_id,
            roster,
            budget: qtv_sampler::params::COMMITTEE_BUDGET,
            slots,
            epoch: 0,
            epoch_len: slots,
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn reweight(&mut self, roster: Vec<ValidatorRegistration>) {
        let mut roster = roster;
        roster.sort_by_key(|r| r.id);
        self.roster = roster;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn epoch_len(&self) -> u64 {
        self.epoch_len
    }

    pub fn own_epoch_root(&self, epoch: u64) -> Root {
        self.own.at_epoch(epoch).root()
    }

    pub fn own_epoch_registration(&self, epoch: u64) -> (Root, qtv_crypto::ml_dsa::Signature) {
        self.own.epoch_registration(epoch)
    }

    pub fn epoch_for(&self, height: u64) -> u64 {
        qtv_sampler::epoch::epoch_of(height, self.epoch_len)
    }

    pub fn slot_for(&self, height: u64) -> u64 {
        qtv_sampler::epoch::slot_in_epoch(height, self.epoch_len)
    }

    pub fn rotate_to_epoch(&mut self, epoch: u64, roster: Vec<ValidatorRegistration>) {
        if epoch != self.epoch {
            self.own = self.own.at_epoch(epoch);
            self.epoch = epoch;
        }
        self.reweight(roster);
    }

    pub fn own_id(&self) -> u64 {
        self.own_id
    }

    pub fn budget(&self) -> u64 {
        self.budget
    }

    pub fn slots(&self) -> u64 {
        self.slots
    }

    fn view(&self) -> CommitteeView {
        CommitteeView::new(self.roster.iter().map(|r| r.registration()).collect())
    }

    pub fn own_reveal(&self, slot: u64) -> Credential {
        self.own.reveal(slot)
    }

    pub fn published_self(&self, beacon: &Beacon, slot: u64) -> Option<PublishedReveal> {
        let credential = self.own.reveal(slot);
        if self.view().admits(beacon, slot, self.own_id, &credential) {
            Some(PublishedReveal::new(self.own_id, credential))
        } else {
            None
        }
    }

    pub fn verify_published(&self, beacon: &Beacon, slot: u64, reveal: &PublishedReveal) -> bool {
        self.view()
            .admits(beacon, slot, reveal.id, &reveal.credential)
    }

    pub fn select(
        &self,
        beacon: &Beacon,
        slot: u64,
        published: &[PublishedReveal],
    ) -> Option<Selection> {
        let view = self.view();
        let committee = view.form_committee(beacon, slot, published);
        if committee.is_empty() {
            return None;
        }
        let members = committee.ids();
        let member_keys: Vec<MemberKey> = members
            .iter()
            .filter_map(|id| self.roster.iter().find(|r| r.id == *id))
            .map(ValidatorRegistration::member_key)
            .collect();
        let weights = view.weights();
        let registered_weight = weights.iter().copied().fold(0u64, u64::saturating_add);
        let commitment = CommitteeCommitment::from_member_keys(slot, member_keys, self.budget)
            .with_total_weight(registered_weight);
        let leader = view.elect_leader(&committee, beacon, slot)?.id;
        let total: u128 = weights
            .iter()
            .map(|&w| w as u128)
            .fold(0u128, u128::saturating_add);
        let saturated = total > 0
            && weights
                .iter()
                .all(|&w| w == 0 || (self.budget as u128).saturating_mul(w as u128) >= total);
        if !saturated {
            return None;
        }
        let expected = qtv_sampler::sortition::expected_committee(&weights, self.budget);
        let tau = qtv_sampler::params::finality_threshold(expected.max(committee.len() as u64));
        let reveals = committee.reveals();
        Some(Selection {
            commitment,
            members,
            leader,
            tau,
            expected,
            reveals,
        })
    }

    pub fn own_attestation(
        &self,
        height: u64,
        slot: u64,
        view: u64,
        committee: CommitteeDigest,
        block: Block,
        beacon: &Beacon,
    ) -> Attestation {
        self.own
            .attest(self.chain_id, height, slot, view, committee, block, beacon)
    }

    pub fn finalize(
        &self,
        selection: &Selection,
        height: u64,
        slot: u64,
        block: Block,
        beacon: &Beacon,
        attestations: &[Attestation],
    ) -> Option<Certificate> {
        aggregate(
            self.chain_id,
            height,
            slot,
            block,
            &selection.commitment,
            beacon,
            attestations,
            selection.tau,
        )
    }

    pub fn verify(
        &self,
        certificate: &Certificate,
        selection: &Selection,
        beacon: &Beacon,
    ) -> bool {
        certificate
            .verify(self.chain_id, &selection.commitment, beacon, selection.tau)
            .is_verified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SLOTS: u64 = DEFAULT_SLOTS;
    const CHAIN_ID: u64 = 1;

    fn secrets(online: &[bool]) -> Vec<ConsensusValidator> {
        online
            .iter()
            .enumerate()
            .map(|(i, &on)| {
                ConsensusValidator::from_secret(
                    i as u64 + 1,
                    qtv_bft::params::VALIDATOR_STAKE_QTOV,
                    on,
                    crate::keys::fixture_secret(i as u64 + 1),
                )
            })
            .collect()
    }

    struct Sim {
        attesters: BTreeMap<u64, Attester>,
        online: BTreeMap<u64, bool>,
    }

    impl Sim {
        fn new(validators: &[ConsensusValidator]) -> Self {
            let attesters = validators
                .iter()
                .map(|v| {
                    (
                        v.id,
                        Attester::from_secret_with_slots(v.id, &v.secret, v.stake, SLOTS),
                    )
                })
                .collect();
            let online = validators.iter().map(|v| (v.id, v.online)).collect();
            Sim { attesters, online }
        }

        fn published(
            &self,
            consensus: &Consensus,
            beacon: &Beacon,
            slot: u64,
        ) -> Vec<PublishedReveal> {
            self.attesters
                .iter()
                .filter_map(|(id, attester)| {
                    let credential = attester.reveal(slot);
                    if consensus.view().admits(beacon, slot, *id, &credential) {
                        Some(PublishedReveal::new(*id, credential))
                    } else {
                        None
                    }
                })
                .collect()
        }

        fn attestations(
            &self,
            selection: &Selection,
            height: u64,
            slot: u64,
            block: Block,
            beacon: &Beacon,
        ) -> Vec<Attestation> {
            selection
                .members
                .iter()
                .filter(|id| self.online.get(id).copied().unwrap_or(false))
                .filter_map(|id| self.attesters.get(id))
                .map(|a| {
                    a.attest(
                        CHAIN_ID,
                        height,
                        slot,
                        0,
                        selection.commitment.digest(),
                        block,
                        beacon,
                    )
                })
                .collect()
        }
    }

    fn consensus_for(validators: &[ConsensusValidator]) -> Consensus {
        Consensus::with_slots(
            CHAIN_ID,
            validators[0].id,
            &validators[0].secret,
            roster_of(validators, SLOTS),
            SLOTS,
        )
    }

    fn block_for(height: u64) -> Block {
        Block::new(height, header_value(&[height as u8; 32]), Parent::Genesis)
    }

    #[test]
    fn a_full_committee_finalizes_and_verifies() {
        let validators = secrets(&[true, true, true, true]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let published = sim.published(&consensus, &beacon, 1);
        let selection = consensus.select(&beacon, 1, &published).expect("committee");
        assert_eq!(selection.members, vec![1, 2, 3, 4]);
        assert!(selection.commitment.contains(selection.leader));
        let atts = sim.attestations(&selection, 1, 1, block_for(1), &beacon);
        let cert = consensus
            .finalize(&selection, 1, 1, block_for(1), &beacon, &atts)
            .expect("finality");
        assert!(consensus.verify(&cert, &selection, &beacon));
        assert_eq!(cert.attesters(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn an_offline_member_lowers_the_count_without_stalling() {
        let validators = secrets(&[true, true, true, false]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let published = sim.published(&consensus, &beacon, 1);
        let selection = consensus.select(&beacon, 1, &published).expect("committee");
        assert_eq!(selection.members, vec![1, 2, 3, 4]);
        let atts = sim.attestations(&selection, 1, 1, block_for(1), &beacon);
        let cert = consensus
            .finalize(&selection, 1, 1, block_for(1), &beacon, &atts)
            .expect("finality still forms");
        assert_eq!(cert.attesters(), vec![1, 2, 3]);
        assert!(consensus.verify(&cert, &selection, &beacon));
    }

    #[test]
    fn too_few_online_members_do_not_finalize() {
        let validators = secrets(&[true, true, false, false]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let published = sim.published(&consensus, &beacon, 1);
        let selection = consensus.select(&beacon, 1, &published).expect("committee");
        let atts = sim.attestations(&selection, 1, 1, block_for(1), &beacon);
        assert!(consensus
            .finalize(&selection, 1, 1, block_for(1), &beacon, &atts)
            .is_none());
    }

    #[test]
    fn a_suppressed_minority_below_tau_cannot_finalise() {
        let validators = secrets(&[true, true, true, true]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let all = sim.published(&consensus, &beacon, 1);
        let minority: Vec<PublishedReveal> =
            all.into_iter().filter(|r| r.id == 1 || r.id == 2).collect();
        let selection = consensus.select(&beacon, 1, &minority).expect("committee");
        assert_eq!(selection.members, vec![1, 2]);
        assert_eq!(selection.expected, 4);
        assert_eq!(selection.tau, 3);
        let atts = sim.attestations(&selection, 1, 1, block_for(1), &beacon);
        assert_eq!(atts.len(), 2);
        assert!(consensus
            .finalize(&selection, 1, 1, block_for(1), &beacon, &atts)
            .is_none());
    }

    #[test]
    fn the_honest_online_set_reaches_tau_and_finalises() {
        let validators = secrets(&[true, true, true, true]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let published = sim.published(&consensus, &beacon, 1);
        let selection = consensus.select(&beacon, 1, &published).expect("committee");
        assert_eq!(selection.expected, 4);
        assert_eq!(selection.tau, 3);
        let atts = sim.attestations(&selection, 1, 1, block_for(1), &beacon);
        let cert = consensus
            .finalize(&selection, 1, 1, block_for(1), &beacon, &atts)
            .expect("finality");
        assert!(cert.attesters().len() as u64 >= selection.tau);
        assert!(consensus.verify(&cert, &selection, &beacon));
    }

    #[test]
    fn tau_is_absolute_and_does_not_follow_the_published_set() {
        let validators = secrets(&[true, true, true, true]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let full = sim.published(&consensus, &beacon, 1);
        let two: Vec<PublishedReveal> = full
            .iter()
            .cloned()
            .filter(|r| r.id == 1 || r.id == 2)
            .collect();
        let three: Vec<PublishedReveal> = full
            .iter()
            .cloned()
            .filter(|r| r.id == 1 || r.id == 2 || r.id == 3)
            .collect();
        let by_two = consensus.select(&beacon, 1, &two).expect("committee");
        let by_three = consensus.select(&beacon, 1, &three).expect("committee");
        let by_four = consensus.select(&beacon, 1, &full).expect("committee");
        assert_eq!((by_two.tau, by_three.tau, by_four.tau), (3, 3, 3));
    }

    #[test]
    fn two_conflicting_blocks_cannot_both_finalise() {
        let validators = secrets(&[true, true, true, true]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let published = sim.published(&consensus, &beacon, 1);
        let selection = consensus.select(&beacon, 1, &published).expect("committee");
        assert_eq!(selection.expected, 4);
        assert_eq!(selection.tau, 3);
        let mk_a = || block_for(1);
        let mk_b = || Block::new(1, header_value(&[42u8; 32]), Parent::Genesis);
        let att = |id: u64, block: Block| {
            sim.attesters.get(&id).unwrap().attest(
                CHAIN_ID,
                1,
                1,
                0,
                selection.commitment.digest(),
                block,
                &beacon,
            )
        };
        let atts_a = vec![att(1, mk_a()), att(2, mk_a()), att(4, mk_a())];
        let atts_b = vec![att(3, mk_b()), att(4, mk_b())];
        let cert_a = consensus.finalize(&selection, 1, 1, mk_a(), &beacon, &atts_a);
        let cert_b = consensus.finalize(&selection, 1, 1, mk_b(), &beacon, &atts_b);
        assert!(
            cert_b.is_none(),
            "one honest seat plus the adversary cannot reach the threshold"
        );
        assert!(
            !(cert_a.is_some() && cert_b.is_some()),
            "two conflicting blocks must never both finalise"
        );
    }

    #[test]
    fn a_subsampling_committee_refuses_to_select() {
        let validators: Vec<ConsensusValidator> = (0..650u64)
            .map(|i| ConsensusValidator::online(i + 1, qtv_bft::params::VALIDATOR_STAKE_QTOV))
            .collect();
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        for slot in 0..8u64 {
            let published = sim.published(&consensus, &beacon, slot);
            assert!(
                consensus.select(&beacon, slot, &published).is_none(),
                "a subsampling committee cannot bound its true draw from the collected reveals, so it refuses to select rather than finalise on a suppressible count"
            );
        }
    }

    #[test]
    fn tau_holds_the_expected_floor_when_the_committee_does_not_over_draw() {
        let validators = secrets(&[true, true, true, true]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let full = sim.published(&consensus, &beacon, 1);
        let minority: Vec<PublishedReveal> = full
            .iter()
            .cloned()
            .filter(|r| r.id == 1 || r.id == 2)
            .collect();
        let by_all = consensus.select(&beacon, 1, &full).expect("committee");
        let by_minority = consensus.select(&beacon, 1, &minority).expect("committee");
        assert!(by_all.members.len() as u64 <= by_all.expected);
        assert_eq!(
            by_all.tau,
            qtv_sampler::params::finality_threshold(by_all.expected),
            "a committee that does not over draw keeps the expected size threshold"
        );
        assert_eq!(
            by_minority.tau, by_all.tau,
            "a suppressed subset cannot lower the threshold below the expected floor"
        );
    }

    #[test]
    fn the_header_value_is_a_deterministic_fold() {
        assert_eq!(header_value(&[3u8; 32]), header_value(&[3u8; 32]));
        assert_ne!(header_value(&[3u8; 32]), header_value(&[4u8; 32]));
    }

    #[test]
    fn the_finality_record_stays_bounded_as_the_chain_advances() {
        // It used to keep one entry per finalized height for the life of the process,
        // with no pruning anywhere, so a validator accumulated over half a million
        // entries a day at a 150ms block. The window has to hold the memory flat while
        // still catching a conflict inside it.
        let mut ledger = FinalityLedger::new();
        let span = FINALITY_RETAINED_HEIGHTS * 4;
        for h in 1..=span {
            ledger.observe(h, [(h % 251) as u8; 32]);
        }
        assert!(
            ledger.finalized.len() as u64 <= FINALITY_RETAINED_HEIGHTS + 1,
            "the record must stay inside its window, held {} over {span} heights",
            ledger.finalized.len()
        );

        // A conflict inside the window is still a violation.
        let recent = span - 1;
        assert_eq!(
            ledger.observe(recent, [0xEEu8; 32]),
            FinalityStatus::Violation {
                height: recent,
                finalized: [(recent % 251) as u8; 32],
                conflicting: [0xEEu8; 32],
            }
        );

        // One far behind the window is dropped rather than recorded, so replaying
        // ancient heights cannot grow the map backwards.
        let before = ledger.finalized.len();
        assert_eq!(ledger.observe(1, [0xAAu8; 32]), FinalityStatus::Confirms);
        assert_eq!(
            ledger.finalized.len(),
            before,
            "an observation older than the window must not be recorded"
        );
    }

    #[test]
    fn a_second_certificate_that_conflicts_at_one_height_is_a_finality_violation() {
        let mut ledger = FinalityLedger::new();
        assert_eq!(ledger.observe(1, [1u8; 32]), FinalityStatus::Extends);
        assert_eq!(ledger.observe(2, [2u8; 32]), FinalityStatus::Extends);
        assert_eq!(ledger.observe(1, [1u8; 32]), FinalityStatus::Confirms);
        assert_eq!(
            ledger.observe(1, [9u8; 32]),
            FinalityStatus::Violation {
                height: 1,
                finalized: [1u8; 32],
                conflicting: [9u8; 32],
            }
        );
        assert_eq!(
            ledger.finalized_value(1),
            Some([1u8; 32]),
            "the first finalized value is never overwritten by a conflicting one"
        );
    }

    #[test]
    fn equivocation_is_flagged_only_when_both_signatures_authenticate() {
        let validators = secrets(&[true, true, true, true]);
        let roster = roster_of(&validators, SLOTS);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();

        let honest: Vec<Attestation> = [1u64, 2, 3, 4]
            .iter()
            .map(|id| sim.attesters[id].attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_for(1), &beacon))
            .collect();
        assert!(equivocation_offenders(CHAIN_ID, &honest, &roster).is_empty());

        let conflict = sim.attesters[&2].attest(
            CHAIN_ID,
            1,
            1,
            0,
            [0u8; 32],
            Block::new(1, header_value(&[9u8; 32]), Parent::Genesis),
            &beacon,
        );
        let mut evidence = honest.clone();
        evidence.push(conflict);
        assert_eq!(
            equivocation_offenders(CHAIN_ID, &evidence, &roster),
            vec![2]
        );

        let mut forged_a =
            sim.attesters[&3].attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_for(1), &beacon);
        let mut forged_b = sim.attesters[&3].attest(
            CHAIN_ID,
            1,
            1,
            0,
            [0u8; 32],
            Block::new(1, header_value(&[7u8; 32]), Parent::Genesis),
            &beacon,
        );
        forged_a.from = 1;
        forged_b.from = 1;
        assert!(
            equivocation_offenders(CHAIN_ID, &[forged_a, forged_b], &roster).is_empty(),
            "a relabelled pair never slashes the named validator"
        );
    }

    #[test]
    fn a_cross_view_double_finalize_is_flagged_while_honest_and_forged_votes_are_not() {
        let validators = secrets(&[true, true, true, true]);
        let roster = roster_of(&validators, SLOTS);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();

        let value_a = block_for(1);
        let value_b = Block::new(1, header_value(&[9u8; 32]), Parent::Genesis);

        let mut evidence: Vec<Attestation> = [1u64, 2, 3, 4]
            .iter()
            .map(|id| sim.attesters[id].attest(CHAIN_ID, 1, 1, 0, [0u8; 32], value_a, &beacon))
            .collect();
        for id in [2u64, 3, 4] {
            evidence
                .push(sim.attesters[&id].attest(CHAIN_ID, 1, 1, 1, [0u8; 32], value_b, &beacon));
        }
        assert_eq!(
            double_finalize_offenders(CHAIN_ID, &evidence, &roster, 3),
            vec![2, 3, 4],
            "a conflicting finalization vote in a different view is slashed"
        );

        let mut honest: Vec<Attestation> = [1u64, 2, 3, 4]
            .iter()
            .map(|id| sim.attesters[id].attest(CHAIN_ID, 1, 1, 0, [0u8; 32], value_a, &beacon))
            .collect();
        honest.push(sim.attesters[&2].attest(CHAIN_ID, 1, 1, 2, [0u8; 32], value_a, &beacon));
        honest.push(sim.attesters[&3].attest(CHAIN_ID, 1, 1, 2, [0u8; 32], value_b, &beacon));
        assert!(
            double_finalize_offenders(CHAIN_ID, &honest, &roster, 3).is_empty(),
            "a lone cross view re vote below a finalizing quorum is not a double finalize"
        );

        let mut framed: Vec<Attestation> = [1u64, 2, 3, 4]
            .iter()
            .map(|id| sim.attesters[id].attest(CHAIN_ID, 1, 1, 0, [0u8; 32], value_a, &beacon))
            .collect();
        for id in [2u64, 3, 4] {
            framed.push(sim.attesters[&id].attest(CHAIN_ID, 1, 1, 1, [0u8; 32], value_b, &beacon));
        }
        let mut forged = sim.attesters[&2].attest(CHAIN_ID, 1, 1, 1, [0u8; 32], value_b, &beacon);
        forged.from = 1;
        framed.push(forged);
        assert_eq!(
            double_finalize_offenders(CHAIN_ID, &framed, &roster, 3),
            vec![2, 3, 4],
            "a relabelled vote never puts an honest validator in a second quorum"
        );
    }

    #[test]
    fn a_node_forms_the_committee_with_no_peer_secret() {
        let validators = secrets(&[true, true, true, true]);
        let own = &validators[0];
        let roster = roster_of(&validators, SLOTS);
        let consensus = Consensus::with_slots(CHAIN_ID, own.id, &own.secret, roster.clone(), SLOTS);
        let beacon = genesis_beacon();
        let slot = 1;

        for entry in &roster {
            let _: &Root = &entry.root;
            let _: &PublicKey = &entry.attest_pk;
        }

        let peers = Sim::new(&validators[1..].to_vec());
        let mut published: Vec<PublishedReveal> = peers.published(&consensus, &beacon, slot);
        if let Some(mine) = consensus.published_self(&beacon, slot) {
            published.push(mine);
        }
        let selection = consensus
            .select(&beacon, slot, &published)
            .expect("committee");
        assert_eq!(selection.members, vec![1, 2, 3, 4]);

        let mislabelled = PublishedReveal::new(2, peers.attesters[&3].reveal(slot));
        assert!(!consensus.verify_published(&beacon, slot, &mislabelled));
        let honest_but_one = vec![
            consensus.published_self(&beacon, slot).unwrap(),
            mislabelled,
        ];
        let partial = consensus
            .select(&beacon, slot, &honest_but_one)
            .expect("committee of the ones that authenticate");
        assert!(partial.members.contains(&1));
        assert!(!partial.members.contains(&2));

        let only_two = vec![
            consensus.published_self(&beacon, slot).unwrap(),
            PublishedReveal::new(3, peers.attesters[&3].reveal(slot)),
        ];
        let liveness = consensus
            .select(&beacon, slot, &only_two)
            .expect("committee");
        assert!(liveness.members.contains(&1) && liveness.members.contains(&3));
        assert!(
            !liveness.members.contains(&4),
            "a silent validator was admitted"
        );
    }

    #[test]
    fn the_running_consensus_rejects_an_old_mechanism_draw() {
        use qtv_attest::verify::RejectReason;
        use qtv_attest::{Attestation, Certificate, Envelope, Verdict};
        use qtv_sampler::onetime::MerklePath;
        use qtv_sampler::sortition::Credential;

        let validators = secrets(&[true, true, true, true]);
        let consensus = consensus_for(&validators);
        let sim = Sim::new(&validators);
        let beacon = genesis_beacon();
        let published = sim.published(&consensus, &beacon, 1);
        let selection = consensus.select(&beacon, 1, &published).expect("committee");
        let block = block_for(1);

        let genuine_atts = sim.attestations(&selection, 1, 1, block, &beacon);
        let genuine = consensus
            .finalize(&selection, 1, 1, block, &beacon, &genuine_atts)
            .expect("finality");
        assert!(consensus.verify(&genuine, &selection, &beacon));

        let mut atts: Vec<Attestation> = sim
            .attesters
            .iter()
            .filter(|(id, _)| selection.members.contains(id))
            .take(3)
            .map(|(_, a)| {
                a.attest(
                    CHAIN_ID,
                    1,
                    1,
                    0,
                    selection.commitment.digest(),
                    block,
                    &beacon,
                )
            })
            .collect();
        let depth = atts[0].membership.path.siblings.len();
        atts[0].membership = Credential {
            position: 1,
            preimage: [171; 32],
            path: MerklePath {
                siblings: vec![[205; 32]; depth],
            },
        };
        let forged = Certificate::new(Envelope::new(1, 1, block, &selection.commitment), atts);

        assert!(!consensus.verify(&forged, &selection, &beacon));
        assert_eq!(
            forged.verify(CHAIN_ID, &selection.commitment, &beacon, selection.tau),
            Verdict::Rejected(RejectReason::NotEntitled)
        );
    }

    #[test]
    fn reweight_matches_a_fresh_build_and_drops_a_zeroed_member() {
        let beacon = genesis_beacon();
        let validators = secrets(&[true, true, true, true]);
        let mut zeroed = validators.clone();
        zeroed[3].stake = 0;
        let zeroed_roster = roster_of(&zeroed, SLOTS);

        let mut reweighted = consensus_for(&validators);
        reweighted.reweight(zeroed_roster.clone());
        let fresh = Consensus::with_slots(
            CHAIN_ID,
            zeroed[0].id,
            &zeroed[0].secret,
            zeroed_roster.clone(),
            SLOTS,
        );
        let sim = Sim::new(&zeroed);

        for slot in 1..=8 {
            let published = sim.published(&reweighted, &beacon, slot);
            let a = reweighted
                .select(&beacon, slot, &published)
                .map(|s| (s.members, s.leader));
            let b = fresh
                .select(&beacon, slot, &published)
                .map(|s| (s.members, s.leader));
            assert_eq!(a, b, "committee differs at slot {slot}");
        }

        for slot in 1..=8 {
            let published = sim.published(&reweighted, &beacon, slot);
            if let Some(selection) = reweighted.select(&beacon, slot, &published) {
                assert!(
                    !selection.members.contains(&4),
                    "a zero weight validator was drawn at slot {slot}"
                );
            }
        }

        let drawn = (1..=8)
            .filter_map(|slot| {
                let published = sim.published(&reweighted, &beacon, slot);
                reweighted.select(&beacon, slot, &published)
            })
            .any(|selection| selection.members.contains(&1));
        assert!(drawn, "a fully weighted validator was never drawn");
    }
}
