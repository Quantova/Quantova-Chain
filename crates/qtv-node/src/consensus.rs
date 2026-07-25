// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_attest::aggregate::aggregate;
use qtv_attest::committee::MemberKey;
use qtv_attest::{Attestation, Attester, Certificate, CommitteeCommitment};
use qtv_crypto::ml_dsa::PublicKey;
use qtv_sampler::committee::{CommitteeView, PublishedReveal};
use qtv_sampler::onetime::Root;
use qtv_sampler::sortition::Credential;
use qtv_sampler::validator::Registration;

pub use qtv_attest::{Beacon, Block, Parent};
pub use qtv_sampler::validator::DEFAULT_SLOTS;

/// A validator named together with its operator secret, used by the holder of a secret
/// to derive its commitments. A node consumes the derived `ValidatorRegistration`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusValidator {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    pub secret: [u8; 32],
    pub bond_address: String,
}

impl ConsensusValidator {
    /// A validator built from its operator secret. Its bond and reward address is the
    /// commitment the secret derives to.
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

// A per id convenience for tests and the single process simulation only, sourcing the
// secret from the gated fixture. Absent from a default node build.
#[cfg(any(test, feature = "test-fixtures"))]
impl ConsensusValidator {
    pub fn online(id: u64, stake: u64) -> Self {
        Self::from_secret(id, stake, true, crate::keys::fixture_secret(id))
    }
}

/// The on chain commitment a node holds for a validator, its id and stake, its online
/// expectation, its bond and reward address, its sortition root, and its attestation
/// public key.
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
    /// The registration a validator's secret derives to.
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

    /// The registration read from a validator's own published genesis registration. It
    /// carries only commitments, so a node assembles the roster from peers' public
    /// registrations without holding or reconstructing any peer secret.
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

/// Derive the public roster from a set of secret carrying descriptors.
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

/// The ids of validators that signed two conflicting attestations at one height in one view,
/// each proven by verifying both signatures against the offender's registered attestation key.
/// The view rides inside each signed attestation, so a pair whose signed views differ is a
/// justified cross view re vote and never flags, and a forged pair naming a validator that
/// never double signed does not authenticate and is never flagged.
pub fn equivocation_offenders(
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
                && !flagged.contains(&first.from)
            {
                if let Some(registration) = roster.iter().find(|r| r.id == first.from) {
                    if first.signature_verifies(&registration.attest_pk)
                        && second.signature_verifies(&registration.attest_pk)
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

#[derive(Debug, Default)]
pub struct FinalityLedger {
    finalized: std::collections::BTreeMap<u64, [u8; 32]>,
}

impl FinalityLedger {
    pub fn new() -> Self {
        FinalityLedger {
            finalized: std::collections::BTreeMap::new(),
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
                self.finalized.insert(height, value);
                FinalityStatus::Extends
            }
        }
    }
}

/// A node's consensus state, its own attester and the roster of public commitments. It
/// computes its own reveal and assembles the committee from published reveals verified
/// against the roster.
pub struct Consensus {
    own: Attester,
    own_id: u64,
    roster: Vec<ValidatorRegistration>,
    budget: u64,
    slots: u64,
    epoch: u64,
    epoch_len: u64,
}

impl Consensus {
    pub fn new(own_id: u64, own_secret: &[u8; 32], roster: Vec<ValidatorRegistration>) -> Self {
        Self::with_slots(own_id, own_secret, roster, DEFAULT_SLOTS)
    }

    pub fn with_slots(
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
            own,
            own_id,
            roster,
            budget: qtv_sampler::params::COMMITTEE_BUDGET,
            slots,
            epoch: 0,
            epoch_len: slots,
        }
    }

    /// Replace the roster with a reweighted one.
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

    /// The node's own one time sortition root for an epoch, the commitment it re registers
    /// so peers admit its rotated reveals.
    pub fn own_epoch_root(&self, epoch: u64) -> Root {
        self.own.at_epoch(epoch).root()
    }

    /// The node's own signed re registration of its rotated root for an epoch, verifiable
    /// by any peer against its stable attestation key.
    pub fn own_epoch_registration(&self, epoch: u64) -> (Root, qtv_crypto::ml_dsa::Signature) {
        self.own.epoch_registration(epoch)
    }

    pub fn epoch_for(&self, height: u64) -> u64 {
        qtv_sampler::epoch::epoch_of(height, self.epoch_len)
    }

    pub fn slot_for(&self, height: u64) -> u64 {
        qtv_sampler::epoch::slot_in_epoch(height, self.epoch_len)
    }

    /// Rotate the node's own attester onto the epoch's fresh one time sortition tree and
    /// install the roster of rotated roots the epoch draws its committee from. Rotation
    /// happens once per epoch boundary; a reweight within the same epoch keeps the roots.
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

    /// The node's own reveal for a slot.
    pub fn own_reveal(&self, slot: u64) -> Credential {
        self.own.reveal(slot)
    }

    /// The node's own published reveal for a slot when its own reveal is selected.
    pub fn published_self(&self, beacon: &Beacon, slot: u64) -> Option<PublishedReveal> {
        let credential = self.own.reveal(slot);
        if self.view().admits(beacon, slot, self.own_id, &credential) {
            Some(PublishedReveal::new(self.own_id, credential))
        } else {
            None
        }
    }

    /// Whether a peer's published reveal authenticates to its committed root and is
    /// selected for the slot.
    pub fn verify_published(&self, beacon: &Beacon, slot: u64, reveal: &PublishedReveal) -> bool {
        self.view()
            .admits(beacon, slot, reveal.id, &reveal.credential)
    }

    /// Assemble the committee for a slot from the published reveals, verified against the
    /// roster, and build its commitment from the member keys.
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
        let commitment = CommitteeCommitment::from_member_keys(slot, member_keys, self.budget);
        let leader = view.elect_leader(&committee, beacon, slot)?.id;
        let expected = qtv_sampler::sortition::expected_committee(&view.weights(), self.budget);
        let tau = qtv_sampler::params::finality_threshold(expected);
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

    /// The node's own attestation over a block, carrying its own reveal.
    pub fn own_attestation(
        &self,
        height: u64,
        slot: u64,
        view: u64,
        block: Block,
        beacon: &Beacon,
    ) -> Attestation {
        self.own.attest(height, slot, view, block, beacon)
    }

    /// Fold the collected attestations into a finality certificate.
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
            .verify(&selection.commitment, beacon, selection.tau)
            .is_verified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SLOTS: u64 = DEFAULT_SLOTS;

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

        fn published(&self, consensus: &Consensus, beacon: &Beacon, slot: u64) -> Vec<PublishedReveal> {
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
                .map(|a| a.attest(height, slot, 0, block, beacon))
                .collect()
        }
    }

    fn consensus_for(validators: &[ConsensusValidator]) -> Consensus {
        Consensus::with_slots(
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
        let two: Vec<PublishedReveal> =
            full.iter().cloned().filter(|r| r.id == 1 || r.id == 2).collect();
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
        let att =
            |id: u64, block: Block| sim.attesters.get(&id).unwrap().attest(1, 1, 0, block, &beacon);
        let atts_a = vec![att(1, mk_a()), att(2, mk_a()), att(4, mk_a())];
        let atts_b = vec![att(3, mk_b()), att(4, mk_b())];
        let cert_a = consensus.finalize(&selection, 1, 1, mk_a(), &beacon, &atts_a);
        let cert_b = consensus.finalize(&selection, 1, 1, mk_b(), &beacon, &atts_b);
        assert!(cert_b.is_none(), "one honest seat plus the adversary cannot reach the threshold");
        assert!(
            !(cert_a.is_some() && cert_b.is_some()),
            "two conflicting blocks must never both finalise"
        );
    }

    #[test]
    fn the_header_value_is_a_deterministic_fold() {
        assert_eq!(header_value(&[3u8; 32]), header_value(&[3u8; 32]));
        assert_ne!(header_value(&[3u8; 32]), header_value(&[4u8; 32]));
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
            .map(|id| sim.attesters[id].attest(1, 1, 0, block_for(1), &beacon))
            .collect();
        assert!(equivocation_offenders(&honest, &roster).is_empty());

        let conflict = sim.attesters[&2].attest(
            1,
            1,
            0,
            Block::new(1, header_value(&[9u8; 32]), Parent::Genesis),
            &beacon,
        );
        let mut evidence = honest.clone();
        evidence.push(conflict);
        assert_eq!(equivocation_offenders(&evidence, &roster), vec![2]);

        let mut forged_a = sim.attesters[&3].attest(1, 1, 0, block_for(1), &beacon);
        let mut forged_b = sim.attesters[&3].attest(
            1,
            1,
            0,
            Block::new(1, header_value(&[7u8; 32]), Parent::Genesis),
            &beacon,
        );
        forged_a.from = 1;
        forged_b.from = 1;
        assert!(
            equivocation_offenders(&[forged_a, forged_b], &roster).is_empty(),
            "a relabelled pair never slashes the named validator"
        );
    }

    #[test]
    fn a_node_forms_the_committee_with_no_peer_secret() {
        let validators = secrets(&[true, true, true, true]);
        let own = &validators[0];
        let roster = roster_of(&validators, SLOTS);
        let consensus = Consensus::with_slots(own.id, &own.secret, roster.clone(), SLOTS);
        let beacon = genesis_beacon();
        let slot = 1;

        // A ValidatorRegistration exposes only commitments, no secret to read.
        for entry in &roster {
            let _: &Root = &entry.root;
            let _: &PublicKey = &entry.attest_pk;
        }

        let peers = Sim::new(&validators[1..].to_vec());
        let mut published: Vec<PublishedReveal> = peers.published(&consensus, &beacon, slot);
        if let Some(mine) = consensus.published_self(&beacon, slot) {
            published.push(mine);
        }
        let selection = consensus.select(&beacon, slot, &published).expect("committee");
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
        let liveness = consensus.select(&beacon, slot, &only_two).expect("committee");
        assert!(liveness.members.contains(&1) && liveness.members.contains(&3));
        assert!(!liveness.members.contains(&4), "a silent validator was admitted");
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
            .map(|(_, a)| a.attest(1, 1, 0, block, &beacon))
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
            forged.verify(&selection.commitment, &beacon, selection.tau),
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
            zeroed[0].id,
            &zeroed[0].secret,
            zeroed_roster.clone(),
            SLOTS,
        );
        let sim = Sim::new(&zeroed);

        for slot in 1..=8 {
            let published = sim.published(&reweighted, &beacon, slot);
            let a = reweighted.select(&beacon, slot, &published).map(|s| (s.members, s.leader));
            let b = fresh.select(&beacon, slot, &published).map(|s| (s.members, s.leader));
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
