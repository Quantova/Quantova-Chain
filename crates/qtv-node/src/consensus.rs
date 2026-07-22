
use std::collections::BTreeMap;

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Certificate, CommitteeCommitment};
use qtv_sampler::committee::Registry;
use qtv_sampler::params::COMMITTEE_BUDGET;
use qtv_sampler::validator::{SamplerValidator, DEFAULT_SLOTS};

pub use qtv_attest::{Beacon, Block, Parent};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusValidator {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
    /// The operator secret behind this validator. All of its consensus key material,
    /// its sortition tree and its ML-DSA signing key, follows from this by domain
    /// separated derivation. It is present because a single process simulates the
    /// whole committee, and it never leaves this process nor any published structure.
    pub secret: [u8; 32],
    /// The published bond and reward account address, the commitment derived from the
    /// secret. The ledger seeds and weighs the validator's stake under this address.
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

#[derive(Clone)]
pub struct Selection {
    pub commitment: CommitteeCommitment,
    pub members: Vec<u64>,
    pub leader: u64,
}

pub fn genesis_beacon() -> Beacon {
    Beacon::genesis()
}

pub fn header_value(header_hash: &[u8; 32]) -> [u8; 32] {
    *header_hash
}

pub struct Consensus {
    registry: Registry,
    attesters: BTreeMap<u64, Attester>,
    online: BTreeMap<u64, bool>,
    budget: u64,
    slots: u64,
}

impl Consensus {
    pub fn new(validators: &[ConsensusValidator]) -> Self {
        Self::with_slots(validators, DEFAULT_SLOTS)
    }

    pub fn with_slots(validators: &[ConsensusValidator], slots: u64) -> Self {
        let sampler = validators
            .iter()
            .map(|v| SamplerValidator::from_secret_with_slots(v.id, &v.secret, v.stake, slots))
            .collect();
        let attesters = validators
            .iter()
            .map(|v| {
                (
                    v.id,
                    Attester::from_secret_with_slots(v.id, &v.secret, v.stake, slots),
                )
            })
            .collect();
        let online = validators.iter().map(|v| (v.id, v.online)).collect();
        Consensus {
            registry: Registry::new(sampler),
            attesters,
            online,
            budget: COMMITTEE_BUDGET,
            slots,
        }
    }

    pub fn reweight(&mut self, validators: &[ConsensusValidator]) {
        let sampler = validators
            .iter()
            .map(|v| SamplerValidator::from_secret_with_slots(v.id, &v.secret, v.stake, self.slots))
            .collect();
        self.registry = Registry::new(sampler);
        self.attesters = validators
            .iter()
            .map(|v| {
                (
                    v.id,
                    Attester::from_secret_with_slots(v.id, &v.secret, v.stake, self.slots),
                )
            })
            .collect();
        self.online = validators.iter().map(|v| (v.id, v.online)).collect();
    }

    pub fn select(&self, beacon: &Beacon, slot: u64) -> Option<Selection> {
        let committee = self.registry.sample_committee(beacon, slot);
        if committee.is_empty() {
            return None;
        }
        let members = committee.ids();
        let refs: Vec<&Attester> = members
            .iter()
            .filter_map(|id| self.attesters.get(id))
            .collect();
        let commitment = CommitteeCommitment::from_attesters_with_budget(slot, &refs, self.budget);
        let leader = self.registry.elect_leader(&committee, beacon, slot)?.id;
        Some(Selection {
            commitment,
            members,
            leader,
        })
    }

    pub fn finalize(
        &self,
        selection: &Selection,
        height: u64,
        slot: u64,
        block: Block,
        beacon: &Beacon,
    ) -> Option<Certificate> {
        let mut attestations = Vec::new();
        for id in &selection.members {
            if !self.online.get(id).copied().unwrap_or(false) {
                continue;
            }
            if let Some(attester) = self.attesters.get(id) {
                attestations.push(attester.attest(height, slot, block, beacon));
            }
        }
        aggregate(
            height,
            slot,
            block,
            &selection.commitment,
            beacon,
            &attestations,
        )
    }

    pub fn verify(
        &self,
        certificate: &Certificate,
        selection: &Selection,
        beacon: &Beacon,
    ) -> bool {
        certificate
            .verify(&selection.commitment, beacon)
            .is_verified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(online: &[bool]) -> Vec<ConsensusValidator> {
        online
            .iter()
            .enumerate()
            .map(|(i, &on)| {
                let id = i as u64 + 1;
                ConsensusValidator::from_secret(
                    id,
                    qtv_bft::params::VALIDATOR_STAKE_QTOV,
                    on,
                    crate::keys::fixture_secret(id),
                )
            })
            .collect()
    }

    fn block_for(height: u64) -> Block {
        Block::new(height, header_value(&[height as u8; 32]), Parent::Genesis)
    }

    #[test]
    fn a_full_committee_finalizes_and_verifies() {
        let consensus = Consensus::new(&set(&[true, true, true, true]));
        let beacon = genesis_beacon();
        let selection = consensus.select(&beacon, 1).expect("committee");
        assert_eq!(selection.members, vec![1, 2, 3, 4]);
        assert!(selection.commitment.contains(selection.leader));
        let cert = consensus
            .finalize(&selection, 1, 1, block_for(1), &beacon)
            .expect("finality");
        assert!(consensus.verify(&cert, &selection, &beacon));
        assert_eq!(cert.attesters(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn an_offline_member_lowers_the_count_without_stalling() {
        let consensus = Consensus::new(&set(&[true, true, true, false]));
        let beacon = genesis_beacon();
        let selection = consensus.select(&beacon, 1).expect("committee");
        assert_eq!(selection.members, vec![1, 2, 3, 4]);
        let cert = consensus
            .finalize(&selection, 1, 1, block_for(1), &beacon)
            .expect("finality still forms");
        assert_eq!(cert.attesters(), vec![1, 2, 3]);
        assert!(consensus.verify(&cert, &selection, &beacon));
    }

    #[test]
    fn too_few_online_members_do_not_finalize() {
        let consensus = Consensus::new(&set(&[true, true, false, false]));
        let beacon = genesis_beacon();
        let selection = consensus.select(&beacon, 1).expect("committee");
        assert!(consensus
            .finalize(&selection, 1, 1, block_for(1), &beacon)
            .is_none());
    }

    #[test]
    fn the_header_value_is_a_deterministic_fold() {
        assert_eq!(header_value(&[3u8; 32]), header_value(&[3u8; 32]));
        assert_ne!(header_value(&[3u8; 32]), header_value(&[4u8; 32]));
    }

    #[test]
    fn the_running_consensus_rejects_an_old_mechanism_draw() {
        use qtv_attest::verify::RejectReason;
        use qtv_attest::{Attestation, Certificate, Envelope, Verdict};
        use qtv_sampler::onetime::MerklePath;
        use qtv_sampler::sortition::Credential;

        let consensus = Consensus::new(&set(&[true, true, true, true]));
        let beacon = genesis_beacon();
        let selection = consensus.select(&beacon, 1).expect("committee");
        let block = block_for(1);

        let genuine = consensus
            .finalize(&selection, 1, 1, block, &beacon)
            .expect("finality");
        assert!(consensus.verify(&genuine, &selection, &beacon));

        let mut atts: Vec<Attestation> = selection
            .members
            .iter()
            .take(3)
            .filter_map(|id| consensus.attesters.get(id))
            .map(|a| a.attest(1, 1, block, &beacon))
            .collect();
        let depth = atts[0].membership.path.siblings.len();
        atts[0].membership = Credential {
            position: 1,
            preimage: [171; 32],
            path: MerklePath {
                siblings: vec![[205; 32]; depth],
            },
        };
        let forged =
            Certificate::new(Envelope::new(1, 1, block, &selection.commitment), atts);

        assert!(!consensus.verify(&forged, &selection, &beacon));
        assert_eq!(
            forged.verify(&selection.commitment, &beacon),
            Verdict::Rejected(RejectReason::NotEntitled)
        );
    }

    #[test]
    fn reweight_matches_a_fresh_build_and_drops_a_zeroed_member() {
        let beacon = genesis_beacon();
        let mut zeroed = set(&[true, true, true, true]);
        zeroed[3].stake = 0;

        let mut reweighted = Consensus::new(&set(&[true, true, true, true]));
        reweighted.reweight(&zeroed);
        let fresh = Consensus::new(&zeroed);
        for slot in 1..=8 {
            let a = reweighted.select(&beacon, slot).map(|s| (s.members, s.leader));
            let b = fresh.select(&beacon, slot).map(|s| (s.members, s.leader));
            assert_eq!(a, b, "committee differs at slot {slot}");
        }

        for slot in 1..=8 {
            if let Some(selection) = reweighted.select(&beacon, slot) {
                assert!(
                    !selection.members.contains(&4),
                    "a zero weight validator was drawn at slot {slot}"
                );
            }
        }

        let drawn = (1..=8)
            .filter_map(|slot| reweighted.select(&beacon, slot))
            .any(|selection| selection.members.contains(&1));
        assert!(drawn, "a fully weighted validator was never drawn");
    }
}
