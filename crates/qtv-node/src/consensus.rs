//! Consensus wiring over qtv-sampler, qtv-bft, and qtv-attest, following
//! SPEC-consensus-qorus.md.
//!
//! For a height the committee is selected by the sampler verifiable random
//! sortition and the proposer is elected the same way. Each online committee
//! member attests the block with its module lattice key through the stage one
//! core, and an entitled supermajority aggregates into a single finality
//! certificate. Only native stake weights the committee. A prover holds zero
//! votes and is never entitled. An offline member simply does not attest, which
//! lowers the count without any penalty, and nothing here slashes.
//!
//! The abstract consensus block and the real chain block are reconciled without
//! forking the block type: the consensus block value is the real chain header
//! hash folded to a word, so the committee attests over the real header. A
//! verifier recomputes the header hash, folds it the same way, and matches it
//! against the value the certificate carries.

use std::collections::BTreeMap;

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Certificate, CommitteeCommitment};
use qtv_sampler::committee::Registry;
use qtv_sampler::params::COMMITTEE_BUDGET;
use qtv_sampler::validator::{SamplerValidator, DEFAULT_SLOTS};

pub use qtv_attest::{Beacon, Block, Parent};

/// A validator in the in process committee: its consensus id, its native stake,
/// and whether it is online this run. Selection does not depend on liveness, so
/// an offline validator is still selected and is simply skipped when it would
/// attest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusValidator {
    pub id: u64,
    pub stake: u64,
    pub online: bool,
}

impl ConsensusValidator {
    /// An online validator with the given native stake.
    pub fn online(id: u64, stake: u64) -> Self {
        ConsensusValidator {
            id,
            stake,
            online: true,
        }
    }
}

/// The committee for a slot: the public commitment a verifier checks against, the
/// selected member ids in ascending order, and the elected leader.
#[derive(Clone)]
pub struct Selection {
    pub commitment: CommitteeCommitment,
    pub members: Vec<u64>,
    pub leader: u64,
}

/// The genesis beacon the first height draws over.
pub fn genesis_beacon() -> Beacon {
    Beacon::genesis()
}

/// The consensus block value that reconciles with a real chain header. It is the
/// header hash itself, the full 256-bit digest, so the committee attests over the
/// real header and forging a certificate onto a different header requires a full
/// SHA3-256 collision rather than a birthday grind over a short fold.
pub fn header_value(header_hash: &[u8; 32]) -> [u8; 32] {
    *header_hash
}

/// The consensus committee driver. It holds one sampler registry and one attester
/// per validator, built once, and reuses them across heights.
pub struct Consensus {
    registry: Registry,
    attesters: BTreeMap<u64, Attester>,
    online: BTreeMap<u64, bool>,
    budget: u64,
}

impl Consensus {
    /// Build the driver over a validator set at the default one time slot count.
    /// Each validator contributes a sampler key for sortition and an attester
    /// holding both the module lattice signing key and the sortition key.
    pub fn new(validators: &[ConsensusValidator]) -> Self {
        Self::with_slots(validators, DEFAULT_SLOTS)
    }

    /// Build the driver over a validator set at an explicit one time slot count. The
    /// sampler tree and the attester tree of every validator are sized to the same
    /// count, so the committee draw, the reveal, and the certificate verification all
    /// serve the same slots. One slot is spent per finalised height, so the count is
    /// the ceiling on how many heights a run can finalise before the sortition
    /// refuses a slot past the commitment. A driver that must sustain more heights
    /// than the default serves sizes the count up here.
    pub fn with_slots(validators: &[ConsensusValidator], slots: u64) -> Self {
        let sampler = validators
            .iter()
            .map(|v| SamplerValidator::with_slots(v.id, v.stake, slots))
            .collect();
        let attesters = validators
            .iter()
            .map(|v| (v.id, Attester::with_slots(v.id, v.stake, slots)))
            .collect();
        let online = validators.iter().map(|v| (v.id, v.online)).collect();
        Consensus {
            registry: Registry::new(sampler),
            attesters,
            online,
            budget: COMMITTEE_BUDGET,
        }
    }

    /// Select the committee and elect the leader for a slot over the beacon. None
    /// when the sortition admits no member.
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

    /// Drive the selected committee through attestation and aggregate the entitled
    /// supermajority into a finality certificate. Only online members attest;
    /// offline members are skipped and never penalized. None when no entitled
    /// supermajority forms.
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

    /// Whether a certificate finalizes its block under the committee commitment
    /// and the beacon, checked from public inputs alone.
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
            .map(|(i, &on)| ConsensusValidator {
                id: i as u64 + 1,
                stake: qtv_bft::params::VALIDATOR_STAKE_QTOV,
                online: on,
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
        // The offline member is still selected but casts no attestation.
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

    // Regression guard: the running consensus rejects a draw made by the old
    // grindable mechanism. A committee membership presented as an old style
    // verifiable random draw, a credential with no Merkle path to the member
    // registered root, is refused by the running verification rather than
    // finalizing the block, so a regression to the grindable path fails here.
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

        // Positive control: a quorum of genuine one time credentials finalizes and
        // verifies through the running consensus.
        let genuine = consensus
            .finalize(&selection, 1, 1, block, &beacon)
            .expect("finality");
        assert!(consensus.verify(&genuine, &selection, &beacon));

        // Rebuild the certificate but replace one member one time credential with an
        // old style draw: a fabricated preimage and path that authenticate to no
        // registered root. The module lattice signatures stay genuine.
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
            Certificate::stage_one(Envelope::new(1, 1, block, &selection.commitment), atts);

        // The running consensus verification refuses the forged certificate.
        assert!(!consensus.verify(&forged, &selection, &beacon));
        assert_eq!(
            forged.verify(&selection.commitment, &beacon),
            Verdict::Rejected(RejectReason::NotEntitled)
        );
    }
}
