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
use qtv_sampler::validator::SamplerValidator;

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
/// header hash folded to a single word, so the committee attests over the real
/// header and a verifier can match the two.
pub fn header_value(header_hash: &[u8; 32]) -> u64 {
    qtv_bft::hash::digest_u64(header_hash)
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
    /// Build the driver over a validator set. Each validator contributes a sampler
    /// key for sortition and an attester holding both the module lattice signing
    /// key and the sortition key.
    pub fn new(validators: &[ConsensusValidator]) -> Self {
        let sampler = validators
            .iter()
            .map(|v| SamplerValidator::new(v.id, v.stake))
            .collect();
        let attesters = validators
            .iter()
            .map(|v| (v.id, Attester::new(v.id, v.stake)))
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
}
