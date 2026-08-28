// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::bls::BlsPubkey;
use crate::bls::BlsSignature;
use crate::ssz;

pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

pub const FINALIZED_ROOT_DEPTH: usize = 6;
pub const FINALIZED_ROOT_INDEX: u64 = 105;

pub const NEXT_SYNC_COMMITTEE_DEPTH: usize = 5;
pub const NEXT_SYNC_COMMITTEE_INDEX: u64 = 55;

pub const CURRENT_SYNC_COMMITTEE_DEPTH: usize = 5;
pub const CURRENT_SYNC_COMMITTEE_INDEX: u64 = 54;

pub const EXECUTION_RECEIPTS_DEPTH: usize = 9;
pub const EXECUTION_RECEIPTS_INDEX: u64 = 803;

pub const FINALIZED_ROOT_GINDEX_ELECTRA: u64 = 169;
pub const FINALIZED_ROOT_DEPTH_ELECTRA: usize = 7;

pub const NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 87;
pub const NEXT_SYNC_COMMITTEE_DEPTH_ELECTRA: usize = 6;

pub const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 86;
pub const CURRENT_SYNC_COMMITTEE_DEPTH_ELECTRA: usize = 6;

pub fn finalized_root_layout(electra: bool) -> (u64, usize) {
    if electra {
        (FINALIZED_ROOT_GINDEX_ELECTRA, FINALIZED_ROOT_DEPTH_ELECTRA)
    } else {
        (FINALIZED_ROOT_INDEX, FINALIZED_ROOT_DEPTH)
    }
}

pub fn next_sync_committee_layout(electra: bool) -> (u64, usize) {
    if electra {
        (
            NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA,
            NEXT_SYNC_COMMITTEE_DEPTH_ELECTRA,
        )
    } else {
        (NEXT_SYNC_COMMITTEE_INDEX, NEXT_SYNC_COMMITTEE_DEPTH)
    }
}

pub fn current_sync_committee_layout(electra: bool) -> (u64, usize) {
    if electra {
        (
            CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA,
            CURRENT_SYNC_COMMITTEE_DEPTH_ELECTRA,
        )
    } else {
        (CURRENT_SYNC_COMMITTEE_INDEX, CURRENT_SYNC_COMMITTEE_DEPTH)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

impl BeaconBlockHeader {
    pub fn hash_tree_root(&self) -> [u8; 32] {
        ssz::merkleize(&[
            ssz::uint64_root(self.slot),
            ssz::uint64_root(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommittee {
    pub pubkeys: Vec<BlsPubkey>,
    pub aggregate_pubkey: BlsPubkey,
}

impl SyncCommittee {
    pub fn hash_tree_root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self
            .pubkeys
            .iter()
            .map(|pk| ssz::bytes48_root(&pk.0))
            .collect();
        let pubkeys_root = ssz::merkleize(&leaves);
        let aggregate_root = ssz::bytes48_root(&self.aggregate_pubkey.0);
        ssz::hash_pair(&pubkeys_root, &aggregate_root)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    pub participation: Vec<bool>,
    pub signature: BlsSignature,
}

impl SyncAggregate {
    pub fn participants(&self) -> usize {
        self.participation.iter().filter(|b| **b).count()
    }
}

pub fn participating_pubkeys(
    committee: &SyncCommittee,
    aggregate: &SyncAggregate,
) -> Vec<BlsPubkey> {
    let mut selected = Vec::new();
    for (i, present) in aggregate.participation.iter().enumerate() {
        if *present {
            if let Some(pk) = committee.pubkeys.get(i) {
                selected.push(*pk);
            }
        }
    }
    selected
}

pub fn compute_fork_data_root(
    fork_version: [u8; 4],
    genesis_validators_root: &[u8; 32],
) -> [u8; 32] {
    let mut version_chunk = [0u8; 32];
    version_chunk[0..4].copy_from_slice(&fork_version);
    ssz::hash_pair(&version_chunk, genesis_validators_root)
}

pub fn compute_domain(
    domain_type: [u8; 4],
    fork_version: [u8; 4],
    genesis_validators_root: &[u8; 32],
) -> [u8; 32] {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[0..4].copy_from_slice(&domain_type);
    domain[4..32].copy_from_slice(&fork_data_root[0..28]);
    domain
}

pub fn compute_signing_root(object_root: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    ssz::hash_pair(object_root, domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: 7_100_000,
            proposer_index: 12345,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        }
    }

    fn committee(seed: u8) -> SyncCommittee {
        let pubkeys: Vec<BlsPubkey> = (0..512)
            .map(|i| {
                let mut b = [0u8; 48];
                b[0] = seed;
                b[1] = (i % 256) as u8;
                b[2] = (i / 256) as u8;
                BlsPubkey(b)
            })
            .collect();
        SyncCommittee {
            pubkeys,
            aggregate_pubkey: BlsPubkey([seed; 48]),
        }
    }

    #[test]
    fn the_header_root_is_deterministic() {
        assert_eq!(header().hash_tree_root(), header().hash_tree_root());
    }

    #[test]
    fn changing_a_header_field_changes_the_root() {
        let mut other = header();
        other.slot += 1;
        assert_ne!(header().hash_tree_root(), other.hash_tree_root());
    }

    #[test]
    fn the_domain_carries_the_domain_type_in_its_leading_bytes() {
        let d = compute_domain(DOMAIN_SYNC_COMMITTEE, [1, 0, 0, 0], &[0x44; 32]);
        assert_eq!(&d[0..4], &DOMAIN_SYNC_COMMITTEE);
    }

    #[test]
    fn a_different_fork_version_gives_a_different_domain() {
        let a = compute_domain(DOMAIN_SYNC_COMMITTEE, [1, 0, 0, 0], &[0x44; 32]);
        let b = compute_domain(DOMAIN_SYNC_COMMITTEE, [2, 0, 0, 0], &[0x44; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_genesis_validators_root_gives_a_different_domain() {
        let a = compute_domain(DOMAIN_SYNC_COMMITTEE, [1, 0, 0, 0], &[0x44; 32]);
        let b = compute_domain(DOMAIN_SYNC_COMMITTEE, [1, 0, 0, 0], &[0x45; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn the_signing_root_binds_both_the_object_and_the_domain() {
        let base = compute_signing_root(&[0x01; 32], &[0x02; 32]);
        assert_ne!(base, compute_signing_root(&[0x09; 32], &[0x02; 32]));
        assert_ne!(base, compute_signing_root(&[0x01; 32], &[0x09; 32]));
    }

    #[test]
    fn the_committee_root_changes_when_a_pubkey_changes() {
        let a = committee(1);
        let mut b = committee(1);
        b.pubkeys[100].0[10] ^= 0xff;
        assert_ne!(a.hash_tree_root(), b.hash_tree_root());
    }

    #[test]
    fn participation_selects_the_present_members() {
        let c = committee(1);
        let mut participation = vec![false; 512];
        participation[0] = true;
        participation[5] = true;
        participation[511] = true;
        let agg = SyncAggregate {
            participation,
            signature: BlsSignature([0u8; 96]),
        };
        assert_eq!(agg.participants(), 3);
        let selected = participating_pubkeys(&c, &agg);
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0], c.pubkeys[0]);
        assert_eq!(selected[2], c.pubkeys[511]);
    }

    #[test]
    fn the_finality_gindex_is_the_composed_state_and_checkpoint_field_index() {
        let finalized_checkpoint_field = 20u64;
        let checkpoint_root_field = 1u64;
        let state_gindex = (1u64 << 5) + finalized_checkpoint_field;
        let composed = state_gindex * (1u64 << 1) + checkpoint_root_field;
        assert_eq!(composed, FINALIZED_ROOT_INDEX);
        assert_eq!(FINALIZED_ROOT_INDEX, 105);
        assert_eq!(FINALIZED_ROOT_DEPTH, 6);
    }

    #[test]
    fn the_next_sync_committee_gindex_is_the_state_top_level_field_index() {
        let next_sync_committee_field = 23u64;
        let state_gindex = (1u64 << 5) + next_sync_committee_field;
        assert_eq!(state_gindex, NEXT_SYNC_COMMITTEE_INDEX);
        assert_eq!(NEXT_SYNC_COMMITTEE_INDEX, 55);
        assert_eq!(NEXT_SYNC_COMMITTEE_DEPTH, 5);
    }

    #[test]
    fn a_pinned_gindex_and_its_branch_local_reduction_walk_the_same_path() {
        let depth = FINALIZED_ROOT_DEPTH;
        let reduced = FINALIZED_ROOT_INDEX % (1u64 << depth);
        for i in 0..depth {
            assert_eq!(
                (FINALIZED_ROOT_INDEX >> i) & 1,
                (reduced >> i) & 1,
                "bit {} diverges",
                i
            );
        }
    }

    #[test]
    fn the_current_sync_committee_gindex_is_the_state_top_level_field_index() {
        let current_sync_committee_field = 22u64;
        let state_gindex = (1u64 << 5) + current_sync_committee_field;
        assert_eq!(state_gindex, CURRENT_SYNC_COMMITTEE_INDEX);
        assert_eq!(CURRENT_SYNC_COMMITTEE_INDEX, 54);
        assert_eq!(CURRENT_SYNC_COMMITTEE_DEPTH, 5);
    }

    #[test]
    fn the_execution_receipts_gindex_composes_the_body_payload_and_receipts_fields() {
        let execution_payload_field = 9u64;
        let receipts_root_field = 3u64;
        let body_to_payload = (1u64 << 4) + execution_payload_field;
        let composed = body_to_payload * (1u64 << 5) + receipts_root_field;
        assert_eq!(composed, EXECUTION_RECEIPTS_INDEX);
        assert_eq!(composed, 803);
        assert_eq!(composed.ilog2() as usize, EXECUTION_RECEIPTS_DEPTH);
    }

    #[test]
    fn the_electra_fork_widens_every_generalized_index_by_one_depth() {
        assert_eq!(FINALIZED_ROOT_GINDEX_ELECTRA, 169);
        assert_eq!(FINALIZED_ROOT_DEPTH_ELECTRA, FINALIZED_ROOT_DEPTH + 1);
        assert_eq!(NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA, 87);
        assert_eq!(
            NEXT_SYNC_COMMITTEE_DEPTH_ELECTRA,
            NEXT_SYNC_COMMITTEE_DEPTH + 1
        );
        assert_eq!(CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA, 86);
        assert_eq!(
            CURRENT_SYNC_COMMITTEE_DEPTH_ELECTRA,
            CURRENT_SYNC_COMMITTEE_DEPTH + 1
        );
    }

    #[test]
    fn the_fork_aware_layout_selects_deneb_or_electra_indices() {
        assert_eq!(finalized_root_layout(false), (105, 6));
        assert_eq!(finalized_root_layout(true), (169, 7));
        assert_eq!(next_sync_committee_layout(false), (55, 5));
        assert_eq!(next_sync_committee_layout(true), (87, 6));
        assert_eq!(current_sync_committee_layout(false), (54, 5));
        assert_eq!(current_sync_committee_layout(true), (86, 6));
    }
}
