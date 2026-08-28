// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::merkle::merkle_root;
use crate::proto::put_varint;
use crate::sha256::sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub pubkey: [u8; 32],
    pub voting_power: u64,
}

impl ValidatorInfo {
    pub fn address(&self) -> [u8; 20] {
        let digest = sha256(&self.pubkey);
        let mut address = [0u8; 20];
        address.copy_from_slice(&digest[0..20]);
        address
    }

    pub fn encode_leaf(&self) -> Vec<u8> {
        let mut pubkey_msg = Vec::with_capacity(34);
        pubkey_msg.push(0x0a);
        pubkey_msg.push(0x20);
        pubkey_msg.extend_from_slice(&self.pubkey);

        let mut leaf = Vec::new();
        leaf.push(0x0a);
        put_varint(&mut leaf, pubkey_msg.len() as u64);
        leaf.extend_from_slice(&pubkey_msg);
        leaf.push(0x10);
        put_varint(&mut leaf, self.voting_power);
        leaf
    }
}

pub const MAX_VALIDATORS: usize = 1 << 13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorInfo>,
}

impl ValidatorSet {
    pub fn new(validators: Vec<ValidatorInfo>) -> ValidatorSet {
        ValidatorSet { validators }
    }

    pub fn total_power(&self) -> u128 {
        let mut total: u128 = 0;
        for v in &self.validators {
            total += v.voting_power as u128;
        }
        total
    }

    pub fn hash(&self) -> [u8; 32] {
        let leaves: Vec<Vec<u8>> = self.validators.iter().map(|v| v.encode_leaf()).collect();
        merkle_root(&leaves)
    }

    pub fn get_by_address(&self, address: &[u8; 20]) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| &v.address() == address)
    }
}

pub fn has_two_thirds(signed_power: u128, total_power: u128) -> bool {
    signed_power * 3 > total_power * 2
}

pub fn overlap_power(old: &ValidatorSet, new: &ValidatorSet) -> u128 {
    let new_addresses: std::collections::HashSet<[u8; 20]> =
        new.validators.iter().map(|v| v.address()).collect();
    let mut overlap: u128 = 0;
    for v in &old.validators {
        if new_addresses.contains(&v.address()) {
            overlap += v.voting_power as u128;
        }
    }
    overlap
}

pub fn overlap_meets(old: &ValidatorSet, new: &ValidatorSet, numerator: u64, denominator: u64) -> bool {
    if numerator == 0 {
        return false;
    }
    let overlap = overlap_power(old, new);
    overlap * (denominator as u128) > old.total_power() * (numerator as u128)
}

pub fn two_thirds_overlap(old: &ValidatorSet, new: &ValidatorSet) -> bool {
    overlap_meets(old, new, 2, 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator(seed: u8, power: u64) -> ValidatorInfo {
        ValidatorInfo {
            pubkey: [seed; 32],
            voting_power: power,
        }
    }

    #[test]
    fn address_is_the_leading_twenty_bytes_of_the_key_hash() {
        let v = validator(7, 100);
        let full = sha256(&v.pubkey);
        assert_eq!(&v.address()[..], &full[0..20]);
    }

    #[test]
    fn total_power_sums_the_set() {
        let set = ValidatorSet::new(vec![validator(1, 10), validator(2, 20), validator(3, 30)]);
        assert_eq!(set.total_power(), 60);
    }

    #[test]
    fn total_power_beyond_u64_does_not_wrap_and_defeat_the_two_thirds_gate() {
        let half = 1u64 << 63;
        let set = ValidatorSet::new(vec![validator(1, half), validator(2, half)]);
        assert_eq!(set.total_power(), (half as u128) * 2);
        assert!(!has_two_thirds(1, set.total_power()));
    }

    #[test]
    fn two_thirds_is_strict() {
        assert!(!has_two_thirds(66, 99));
        assert!(has_two_thirds(67, 99));
        assert!(!has_two_thirds(2, 3));
        assert!(has_two_thirds(3, 3));
    }

    #[test]
    fn the_set_hash_binds_each_power() {
        let a = ValidatorSet::new(vec![validator(1, 10), validator(2, 20)]);
        let mut b = a.clone();
        b.validators[1].voting_power = 21;
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn the_set_hash_binds_each_key() {
        let a = ValidatorSet::new(vec![validator(1, 10), validator(2, 20)]);
        let mut b = a.clone();
        b.validators[0].pubkey[0] ^= 0xff;
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn a_zero_overlap_numerator_fails_closed_even_at_full_overlap() {
        let set = ValidatorSet::new(vec![validator(1, 50), validator(2, 50)]);
        assert!(overlap_meets(&set, &set, 2, 3));
        assert!(
            !overlap_meets(&set, &set, 0, 3),
            "a zero numerator would otherwise admit a near-empty overlap"
        );
    }

    #[test]
    fn a_set_that_keeps_more_than_two_thirds_of_power_overlaps() {
        let old = ValidatorSet::new(vec![validator(1, 40), validator(2, 40), validator(3, 10)]);
        let new = ValidatorSet::new(vec![validator(1, 5), validator(2, 5), validator(9, 999)]);
        assert!(two_thirds_overlap(&old, &new));
    }

    #[test]
    fn a_set_that_keeps_two_thirds_or_less_does_not_overlap() {
        let old = ValidatorSet::new(vec![validator(1, 30), validator(2, 30), validator(3, 30)]);
        let new = ValidatorSet::new(vec![validator(1, 30), validator(2, 30)]);
        assert!(!two_thirds_overlap(&old, &new));

        let barely = ValidatorSet::new(vec![validator(1, 45), validator(9, 999)]);
        assert!(!two_thirds_overlap(&old, &barely));
    }

    #[test]
    fn the_overlap_threshold_is_configurable() {
        let old = ValidatorSet::new(vec![validator(1, 40), validator(2, 30), validator(3, 20)]);
        let new = ValidatorSet::new(vec![validator(1, 1), validator(9, 999)]);
        assert_eq!(overlap_power(&old, &new), 40);
        assert!(overlap_meets(&old, &new, 1, 3));
        assert!(!overlap_meets(&old, &new, 2, 3));
    }

    fn distinct_key(i: u32) -> [u8; 32] {
        let mut k = [0xf1u8; 32];
        k[0..4].copy_from_slice(&i.to_le_bytes());
        k
    }

    #[test]
    fn total_power_and_the_two_thirds_multiply_do_not_overflow_at_maximum_voting_power() {
        let set = ValidatorSet::new((0..200).map(|i| validator(i as u8, u64::MAX)).collect());
        assert_eq!(set.total_power(), (u64::MAX as u128) * 200);
        assert!(has_two_thirds(set.total_power(), set.total_power()));
        assert!(!has_two_thirds(set.total_power() / 2, set.total_power()));
    }

    #[test]
    fn the_validator_set_hash_stays_linear_against_a_large_untrusted_set() {
        let set = ValidatorSet::new(
            (0..60_000u32)
                .map(|i| ValidatorInfo { pubkey: distinct_key(i), voting_power: 1 })
                .collect(),
        );
        let start = std::time::Instant::now();
        let _ = set.hash();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "hashing a large untrusted validator set must not be quadratic"
        );
    }

    #[test]
    fn overlap_stays_linear_against_a_large_untrusted_set() {
        let old = ValidatorSet::new((0..128).map(|i| validator(i as u8, 10)).collect());
        let mut new_vals: Vec<ValidatorInfo> = (0..40).map(|i| validator(i as u8, 10)).collect();
        for i in 0..40_000u32 {
            new_vals.push(ValidatorInfo { pubkey: distinct_key(i), voting_power: 1 });
        }
        let new = ValidatorSet::new(new_vals);
        let start = std::time::Instant::now();
        let overlap = overlap_power(&old, &new);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "overlap over a large untrusted set must not be quadratic"
        );
        assert_eq!(overlap, 40 * 10, "the forty shared validators contribute their power once each");
    }
}
