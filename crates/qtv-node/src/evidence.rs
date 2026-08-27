// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{HashMap, HashSet};

use qtv_codec::{Decoder, Encoder};
use qtv_crypto::ml_dsa::{self, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

use qtv_attest::params::ATTEST_CONTEXT;

fn subject_is_view_change(block_bytes: &[u8]) -> bool {
    let len = block_bytes.len();
    len >= 8
        && block_bytes[len - 8..] == crate::consensus::VIEW_CHANGE_SUBJECT_COST.to_le_bytes()
}

fn attestation_message(
    chain_id: u64,
    height: u64,
    slot: u64,
    view: u64,
    committee: &[u8; 32],
    block_bytes: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 24 + block_bytes.len());
    msg.extend_from_slice(&chain_id.to_le_bytes());
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(&slot.to_le_bytes());
    msg.extend_from_slice(&view.to_le_bytes());
    msg.extend_from_slice(committee);
    msg.extend_from_slice(block_bytes);
    msg
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Equivocation {
    pub offender: String,
    pub height: u64,
    pub view_a: u64,
    pub view_b: u64,
    pub slot_a: u64,
    pub slot_b: u64,
    pub committee_a: [u8; 32],
    pub committee_b: [u8; 32],
    pub block_a: Vec<u8>,
    pub sig_a: Vec<u8>,
    pub block_b: Vec<u8>,
    pub sig_b: Vec<u8>,
}

impl Equivocation {
    pub fn attributes(&self, chain_id: u64, attest_pk: &[u8]) -> bool {
        if self.block_a == self.block_b {
            return false;
        }
        if self.view_a != self.view_b {
            return false;
        }
        if subject_is_view_change(&self.block_a) || subject_is_view_change(&self.block_b) {
            return false;
        }
        let pk: [u8; PUBLIC_KEY_BYTES] = match attest_pk.try_into() {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig_a: [u8; SIGNATURE_BYTES] = match self.sig_a.as_slice().try_into() {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        let sig_b: [u8; SIGNATURE_BYTES] = match self.sig_b.as_slice().try_into() {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        let msg_a = attestation_message(
            chain_id,
            self.height,
            self.slot_a,
            self.view_a,
            &self.committee_a,
            &self.block_a,
        );
        let msg_b = attestation_message(
            chain_id,
            self.height,
            self.slot_b,
            self.view_b,
            &self.committee_b,
            &self.block_b,
        );
        ml_dsa::verify(&pk, &msg_a, &sig_a, ATTEST_CONTEXT)
            && ml_dsa::verify(&pk, &msg_b, &sig_b, ATTEST_CONTEXT)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_bytes(self.offender.as_bytes());
        encoder.put_u64(self.height);
        encoder.put_u64(self.view_a);
        encoder.put_u64(self.view_b);
        encoder.put_u64(self.slot_a);
        encoder.put_u64(self.slot_b);
        encoder.put_bytes(&self.committee_a);
        encoder.put_bytes(&self.committee_b);
        encoder.put_bytes(&self.block_a);
        encoder.put_bytes(&self.sig_a);
        encoder.put_bytes(&self.block_b);
        encoder.put_bytes(&self.sig_b);
        encoder.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Option<Equivocation> {
        let mut decoder = Decoder::new(bytes);
        let offender = String::from_utf8(decoder.get_bytes().ok()?.to_vec()).ok()?;
        let height = decoder.get_u64().ok()?;
        let view_a = decoder.get_u64().ok()?;
        let view_b = decoder.get_u64().ok()?;
        let slot_a = decoder.get_u64().ok()?;
        let slot_b = decoder.get_u64().ok()?;
        let committee_a: [u8; 32] = decoder.get_bytes().ok()?.try_into().ok()?;
        let committee_b: [u8; 32] = decoder.get_bytes().ok()?.try_into().ok()?;
        let block_a = decoder.get_bytes().ok()?.to_vec();
        let sig_a = decoder.get_bytes().ok()?.to_vec();
        let block_b = decoder.get_bytes().ok()?.to_vec();
        let sig_b = decoder.get_bytes().ok()?.to_vec();
        decoder.finish().ok()?;
        Some(Equivocation {
            offender,
            height,
            view_a,
            view_b,
            slot_a,
            slot_b,
            committee_a,
            committee_b,
            block_a,
            sig_a,
            block_b,
            sig_b,
        })
    }
}

pub const MAX_HEIGHT_VIEW: u64 = 256;

#[derive(Default)]
pub struct EvidencePool {
    seen: HashMap<(String, u64, u64), (u64, [u8; 32], Vec<u8>, Vec<u8>)>,
    pending: Vec<Equivocation>,
    flagged: HashSet<(String, u64, u64)>,
    floor: u64,
}

impl EvidencePool {
    pub fn new() -> Self {
        EvidencePool::default()
    }

    pub fn observe(
        &mut self,
        offender: &str,
        height: u64,
        slot: u64,
        view: u64,
        committee: [u8; 32],
        block_bytes: Vec<u8>,
        sig: Vec<u8>,
    ) -> Option<Equivocation> {
        if subject_is_view_change(&block_bytes) {
            return None;
        }
        if view >= MAX_HEIGHT_VIEW {
            return None;
        }
        if height > self.floor {
            self.floor = height;
            self.seen.retain(|(_, h, _), _| *h >= height);
            self.flagged.retain(|(_, h, _)| *h >= height);
        }
        let key = (offender.to_string(), height, view);
        match self.seen.get(&key) {
            Some((prev_slot, prev_committee, prev_block, prev_sig)) => {
                if *prev_block == block_bytes {
                    return None;
                }
                if self.flagged.contains(&key) {
                    return None;
                }
                let evidence = Equivocation {
                    offender: offender.to_string(),
                    height,
                    view_a: view,
                    view_b: view,
                    slot_a: *prev_slot,
                    slot_b: slot,
                    committee_a: *prev_committee,
                    committee_b: committee,
                    block_a: prev_block.clone(),
                    sig_a: prev_sig.clone(),
                    block_b: block_bytes,
                    sig_b: sig,
                };
                self.flagged.insert(key);
                self.pending.push(evidence.clone());
                Some(evidence)
            }
            None => {
                self.seen.insert(key, (slot, committee, block_bytes, sig));
                None
            }
        }
    }

    pub fn drain(&mut self) -> Vec<Equivocation> {
        std::mem::take(&mut self.pending)
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_attest::{Attester, Beacon, Block, Parent};

    const CHAIN_ID: u64 = 1;

    fn attester() -> (Attester, String) {
        let secret = [5u8; 32];
        let attester = Attester::from_secret(1, &secret, 2_000);
        let address = crate::keys::validator_address(&secret);
        (attester, address)
    }

    fn equivocation(attester: &Attester, address: &str) -> (Equivocation, Vec<u8>) {
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let b = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_b, &beacon);
        let evidence = Equivocation {
            offender: address.to_string(),
            height: 1,
            view_a: 0,
            view_b: 0,
            slot_a: 1,
            slot_b: 1,
            committee_a: [0u8; 32],
            committee_b: [0u8; 32],
            block_a: block_a.to_bytes(),
            sig_a: a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: b.sig.to_vec(),
        };
        (evidence, attester.attest_public_key().to_vec())
    }

    #[test]
    fn a_genuine_pair_of_conflicting_signatures_attributes_to_the_key() {
        let (attester, address) = attester();
        let (evidence, pk) = equivocation(&attester, &address);
        assert!(evidence.attributes(CHAIN_ID, &pk));
        assert_eq!(Equivocation::decode(&evidence.encode()), Some(evidence));
    }

    #[test]
    fn a_pair_for_the_same_block_is_not_an_equivocation() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block = Block::new(1, [1u8; 32], Parent::Genesis);
        let a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block, &beacon);
        let evidence = Equivocation {
            offender: address,
            height: 1,
            view_a: 0,
            view_b: 0,
            slot_a: 1,
            slot_b: 1,
            committee_a: [0u8; 32],
            committee_b: [0u8; 32],
            block_a: block.to_bytes(),
            sig_a: a.sig.to_vec(),
            block_b: block.to_bytes(),
            sig_b: a.sig.to_vec(),
        };
        assert!(!evidence.attributes(CHAIN_ID, attester.attest_public_key()));
    }

    #[test]
    fn evidence_never_attributes_to_another_key() {
        let (attester, address) = attester();
        let (evidence, _) = equivocation(&attester, &address);
        let stranger = Attester::from_secret(2, &[6u8; 32], 2_000);
        assert!(!evidence.attributes(CHAIN_ID, stranger.attest_public_key()));
    }

    #[test]
    fn conflicting_blocks_signed_under_different_committees_still_attribute_and_cannot_poison() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let g1 = [0x11u8; 32];
        let g2 = [0x22u8; 32];
        let a = attester.attest(CHAIN_ID, 1, 1, 0, g1, block_a, &beacon);
        let b = attester.attest(CHAIN_ID, 1, 1, 0, g2, block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 0, g1, block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        let flagged = pool
            .observe(&address, 1, 1, 0, g2, block_b.to_bytes(), b.sig.to_vec())
            .expect("a conflicting block in the same view is a double vote whatever committee it names");
        assert_eq!((flagged.committee_a, flagged.committee_b), (g1, g2));
        assert!(
            flagged.attributes(CHAIN_ID, attester.attest_public_key()),
            "each half authenticates under its own committee, so the pair still slashes"
        );
    }

    #[test]
    fn a_flood_of_distinct_view_votes_cannot_evict_a_stored_double_sign() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(CHAIN_ID, 1, 1, 3, [0u8; 32], block_a, &beacon);
        let b = attester.attest(CHAIN_ID, 1, 1, 3, [0u8; 32], block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 3, [0u8; 32], block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        for v in 0..super::MAX_HEIGHT_VIEW + 10 {
            if v == 3 {
                continue;
            }
            let filler = Block::new(1, [(v % 251) as u8 + 3; 32], Parent::Genesis);
            let f = attester.attest(CHAIN_ID, 1, 1, v, [0u8; 32], filler, &beacon);
            let _ = pool.observe(&address, 1, 1, v, [0u8; 32], filler.to_bytes(), f.sig.to_vec());
        }
        let flagged = pool
            .observe(&address, 1, 1, 3, [0u8; 32], block_b.to_bytes(), b.sig.to_vec())
            .expect("the stored view 3 vote was not evicted by the flood");
        assert_eq!((flagged.view_a, flagged.view_b), (3, 3));
        assert!(flagged.attributes(CHAIN_ID, attester.attest_public_key()));
    }

    #[test]
    fn a_same_view_double_vote_attributes_and_is_slashable() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let b = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 0, [0u8; 32], block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        let flagged = pool
            .observe(&address, 1, 1, 0, [0u8; 32], block_b.to_bytes(), b.sig.to_vec())
            .expect("a conflicting block in the same view is a genuine double vote");
        assert_eq!((flagged.view_a, flagged.view_b), (0, 0));
        assert!(
            flagged.attributes(CHAIN_ID, attester.attest_public_key()),
            "the same view double vote authenticates and slashes"
        );
    }

    #[test]
    fn a_high_view_vote_first_does_not_hide_a_lower_view_double_sign() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let high = Block::new(1, [7u8; 32], Parent::Genesis);
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let h = attester.attest(CHAIN_ID, 1, 1, 5, [0u8; 32], high, &beacon);
        let a = attester.attest(CHAIN_ID, 1, 1, 2, [0u8; 32], block_a, &beacon);
        let b = attester.attest(CHAIN_ID, 1, 1, 2, [0u8; 32], block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 5, [0u8; 32], high.to_bytes(), h.sig.to_vec())
            .is_none());
        assert!(pool
            .observe(&address, 1, 1, 2, [0u8; 32], block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        let flagged = pool
            .observe(&address, 1, 1, 2, [0u8; 32], block_b.to_bytes(), b.sig.to_vec())
            .expect("the lower view double sign is still attributed under the higher view vote");
        assert_eq!((flagged.view_a, flagged.view_b), (2, 2));
        assert!(flagged.attributes(CHAIN_ID, attester.attest_public_key()));
    }

    #[test]
    fn an_honest_cross_view_re_vote_is_not_slashed() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let b = attester.attest(CHAIN_ID, 1, 1, 1, [0u8; 32], block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 0, [0u8; 32], block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        assert!(
            pool.observe(&address, 1, 1, 1, [0u8; 32], block_b.to_bytes(), b.sig.to_vec())
                .is_none(),
            "a higher view re vote is a justified vote change"
        );
        assert!(pool.drain().is_empty(), "no evidence is attributed for a view change");

        let hand_built = Equivocation {
            offender: address,
            height: 1,
            view_a: 0,
            view_b: 1,
            slot_a: 1,
            slot_b: 1,
            committee_a: [0u8; 32],
            committee_b: [0u8; 32],
            block_a: block_a.to_bytes(),
            sig_a: a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: b.sig.to_vec(),
        };
        assert!(
            !hand_built.attributes(CHAIN_ID, attester.attest_public_key()),
            "the deterministic gate refuses a cross view pair even with valid signatures"
        );
    }

    #[test]
    fn a_lower_view_attestation_arriving_late_is_ignored() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let b = attester.attest(CHAIN_ID, 1, 1, 2, [0u8; 32], block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 2, [0u8; 32], block_b.to_bytes(), b.sig.to_vec())
            .is_none());
        assert!(
            pool.observe(&address, 1, 1, 0, [0u8; 32], block_a.to_bytes(), a.sig.to_vec())
                .is_none(),
            "an older view arriving after the node advanced is not evidence"
        );
        assert!(pool.drain().is_empty());
    }

    #[test]
    fn the_pool_emits_evidence_once_on_the_second_conflicting_attestation() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let b = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 0, [0u8; 32], block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        let flagged = pool
            .observe(&address, 1, 1, 0, [0u8; 32], block_b.to_bytes(), b.sig.to_vec())
            .expect("the conflicting attestation is flagged");
        assert!(flagged.attributes(CHAIN_ID, attester.attest_public_key()));
        assert!(pool
            .observe(&address, 1, 1, 0, [0u8; 32], block_b.to_bytes(), b.sig.to_vec())
            .is_none(), "a validator is flagged only once");
        assert_eq!(pool.drain().len(), 1);
    }

    #[test]
    fn the_dedup_maps_stay_bounded_across_advancing_heights() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block = Block::new(1, [1u8; 32], Parent::Genesis);
        let mut pool = EvidencePool::new();

        for height in 1..=10_000u64 {
            let att = attester.attest(CHAIN_ID, height, 1, 0, [0u8; 32], block, &beacon);
            let _ = pool.observe(&address, height, 1, 0, [0u8; 32], block.to_bytes(), att.sig.to_vec());
        }

        assert!(
            pool.seen.len() <= 1,
            "seen holds only the current height, held {}",
            pool.seen.len()
        );
        assert!(
            pool.flagged.len() <= 1,
            "flagged holds only the current height, held {}",
            pool.flagged.len()
        );
    }

    #[test]
    fn a_signed_view_binds_equivocation_and_closes_the_frame() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);

        let honest_a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let honest_b = attester.attest(CHAIN_ID, 1, 1, 1, [0u8; 32], block_b, &beacon);
        let framed = Equivocation {
            offender: address.clone(),
            height: 1,
            view_a: 0,
            view_b: 0,
            slot_a: 1,
            slot_b: 1,
            committee_a: [0u8; 32],
            committee_b: [0u8; 32],
            block_a: block_a.to_bytes(),
            sig_a: honest_a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: honest_b.sig.to_vec(),
        };
        assert!(
            !framed.attributes(CHAIN_ID, attester.attest_public_key()),
            "a forged equal view over a genuine cross view re vote no longer authenticates"
        );

        let double_a = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let double_b = attester.attest(CHAIN_ID, 1, 1, 0, [0u8; 32], block_b, &beacon);
        let genuine = Equivocation {
            offender: address,
            height: 1,
            view_a: 0,
            view_b: 0,
            slot_a: 1,
            slot_b: 1,
            committee_a: [0u8; 32],
            committee_b: [0u8; 32],
            block_a: block_a.to_bytes(),
            sig_a: double_a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: double_b.sig.to_vec(),
        };
        assert!(
            genuine.attributes(CHAIN_ID, attester.attest_public_key()),
            "a genuine same signed view double vote attributes and is slashable"
        );
    }
}
