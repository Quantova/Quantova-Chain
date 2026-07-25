use std::collections::HashMap;

use qtv_codec::{Decoder, Encoder};
use qtv_crypto::ml_dsa::{self, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

use qtv_attest::params::ATTEST_CONTEXT;

fn attestation_message(height: u64, slot: u64, view: u64, block_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(24 + block_bytes.len());
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(&slot.to_le_bytes());
    msg.extend_from_slice(&view.to_le_bytes());
    msg.extend_from_slice(block_bytes);
    msg
}

/// Attributable equivocation evidence, the two conflicting attestations one validator
/// signed at one height in one view for two different blocks. It carries the offender's bond
/// address, the height and slot, the view each conflicting attestation was cast in, and each
/// signed block with its signature. It authenticates against the offender's registered
/// attestation key alone, so any node can verify it from state with no access to the live
/// roster and slash the same offender deterministically.
///
/// The two views gate the offence. Only a same view double vote, the same target voted twice
/// with two different blocks, attributes and is slashable. A pair whose views differ is a
/// justified vote change, a block that failed to lock in one view followed by a different
/// block in a higher view, and it never attributes. The view each attestation was cast in is
/// committed inside the signed attestation message, so each view rides into its own signature
/// preimage. A reporter that forges an equal view over an honest cross view pair no longer
/// authenticates, since a view stated here that differs from the one the offender signed
/// breaks the signature check. The gate binds the offender's own signed views, not a
/// reporter's claim about them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Equivocation {
    pub offender: String,
    pub height: u64,
    pub slot: u64,
    pub view_a: u64,
    pub view_b: u64,
    pub block_a: Vec<u8>,
    pub sig_a: Vec<u8>,
    pub block_b: Vec<u8>,
    pub sig_b: Vec<u8>,
}

impl Equivocation {
    pub fn attributes(&self, attest_pk: &[u8]) -> bool {
        if self.block_a == self.block_b {
            return false;
        }
        if self.view_a != self.view_b {
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
        let msg_a = attestation_message(self.height, self.slot, self.view_a, &self.block_a);
        let msg_b = attestation_message(self.height, self.slot, self.view_b, &self.block_b);
        ml_dsa::verify(&pk, &msg_a, &sig_a, ATTEST_CONTEXT)
            && ml_dsa::verify(&pk, &msg_b, &sig_b, ATTEST_CONTEXT)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.put_bytes(self.offender.as_bytes());
        encoder.put_u64(self.height);
        encoder.put_u64(self.slot);
        encoder.put_u64(self.view_a);
        encoder.put_u64(self.view_b);
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
        let slot = decoder.get_u64().ok()?;
        let view_a = decoder.get_u64().ok()?;
        let view_b = decoder.get_u64().ok()?;
        let block_a = decoder.get_bytes().ok()?.to_vec();
        let sig_a = decoder.get_bytes().ok()?.to_vec();
        let block_b = decoder.get_bytes().ok()?.to_vec();
        let sig_b = decoder.get_bytes().ok()?.to_vec();
        decoder.finish().ok()?;
        Some(Equivocation {
            offender,
            height,
            slot,
            view_a,
            view_b,
            block_a,
            sig_a,
            block_b,
            sig_b,
        })
    }
}

/// A pool that watches the attestations a node sees and turns two conflicting attestations
/// from one validator at one height in one view into attributable evidence. The first
/// attestation seen for a validator at a height is remembered with the view it was cast in. A
/// later attestation for a different block in the same view is an equivocation the pool emits
/// once for a block to carry. A later attestation in a higher view is a justified vote change,
/// so the pool supersedes the remembered vote and emits nothing. A later attestation in a
/// lower view arrived after the node moved on and is ignored.
#[derive(Default)]
pub struct EvidencePool {
    seen: HashMap<(String, u64), (u64, u64, Vec<u8>, Vec<u8>)>,
    pending: Vec<Equivocation>,
    flagged: Vec<(String, u64)>,
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
        block_bytes: Vec<u8>,
        sig: Vec<u8>,
    ) -> Option<Equivocation> {
        let key = (offender.to_string(), height);
        match self.seen.get(&key) {
            Some((prev_view, _, prev_block, prev_sig)) => {
                if view > *prev_view {
                    self.seen.insert(key, (view, slot, block_bytes, sig));
                    return None;
                }
                if view < *prev_view {
                    return None;
                }
                if *prev_block == block_bytes {
                    return None;
                }
                if self.flagged.contains(&key) {
                    return None;
                }
                let evidence = Equivocation {
                    offender: offender.to_string(),
                    height,
                    slot,
                    view_a: *prev_view,
                    view_b: view,
                    block_a: prev_block.clone(),
                    sig_a: prev_sig.clone(),
                    block_b: block_bytes,
                    sig_b: sig,
                };
                self.flagged.push(key);
                self.pending.push(evidence.clone());
                Some(evidence)
            }
            None => {
                self.seen.insert(key, (view, slot, block_bytes, sig));
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
        let a = attester.attest(1, 1, 0, block_a, &beacon);
        let b = attester.attest(1, 1, 0, block_b, &beacon);
        let evidence = Equivocation {
            offender: address.to_string(),
            height: 1,
            slot: 1,
            view_a: 0,
            view_b: 0,
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
        assert!(evidence.attributes(&pk));
        assert_eq!(Equivocation::decode(&evidence.encode()), Some(evidence));
    }

    #[test]
    fn a_pair_for_the_same_block_is_not_an_equivocation() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block = Block::new(1, [1u8; 32], Parent::Genesis);
        let a = attester.attest(1, 1, 0, block, &beacon);
        let evidence = Equivocation {
            offender: address,
            height: 1,
            slot: 1,
            view_a: 0,
            view_b: 0,
            block_a: block.to_bytes(),
            sig_a: a.sig.to_vec(),
            block_b: block.to_bytes(),
            sig_b: a.sig.to_vec(),
        };
        assert!(!evidence.attributes(attester.attest_public_key()));
    }

    #[test]
    fn evidence_never_attributes_to_another_key() {
        let (attester, address) = attester();
        let (evidence, _) = equivocation(&attester, &address);
        let stranger = Attester::from_secret(2, &[6u8; 32], 2_000);
        assert!(!evidence.attributes(stranger.attest_public_key()));
    }

    #[test]
    fn a_same_view_double_vote_attributes_and_is_slashable() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(1, 1, 0, block_a, &beacon);
        let b = attester.attest(1, 1, 0, block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 0, block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        let flagged = pool
            .observe(&address, 1, 1, 0, block_b.to_bytes(), b.sig.to_vec())
            .expect("a conflicting block in the same view is a genuine double vote");
        assert_eq!((flagged.view_a, flagged.view_b), (0, 0));
        assert!(
            flagged.attributes(attester.attest_public_key()),
            "the same view double vote authenticates and slashes"
        );
    }

    #[test]
    fn an_honest_cross_view_re_vote_is_not_slashed() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(1, 1, 0, block_a, &beacon);
        let b = attester.attest(1, 1, 1, block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 0, block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        assert!(
            pool.observe(&address, 1, 1, 1, block_b.to_bytes(), b.sig.to_vec())
                .is_none(),
            "a higher view re vote is a justified vote change"
        );
        assert!(pool.drain().is_empty(), "no evidence is attributed for a view change");

        let hand_built = Equivocation {
            offender: address,
            height: 1,
            slot: 1,
            view_a: 0,
            view_b: 1,
            block_a: block_a.to_bytes(),
            sig_a: a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: b.sig.to_vec(),
        };
        assert!(
            !hand_built.attributes(attester.attest_public_key()),
            "the deterministic gate refuses a cross view pair even with valid signatures"
        );
    }

    #[test]
    fn a_lower_view_attestation_arriving_late_is_ignored() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(1, 1, 0, block_a, &beacon);
        let b = attester.attest(1, 1, 2, block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 2, block_b.to_bytes(), b.sig.to_vec())
            .is_none());
        assert!(
            pool.observe(&address, 1, 1, 0, block_a.to_bytes(), a.sig.to_vec())
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
        let a = attester.attest(1, 1, 0, block_a, &beacon);
        let b = attester.attest(1, 1, 0, block_b, &beacon);

        let mut pool = EvidencePool::new();
        assert!(pool
            .observe(&address, 1, 1, 0, block_a.to_bytes(), a.sig.to_vec())
            .is_none());
        let flagged = pool
            .observe(&address, 1, 1, 0, block_b.to_bytes(), b.sig.to_vec())
            .expect("the conflicting attestation is flagged");
        assert!(flagged.attributes(attester.attest_public_key()));
        assert!(pool
            .observe(&address, 1, 1, 0, block_b.to_bytes(), b.sig.to_vec())
            .is_none(), "a validator is flagged only once");
        assert_eq!(pool.drain().len(), 1);
    }

    #[test]
    fn a_signed_view_binds_equivocation_and_closes_the_frame() {
        let (attester, address) = attester();
        let beacon = Beacon::genesis();
        let block_a = Block::new(1, [1u8; 32], Parent::Genesis);
        let block_b = Block::new(1, [2u8; 32], Parent::Genesis);

        // An honest validator legitimately re votes across a view change, block_a in view 0
        // and block_b in view 1. A malicious reporter pairs the two and asserts an equal view
        // to frame the honest signer as a same view double vote.
        let honest_a = attester.attest(1, 1, 0, block_a, &beacon);
        let honest_b = attester.attest(1, 1, 1, block_b, &beacon);
        let framed = Equivocation {
            offender: address.clone(),
            height: 1,
            slot: 1,
            view_a: 0,
            view_b: 0,
            block_a: block_a.to_bytes(),
            sig_a: honest_a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: honest_b.sig.to_vec(),
        };
        assert!(
            !framed.attributes(attester.attest_public_key()),
            "a forged equal view over a genuine cross view re vote no longer authenticates"
        );

        // Two conflicting blocks the offender actually signed in one and the same view are a
        // genuine double vote that attributes and slashes.
        let double_a = attester.attest(1, 1, 0, block_a, &beacon);
        let double_b = attester.attest(1, 1, 0, block_b, &beacon);
        let genuine = Equivocation {
            offender: address,
            height: 1,
            slot: 1,
            view_a: 0,
            view_b: 0,
            block_a: block_a.to_bytes(),
            sig_a: double_a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: double_b.sig.to_vec(),
        };
        assert!(
            genuine.attributes(attester.attest_public_key()),
            "a genuine same signed view double vote attributes and is slashable"
        );
    }
}
