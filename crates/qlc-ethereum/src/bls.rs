// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub const PUBKEY_LEN: usize = 48;
pub const SIGNATURE_LEN: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsPubkey(pub [u8; PUBKEY_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsSignature(pub [u8; SIGNATURE_LEN]);

impl BlsPubkey {
    pub fn from_bytes(bytes: &[u8]) -> Option<BlsPubkey> {
        if bytes.len() != PUBKEY_LEN {
            return None;
        }
        let mut inner = [0u8; PUBKEY_LEN];
        inner.copy_from_slice(bytes);
        Some(BlsPubkey(inner))
    }
}

impl BlsSignature {
    pub fn from_bytes(bytes: &[u8]) -> Option<BlsSignature> {
        if bytes.len() != SIGNATURE_LEN {
            return None;
        }
        let mut inner = [0u8; SIGNATURE_LEN];
        inner.copy_from_slice(bytes);
        Some(BlsSignature(inner))
    }
}

pub trait BlsAggregateVerifier {
    fn fast_aggregate_verify(
        &self,
        pubkeys: &[BlsPubkey],
        message: &[u8; 32],
        signature: &BlsSignature,
    ) -> bool;
}

#[cfg(test)]
pub mod testkit {
    use super::*;
    use qlc_bitcoin::sha256;

    pub const DST: &[u8] = b"QLC-ETH-BLS-TESTKIT";

    pub struct HashCommitmentBls;

    fn model_pubkey_bytes(secret: &[u8; 32]) -> [u8; PUBKEY_LEN] {
        let mut seed = Vec::new();
        seed.extend_from_slice(b"PK");
        seed.extend_from_slice(secret);
        let a = sha256(&seed);
        let mut b_seed = Vec::new();
        b_seed.extend_from_slice(b"PK2");
        b_seed.extend_from_slice(secret);
        let b = sha256(&b_seed);
        let mut out = [0u8; PUBKEY_LEN];
        out[0..32].copy_from_slice(&a);
        out[32..48].copy_from_slice(&b[0..16]);
        out
    }

    pub fn model_pubkey(secret: &[u8; 32]) -> BlsPubkey {
        BlsPubkey(model_pubkey_bytes(secret))
    }

    fn fold_pubkeys(pubkeys: &[BlsPubkey]) -> [u8; 32] {
        let mut acc = [0u8; 32];
        for pk in pubkeys {
            let h = sha256(&pk.0);
            for i in 0..32 {
                acc[i] ^= h[i];
            }
        }
        acc
    }

    fn commitment(pubkeys: &[BlsPubkey], message: &[u8; 32]) -> [u8; 32] {
        let agg = fold_pubkeys(pubkeys);
        let mut buf = Vec::new();
        buf.extend_from_slice(DST);
        buf.extend_from_slice(&agg);
        buf.extend_from_slice(message);
        sha256(&buf)
    }

    pub fn model_sign(pubkeys: &[BlsPubkey], message: &[u8; 32]) -> BlsSignature {
        let c = commitment(pubkeys, message);
        let mut out = [0u8; SIGNATURE_LEN];
        out[0..32].copy_from_slice(&c);
        BlsSignature(out)
    }

    impl BlsAggregateVerifier for HashCommitmentBls {
        fn fast_aggregate_verify(
            &self,
            pubkeys: &[BlsPubkey],
            message: &[u8; 32],
            signature: &BlsSignature,
        ) -> bool {
            if pubkeys.is_empty() {
                return false;
            }
            let expected = model_sign(pubkeys, message);
            expected == *signature
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    fn secret(i: u8) -> [u8; 32] {
        [i; 32]
    }

    #[test]
    fn a_signature_over_the_committee_and_message_verifies() {
        let keys: Vec<BlsPubkey> = (0..8).map(|i| model_pubkey(&secret(i))).collect();
        let msg = [0x33u8; 32];
        let sig = model_sign(&keys, &msg);
        assert!(HashCommitmentBls.fast_aggregate_verify(&keys, &msg, &sig));
    }

    #[test]
    fn a_flipped_signature_byte_fails() {
        let keys: Vec<BlsPubkey> = (0..8).map(|i| model_pubkey(&secret(i))).collect();
        let msg = [0x33u8; 32];
        let mut sig = model_sign(&keys, &msg);
        sig.0[0] ^= 0xff;
        assert!(!HashCommitmentBls.fast_aggregate_verify(&keys, &msg, &sig));
    }

    #[test]
    fn a_different_message_fails() {
        let keys: Vec<BlsPubkey> = (0..8).map(|i| model_pubkey(&secret(i))).collect();
        let sig = model_sign(&keys, &[0x33u8; 32]);
        assert!(!HashCommitmentBls.fast_aggregate_verify(&keys, &[0x34u8; 32], &sig));
    }

    #[test]
    fn dropping_a_participant_fails() {
        let keys: Vec<BlsPubkey> = (0..8).map(|i| model_pubkey(&secret(i))).collect();
        let msg = [0x33u8; 32];
        let sig = model_sign(&keys, &msg);
        assert!(!HashCommitmentBls.fast_aggregate_verify(&keys[0..7], &msg, &sig));
    }

    #[test]
    fn the_aggregate_is_order_independent() {
        let keys: Vec<BlsPubkey> = (0..8).map(|i| model_pubkey(&secret(i))).collect();
        let msg = [0x33u8; 32];
        let sig = model_sign(&keys, &msg);
        let mut reordered = keys.clone();
        reordered.reverse();
        assert!(HashCommitmentBls.fast_aggregate_verify(&reordered, &msg, &sig));
    }

    #[test]
    fn an_empty_committee_never_verifies() {
        let sig = BlsSignature([0u8; SIGNATURE_LEN]);
        assert!(!HashCommitmentBls.fast_aggregate_verify(&[], &[0u8; 32], &sig));
    }
}
