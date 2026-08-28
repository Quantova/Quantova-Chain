// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use qlc_ethereum::bls::{BlsAggregateVerifier, BlsPubkey, BlsSignature};

pub const ETH_SYNC_COMMITTEE_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, Default, Clone, Copy)]
pub struct Bls12381AggregateVerifier;

impl Bls12381AggregateVerifier {
    pub fn new() -> Self {
        Bls12381AggregateVerifier
    }
}

impl BlsAggregateVerifier for Bls12381AggregateVerifier {
    fn fast_aggregate_verify(
        &self,
        pubkeys: &[BlsPubkey],
        message: &[u8; 32],
        signature: &BlsSignature,
    ) -> bool {
        if pubkeys.is_empty() {
            return false;
        }
        let mut keys = Vec::with_capacity(pubkeys.len());
        for pubkey in pubkeys {
            match PublicKey::key_validate(&pubkey.0) {
                Ok(key) => keys.push(key),
                Err(_) => return false,
            }
        }
        let signature = match Signature::from_bytes(&signature.0) {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        let borrowed: Vec<&PublicKey> = keys.iter().collect();
        signature.fast_aggregate_verify(true, message, ETH_SYNC_COMMITTEE_DST, &borrowed)
            == BLST_ERROR::BLST_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_from_hex(text: &str) -> Vec<u8> {
        let clean = text.strip_prefix("0x").unwrap_or(text);
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    fn pubkey(text: &str) -> BlsPubkey {
        BlsPubkey::from_bytes(&bytes_from_hex(text)).unwrap()
    }

    fn signature(text: &str) -> BlsSignature {
        BlsSignature::from_bytes(&bytes_from_hex(text)).unwrap()
    }

    fn message(text: &str) -> [u8; 32] {
        let raw = bytes_from_hex(text);
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    }

    const PK_A: &str = "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
    const PK_B: &str = "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81";
    const PK_C: &str = "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f";

    const MESSAGE_ABAB: &str =
        "0xabababababababababababababababababababababababababababababababab";
    const MESSAGE_5656: &str =
        "0x5656565656565656565656565656565656565656565656565656565656565656";
    const MESSAGE_ZERO: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    const AGGREGATE_ABAB_VALID: &str = "0x9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930";
    const AGGREGATE_ABAB_TAMPERED: &str = "0x9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfcffffffff";
    const SIGNATURE_ZERO_SINGLE: &str = "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55";

    #[test]
    fn a_real_ethereum_aggregate_over_a_finalized_message_verifies() {
        let keys = vec![pubkey(PK_A), pubkey(PK_B), pubkey(PK_C)];
        let signed = message(MESSAGE_ABAB);
        let aggregate = signature(AGGREGATE_ABAB_VALID);
        assert!(Bls12381AggregateVerifier::new().fast_aggregate_verify(&keys, &signed, &aggregate));
    }

    #[test]
    fn a_single_signer_published_vector_verifies() {
        let keys = vec![pubkey(PK_A)];
        let signed = message(MESSAGE_ZERO);
        let aggregate = signature(SIGNATURE_ZERO_SINGLE);
        assert!(Bls12381AggregateVerifier::new().fast_aggregate_verify(&keys, &signed, &aggregate));
    }

    #[test]
    fn a_tampered_published_aggregate_fails() {
        let keys = vec![pubkey(PK_A), pubkey(PK_B), pubkey(PK_C)];
        let signed = message(MESSAGE_ABAB);
        let aggregate = signature(AGGREGATE_ABAB_TAMPERED);
        assert!(!Bls12381AggregateVerifier::new().fast_aggregate_verify(&keys, &signed, &aggregate));
    }

    #[test]
    fn the_valid_aggregate_over_a_different_message_fails() {
        let keys = vec![pubkey(PK_A), pubkey(PK_B), pubkey(PK_C)];
        let other = message(MESSAGE_5656);
        let aggregate = signature(AGGREGATE_ABAB_VALID);
        assert!(!Bls12381AggregateVerifier::new().fast_aggregate_verify(&keys, &other, &aggregate));
    }

    #[test]
    fn dropping_a_signer_from_the_committee_fails() {
        let keys = vec![pubkey(PK_A), pubkey(PK_B)];
        let signed = message(MESSAGE_ABAB);
        let aggregate = signature(AGGREGATE_ABAB_VALID);
        assert!(!Bls12381AggregateVerifier::new().fast_aggregate_verify(&keys, &signed, &aggregate));
    }

    #[test]
    fn an_empty_committee_never_verifies() {
        let aggregate = signature(AGGREGATE_ABAB_VALID);
        assert!(
            !Bls12381AggregateVerifier::new().fast_aggregate_verify(
                &[],
                &message(MESSAGE_ABAB),
                &aggregate
            )
        );
    }

    #[test]
    fn a_malformed_pubkey_fails_closed() {
        let keys = vec![BlsPubkey([0xff; 48])];
        let aggregate = signature(SIGNATURE_ZERO_SINGLE);
        assert!(
            !Bls12381AggregateVerifier::new().fast_aggregate_verify(
                &keys,
                &message(MESSAGE_ZERO),
                &aggregate
            )
        );
    }
}
