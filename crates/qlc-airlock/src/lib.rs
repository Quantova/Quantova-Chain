#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qlc_core::VerificationTier;
use qlc_registry::{corridor_for_id, ChainFamily};
use qlc_stark::corridors::is_proof_corridor;
use qlc_stark::{StarkStatement, StatementKind, QUANTOVA_DEST_CHAIN_ID};

pub const MAGIC: [u8; 4] = *b"QALK";
pub const VERSION: u8 = 1;

pub const SUITE_ML_DSA: u8 = 0x01;
pub const SUITE_HASH_STARK: u8 = 0x02;

pub const ML_DSA_65_SIG_LEN: usize = 3309;
pub const STARK_STATEMENT_LEN: usize = StarkStatement::ENCODED_LEN;
pub const MIN_HASH_STARK_LEN: usize = STARK_STATEMENT_LEN + 1;
pub const MAX_HASH_STARK_LEN: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressError {
    TooShort,
    BadMagic,
    BadVersion,
    UnknownSuite { slot: usize, suite: u8 },
    SlotOutOfOrder { slot: usize, expected: u8, found: u8 },
    BadArtifactLength { slot: usize },
    Truncated { slot: usize },
    TrailingBytes,
    BadStatement,
    NotProofCorridor,
    WrongDestination { expected: u32, found: u32 },
    UnknownCorridor { corridor_id: u32 },
    CorridorKindMismatch { corridor_id: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlDsaAttestation {
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashStark {
    pub statement: StarkStatement,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingress {
    pub attestation: MlDsaAttestation,
    pub proof: HashStark,
}

pub trait AttestationVerifier {
    fn verify(&self, message: &[u8], attestation: &MlDsaAttestation) -> bool;
}

fn read_slot(bytes: &[u8], off: usize, slot: usize) -> Result<(u8, &[u8], usize), IngressError> {
    if off + 5 > bytes.len() {
        return Err(IngressError::Truncated { slot });
    }
    let suite = bytes[off];
    if suite != SUITE_ML_DSA && suite != SUITE_HASH_STARK {
        return Err(IngressError::UnknownSuite { slot, suite });
    }
    let len = u32::from_le_bytes([bytes[off + 1], bytes[off + 2], bytes[off + 3], bytes[off + 4]]) as usize;
    if len > MAX_HASH_STARK_LEN {
        return Err(IngressError::BadArtifactLength { slot });
    }
    let start = off + 5;
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(IngressError::Truncated { slot }),
    };
    if end > bytes.len() {
        return Err(IngressError::Truncated { slot });
    }
    Ok((suite, &bytes[start..end], end))
}

pub fn parse_ingress(bytes: &[u8]) -> Result<Ingress, IngressError> {
    if bytes.len() < MAGIC.len() + 1 {
        return Err(IngressError::TooShort);
    }
    if bytes[0..4] != MAGIC {
        return Err(IngressError::BadMagic);
    }
    if bytes[4] != VERSION {
        return Err(IngressError::BadVersion);
    }

    let (suite0, payload0, off1) = read_slot(bytes, 5, 0)?;
    if suite0 != SUITE_ML_DSA {
        return Err(IngressError::SlotOutOfOrder { slot: 0, expected: SUITE_ML_DSA, found: suite0 });
    }
    if payload0.len() != ML_DSA_65_SIG_LEN {
        return Err(IngressError::BadArtifactLength { slot: 0 });
    }

    let (suite1, payload1, off2) = read_slot(bytes, off1, 1)?;
    if suite1 != SUITE_HASH_STARK {
        return Err(IngressError::SlotOutOfOrder { slot: 1, expected: SUITE_HASH_STARK, found: suite1 });
    }
    if payload1.len() < MIN_HASH_STARK_LEN {
        return Err(IngressError::BadArtifactLength { slot: 1 });
    }

    if off2 != bytes.len() {
        return Err(IngressError::TrailingBytes);
    }

    let statement = StarkStatement::decode(&payload1[0..STARK_STATEMENT_LEN]).ok_or(IngressError::BadStatement)?;
    if statement.dest_chain_id != QUANTOVA_DEST_CHAIN_ID {
        return Err(IngressError::WrongDestination {
            expected: QUANTOVA_DEST_CHAIN_ID,
            found: statement.dest_chain_id,
        });
    }
    if !is_proof_corridor(statement.kind) {
        return Err(IngressError::NotProofCorridor);
    }
    // The corridor id must name a registered corridor whose verification tier AND chain family match
    // the proof kind, so a proof cannot be presented under an unregistered id, a federated corridor it
    // was not built for, or a same-tier corridor of the wrong family (an EVM proof under a Cosmos
    // corridor). Both share the LightClient tier, so the family check is what separates them.
    let corridor = corridor_for_id(statement.corridor_id)
        .map_err(|_| IngressError::UnknownCorridor { corridor_id: statement.corridor_id })?;
    let (expected_tier, expected_family) = match statement.kind {
        StatementKind::BitcoinSpv => (VerificationTier::Spv, ChainFamily::Bitcoin),
        StatementKind::EvmLightClient => (VerificationTier::LightClient, ChainFamily::Evm),
        StatementKind::CosmosTendermint => (VerificationTier::LightClient, ChainFamily::Cosmos),
        _ => return Err(IngressError::NotProofCorridor),
    };
    if corridor.tier != expected_tier || corridor.id.family() != expected_family {
        return Err(IngressError::CorridorKindMismatch { corridor_id: statement.corridor_id });
    }

    Ok(Ingress {
        attestation: MlDsaAttestation { signature: payload0.to_vec() },
        proof: HashStark { statement, proof: payload1[STARK_STATEMENT_LEN..].to_vec() },
    })
}

fn push_slot(out: &mut Vec<u8>, suite: u8, payload: &[u8]) {
    out.push(suite);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

pub fn encode_ingress(attestation: &[u8], statement: &StarkStatement, proof: &[u8]) -> Vec<u8> {
    let mut stark_payload = statement.encode();
    stark_payload.extend_from_slice(proof);
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    push_slot(&mut out, SUITE_ML_DSA, attestation);
    push_slot(&mut out, SUITE_HASH_STARK, &stark_payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlc_stark::StatementKind;

    const FOREIGN_SUITE_ED25519: u8 = 0x10;
    const FOREIGN_SUITE_SECP256K1: u8 = 0x11;
    const FOREIGN_SUITE_BLS: u8 = 0x12;

    fn ml_dsa_attestation() -> Vec<u8> {
        vec![0x07u8; ML_DSA_65_SIG_LEN]
    }

    fn proof_statement() -> StarkStatement {
        StarkStatement { corridor_id: 0, dest_chain_id: 4801, nonce: 990_001, kind: StatementKind::BitcoinSpv, public_input_digest: [0x5au8; 32] }
    }

    fn ed25519_signature() -> Vec<u8> {
        vec![0xa1u8; 64]
    }

    fn ed25519_public_key() -> Vec<u8> {
        vec![0xa2u8; 32]
    }

    fn secp256k1_compressed_pubkey() -> Vec<u8> {
        let mut v = vec![0x02u8];
        v.extend_from_slice(&[0xb1u8; 32]);
        v
    }

    fn secp256k1_ecdsa_der() -> Vec<u8> {
        let mut v = vec![0x30u8, 0x44, 0x02, 0x20];
        v.extend_from_slice(&[0xc1u8; 32]);
        v.extend_from_slice(&[0x02u8, 0x20]);
        v.extend_from_slice(&[0xc2u8; 32]);
        v
    }

    fn bls12_381_g1_compressed() -> Vec<u8> {
        let mut v = vec![0xa0u8];
        v.extend_from_slice(&[0xd1u8; 47]);
        v
    }

    fn bls12_381_g2_compressed() -> Vec<u8> {
        let mut v = vec![0xa0u8];
        v.extend_from_slice(&[0xd2u8; 95]);
        v
    }

    fn wrap_two_slots(suite0: u8, payload0: &[u8], suite1: u8, payload1: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        push_slot(&mut out, suite0, payload0);
        push_slot(&mut out, suite1, payload1);
        out
    }

    #[test]
    fn the_statement_length_constant_tracks_the_stark_encoding() {
        assert_eq!(proof_statement().encode().len(), STARK_STATEMENT_LEN);
    }

    #[test]
    fn a_well_formed_ingress_parses_to_the_two_post_quantum_artifacts() {
        let bytes = encode_ingress(&ml_dsa_attestation(), &proof_statement(), &[0x01u8; 200]);
        let ingress = parse_ingress(&bytes).unwrap();
        assert_eq!(ingress.attestation.signature.len(), ML_DSA_65_SIG_LEN);
        assert!(is_proof_corridor(ingress.proof.statement.kind));
        assert_eq!(ingress.proof.proof, vec![0x01u8; 200]);
    }

    #[test]
    fn an_oversized_proof_slot_is_refused() {
        let huge = vec![0u8; MAX_HASH_STARK_LEN + 1];
        let bytes = encode_ingress(&ml_dsa_attestation(), &proof_statement(), &huge);
        assert_eq!(parse_ingress(&bytes), Err(IngressError::BadArtifactLength { slot: 1 }));
    }

    #[test]
    fn every_proof_corridor_statement_crosses_the_airlock() {
        // Each kind is presented under a corridor whose tier matches: Bitcoin (Spv), Ethereum and
        // Cosmos Hub (LightClient). A mismatched or unregistered corridor id is rejected below.
        for (kind, corridor_id) in [
            (StatementKind::BitcoinSpv, 0u32),
            (StatementKind::EvmLightClient, 2u32),
            (StatementKind::CosmosTendermint, 16u32),
        ] {
            let statement = StarkStatement { corridor_id, dest_chain_id: 4801, nonce: 990_001, kind, public_input_digest: [9u8; 32] };
            let bytes = encode_ingress(&ml_dsa_attestation(), &statement, &[0x02u8; 8]);
            assert_eq!(parse_ingress(&bytes).unwrap().proof.statement.kind, kind);
        }
    }

    #[test]
    fn a_proof_under_a_mismatched_or_unknown_corridor_is_rejected() {
        // A Bitcoin SPV proof presented under a federated corridor (Circle CCTP, id 38).
        let mismatched = StarkStatement { corridor_id: 38, dest_chain_id: 4801, nonce: 990_001, kind: StatementKind::BitcoinSpv, public_input_digest: [9u8; 32] };
        let bytes = encode_ingress(&ml_dsa_attestation(), &mismatched, &[0x02u8; 8]);
        assert_eq!(parse_ingress(&bytes), Err(IngressError::CorridorKindMismatch { corridor_id: 38 }));

        // An unregistered corridor id past the registry.
        let unknown = StarkStatement { corridor_id: 4_000_000_000, dest_chain_id: 4801, nonce: 990_001, kind: StatementKind::EvmLightClient, public_input_digest: [9u8; 32] };
        let bytes = encode_ingress(&ml_dsa_attestation(), &unknown, &[0x02u8; 8]);
        assert_eq!(parse_ingress(&bytes), Err(IngressError::UnknownCorridor { corridor_id: 4_000_000_000 }));

        // An EVM light-client proof presented under a Cosmos corridor (Cosmos Hub, id 16): both are the
        // LightClient tier, so only the family check rejects the cross-family crossing.
        let cross = StarkStatement { corridor_id: 16, dest_chain_id: 4801, nonce: 990_001, kind: StatementKind::EvmLightClient, public_input_digest: [9u8; 32] };
        let bytes = encode_ingress(&ml_dsa_attestation(), &cross, &[0x02u8; 8]);
        assert_eq!(parse_ingress(&bytes), Err(IngressError::CorridorKindMismatch { corridor_id: 16 }));
    }

    #[test]
    fn a_generic_non_proof_statement_does_not_cross() {
        let statement = StarkStatement { corridor_id: 1, dest_chain_id: 4801, nonce: 990_001, kind: StatementKind::LightClientStep, public_input_digest: [9u8; 32] };
        let bytes = encode_ingress(&ml_dsa_attestation(), &statement, &[0x02u8; 8]);
        assert_eq!(parse_ingress(&bytes), Err(IngressError::NotProofCorridor));
    }

    #[test]
    fn a_statement_addressed_to_another_chain_does_not_cross() {
        let statement = StarkStatement { corridor_id: 0, dest_chain_id: 4802, nonce: 990_001, kind: StatementKind::BitcoinSpv, public_input_digest: [0x5au8; 32] };
        let bytes = encode_ingress(&ml_dsa_attestation(), &statement, &[0x02u8; 8]);
        assert_eq!(
            parse_ingress(&bytes),
            Err(IngressError::WrongDestination { expected: QUANTOVA_DEST_CHAIN_ID, found: 4802 })
        );
    }

    #[test]
    fn exactly_two_artifacts_a_third_slot_is_trailing() {
        let mut bytes = encode_ingress(&ml_dsa_attestation(), &proof_statement(), &[0x01u8; 8]);
        push_slot(&mut bytes, SUITE_ML_DSA, &ml_dsa_attestation());
        assert_eq!(parse_ingress(&bytes), Err(IngressError::TrailingBytes));
    }

    #[test]
    fn exactly_two_artifacts_a_single_slot_is_truncated() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        push_slot(&mut bytes, SUITE_ML_DSA, &ml_dsa_attestation());
        assert_eq!(parse_ingress(&bytes), Err(IngressError::Truncated { slot: 1 }));
    }

    #[test]
    fn empty_input_is_too_short() {
        assert_eq!(parse_ingress(&[]), Err(IngressError::TooShort));
    }

    #[test]
    fn the_two_slots_may_not_be_swapped() {
        let mut stark_payload = proof_statement().encode();
        stark_payload.extend_from_slice(&[0x01u8; 8]);
        let bytes = wrap_two_slots(SUITE_HASH_STARK, &stark_payload, SUITE_ML_DSA, &ml_dsa_attestation());
        assert_eq!(
            parse_ingress(&bytes),
            Err(IngressError::SlotOutOfOrder { slot: 0, expected: SUITE_ML_DSA, found: SUITE_HASH_STARK })
        );
    }

    #[test]
    fn negative_vector_ed25519_signature_is_unparseable() {
        let sig = ed25519_signature();
        assert_eq!(parse_ingress(&sig), Err(IngressError::BadMagic));

        let wrapped = wrap_two_slots(FOREIGN_SUITE_ED25519, &sig, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&wrapped), Err(IngressError::UnknownSuite { slot: 0, suite: FOREIGN_SUITE_ED25519 }));

        let spoofed = wrap_two_slots(SUITE_ML_DSA, &sig, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&spoofed), Err(IngressError::BadArtifactLength { slot: 0 }));
    }

    #[test]
    fn negative_vector_ed25519_public_key_is_unparseable() {
        let key = ed25519_public_key();
        assert_eq!(parse_ingress(&key), Err(IngressError::BadMagic));
        let spoofed = wrap_two_slots(SUITE_ML_DSA, &key, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&spoofed), Err(IngressError::BadArtifactLength { slot: 0 }));
    }

    #[test]
    fn negative_vector_secp256k1_pubkey_is_unparseable() {
        let key = secp256k1_compressed_pubkey();
        assert_eq!(parse_ingress(&key), Err(IngressError::BadMagic));

        let wrapped = wrap_two_slots(FOREIGN_SUITE_SECP256K1, &key, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&wrapped), Err(IngressError::UnknownSuite { slot: 0, suite: FOREIGN_SUITE_SECP256K1 }));

        let spoofed = wrap_two_slots(SUITE_ML_DSA, &key, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&spoofed), Err(IngressError::BadArtifactLength { slot: 0 }));
    }

    #[test]
    fn negative_vector_secp256k1_ecdsa_der_is_unparseable() {
        let sig = secp256k1_ecdsa_der();
        assert_eq!(parse_ingress(&sig), Err(IngressError::BadMagic));
        let spoofed = wrap_two_slots(SUITE_ML_DSA, &sig, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&spoofed), Err(IngressError::BadArtifactLength { slot: 0 }));
    }

    #[test]
    fn negative_vector_bls12_381_g1_is_unparseable() {
        let point = bls12_381_g1_compressed();
        assert_eq!(parse_ingress(&point), Err(IngressError::BadMagic));

        let wrapped = wrap_two_slots(FOREIGN_SUITE_BLS, &point, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&wrapped), Err(IngressError::UnknownSuite { slot: 0, suite: FOREIGN_SUITE_BLS }));

        let spoofed = wrap_two_slots(SUITE_ML_DSA, &point, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&spoofed), Err(IngressError::BadArtifactLength { slot: 0 }));
    }

    #[test]
    fn negative_vector_bls12_381_g2_is_unparseable() {
        let point = bls12_381_g2_compressed();
        assert_eq!(parse_ingress(&point), Err(IngressError::BadMagic));
        let spoofed = wrap_two_slots(SUITE_ML_DSA, &point, SUITE_HASH_STARK, &proof_statement().encode());
        assert_eq!(parse_ingress(&spoofed), Err(IngressError::BadArtifactLength { slot: 0 }));
    }

    #[test]
    fn a_foreign_suite_in_the_proof_slot_is_also_refused() {
        let bytes = wrap_two_slots(SUITE_ML_DSA, &ml_dsa_attestation(), FOREIGN_SUITE_BLS, &bls12_381_g2_compressed());
        assert_eq!(parse_ingress(&bytes), Err(IngressError::UnknownSuite { slot: 1, suite: FOREIGN_SUITE_BLS }));
    }
}
