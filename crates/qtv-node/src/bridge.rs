// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_codec::{Decode, Decoder, Encode, Encoder, Error};
use qtv_crypto::ml_dsa::{self, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use qtv_crypto::sha3;

pub const ATTEST_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/ATTEST/v1";
pub const STATEMENT_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/BRIDGE-PROVER/v1";

pub const FACT_VERSION: u8 = 1;
pub const FACT_ENCODED_LEN: usize = 138;

pub const ARTIFACT_ATTESTATION: u8 = 0x01;
pub const ARTIFACT_STARK: u8 = 0x02;
pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Deposit,
    ExitAck,
}

impl Direction {
    fn tag(self) -> u8 {
        match self {
            Direction::Deposit => 0,
            Direction::ExitAck => 1,
        }
    }

    fn from_tag(tag: u8) -> Option<Direction> {
        match tag {
            0 => Some(Direction::Deposit),
            1 => Some(Direction::ExitAck),
            _ => None,
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn u128(&mut self) -> Option<u128> {
        Some(u128::from_le_bytes(self.take(16)?.try_into().ok()?))
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    pub version: u8,
    pub source_chain: u32,
    pub dest_chain: u32,
    pub route_id: u32,
    pub direction: Direction,
    pub nonce: u64,
    pub source_ref: [u8; 32],
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub recipient: [u8; 32],
    pub finality_depth: u32,
    pub observed_height: u64,
    pub expiry_height: u64,
}

impl Fact {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FACT_ENCODED_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.source_chain.to_le_bytes());
        out.extend_from_slice(&self.dest_chain.to_le_bytes());
        out.extend_from_slice(&self.route_id.to_le_bytes());
        out.push(self.direction.tag());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.source_ref);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.finality_depth.to_le_bytes());
        out.extend_from_slice(&self.observed_height.to_le_bytes());
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        out
    }

    fn read(reader: &mut Reader<'_>) -> Option<Fact> {
        let version = reader.u8()?;
        let source_chain = reader.u32()?;
        let dest_chain = reader.u32()?;
        let route_id = reader.u32()?;
        let direction = Direction::from_tag(reader.u8()?)?;
        let nonce = reader.u64()?;
        let source_ref = reader.array::<32>()?;
        let asset_id = reader.array::<16>()?;
        let amount = reader.u128()?;
        let recipient = reader.array::<32>()?;
        let finality_depth = reader.u32()?;
        let observed_height = reader.u64()?;
        let expiry_height = reader.u64()?;
        Some(Fact {
            version,
            source_chain,
            dest_chain,
            route_id,
            direction,
            nonce,
            source_ref,
            asset_id,
            amount,
            recipient,
            finality_depth,
            observed_height,
            expiry_height,
        })
    }

    pub fn decode(bytes: &[u8]) -> Option<Fact> {
        let mut reader = Reader::new(bytes);
        let fact = Fact::read(&mut reader)?;
        reader.done().then_some(fact)
    }

    pub fn attest_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATTEST_DOMAIN.len() + FACT_ENCODED_LEN);
        out.extend_from_slice(ATTEST_DOMAIN);
        out.extend_from_slice(&self.encode());
        out
    }

    pub fn statement_digest(&self, operator: u32) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(STATEMENT_DOMAIN.len() + 4 + FACT_ENCODED_LEN);
        preimage.extend_from_slice(STATEMENT_DOMAIN);
        preimage.extend_from_slice(&operator.to_le_bytes());
        preimage.extend_from_slice(&self.encode());
        let mut digest = [0u8; 32];
        sha3::shake256(&preimage, &mut digest);
        digest
    }

    fn well_formed(&self) -> bool {
        self.version == FACT_VERSION
            && self.source_chain != 0
            && self.dest_chain != 0
            && self.amount != 0
            && self.asset_id != [0u8; 16]
            && self.recipient != [0u8; 32]
            && self.source_ref != [0u8; 32]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerSig {
    pub operator_id: u32,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub fact: Fact,
    pub signatures: Vec<SignerSig>,
}

impl Attestation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ARTIFACT_ATTESTATION);
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.fact.encode());
        out.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for signer in &self.signatures {
            out.extend_from_slice(&signer.operator_id.to_le_bytes());
            out.extend_from_slice(&(signer.signature.len() as u16).to_le_bytes());
            out.extend_from_slice(&signer.signature);
        }
        out
    }

    fn read(reader: &mut Reader<'_>) -> Option<Attestation> {
        if reader.u8()? != ARTIFACT_ATTESTATION {
            return None;
        }
        if reader.u8()? != ENVELOPE_VERSION {
            return None;
        }
        let fact = Fact::read(reader)?;
        let count = reader.u32()? as usize;
        let mut signatures = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let operator_id = reader.u32()?;
            let len = reader.u16()? as usize;
            let signature = reader.take(len)?.to_vec();
            signatures.push(SignerSig {
                operator_id,
                signature,
            });
        }
        Some(Attestation { fact, signatures })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkEnvelope {
    pub statement_digest: [u8; 32],
    pub proof: Vec<u8>,
}

impl StarkEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 4 + self.proof.len());
        out.push(ARTIFACT_STARK);
        out.extend_from_slice(&self.statement_digest);
        out.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof);
        out
    }

    fn read(reader: &mut Reader<'_>) -> Option<StarkEnvelope> {
        if reader.u8()? != ARTIFACT_STARK {
            return None;
        }
        let statement_digest = reader.array::<32>()?;
        let len = reader.u32()? as usize;
        let proof = reader.take(len)?.to_vec();
        Some(StarkEnvelope {
            statement_digest,
            proof,
        })
    }
}

/// The airlock artifact a bridge mint carries in its call payload: the ML-DSA attestation
/// envelope always, and the hash STARK envelope when the corridor is proof backed. The two
/// framed lengths let the chain read both without the oracle's parser and reject any trailing
/// byte, so the same artifact the oracle emits across the airlock is the one the chain reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintArtifact {
    pub attestation: Attestation,
    pub stark: Option<StarkEnvelope>,
}

impl MintArtifact {
    pub fn encode(&self) -> Vec<u8> {
        let attestation = self.attestation.encode();
        let stark = self.stark.as_ref().map(StarkEnvelope::encode).unwrap_or_default();
        let mut out = Vec::with_capacity(8 + attestation.len() + stark.len());
        out.extend_from_slice(&(attestation.len() as u32).to_le_bytes());
        out.extend_from_slice(&attestation);
        out.extend_from_slice(&(stark.len() as u32).to_le_bytes());
        out.extend_from_slice(&stark);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<MintArtifact> {
        let mut reader = Reader::new(bytes);
        let attestation_len = reader.u32()? as usize;
        let attestation_bytes = reader.take(attestation_len)?;
        let mut attestation_reader = Reader::new(attestation_bytes);
        let attestation = Attestation::read(&mut attestation_reader)?;
        if !attestation_reader.done() {
            return None;
        }
        let stark_len = reader.u32()? as usize;
        let stark = if stark_len == 0 {
            None
        } else {
            let stark_bytes = reader.take(stark_len)?;
            let mut stark_reader = Reader::new(stark_bytes);
            let envelope = StarkEnvelope::read(&mut stark_reader)?;
            if !stark_reader.done() {
                return None;
            }
            Some(envelope)
        };
        reader.done().then_some(MintArtifact { attestation, stark })
    }
}

/// The M of N operator committee the chain holds in state. The envelope names each signer by
/// index only, so the chain resolves the public key here and never trusts a key that rides in
/// with the artifact. The threshold is chain side config, not on the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperatorSet {
    pub operators: Vec<(u32, Vec<u8>)>,
    pub threshold: u32,
}

impl OperatorSet {
    pub fn new(operators: Vec<(u32, Vec<u8>)>, threshold: u32) -> Self {
        OperatorSet {
            operators,
            threshold,
        }
    }

    fn public_key(&self, operator_id: u32) -> Option<&[u8]> {
        self.operators
            .iter()
            .find(|(id, _)| *id == operator_id)
            .map(|(_, key)| key.as_slice())
    }
}

impl Encode for OperatorSet {
    fn encode(&self, encoder: &mut Encoder) {
        (self.operators.len() as u32).encode(encoder);
        for (id, key) in &self.operators {
            id.encode(encoder);
            key.encode(encoder);
        }
        self.threshold.encode(encoder);
    }
}

impl Decode for OperatorSet {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let count = u32::decode(decoder)? as usize;
        let mut operators = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let id = u32::decode(decoder)?;
            let key = Vec::<u8>::decode(decoder)?;
            operators.push((id, key));
        }
        let threshold = u32::decode(decoder)?;
        Ok(OperatorSet {
            operators,
            threshold,
        })
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static VERIFY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn verify_signature(pk: &[u8; PUBLIC_KEY_BYTES], message: &[u8], sig: &[u8; SIGNATURE_BYTES]) -> bool {
    #[cfg(test)]
    VERIFY_CALLS.with(|c| c.set(c.get() + 1));
    ml_dsa::verify(pk, message, sig, ATTEST_DOMAIN)
}

/// Whether a quorum of the committee attested this deposit fact to this chain. Verifies each
/// carried signature against the registered operator key at its index over the exact bytes the
/// operators sign, counts only distinct valid signers, and holds when the count reaches the
/// threshold. This is the mint authority: no signer key rides in with the artifact, so a mint
/// stands only on keys the chain already holds.
pub fn quorum_attests(set: &OperatorSet, attestation: &Attestation, dest_chain: u32) -> bool {
    if set.threshold == 0 {
        return false;
    }
    let fact = &attestation.fact;
    if !fact.well_formed() {
        return false;
    }
    if fact.dest_chain != dest_chain || fact.direction != Direction::Deposit {
        return false;
    }
    let message = fact.attest_preimage();
    let mut attempted: Vec<u32> = Vec::new();
    let mut counted_keys: Vec<&[u8]> = Vec::new();
    for signer in &attestation.signatures {
        if attempted.contains(&signer.operator_id) {
            continue;
        }
        attempted.push(signer.operator_id);
        let public_key = match set.public_key(signer.operator_id) {
            Some(key) => key,
            None => continue,
        };
        if counted_keys.contains(&public_key) {
            continue;
        }
        let pk: &[u8; PUBLIC_KEY_BYTES] = match public_key.try_into() {
            Ok(pk) => pk,
            Err(_) => continue,
        };
        let sig: &[u8; SIGNATURE_BYTES] = match signer.signature.as_slice().try_into() {
            Ok(sig) => sig,
            Err(_) => continue,
        };
        if verify_signature(pk, &message, sig) {
            counted_keys.push(public_key);
        }
    }
    counted_keys.len() as u32 >= set.threshold
}

/// The outcome of looking at the hash STARK envelope that rides beside the attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StarkCheck {
    /// No STARK envelope rode with the artifact.
    Absent,
    /// The envelope binds to the fact by its statement digest, but the FRI proof itself is not
    /// yet verified on chain. SEAM: the corridor statement AIR that a full verification needs
    /// lives in the oracle's q-prover-bridge, an oracle crate the chain must not link, and a
    /// chain side corridor verifier is a founder gated bridge decision. The mint does not rest on
    /// this result today, the ML-DSA operator quorum is the authority.
    BoundUnverified,
    /// The envelope does not bind to the fact.
    Unbound,
}

/// Check the STARK envelope against the fact by its statement digest. This is a real hash
/// binding over qtv-crypto SHAKE, not a proof verification: it confirms the envelope commits to
/// this exact fact, and marks that the FRI proof is not verified on chain. It never fakes a
/// proof check and the mint never treats a bound envelope as a proof.
pub fn check_stark(fact: &Fact, stark: Option<&StarkEnvelope>, operator: u32) -> StarkCheck {
    match stark {
        None => StarkCheck::Absent,
        Some(env) => {
            if env.statement_digest == fact.statement_digest(operator) {
                StarkCheck::BoundUnverified
            } else {
                StarkCheck::Unbound
            }
        }
    }
}

/// A holder driven exit that burns a bridged amount so the oracle releases it on the far side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitRequest {
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub destination: [u8; 32],
}

impl ExitRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 16 + 32);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.destination);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<ExitRequest> {
        let mut reader = Reader::new(bytes);
        let asset_id = reader.array::<16>()?;
        let amount = reader.u128()?;
        let destination = reader.array::<32>()?;
        reader.done().then_some(ExitRequest {
            asset_id,
            amount,
            destination,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fact() -> Fact {
        Fact {
            version: FACT_VERSION,
            source_chain: 1,
            dest_chain: 9000,
            route_id: 7,
            direction: Direction::Deposit,
            nonce: 42,
            source_ref: [9u8; 32],
            asset_id: [3u8; 16],
            amount: 1_000_000,
            recipient: [5u8; 32],
            finality_depth: 6,
            observed_height: 111,
            expiry_height: 222,
        }
    }

    fn operator(index: u64) -> ([u8; PUBLIC_KEY_BYTES], [u8; qtv_crypto::ml_dsa::SECRET_KEY_BYTES]) {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&index.to_le_bytes());
        ml_dsa::keygen(&seed)
    }

    fn sign_fact(sk: &[u8; qtv_crypto::ml_dsa::SECRET_KEY_BYTES], fact: &Fact) -> Vec<u8> {
        ml_dsa::sign(sk, &fact.attest_preimage(), ATTEST_DOMAIN, &[0u8; 32])
            .expect("the fact preimage stays within the length bound")
            .to_vec()
    }

    #[test]
    fn a_fact_round_trips_and_is_the_fixed_length() {
        let fact = sample_fact();
        let bytes = fact.encode();
        assert_eq!(bytes.len(), FACT_ENCODED_LEN);
        assert_eq!(Fact::decode(&bytes), Some(fact));
        assert!(Fact::decode(&bytes[..FACT_ENCODED_LEN - 1]).is_none());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Fact::decode(&trailing).is_none());
    }

    #[test]
    fn direction_offset_matches_the_oracle_layout() {
        let bytes = sample_fact().encode();
        assert_eq!(bytes[13], 0, "direction tag rides at offset 13");
    }

    #[test]
    fn an_artifact_round_trips_with_and_without_a_stark() {
        let (_pk, sk) = operator(1);
        let fact = sample_fact();
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![SignerSig {
                operator_id: 0,
                signature: sign_fact(&sk, &fact),
            }],
        };
        let bare = MintArtifact {
            attestation: attestation.clone(),
            stark: None,
        };
        assert_eq!(MintArtifact::decode(&bare.encode()), Some(bare));

        let proved = MintArtifact {
            attestation,
            stark: Some(StarkEnvelope {
                statement_digest: fact.statement_digest(0),
                proof: vec![1, 2, 3, 4],
            }),
        };
        assert_eq!(MintArtifact::decode(&proved.encode()), Some(proved));
    }

    #[test]
    fn a_sub_frame_with_trailing_bytes_is_rejected() {
        let (_pk, sk) = operator(1);
        let fact = sample_fact();
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![SignerSig { operator_id: 0, signature: sign_fact(&sk, &fact) }],
        };
        assert!(MintArtifact::decode(&MintArtifact { attestation: attestation.clone(), stark: None }.encode()).is_some());

        let mut padded_attestation = attestation.encode();
        padded_attestation.push(0u8);
        let mut out = Vec::new();
        out.extend_from_slice(&(padded_attestation.len() as u32).to_le_bytes());
        out.extend_from_slice(&padded_attestation);
        out.extend_from_slice(&0u32.to_le_bytes());
        assert!(
            MintArtifact::decode(&out).is_none(),
            "a trailing byte inside the attestation sub-frame is rejected"
        );

        let stark = StarkEnvelope { statement_digest: fact.statement_digest(0), proof: vec![1, 2, 3] };
        let mut padded_stark = stark.encode();
        padded_stark.push(0u8);
        let attestation_bytes = attestation.encode();
        let mut out2 = Vec::new();
        out2.extend_from_slice(&(attestation_bytes.len() as u32).to_le_bytes());
        out2.extend_from_slice(&attestation_bytes);
        out2.extend_from_slice(&(padded_stark.len() as u32).to_le_bytes());
        out2.extend_from_slice(&padded_stark);
        assert!(
            MintArtifact::decode(&out2).is_none(),
            "a trailing byte inside the stark sub-frame is rejected"
        );
    }

    #[test]
    fn a_quorum_of_distinct_valid_signers_attests() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(10);
        let (pk1, sk1) = operator(11);
        let (pk2, _sk2) = operator(12);
        let set = OperatorSet::new(
            vec![(0, pk0.to_vec()), (1, pk1.to_vec()), (2, pk2.to_vec())],
            2,
        );
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig {
                    operator_id: 0,
                    signature: sign_fact(&sk0, &fact),
                },
                SignerSig {
                    operator_id: 1,
                    signature: sign_fact(&sk1, &fact),
                },
            ],
        };
        assert!(quorum_attests(&set, &attestation, fact.dest_chain));
        assert!(
            !quorum_attests(&set, &attestation, fact.dest_chain + 1),
            "a fact bound for another chain does not attest here"
        );
    }

    #[test]
    fn one_signer_falls_short_of_a_two_threshold() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(10);
        let (pk1, _sk1) = operator(11);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![SignerSig {
                operator_id: 0,
                signature: sign_fact(&sk0, &fact),
            }],
        };
        assert!(!quorum_attests(&set, &attestation, fact.dest_chain));
    }

    #[test]
    fn a_padded_artifact_runs_at_most_one_verify_per_operator() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(10);
        let (pk1, _sk1) = operator(11);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let mut signatures = Vec::new();
        for _ in 0..500 {
            signatures.push(SignerSig { operator_id: 0, signature: vec![0u8; SIGNATURE_BYTES] });
            signatures.push(SignerSig { operator_id: 1, signature: vec![7u8; SIGNATURE_BYTES] });
            signatures.push(SignerSig { operator_id: 9, signature: vec![3u8; SIGNATURE_BYTES] });
        }
        signatures.push(SignerSig { operator_id: 0, signature: sign_fact(&sk0, &fact) });
        let attestation = Attestation { fact: fact.clone(), signatures };
        VERIFY_CALLS.with(|c| c.set(0));
        let _ = quorum_attests(&set, &attestation, fact.dest_chain);
        let calls = VERIFY_CALLS.with(|c| c.get());
        assert!(
            calls <= set.operators.len(),
            "ran {calls} verifies for a committee of {} operators",
            set.operators.len()
        );
    }

    #[test]
    fn a_duplicated_index_counts_once() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(10);
        let (pk1, _sk1) = operator(11);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let signature = sign_fact(&sk0, &fact);
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig {
                    operator_id: 0,
                    signature: signature.clone(),
                },
                SignerSig {
                    operator_id: 0,
                    signature,
                },
            ],
        };
        assert!(!quorum_attests(&set, &attestation, fact.dest_chain));
    }

    #[test]
    fn a_duplicate_public_key_fills_only_one_slot() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(10);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk0.to_vec())], 2);
        let signature = sign_fact(&sk0, &fact);
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: signature.clone() },
                SignerSig { operator_id: 1, signature },
            ],
        };
        assert!(
            !quorum_attests(&set, &attestation, fact.dest_chain),
            "one public key under two ids fills only one slot"
        );
    }

    #[test]
    fn a_tampered_fact_breaks_the_quorum() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(10);
        let (pk1, sk1) = operator(11);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let mut signatures = vec![
            SignerSig {
                operator_id: 0,
                signature: sign_fact(&sk0, &fact),
            },
            SignerSig {
                operator_id: 1,
                signature: sign_fact(&sk1, &fact),
            },
        ];
        let mut tampered = fact.clone();
        tampered.amount += 1;
        let attestation = Attestation {
            fact: tampered,
            signatures: std::mem::take(&mut signatures),
        };
        assert!(!quorum_attests(&set, &attestation, fact.dest_chain));
    }

    #[test]
    fn a_stranger_key_never_reaches_the_threshold() {
        let fact = sample_fact();
        let (pk0, _sk0) = operator(10);
        let (pk1, _sk1) = operator(11);
        let (_pkx, skx) = operator(99);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 1);
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![SignerSig {
                operator_id: 0,
                signature: sign_fact(&skx, &fact),
            }],
        };
        assert!(!quorum_attests(&set, &attestation, fact.dest_chain));
    }

    #[test]
    fn the_stark_binds_to_its_fact_and_flags_when_it_does_not() {
        let fact = sample_fact();
        let bound = StarkEnvelope {
            statement_digest: fact.statement_digest(0),
            proof: vec![7u8; 16],
        };
        assert_eq!(check_stark(&fact, Some(&bound), 0), StarkCheck::BoundUnverified);
        assert_eq!(check_stark(&fact, Some(&bound), 1), StarkCheck::Unbound);
        assert_eq!(check_stark(&fact, None, 0), StarkCheck::Absent);
    }

    #[test]
    fn the_operator_set_round_trips_through_state() {
        let set = OperatorSet::new(vec![(0, vec![1, 2, 3]), (5, vec![9, 9])], 2);
        let bytes = qtv_codec::to_bytes(&set);
        assert_eq!(qtv_codec::from_bytes::<OperatorSet>(&bytes).unwrap(), set);
    }

    #[test]
    fn an_exit_request_round_trips() {
        let request = ExitRequest {
            asset_id: [4u8; 16],
            amount: 500,
            destination: [8u8; 32],
        };
        assert_eq!(ExitRequest::decode(&request.encode()), Some(request));
    }
}
