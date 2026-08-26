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

    pub fn attest_preimage(&self, chain_id: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATTEST_DOMAIN.len() + FACT_ENCODED_LEN + 8);
        out.extend_from_slice(ATTEST_DOMAIN);
        out.extend_from_slice(&self.encode());
        out.extend_from_slice(&chain_id.to_le_bytes());
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

pub const POP_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/OPERATOR-POP/v1";

pub fn operator_pop_challenge(operator_id: u32, public_key: &[u8], chain_id: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(8 + 4 + public_key.len());
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(&operator_id.to_le_bytes());
    message.extend_from_slice(public_key);
    message
}

pub fn operator_pop_ok(operator_id: u32, public_key: &[u8], pop: &[u8], chain_id: u64) -> bool {
    let pk: &[u8; PUBLIC_KEY_BYTES] = match public_key.try_into() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig: &[u8; SIGNATURE_BYTES] = match pop.try_into() {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    ml_dsa::verify(pk, &operator_pop_challenge(operator_id, public_key, chain_id), sig, POP_DOMAIN)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperatorSet {
    pub operators: Vec<(u32, Vec<u8>)>,
    pub threshold: u32,
    pub revoked: Vec<u32>,
}

impl OperatorSet {
    pub fn new(operators: Vec<(u32, Vec<u8>)>, threshold: u32) -> Self {
        OperatorSet {
            operators,
            threshold,
            revoked: Vec::new(),
        }
    }

    pub fn is_revoked(&self, operator_id: u32) -> bool {
        self.revoked.contains(&operator_id)
    }

    pub fn revoke(&mut self, operator_id: u32) -> bool {
        let known = self.operators.iter().any(|(id, _)| *id == operator_id);
        if !known || self.is_revoked(operator_id) {
            return false;
        }
        self.revoked.push(operator_id);
        true
    }

    fn public_key(&self, operator_id: u32) -> Option<&[u8]> {
        if self.is_revoked(operator_id) {
            return None;
        }
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
        (self.revoked.len() as u32).encode(encoder);
        for id in &self.revoked {
            id.encode(encoder);
        }
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
        let revoked_count = u32::decode(decoder)? as usize;
        let mut revoked = Vec::with_capacity(revoked_count.min(4096));
        for _ in 0..revoked_count {
            revoked.push(u32::decode(decoder)?);
        }
        Ok(OperatorSet {
            operators,
            threshold,
            revoked,
        })
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static VERIFY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn verify_signature(pk: &[u8; PUBLIC_KEY_BYTES], message: &[u8], sig: &[u8; SIGNATURE_BYTES], era: &[u8; 32]) -> bool {
    #[cfg(test)]
    VERIFY_CALLS.with(|c| c.set(c.get() + 1));
    ml_dsa::verify(pk, message, sig, &attest_context(era))
}

pub fn quorum_attests(
    set: &OperatorSet,
    attestation: &Attestation,
    dest_chain: u32,
    chain_id: u64,
    era: &[u8; 32],
) -> bool {
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
    let message = fact.attest_preimage(chain_id);
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
        if verify_signature(pk, &message, sig, era) {
            counted_keys.push(public_key);
        }
    }
    counted_keys.len() as u32 >= set.threshold
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StarkCheck {
    Absent,
    BoundUnverified,
    Unbound,
}

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

pub const EXIT_ACK_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/EXIT-ACK/v1";

// The signature context binds an attestation to the chain era it was raised for, so a deposit or exit
// proof from one launch of a reused chain name cannot be replayed on the next. The era is the genesis
// hash the node seeds at launch and the operators sign under.
pub fn attest_context(era: &[u8; 32]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(ATTEST_DOMAIN.len() + 32);
    ctx.extend_from_slice(ATTEST_DOMAIN);
    ctx.extend_from_slice(era);
    ctx
}

pub fn exit_ack_context(era: &[u8; 32]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(EXIT_ACK_DOMAIN.len() + 32);
    ctx.extend_from_slice(EXIT_ACK_DOMAIN);
    ctx.extend_from_slice(era);
    ctx
}
pub const EXIT_FACT_VERSION: u8 = 1;
pub const EXIT_FACT_ENCODED_LEN: usize = 106;
pub const ARTIFACT_EXIT_ACK: u8 = 0x03;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitOutcome {
    Settle,
    Slash,
}

impl ExitOutcome {
    fn tag(self) -> u8 {
        match self {
            ExitOutcome::Settle => 1,
            ExitOutcome::Slash => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<ExitOutcome> {
        match tag {
            1 => Some(ExitOutcome::Settle),
            2 => Some(ExitOutcome::Slash),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitFact {
    pub version: u8,
    pub corridor: u32,
    pub dest_chain: u32,
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub burn_ref: [u8; 32],
    pub outcome: ExitOutcome,
}

impl ExitFact {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EXIT_FACT_ENCODED_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.corridor.to_le_bytes());
        out.extend_from_slice(&self.dest_chain.to_le_bytes());
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.beneficiary);
        out.extend_from_slice(&self.burn_ref);
        out.push(self.outcome.tag());
        out
    }

    fn read(reader: &mut Reader<'_>) -> Option<ExitFact> {
        let version = reader.u8()?;
        let corridor = reader.u32()?;
        let dest_chain = reader.u32()?;
        let asset_id = reader.array::<16>()?;
        let amount = reader.u128()?;
        let beneficiary = reader.array::<32>()?;
        let burn_ref = reader.array::<32>()?;
        let outcome = ExitOutcome::from_tag(reader.u8()?)?;
        Some(ExitFact {
            version,
            corridor,
            dest_chain,
            asset_id,
            amount,
            beneficiary,
            burn_ref,
            outcome,
        })
    }

    pub fn decode(bytes: &[u8]) -> Option<ExitFact> {
        let mut reader = Reader::new(bytes);
        let fact = ExitFact::read(&mut reader)?;
        reader.done().then_some(fact)
    }

    pub fn ack_preimage(&self, chain_id: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(EXIT_ACK_DOMAIN.len() + EXIT_FACT_ENCODED_LEN + 8);
        out.extend_from_slice(EXIT_ACK_DOMAIN);
        out.extend_from_slice(&self.encode());
        out.extend_from_slice(&chain_id.to_le_bytes());
        out
    }

    fn well_formed(&self) -> bool {
        self.version == EXIT_FACT_VERSION
            && self.corridor != 0
            && self.dest_chain != 0
            && self.amount != 0
            && self.asset_id != [0u8; 16]
            && self.beneficiary != [0u8; 32]
            && self.burn_ref != [0u8; 32]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitAttestation {
    pub fact: ExitFact,
    pub signatures: Vec<SignerSig>,
}

impl ExitAttestation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ARTIFACT_EXIT_ACK);
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

    fn read(reader: &mut Reader<'_>) -> Option<ExitAttestation> {
        if reader.u8()? != ARTIFACT_EXIT_ACK {
            return None;
        }
        if reader.u8()? != ENVELOPE_VERSION {
            return None;
        }
        let fact = ExitFact::read(reader)?;
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
        Some(ExitAttestation { fact, signatures })
    }

    pub fn decode(bytes: &[u8]) -> Option<ExitAttestation> {
        let mut reader = Reader::new(bytes);
        let attestation = ExitAttestation::read(&mut reader)?;
        reader.done().then_some(attestation)
    }
}

fn verify_exit_signature(
    pk: &[u8; PUBLIC_KEY_BYTES],
    message: &[u8],
    sig: &[u8; SIGNATURE_BYTES],
    era: &[u8; 32],
) -> bool {
    #[cfg(test)]
    VERIFY_CALLS.with(|c| c.set(c.get() + 1));
    ml_dsa::verify(pk, message, sig, &exit_ack_context(era))
}

// verifies the exit attestation exactly as quorum_attests verifies a mint, no weaker
pub fn exit_quorum_attests(
    set: &OperatorSet,
    attestation: &ExitAttestation,
    dest_chain: u32,
    chain_id: u64,
    era: &[u8; 32],
) -> bool {
    if set.threshold == 0 {
        return false;
    }
    let fact = &attestation.fact;
    if !fact.well_formed() {
        return false;
    }
    if fact.dest_chain != dest_chain {
        return false;
    }
    let message = fact.ack_preimage(chain_id);
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
        if verify_exit_signature(pk, &message, sig, era) {
            counted_keys.push(public_key);
        }
    }
    counted_keys.len() as u32 >= set.threshold
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

    const TEST_CHAIN_ID: u64 = 0x0123_4567_89AB_CDEF;
    const TEST_ERA: [u8; 32] = [0x5Au8; 32];

    fn sign_fact(sk: &[u8; qtv_crypto::ml_dsa::SECRET_KEY_BYTES], fact: &Fact) -> Vec<u8> {
        ml_dsa::sign(sk, &fact.attest_preimage(TEST_CHAIN_ID), &attest_context(&TEST_ERA), &[0u8; 32])
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
        assert!(quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
        assert!(
            !quorum_attests(&set, &attestation, fact.dest_chain + 1, TEST_CHAIN_ID, &TEST_ERA),
            "a fact bound for another chain does not attest here"
        );
    }

    #[test]
    fn a_quorum_signed_for_one_chain_id_is_refused_under_a_sibling() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(10);
        let (pk1, sk1) = operator(11);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let chain_a = TEST_CHAIN_ID;
        let chain_b = TEST_CHAIN_ID ^ (1u64 << 40);
        assert_eq!(chain_a as u32, chain_b as u32, "the two siblings share the low 32 bits");
        let sign_a = |sk: &[u8; qtv_crypto::ml_dsa::SECRET_KEY_BYTES]| {
            ml_dsa::sign(sk, &fact.attest_preimage(chain_a), &attest_context(&TEST_ERA), &[0u8; 32])
                .expect("the fact preimage stays within the length bound")
                .to_vec()
        };
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: sign_a(&sk0) },
                SignerSig { operator_id: 1, signature: sign_a(&sk1) },
            ],
        };
        assert!(
            quorum_attests(&set, &attestation, fact.dest_chain, chain_a, &TEST_ERA),
            "the quorum attests under the chain id it was signed for"
        );
        assert!(
            !quorum_attests(&set, &attestation, fact.dest_chain, chain_b, &TEST_ERA),
            "a sibling sharing the u32 dest chain refuses the replay"
        );
    }

    #[test]
    fn a_quorum_signed_for_one_era_is_refused_under_another() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(12);
        let (pk1, sk1) = operator(13);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let era_a = [0x11u8; 32];
        let era_b = [0x22u8; 32];
        let sign_a = |sk: &[u8; qtv_crypto::ml_dsa::SECRET_KEY_BYTES]| {
            ml_dsa::sign(sk, &fact.attest_preimage(TEST_CHAIN_ID), &attest_context(&era_a), &[0u8; 32])
                .expect("the fact preimage stays within the length bound")
                .to_vec()
        };
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: sign_a(&sk0) },
                SignerSig { operator_id: 1, signature: sign_a(&sk1) },
            ],
        };
        assert!(
            quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &era_a),
            "the quorum attests under the era it was signed for"
        );
        assert!(
            !quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &era_b),
            "a deposit proof from one launch cannot replay on a relaunch with a new genesis era"
        );
    }

    #[test]
    fn the_attest_preimage_matches_the_pinned_cross_chain_vector() {
        const PINNED: [u8; 173] = [
            81, 85, 65, 78, 84, 79, 86, 65, 47, 81, 45, 79, 82, 65, 67, 76, 69, 47, 65, 84, 84, 69,
            83, 84, 47, 118, 49, 1, 1, 0, 0, 0, 40, 35, 0, 0, 7, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0,
            0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
            9, 9, 9, 9, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 64, 66, 15, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 0, 0, 0, 111, 0, 0, 0, 0, 0, 0, 0, 222, 0, 0, 0, 0,
            0, 0, 0, 239, 205, 171, 137, 103, 69, 35, 1,
        ];
        let preimage = sample_fact().attest_preimage(0x0123_4567_89AB_CDEF);
        assert_eq!(preimage.len(), ATTEST_DOMAIN.len() + FACT_ENCODED_LEN + 8);
        assert_eq!(preimage.len(), 173);
        assert_eq!(preimage.as_slice(), PINNED.as_slice());
        assert!(preimage.starts_with(ATTEST_DOMAIN));
        assert_eq!(
            &preimage[ATTEST_DOMAIN.len()..ATTEST_DOMAIN.len() + FACT_ENCODED_LEN],
            sample_fact().encode().as_slice()
        );
        assert_eq!(
            &preimage[ATTEST_DOMAIN.len() + FACT_ENCODED_LEN..],
            0x0123_4567_89AB_CDEFu64.to_le_bytes()
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
        assert!(!quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
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
        let _ = quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA);
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
        assert!(!quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
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
            !quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA),
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
        assert!(!quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
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
        assert!(!quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
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

        let mut revoked = OperatorSet::new(vec![(0, vec![1, 2, 3]), (5, vec![9, 9])], 2);
        assert!(revoked.revoke(5));
        assert!(!revoked.revoke(5), "a second revocation of the same id is a no op");
        assert!(!revoked.revoke(7), "an unknown id cannot be revoked");
        let bytes = qtv_codec::to_bytes(&revoked);
        assert_eq!(qtv_codec::from_bytes::<OperatorSet>(&bytes).unwrap(), revoked);
    }

    #[test]
    fn an_operator_pop_binds_the_key_to_its_id() {
        let (pk, sk) = operator(30);
        let pop = ml_dsa::sign(&sk, &operator_pop_challenge(4, &pk, 7), POP_DOMAIN, &[0u8; 32])
            .expect("the pop challenge stays within the length bound")
            .to_vec();
        assert!(operator_pop_ok(4, &pk, &pop, 7));
        assert!(!operator_pop_ok(5, &pk, &pop, 7), "the pop is bound to the operator id it signed");
        let (other_pk, _other_sk) = operator(31);
        assert!(!operator_pop_ok(4, &other_pk, &pop, 7), "the pop is bound to its own public key");
        assert!(!operator_pop_ok(4, &pk, &[0u8; SIGNATURE_BYTES], 7), "a forged pop never verifies");
    }

    #[test]
    fn an_operator_pop_binds_the_chain_it_was_signed_under() {
        let (pk, sk) = operator(32);
        let pop = ml_dsa::sign(&sk, &operator_pop_challenge(4, &pk, 100), POP_DOMAIN, &[0u8; 32])
            .expect("the pop challenge stays within the length bound")
            .to_vec();
        assert!(operator_pop_ok(4, &pk, &pop, 100));
        assert!(
            !operator_pop_ok(4, &pk, &pop, 101),
            "a pop signed for one chain id never verifies under another"
        );
    }

    #[test]
    fn a_revoked_operator_no_longer_counts_toward_quorum() {
        let fact = sample_fact();
        let (pk0, sk0) = operator(40);
        let (pk1, sk1) = operator(41);
        let (pk2, sk2) = operator(42);
        let mut set = OperatorSet::new(
            vec![(0, pk0.to_vec()), (1, pk1.to_vec()), (2, pk2.to_vec())],
            2,
        );
        let attestation = Attestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: sign_fact(&sk0, &fact) },
                SignerSig { operator_id: 1, signature: sign_fact(&sk1, &fact) },
            ],
        };
        assert!(quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));

        assert!(set.revoke(1));
        assert!(
            !quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA),
            "a revoked key drops below the threshold"
        );

        let healed = Attestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: sign_fact(&sk0, &fact) },
                SignerSig { operator_id: 2, signature: sign_fact(&sk2, &fact) },
            ],
        };
        assert!(
            quorum_attests(&set, &healed, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA),
            "the remaining live keys still reach the threshold"
        );
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

    fn sample_exit_fact(outcome: ExitOutcome) -> ExitFact {
        ExitFact {
            version: EXIT_FACT_VERSION,
            corridor: 1,
            dest_chain: 9000,
            asset_id: [3u8; 16],
            amount: 1_100_000,
            beneficiary: [5u8; 32],
            burn_ref: [9u8; 32],
            outcome,
        }
    }

    fn sign_exit(sk: &[u8; qtv_crypto::ml_dsa::SECRET_KEY_BYTES], fact: &ExitFact, chain_id: u64) -> Vec<u8> {
        ml_dsa::sign(sk, &fact.ack_preimage(chain_id), &exit_ack_context(&TEST_ERA), &[0u8; 32])
            .expect("the exit preimage stays within the length bound")
            .to_vec()
    }

    #[test]
    fn an_exit_fact_round_trips_and_is_the_fixed_length() {
        let fact = sample_exit_fact(ExitOutcome::Slash);
        let bytes = fact.encode();
        assert_eq!(bytes.len(), EXIT_FACT_ENCODED_LEN);
        assert_eq!(ExitFact::decode(&bytes), Some(fact));
        assert!(ExitFact::decode(&bytes[..EXIT_FACT_ENCODED_LEN - 1]).is_none());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ExitFact::decode(&trailing).is_none());
    }

    #[test]
    fn the_exit_fact_encoding_matches_the_pinned_cross_repo_layout() {
        // pins the wire layout the oracle's q-exits decision encoder must match
        let fact = ExitFact {
            version: EXIT_FACT_VERSION,
            corridor: 1,
            dest_chain: 9000,
            asset_id: [0x3; 16],
            amount: 1_100_000,
            beneficiary: [0x5; 32],
            burn_ref: [0x9; 32],
            outcome: ExitOutcome::Slash,
        };
        let bytes = fact.encode();
        assert_eq!(bytes.len(), EXIT_FACT_ENCODED_LEN);
        assert_eq!(bytes[0], EXIT_FACT_VERSION);
        assert_eq!(&bytes[1..5], 1u32.to_le_bytes());
        assert_eq!(&bytes[5..9], 9000u32.to_le_bytes());
        assert_eq!(&bytes[9..25], [0x3u8; 16]);
        assert_eq!(&bytes[25..41], 1_100_000u128.to_le_bytes());
        assert_eq!(&bytes[41..73], [0x5u8; 32]);
        assert_eq!(&bytes[73..105], [0x9u8; 32]);
        assert_eq!(bytes[105], 2, "the slash outcome rides in the final byte");
        let preimage = fact.ack_preimage(0x0123_4567_89AB_CDEF);
        assert_eq!(preimage.len(), EXIT_ACK_DOMAIN.len() + EXIT_FACT_ENCODED_LEN + 8);
        assert!(preimage.starts_with(EXIT_ACK_DOMAIN));
        assert_eq!(&preimage[EXIT_ACK_DOMAIN.len() + EXIT_FACT_ENCODED_LEN..], 0x0123_4567_89AB_CDEFu64.to_le_bytes());
    }

    #[test]
    fn an_exit_attestation_round_trips_and_carries_the_outcome() {
        let fact = sample_exit_fact(ExitOutcome::Settle);
        let (_pk, sk) = operator(60);
        let attestation = ExitAttestation {
            fact: fact.clone(),
            signatures: vec![SignerSig { operator_id: 0, signature: sign_exit(&sk, &fact, 7) }],
        };
        assert_eq!(ExitAttestation::decode(&attestation.encode()), Some(attestation));
    }

    #[test]
    fn a_quorum_of_distinct_valid_signers_acks_an_exit() {
        let fact = sample_exit_fact(ExitOutcome::Slash);
        let (pk0, sk0) = operator(50);
        let (pk1, sk1) = operator(51);
        let (pk2, _sk2) = operator(52);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec()), (2, pk2.to_vec())], 2);
        let attestation = ExitAttestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: sign_exit(&sk0, &fact, TEST_CHAIN_ID) },
                SignerSig { operator_id: 1, signature: sign_exit(&sk1, &fact, TEST_CHAIN_ID) },
            ],
        };
        assert!(exit_quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
    }

    #[test]
    fn an_exit_quorum_for_a_sibling_chain_id_is_refused() {
        let fact = sample_exit_fact(ExitOutcome::Slash);
        let (pk0, sk0) = operator(50);
        let (pk1, sk1) = operator(51);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let chain_a = TEST_CHAIN_ID;
        let chain_b = TEST_CHAIN_ID ^ (1u64 << 40);
        assert_eq!(chain_a as u32, chain_b as u32, "the two siblings share the low 32 bits");
        let attestation = ExitAttestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: sign_exit(&sk0, &fact, chain_a) },
                SignerSig { operator_id: 1, signature: sign_exit(&sk1, &fact, chain_a) },
            ],
        };
        assert!(exit_quorum_attests(&set, &attestation, fact.dest_chain, chain_a, &TEST_ERA));
        assert!(
            !exit_quorum_attests(&set, &attestation, fact.dest_chain, chain_b, &TEST_ERA),
            "a sibling sharing the u32 dest chain refuses the exit replay"
        );
    }

    #[test]
    fn an_exit_quorum_bound_to_another_dest_chain_is_refused() {
        let fact = sample_exit_fact(ExitOutcome::Settle);
        let (pk0, sk0) = operator(50);
        let (pk1, sk1) = operator(51);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let attestation = ExitAttestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: sign_exit(&sk0, &fact, TEST_CHAIN_ID) },
                SignerSig { operator_id: 1, signature: sign_exit(&sk1, &fact, TEST_CHAIN_ID) },
            ],
        };
        assert!(
            !exit_quorum_attests(&set, &attestation, fact.dest_chain + 1, TEST_CHAIN_ID, &TEST_ERA),
            "a fact bound for another dest chain does not ack here"
        );
    }

    #[test]
    fn a_prove_nothing_exit_attestation_is_refused() {
        let (pk0, _sk0) = operator(50);
        let (pk1, _sk1) = operator(51);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let empty = ExitFact {
            version: EXIT_FACT_VERSION,
            corridor: 0,
            dest_chain: 0,
            asset_id: [0u8; 16],
            amount: 0,
            beneficiary: [0u8; 32],
            burn_ref: [0u8; 32],
            outcome: ExitOutcome::Settle,
        };
        let attestation = ExitAttestation { fact: empty, signatures: vec![] };
        assert!(
            !exit_quorum_attests(&set, &attestation, 9000, TEST_CHAIN_ID, &TEST_ERA),
            "an empty prove nothing attestation never acks"
        );
        let zero_threshold = OperatorSet::new(vec![(0, pk0.to_vec())], 0);
        assert!(
            !exit_quorum_attests(&zero_threshold, &attestation, 9000, TEST_CHAIN_ID, &TEST_ERA),
            "a zero threshold set never acks"
        );
    }

    #[test]
    fn a_duplicated_exit_signer_index_counts_once() {
        let fact = sample_exit_fact(ExitOutcome::Slash);
        let (pk0, sk0) = operator(50);
        let (pk1, _sk1) = operator(51);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let signature = sign_exit(&sk0, &fact, TEST_CHAIN_ID);
        let attestation = ExitAttestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: signature.clone() },
                SignerSig { operator_id: 0, signature },
            ],
        };
        assert!(!exit_quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
    }

    #[test]
    fn a_duplicate_exit_public_key_fills_only_one_slot() {
        let fact = sample_exit_fact(ExitOutcome::Slash);
        let (pk0, sk0) = operator(50);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk0.to_vec())], 2);
        let signature = sign_exit(&sk0, &fact, TEST_CHAIN_ID);
        let attestation = ExitAttestation {
            fact: fact.clone(),
            signatures: vec![
                SignerSig { operator_id: 0, signature: signature.clone() },
                SignerSig { operator_id: 1, signature },
            ],
        };
        assert!(
            !exit_quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA),
            "one public key under two ids fills only one slot"
        );
    }

    #[test]
    fn one_exit_signer_falls_short_of_a_two_threshold() {
        let fact = sample_exit_fact(ExitOutcome::Slash);
        let (pk0, sk0) = operator(50);
        let (pk1, _sk1) = operator(51);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let attestation = ExitAttestation {
            fact: fact.clone(),
            signatures: vec![SignerSig { operator_id: 0, signature: sign_exit(&sk0, &fact, TEST_CHAIN_ID) }],
        };
        assert!(!exit_quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
    }

    #[test]
    fn a_stranger_key_never_acks_an_exit() {
        let fact = sample_exit_fact(ExitOutcome::Slash);
        let (pk0, _sk0) = operator(50);
        let (pk1, _sk1) = operator(51);
        let (_pkx, skx) = operator(99);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 1);
        let attestation = ExitAttestation {
            fact: fact.clone(),
            signatures: vec![SignerSig { operator_id: 0, signature: sign_exit(&skx, &fact, TEST_CHAIN_ID) }],
        };
        assert!(!exit_quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
    }

    #[test]
    fn a_tampered_exit_fact_breaks_the_quorum() {
        let fact = sample_exit_fact(ExitOutcome::Slash);
        let (pk0, sk0) = operator(50);
        let (pk1, sk1) = operator(51);
        let set = OperatorSet::new(vec![(0, pk0.to_vec()), (1, pk1.to_vec())], 2);
        let signatures = vec![
            SignerSig { operator_id: 0, signature: sign_exit(&sk0, &fact, TEST_CHAIN_ID) },
            SignerSig { operator_id: 1, signature: sign_exit(&sk1, &fact, TEST_CHAIN_ID) },
        ];
        let mut tampered = fact.clone();
        tampered.amount += 1;
        let attestation = ExitAttestation { fact: tampered, signatures };
        assert!(!exit_quorum_attests(&set, &attestation, fact.dest_chain, TEST_CHAIN_ID, &TEST_ERA));
    }
}
