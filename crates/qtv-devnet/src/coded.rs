// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::HashMap;

use qtv_attest::Attestation;
use qtv_block::{transaction_root, Block as ChainBlock, Header};
use qtv_codec::{to_bytes, Decoder, Encoder};
use qtv_crypto::sha3::sha3_256;
use qtv_net::erasure::{self, Commitment, Shard, ShardProof, DIGEST_LEN};

use crate::wire::{chain_block_from_bytes, CodedProposal, Proposal, ViewChange};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodedError {
    Erasure(erasure::Error),
    NotEnough,
    Decode,
    HeaderMismatch,
    BodyMismatch,
    CommitmentMismatch,
    BadCommitment,
}

impl From<erasure::Error> for CodedError {
    fn from(error: erasure::Error) -> Self {
        CodedError::Erasure(error)
    }
}

impl std::fmt::Display for CodedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodedError::Erasure(error) => write!(f, "the erasure code refused the input: {error}"),
            CodedError::NotEnough => {
                write!(f, "fewer than k shards verified against the commitment")
            }
            CodedError::Decode => write!(f, "the reconstructed bytes did not decode into a block"),
            CodedError::HeaderMismatch => {
                write!(f, "the reconstructed block did not match the header")
            }
            CodedError::BodyMismatch => {
                write!(
                    f,
                    "the reconstructed body did not match the transaction root"
                )
            }
            CodedError::CommitmentMismatch => {
                write!(
                    f,
                    "the reconstructed block does not produce the advertised commitment"
                )
            }
            CodedError::BadCommitment => write!(f, "a commitment field did not decode"),
        }
    }
}

impl std::error::Error for CodedError {}

pub struct CodedBlock {
    header: Header,
    header_hash: [u8; DIGEST_LEN],
    coded: erasure::Coded,
}

impl CodedBlock {
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_hash(&self) -> [u8; DIGEST_LEN] {
        self.header_hash
    }

    pub fn commitment(&self) -> &Commitment {
        self.coded.commitment()
    }

    pub fn shard_count(&self) -> usize {
        self.coded.commitment().n
    }

    pub fn piece(&self, index: usize) -> Option<(Shard, ShardProof)> {
        Some((self.coded.shard(index)?.clone(), self.coded.proof(index)?))
    }
}

pub fn code_block(block: &ChainBlock, k: usize, n: usize) -> Result<CodedBlock, CodedError> {
    let bytes = to_bytes(block);
    let coded = erasure::encode(&bytes, k, n)?;
    Ok(CodedBlock {
        header: block.header().clone(),
        header_hash: block.header_hash(),
        coded,
    })
}

pub fn commitment_in_bounds(commitment: &Commitment) -> bool {
    commitment.k >= 1
        && commitment.n >= commitment.k
        && commitment.n <= erasure::MAX_SHARDS
        && commitment.n <= commitment.k.saturating_mul(2)
}

pub fn reconstruct_block(
    header: &Header,
    header_hash: &[u8; DIGEST_LEN],
    commitment: &Commitment,
    received: &[(Shard, ShardProof)],
) -> Result<ChainBlock, CodedError> {
    if !commitment_in_bounds(commitment) {
        return Err(CodedError::BadCommitment);
    }
    let mut verified: Vec<Shard> = Vec::with_capacity(commitment.k);
    for (shard, proof) in received {
        if verified.len() == commitment.k {
            break;
        }
        if commitment.verify_shard(shard, proof) && !verified.iter().any(|s| s.index == shard.index)
        {
            verified.push(shard.clone());
        }
    }
    if verified.len() < commitment.k {
        return Err(CodedError::NotEnough);
    }

    let bytes = erasure::reconstruct(commitment, &verified)?;
    let block = chain_block_from_bytes(&bytes).map_err(|_| CodedError::Decode)?;

    if block.header() != header || &sha3_256(&to_bytes(block.header())) != header_hash {
        return Err(CodedError::HeaderMismatch);
    }
    if transaction_root(block.body()) != *header.transaction_root() {
        return Err(CodedError::BodyMismatch);
    }
    let rederived = erasure::encode(&bytes, commitment.k, commitment.n)?;
    if rederived.commitment() != commitment {
        return Err(CodedError::CommitmentMismatch);
    }
    Ok(block)
}

pub const SHARD_TARGET: usize = 1 << 18;

pub fn coding_params(payload_len: usize) -> (usize, usize) {
    let k = payload_len
        .div_ceil(SHARD_TARGET)
        .clamp(2, erasure::MAX_SHARDS / 2);
    let n = (2 * k).min(erasure::MAX_SHARDS);
    (k, n)
}

pub fn code_proposal(proposal: &Proposal) -> Result<Vec<CodedProposal>, CodedError> {
    let block = ChainBlock::new(proposal.header.clone(), Vec::new(), proposal.body.clone());
    let (k, n) = coding_params(to_bytes(&block).len());
    let coded = code_block(&block, k, n)?;
    let commitment = coded.commitment().clone();
    let mut shards = Vec::with_capacity(coded.shard_count());
    for index in 0..coded.shard_count() {
        let (shard, proof) = coded.piece(index).expect("index is within shard_count");
        shards.push(CodedProposal {
            view: proposal.view,
            header: proposal.header.clone(),
            commitment: commitment.clone(),
            justification: proposal.justification.clone(),
            shard,
            proof,
            auth: proposal.auth.clone(),
        });
    }
    Ok(shards)
}

type ProposalKey = (u64, [u8; DIGEST_LEN]);

const MAX_PENDING_PROPOSALS: usize = 256;

const MAX_DONE_KEYS: usize = 4_096;

const MAX_ASSEMBLER_BYTES: usize = 128 * 1024 * 1024;

fn piece_weight(shard: &Shard, proof: &ShardProof) -> usize {
    shard.bytes.len() + proof.siblings.len() * DIGEST_LEN
}

fn entry_weight(pending: &Pending) -> usize {
    pending.overhead
        + pending
            .pieces
            .iter()
            .map(|(shard, proof)| piece_weight(shard, proof))
            .sum::<usize>()
}

#[derive(Clone)]
pub struct ProposalAssembler {
    pending: HashMap<ProposalKey, Pending>,
    done: HashMap<ProposalKey, u64>,
    horizon: u64,
    bytes: usize,
    max_bytes: usize,
}

impl Default for ProposalAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
struct Pending {
    height: u64,
    view: u64,
    header: Header,
    commitment: Commitment,
    justification: Vec<ViewChange>,
    pieces: Vec<(Shard, ShardProof)>,
    overhead: usize,
    auth: Attestation,
}

impl ProposalAssembler {
    pub fn new() -> Self {
        ProposalAssembler {
            pending: HashMap::new(),
            done: HashMap::new(),
            horizon: 0,
            bytes: 0,
            max_bytes: MAX_ASSEMBLER_BYTES,
        }
    }

    #[cfg(test)]
    fn with_byte_budget(max_bytes: usize) -> Self {
        ProposalAssembler {
            max_bytes,
            ..Self::new()
        }
    }

    #[cfg(test)]
    fn buffered_bytes(&self) -> usize {
        self.bytes
    }

    pub fn admit(&mut self, coded: CodedProposal) -> Option<Result<Proposal, CodedError>> {
        let key: ProposalKey = (coded.view, coded.commitment.root);
        if self.done.contains_key(&key) {
            return None;
        }
        if !commitment_in_bounds(&coded.commitment) {
            return None;
        }
        if !coded.commitment.verify_shard(&coded.shard, &coded.proof) {
            return None;
        }
        let height = coded.header.height();
        self.prune(height);

        let CodedProposal {
            view,
            header,
            commitment,
            justification,
            shard,
            proof,
            auth,
        } = coded;
        let is_new = !self.pending.contains_key(&key);
        if is_new && self.pending.len() >= MAX_PENDING_PROPOSALS {
            self.evict_lowest_pending();
        }
        {
            let entry = self.pending.entry(key).or_insert_with(|| {
                let overhead =
                    crate::wire::coded_overhead(&header, &commitment, &justification, &auth);
                Pending {
                    height,
                    view,
                    header: header.clone(),
                    commitment: commitment.clone(),
                    justification,
                    pieces: Vec::new(),
                    overhead,
                    auth,
                }
            });
            if entry.commitment != commitment {
                return None;
            }
            if entry.pieces.iter().any(|(s, _)| s.index == shard.index) {
                return None;
            }
        }
        let overhead = if is_new {
            self.pending[&key].overhead
        } else {
            0
        };
        let weight = piece_weight(&shard, &proof) + overhead;
        if weight > self.max_bytes {
            if is_new {
                self.pending.remove(&key);
            }
            return None;
        }
        self.evict_until_fits(weight, &key);
        if self.bytes + weight > self.max_bytes {
            if is_new {
                self.pending.remove(&key);
            }
            return None;
        }
        let Some(entry) = self.pending.get_mut(&key) else {
            return None;
        };
        self.bytes += weight;
        entry.pieces.push((shard, proof));
        if entry.pieces.len() < entry.commitment.k {
            return None;
        }

        let pending = self
            .pending
            .remove(&key)
            .expect("the pending proposal was just present");
        self.bytes = self.bytes.saturating_sub(entry_weight(&pending));
        if !self.done.contains_key(&key) && self.done.len() >= MAX_DONE_KEYS {
            self.evict_lowest_done();
        }
        self.done.insert(key, pending.height);
        let header_hash = pending.header.hash();
        let rebuilt = reconstruct_block(
            &pending.header,
            &header_hash,
            &pending.commitment,
            &pending.pieces,
        );
        Some(rebuilt.map(|block| Proposal {
            view: pending.view,
            header: pending.header,
            body: block.body().to_vec(),
            justification: pending.justification,
            auth: pending.auth,
        }))
    }

    fn prune(&mut self, height: u64) {
        if height <= self.horizon {
            return;
        }
        self.horizon = height;
        let floor = height.saturating_sub(2);
        self.pending.retain(|_, p| p.height >= floor);
        self.done.retain(|_, &mut h| h >= floor);
        self.bytes = self.pending.values().map(entry_weight).sum();
    }

    fn evict_lowest_pending(&mut self) {
        if let Some(key) = self
            .pending
            .iter()
            .min_by_key(|(_, p)| p.height)
            .map(|(key, _)| *key)
        {
            if let Some(pending) = self.pending.remove(&key) {
                self.bytes = self.bytes.saturating_sub(entry_weight(&pending));
            }
        }
    }

    fn evict_until_fits(&mut self, weight: usize, keep: &ProposalKey) {
        while self.bytes + weight > self.max_bytes {
            let victim = self
                .pending
                .iter()
                .filter(|(key, _)| *key != keep)
                .min_by_key(|(_, p)| p.height)
                .map(|(key, _)| *key);
            match victim {
                Some(key) => {
                    if let Some(pending) = self.pending.remove(&key) {
                        self.bytes = self.bytes.saturating_sub(entry_weight(&pending));
                    }
                }
                None => break,
            }
        }
    }

    fn evict_lowest_done(&mut self) {
        if let Some(key) = self
            .done
            .iter()
            .min_by_key(|(_, &height)| height)
            .map(|(key, _)| *key)
        {
            self.done.remove(&key);
        }
    }
}

pub fn encode_commitment(commitment: &Commitment) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.put_bytes(&commitment.root);
    encoder.put_u64(commitment.k as u64);
    encoder.put_u64(commitment.n as u64);
    encoder.put_u64(commitment.shard_len as u64);
    encoder.put_u64(commitment.data_len as u64);
    encoder.into_bytes()
}

pub fn decode_commitment(bytes: &[u8]) -> Result<Commitment, CodedError> {
    let mut decoder = Decoder::new(bytes);
    let root_bytes = decoder.get_bytes().map_err(|_| CodedError::BadCommitment)?;
    let root: [u8; DIGEST_LEN] = root_bytes
        .try_into()
        .map_err(|_| CodedError::BadCommitment)?;
    let k = decoder.get_u64().map_err(|_| CodedError::BadCommitment)? as usize;
    let n = decoder.get_u64().map_err(|_| CodedError::BadCommitment)? as usize;
    let shard_len = decoder.get_u64().map_err(|_| CodedError::BadCommitment)? as usize;
    let data_len = decoder.get_u64().map_err(|_| CodedError::BadCommitment)? as usize;
    decoder.finish().map_err(|_| CodedError::BadCommitment)?;
    Ok(Commitment {
        root,
        k,
        n,
        shard_len,
        data_len,
    })
}

pub fn encode_piece(shard: &Shard, proof: &ShardProof) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.put_u64(shard.index as u64);
    encoder.put_bytes(&shard.bytes);
    encoder.put_u64(proof.siblings.len() as u64);
    for sibling in &proof.siblings {
        encoder.put_bytes(sibling);
    }
    encoder.into_bytes()
}

#[derive(Debug, Clone, Copy)]
pub struct Bandwidth {
    pub erasure_coded: usize,
    pub whole_block: usize,
}

impl Bandwidth {
    pub fn saving_factor(&self) -> f64 {
        self.whole_block as f64 / self.erasure_coded as f64
    }
}

pub fn per_node_bandwidth(coded: &CodedBlock, whole_block_len: usize, nodes: usize) -> Bandwidth {
    let n = coded.shard_count();
    let held = n.div_ceil(nodes.max(1));
    let header_len = to_bytes(coded.header()).len();
    let commitment_len = encode_commitment(coded.commitment()).len();
    let mut shard_bytes = 0;
    for index in 0..held.min(n) {
        let (shard, proof) = coded.piece(index).expect("index is within shard_count");
        shard_bytes += encode_piece(&shard, &proof).len();
    }
    Bandwidth {
        erasure_coded: header_len + commitment_len + shard_bytes,
        whole_block: whole_block_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_block::empty_transaction_root;
    use qtv_tx::{Body, Call, Wrapper};

    fn sample_block(count: usize) -> ChainBlock {
        let mut body = Vec::with_capacity(count);
        for i in 0..count {
            let target = qtv_idfmt::render_address(&[(i as u8).wrapping_add(1); 32])
                .expect("a full width payload renders");
            let sender = qtv_idfmt::render_address(&[(i as u8).wrapping_add(151); 32])
                .expect("a full width payload renders");
            let call = Call::new(target, vec![(i % 251) as u8; 64]);
            let inner = Body::new(sender, i as u64, 21_000, 1, call);
            let signature = vec![(i % 253) as u8; 2420];
            body.push(Wrapper::new(inner, 1, signature));
        }
        let header = Header::new(
            7,
            [1u8; 32],
            [2u8; 32],
            transaction_root(&body),
            empty_transaction_root(),
            [3u8; 32],
            "proposer-1".to_string(),
            1_700_000_000_000,
        );
        ChainBlock::new(header, vec![9u8; 96], body)
    }

    #[test]
    fn a_coded_block_reconstructs_and_verifies_against_the_header() {
        let block = sample_block(64);
        let coded = code_block(&block, 16, 32).expect("code");
        let pieces: Vec<(Shard, ShardProof)> = (16..32).map(|i| coded.piece(i).unwrap()).collect();
        let out = reconstruct_block(
            coded.header(),
            &coded.header_hash(),
            coded.commitment(),
            &pieces,
        )
        .expect("reconstruct");
        assert_eq!(out, block, "the reconstructed block was not byte identical");
    }

    #[test]
    fn a_scattered_subset_of_k_reconstructs_the_block() {
        let block = sample_block(50);
        let coded = code_block(&block, 16, 32).expect("code");
        let picks = [0, 2, 5, 6, 9, 10, 13, 14, 18, 21, 22, 25, 26, 29, 30, 31];
        let pieces: Vec<(Shard, ShardProof)> =
            picks.iter().map(|&i| coded.piece(i).unwrap()).collect();
        let out = reconstruct_block(
            coded.header(),
            &coded.header_hash(),
            coded.commitment(),
            &pieces,
        )
        .expect("reconstruct");
        assert_eq!(out, block);
    }

    #[test]
    fn a_wrong_shard_is_rejected_and_a_clean_set_still_reconstructs() {
        let block = sample_block(40);
        let coded = code_block(&block, 16, 32).expect("code");

        let (mut shard, proof) = coded.piece(3).unwrap();
        shard.bytes[0] ^= 255;
        assert!(!coded.commitment().verify_shard(&shard, &proof));

        let mut pieces: Vec<(Shard, ShardProof)> = vec![(shard, proof)];
        for i in (0..32).filter(|&i| i != 3).take(16) {
            pieces.push(coded.piece(i).unwrap());
        }
        let out = reconstruct_block(
            coded.header(),
            &coded.header_hash(),
            coded.commitment(),
            &pieces,
        )
        .expect("reconstruct");
        assert_eq!(out, block);
    }

    #[test]
    fn a_block_reconstructed_under_the_wrong_header_is_refused() {
        let block = sample_block(32);
        let coded = code_block(&block, 16, 32).expect("code");
        let pieces: Vec<(Shard, ShardProof)> = (0..16).map(|i| coded.piece(i).unwrap()).collect();

        let other = sample_block(33);
        let result = reconstruct_block(
            other.header(),
            &other.header_hash(),
            coded.commitment(),
            &pieces,
        );
        assert_eq!(result, Err(CodedError::HeaderMismatch));
    }

    #[test]
    fn the_commitment_round_trips_over_the_wire() {
        let block = sample_block(20);
        let coded = code_block(&block, 16, 32).expect("code");
        let bytes = encode_commitment(coded.commitment());
        let back = decode_commitment(&bytes).expect("decode");
        assert_eq!(&back, coded.commitment());
    }

    #[test]
    fn the_coding_is_deterministic_for_a_block() {
        let block = sample_block(24);
        let a = code_block(&block, 16, 32).expect("code");
        let b = code_block(&block, 16, 32).expect("code");
        assert_eq!(a.commitment(), b.commitment());
        assert_eq!(a.header_hash(), b.header_hash());
        for i in 0..a.shard_count() {
            assert_eq!(a.piece(i), b.piece(i));
        }
    }

    fn dummy_auth() -> Attestation {
        use qtv_attest::{Block, Parent};
        use qtv_crypto::ml_dsa::SIGNATURE_BYTES;
        use qtv_sampler::onetime::{MerklePath, PREIMAGE_BYTES};
        use qtv_sampler::sortition::Credential;
        Attestation {
            from: 0,
            height: 0,
            slot: 0,
            view: 0,
            committee: [0u8; 32],
            block: Block::new(0, [0u8; 32], Parent::Genesis),
            membership: Credential {
                position: 0,
                preimage: [0u8; PREIMAGE_BYTES],
                path: MerklePath {
                    siblings: Vec::new(),
                },
            },
            sig: [0u8; SIGNATURE_BYTES],
        }
    }

    fn sample_proposal(count: usize, view: u64) -> Proposal {
        let block = sample_block(count);
        Proposal {
            view,
            header: block.header().clone(),
            body: block.body().to_vec(),
            justification: Vec::new(),
            auth: dummy_auth(),
        }
    }

    fn same_proposal(rebuilt: &Proposal, original: &Proposal) {
        assert_eq!(rebuilt.view, original.view, "the view differed");
        assert_eq!(rebuilt.header, original.header, "the header differed");
        assert_eq!(
            rebuilt.body.len(),
            original.body.len(),
            "the body length differed"
        );
        for (a, b) in rebuilt.body.iter().zip(original.body.iter()) {
            assert_eq!(a.id(), b.id(), "a body transaction differed");
        }
    }

    #[test]
    fn the_assembler_bounds_pending_under_a_flood_of_distinct_keys() {
        let mut assembler = ProposalAssembler::new();
        for view in 0..(MAX_PENDING_PROPOSALS as u64 + 64) {
            let proposal = sample_proposal(1, view);
            let shards = code_proposal(&proposal).expect("code the proposal");
            let _ = assembler.admit(shards[0].clone());
        }
        assert!(
            assembler.pending.len() <= MAX_PENDING_PROPOSALS,
            "pending stays bounded under a distinct-key flood, got {}",
            assembler.pending.len()
        );
    }

    #[test]
    fn a_coded_proposal_reassembles_byte_for_byte_from_any_k() {
        let proposal = sample_proposal(64, 3);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let k = shards[0].commitment.k;
        let n = shards[0].commitment.n;
        assert_eq!(n, 2 * k);
        assert_eq!(shards.len(), n);

        let mut assembler = ProposalAssembler::new();
        let mut rebuilt = None;
        for (fed, coded) in shards.iter().skip(n - k).cloned().enumerate() {
            match assembler.admit(coded) {
                Some(result) => {
                    assert_eq!(fed + 1, k, "reassembly completed before k shards");
                    rebuilt = Some(result.expect("k verified shards reconstruct"));
                }
                None => assert!(fed + 1 < k, "reassembly did not complete at k shards"),
            }
        }
        same_proposal(
            &rebuilt.expect("k shards reconstruct the proposal"),
            &proposal,
        );
    }

    #[test]
    fn a_wrong_proposal_shard_is_refused_and_a_clean_set_still_reassembles() {
        let proposal = sample_proposal(48, 0);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let k = shards[0].commitment.k;
        let mut assembler = ProposalAssembler::new();

        let mut corrupt = shards[0].clone();
        corrupt.shard.bytes[0] ^= 255;
        assert!(
            assembler.admit(corrupt).is_none(),
            "a corrupted shard was admitted"
        );

        let mut rebuilt = None;
        for coded in shards.iter().take(k).cloned() {
            if let Some(result) = assembler.admit(coded) {
                rebuilt = Some(result.expect("the clean k reconstruct"));
            }
        }
        same_proposal(
            &rebuilt.expect("the clean k reconstruct the proposal"),
            &proposal,
        );
    }

    #[test]
    fn each_coded_proposal_shard_fits_one_record() {
        let proposal = sample_proposal(800, 0);
        let block = ChainBlock::new(proposal.header.clone(), Vec::new(), proposal.body.clone());
        let block_len = to_bytes(&block).len();
        let record_bound = 1usize << 20;
        assert!(
            block_len > record_bound,
            "the sample block {block_len} did not exceed one record, so the test is not meaningful"
        );

        let shards = code_proposal(&proposal).expect("code the proposal");
        for coded in &shards {
            let message = crate::wire::Message::CodedProposal(Box::new(coded.clone()));
            let bytes = message.encode();
            assert!(
                bytes.len() < record_bound,
                "a coded proposal shard message {} was not below the record bound",
                bytes.len()
            );
        }
    }

    #[test]
    fn a_reassembled_proposal_is_dropped_when_its_shards_do_not_match_the_header() {
        let proposal = sample_proposal(32, 0);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let k = shards[0].commitment.k;

        let other = sample_proposal(33, 0);
        let mut assembler = ProposalAssembler::new();
        let mut outcome = None;
        for coded in shards.iter().take(k).cloned() {
            let forged = CodedProposal {
                header: other.header.clone(),
                ..coded
            };
            if let Some(result) = assembler.admit(forged) {
                outcome = Some(result);
            }
        }
        assert!(
            matches!(outcome, Some(Err(_))),
            "a header that did not match the coded block was not refused"
        );
    }

    #[test]
    fn the_assembler_bounds_total_shard_bytes_under_a_distinct_key_flood() {
        let proposal = sample_proposal(48, 0);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let one = shards[0].clone();
        let piece = super::piece_weight(&one.shard, &one.proof);
        assert!(piece > 0, "a shard carries bytes");

        assert!(
            one.commitment.k > 1,
            "the shard must not complete on its own"
        );
        let budget = piece * 4 + piece / 2;
        let mut assembler = ProposalAssembler::with_byte_budget(budget);
        for view in 0..256u64 {
            let mut coded = shards[0].clone();
            coded.view = view;
            let admitted = assembler.admit(coded);
            assert!(
                admitted.is_none(),
                "a lone shard never completes a k>1 proposal"
            );
            assert!(
                assembler.buffered_bytes() <= budget,
                "held bytes {} breached the ceiling {budget} at view {view}",
                assembler.buffered_bytes()
            );
        }
        assert!(
            assembler.pending.len() <= budget / piece + 1,
            "the entry count tracks the byte ceiling, got {}",
            assembler.pending.len()
        );
    }

    #[test]
    fn a_coded_proposal_with_out_of_range_parameters_is_refused() {
        let proposal = sample_proposal(32, 0);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let mut assembler = ProposalAssembler::new();

        let mut oversized = shards[0].clone();
        oversized.commitment.n = erasure::MAX_SHARDS + 1;
        assert!(assembler.admit(oversized).is_none());

        let mut zero_k = shards[1].clone();
        zero_k.commitment.k = 0;
        assert!(assembler.admit(zero_k).is_none());

        let mut inverted = shards[2].clone();
        inverted.commitment.k = inverted.commitment.n + 1;
        assert!(assembler.admit(inverted).is_none());

        let mut rebuilt = None;
        let k = shards[0].commitment.k;
        for coded in shards.iter().take(k).cloned() {
            if let Some(result) = assembler.admit(coded) {
                rebuilt = Some(result.expect("the clean k reconstruct"));
            }
        }
        same_proposal(
            &rebuilt.expect("the clean k reconstruct the proposal"),
            &proposal,
        );
    }

    #[test]
    fn a_lopsided_erasure_commitment_is_refused_before_the_costly_re_encode() {
        let proposal = sample_proposal(32, 0);
        let shards = code_proposal(&proposal).expect("code the proposal");

        let honest = &shards[0].commitment;
        assert_eq!(
            honest.n,
            honest.k * 2,
            "the honest coder emits n equal to twice k"
        );
        assert!(
            commitment_in_bounds(honest),
            "the honest commitment stays in bounds"
        );

        let mut hostile = shards[0].clone();
        hostile.commitment.k = 1;
        hostile.commitment.n = erasure::MAX_SHARDS;
        assert!(
            !commitment_in_bounds(&hostile.commitment),
            "a spread past twice k is refused before the costly re encode"
        );

        let mut assembler = ProposalAssembler::new();
        assert!(
            assembler.admit(hostile).is_none(),
            "the assembler drops a lopsided shard"
        );
        assert_eq!(
            assembler.buffered_bytes(),
            0,
            "no piece buffers for a refused commitment"
        );
    }

    #[test]
    fn coding_params_keep_a_shard_within_the_record_bound() {
        let record_bound = 1usize << 20;
        for mib in [1usize, 2, 4, 8, 16, 31] {
            let len = mib * 1024 * 1024;
            let (k, n) = coding_params(len);
            assert!(k >= 2 && n == 2 * k && n <= erasure::MAX_SHARDS);
            let shard_len = len.div_ceil(k);
            assert!(
                shard_len < record_bound / 2,
                "a {mib} MiB payload gave a {shard_len} byte shard, too close to the record bound"
            );
        }
    }

    fn heavy_justification() -> Vec<ViewChange> {
        use crate::wire::LockedBlock;
        use qtv_attest::{Attestation, Block, Parent};
        use qtv_crypto::ml_dsa::SIGNATURE_BYTES;
        use qtv_sampler::onetime::{MerklePath, PREIMAGE_BYTES};
        use qtv_sampler::sortition::Credential;

        let block = sample_block(400);
        let locked = LockedBlock {
            header: block.header().clone(),
            body: block.body().to_vec(),
        };
        let att = Attestation {
            from: 0,
            height: 1,
            slot: 0,
            view: 0,
            committee: [0u8; 32],
            block: Block::new(1, [0u8; 32], Parent::Genesis),
            membership: Credential {
                position: 0,
                preimage: [0u8; PREIMAGE_BYTES],
                path: MerklePath {
                    siblings: Vec::new(),
                },
            },
            sig: [0u8; SIGNATURE_BYTES],
        };
        vec![ViewChange {
            height: 1,
            target_view: 1,
            lock_view: 0,
            locked: Some(locked),
            att,
            polka: None,
        }]
    }

    #[test]
    fn the_byte_ceiling_charges_the_stored_justification_not_just_the_shard() {
        let proposal = sample_proposal(48, 0);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let base = shards[0].clone();
        let piece = super::piece_weight(&base.shard, &base.proof);
        assert!(base.commitment.k > 1, "a lone shard must not complete");

        let heavy = heavy_justification();
        let jbytes =
            crate::wire::coded_overhead(&base.header, &base.commitment, &heavy, &base.auth);
        assert!(
            jbytes > piece * 8,
            "the justification must dominate a shard piece"
        );

        let budget = jbytes + piece * 4;
        let mut assembler = ProposalAssembler::with_byte_budget(budget);
        for view in 0..48u64 {
            let mut coded = base.clone();
            coded.view = view;
            coded.justification = heavy.clone();
            let _ = assembler.admit(coded);
        }
        let retained: usize = assembler
            .pending
            .values()
            .map(|p| {
                crate::wire::coded_overhead(&p.header, &p.commitment, &p.justification, &p.auth)
                    + p.pieces
                        .iter()
                        .map(|(s, pr)| super::piece_weight(s, pr))
                        .sum::<usize>()
            })
            .sum();
        assert!(
            retained <= budget,
            "the assembler retained {retained} bytes past the {budget} byte ceiling"
        );
        assert!(assembler.buffered_bytes() <= budget);
    }
}
