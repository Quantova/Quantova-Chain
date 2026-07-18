//! Erasure coded block propagation over the overlay.
//!
//! Today a block spreads whole: the proposal carries the header and the entire
//! ordered body, so every node downloads every byte of the block. At a hundred
//! thousand transactions a second each block runs to tens of megabytes, and the
//! link, not the processor, is the bottleneck. This module removes that waste. It
//! codes the block into k data shards and n minus k parity shards with the qtv-net
//! erasure code, commits to the n shards under a SHA3 Merkle root the header
//! carries, and disperses the shards over the overlay so a node holds and verifies
//! only its share rather than the whole block. Any k of the n shards reconstruct the
//! block byte for byte, so the block survives the loss of shards and any node that
//! needs the whole block gathers k shards and rebuilds it.
//!
//! A shard is checked against the commitment root before it is used, so a corrupted
//! or misplaced shard is rejected at the edge. A reconstructed block is checked
//! against the header it codes from: its header hashes to the expected value, its
//! body matches the transaction root the header commits to, and the shards it
//! produces match the advertised commitment. Nothing about the disperser is
//! trusted; a block that fails any check is refused.

use std::collections::HashMap;

use qtv_block::{transaction_root, Block as ChainBlock, Header};
use qtv_codec::{to_bytes, Decoder, Encoder};
use qtv_crypto::sha3::sha3_256;
use qtv_net::erasure::{self, Commitment, Shard, ShardProof, DIGEST_LEN};

use crate::wire::{chain_block_from_bytes, CodedProposal, Proposal, ViewChange};

/// A reason an erasure coded block was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodedError {
    /// The erasure code refused the parameters or the shard set.
    Erasure(erasure::Error),
    /// Fewer than k shards verified against the commitment, so the block could not
    /// be reconstructed.
    NotEnough,
    /// The reconstructed bytes did not decode into a block.
    Decode,
    /// The reconstructed block did not hash to the expected header.
    HeaderMismatch,
    /// The reconstructed body did not match the transaction root the header commits
    /// to.
    BodyMismatch,
    /// The reconstructed block does not produce the advertised commitment, so the
    /// shards were not bound to this block.
    CommitmentMismatch,
    /// A commitment field did not decode from the wire.
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

/// The erasure coded form of a block: the header the shards reconstruct to, the
/// commitment the header carries over the shards, and the coded payload with its
/// Merkle tree. The producer builds this once, binds the commitment to the header,
/// and disperses the shards.
pub struct CodedBlock {
    header: Header,
    header_hash: [u8; DIGEST_LEN],
    coded: erasure::Coded,
}

impl CodedBlock {
    /// The header the shards reconstruct to.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The header hash the reconstructed block must match.
    pub fn header_hash(&self) -> [u8; DIGEST_LEN] {
        self.header_hash
    }

    /// The commitment the header carries over the shards, the Merkle root and the
    /// coding parameters.
    pub fn commitment(&self) -> &Commitment {
        self.coded.commitment()
    }

    /// The number of shards the block coded into.
    pub fn shard_count(&self) -> usize {
        self.coded.commitment().n
    }

    /// One shard and its inclusion proof, the unit dispersed to a custodian.
    pub fn piece(&self, index: usize) -> (Shard, ShardProof) {
        (self.coded.shard(index).clone(), self.coded.proof(index))
    }
}

/// Code a block into k data shards and n minus k parity shards over its canonical
/// encoding, and commit to the n shards under a SHA3 Merkle root. The coding is
/// deterministic, so one block always yields the same shards, the same root, and the
/// same header binding.
pub fn code_block(block: &ChainBlock, k: usize, n: usize) -> Result<CodedBlock, CodedError> {
    let bytes = to_bytes(block);
    let coded = erasure::encode(&bytes, k, n)?;
    Ok(CodedBlock {
        header: block.header().clone(),
        header_hash: block.header_hash(),
        coded,
    })
}

/// Reconstruct a block from a set of received shards, each with its inclusion proof,
/// and verify it against the header. A shard that fails the commitment is dropped, so
/// a corrupted or misplaced shard never enters the reconstruction. Once k shards
/// verify, the payload is rebuilt, decoded into a block, and checked against the
/// header: the reconstructed header must hash to the expected value, the body must
/// match the transaction root the header commits to, and the block must produce the
/// advertised commitment. A block that fails any check is refused, so nothing about
/// the disperser is trusted.
pub fn reconstruct_block(
    header: &Header,
    header_hash: &[u8; DIGEST_LEN],
    commitment: &Commitment,
    received: &[(Shard, ShardProof)],
) -> Result<ChainBlock, CodedError> {
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
    // Re-derive the commitment from the reconstructed block and match it, so the
    // shards are bound to exactly this block and not merely to some payload of the
    // same length.
    let rederived = erasure::encode(&bytes, commitment.k, commitment.n)?;
    if rederived.commitment() != commitment {
        return Err(CodedError::CommitmentMismatch);
    }
    Ok(block)
}

/// The size one data shard aims for, chosen well under the qtv-net record plaintext
/// bound of one mebibyte so a shard, its Merkle proof, the header, the commitment,
/// and any justification travel in one record with room to spare. At a quarter of a
/// mebibyte a shard is a quarter of the record, leaving three quarters for the
/// metadata that rides with it, so a coded proposal shard never approaches the bound.
pub const SHARD_TARGET: usize = 1 << 18;

/// The erasure parameters for a payload of a given canonical length: the data shard
/// count k sized so each data shard sits near the shard target, and the total shard
/// count n at twice k for a half rate code so up to k shards may be lost and any k
/// reconstruct. Both are clamped to the field: k stays at least two for a real code
/// and at most half the field, so n stays within the field size. A wider block draws
/// more shards rather than a larger shard, so a shard stays within the record bound
/// and the block width is carried by the shard count, not the record size.
pub fn coding_params(payload_len: usize) -> (usize, usize) {
    let k = payload_len.div_ceil(SHARD_TARGET).clamp(2, erasure::MAX_SHARDS / 2);
    let n = (2 * k).min(erasure::MAX_SHARDS);
    (k, n)
}

/// Code a block proposal into the erasure coded shards that disseminate it over the
/// overlay in place of a single whole record. The block the proposal's header commits
/// to is coded, header and ordered body with an empty certificate slot since a
/// proposal carries no certificate yet, so any k of the returned shards reconstruct
/// that block byte for byte and check against the header exactly as the coded block
/// path does. Each returned shard is one gossip message: it carries the view, the
/// header, the shared commitment, the justification, and its own shard and proof, so
/// a receiver that holds any k of them rebuilds the whole proposal without a separate
/// metadata message.
pub fn code_proposal(proposal: &Proposal) -> Result<Vec<CodedProposal>, CodedError> {
    let block = ChainBlock::new(
        proposal.header.clone(),
        Vec::new(),
        proposal.body.clone(),
    );
    let (k, n) = coding_params(to_bytes(&block).len());
    let coded = code_block(&block, k, n)?;
    let commitment = coded.commitment().clone();
    let mut shards = Vec::with_capacity(coded.shard_count());
    for index in 0..coded.shard_count() {
        let (shard, proof) = coded.piece(index);
        shards.push(CodedProposal {
            view: proposal.view,
            header: proposal.header.clone(),
            commitment: commitment.clone(),
            justification: proposal.justification.clone(),
            shard,
            proof,
        });
    }
    Ok(shards)
}

/// The key that identifies one proposal a node reassembles: the view it was offered
/// in and the commitment root over its shards. The view is part of the key because
/// the same block is re-proposed at a later view after a split, once bare and once
/// carrying a view change justification, and each re-proposal must reconstruct and
/// reach the consensus layer on its own, exactly as each distinct whole proposal
/// message did before coding.
type ProposalKey = (u64, [u8; DIGEST_LEN]);

/// A per node reassembly buffer that turns received coded proposal shards back into
/// whole block proposals. It is the receive side of coded dissemination: a shard is
/// admitted only once it verifies against its commitment, and once k distinct
/// verified shards for one proposal are in hand the block is reconstructed and checked
/// against the header exactly as the coded block path does. A shard that fails its
/// commitment never enters the buffer, and a full set that fails reconstruction or its
/// header check is refused, so nothing about the disperser is trusted. The buffer
/// keys a proposal by its view and commitment root, forgets it once it reconstructs so
/// a late duplicate shard is dropped rather than rebuilt twice, and prunes proposals
/// from heights the node has passed so the buffer stays bounded over a long run.
#[derive(Clone, Default)]
pub struct ProposalAssembler {
    /// Proposals still gathering shards, keyed by view and commitment root.
    pending: HashMap<ProposalKey, Pending>,
    /// The proposals already reconstructed, keyed to their height so a stale one
    /// prunes, so a late shard for a finished proposal is dropped.
    done: HashMap<ProposalKey, u64>,
    /// The highest proposal height seen, the point older buffered state prunes below.
    horizon: u64,
}

/// One proposal gathering its shards: the routing metadata every shard repeats and
/// the distinct verified pieces collected so far.
#[derive(Clone)]
struct Pending {
    height: u64,
    view: u64,
    header: Header,
    commitment: Commitment,
    justification: Vec<ViewChange>,
    pieces: Vec<(Shard, ShardProof)>,
}

impl ProposalAssembler {
    /// An empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit one coded proposal shard. Returns `Some(Ok(proposal))` when this shard
    /// completed a set of k verified shards that reconstructs the block and checks
    /// against the header, `Some(Err(_))` when a full set failed reconstruction or its
    /// header check, so the proposal is refused, and `None` while still gathering or
    /// when the shard did not verify against its commitment and was dropped.
    pub fn admit(&mut self, coded: CodedProposal) -> Option<Result<Proposal, CodedError>> {
        let key: ProposalKey = (coded.view, coded.commitment.root);
        if self.done.contains_key(&key) {
            return None;
        }
        // A shard is checked against the commitment before it is used, so a corrupted
        // or misplaced shard is rejected at the edge and never enters the reassembly.
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
        } = coded;
        let entry = self.pending.entry(key).or_insert_with(|| Pending {
            height,
            view,
            header: header.clone(),
            commitment: commitment.clone(),
            justification,
            pieces: Vec::new(),
        });
        // Every shard under one root carries the same commitment; a shard whose
        // commitment does not match the one the root fixes is dropped rather than
        // mixed into the set.
        if entry.commitment != commitment {
            return None;
        }
        if entry.pieces.iter().any(|(s, _)| s.index == shard.index) {
            return None;
        }
        entry.pieces.push((shard, proof));
        if entry.pieces.len() < entry.commitment.k {
            return None;
        }

        // k verified shards are in hand: rebuild the block and check it against the
        // header. The proposal is retired whatever the outcome, since any k of the
        // verified shards yield the same payload, so a failed set never reconstructs
        // from a later shard.
        let pending = self
            .pending
            .remove(&key)
            .expect("the pending proposal was just present");
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
        }))
    }

    /// Drop buffered proposals from heights the node has passed. A proposal keyed by a
    /// commitment root never collides with another height's, so this only reclaims
    /// memory; it never changes which proposal a shard belongs to. A small window is
    /// kept so a shard that arrives a little out of height order is not discarded.
    fn prune(&mut self, height: u64) {
        if height <= self.horizon {
            return;
        }
        self.horizon = height;
        let floor = height.saturating_sub(2);
        self.pending.retain(|_, p| p.height >= floor);
        self.done.retain(|_, &mut h| h >= floor);
    }
}

/// The canonical encoding of a commitment, the bytes the header carries and a node
/// reads back before it verifies a shard. The root is fixed width, the parameters
/// are eight byte integers.
pub fn encode_commitment(commitment: &Commitment) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.put_bytes(&commitment.root);
    encoder.put_u64(commitment.k as u64);
    encoder.put_u64(commitment.n as u64);
    encoder.put_u64(commitment.shard_len as u64);
    encoder.put_u64(commitment.data_len as u64);
    encoder.into_bytes()
}

/// Read a commitment from its canonical encoding, refusing trailing bytes.
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

/// The canonical encoding of a shard and its inclusion proof, the unit that travels
/// the overlay to a custodian: the index, the shard bytes, and the sibling hashes of
/// the proof.
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

/// The number of bytes a node downloads per block under erasure coding, and under
/// downloading the whole block, at a shard assignment. The erasure figure is the
/// header, the commitment, and the shard pieces the node custodies, each counted from
/// its real canonical encoding; the whole block figure is the canonical block
/// encoding every node downloads today. The ratio is the per node saving.
///
/// Read this figure for exactly what it is. It is the saving for a node performing the
/// custody and availability duty, holding and verifying its share rather than the whole
/// block. A node that must reconstruct the whole block, a committee member that executes
/// and attests, gathers k shards and by information theory downloads a full block worth,
/// so for that node the gain is not fewer bytes but loss tolerance and a parallel pull
/// from k sources instead of the whole block from one. The saving is real for the
/// availability layer and it does not by itself reduce what a reconstructing validator
/// downloads. It is never to be reported as a plain per validator bandwidth cut.
#[derive(Debug, Clone, Copy)]
pub struct Bandwidth {
    /// The bytes a node downloads under erasure coding: header, commitment, and its
    /// custodied shard pieces.
    pub erasure_coded: usize,
    /// The bytes a node downloads today: the whole block.
    pub whole_block: usize,
}

impl Bandwidth {
    /// The per node saving as a factor, the whole block bytes over the erasure coded
    /// bytes.
    pub fn saving_factor(&self) -> f64 {
        self.whole_block as f64 / self.erasure_coded as f64
    }
}

/// The per node download of a coded block when the n shards are dispersed round
/// robin over `nodes` custodians, so each node holds either the floor or the ceiling
/// of n over nodes shards. The reported figure is the busiest node, the one that
/// holds the ceiling, so the saving is the honest worst case. The whole block figure
/// is the block every node downloads today.
pub fn per_node_bandwidth(coded: &CodedBlock, whole_block_len: usize, nodes: usize) -> Bandwidth {
    let n = coded.shard_count();
    // The busiest custodian holds the ceiling of n over nodes shards.
    let held = n.div_ceil(nodes.max(1));
    let header_len = to_bytes(coded.header()).len();
    let commitment_len = encode_commitment(coded.commitment()).len();
    let mut shard_bytes = 0;
    for index in 0..held.min(n) {
        let (shard, proof) = coded.piece(index);
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

    /// A block whose body holds `count` distinct transaction wrappers of a realistic
    /// size, and a header that commits to that body. The wrappers carry a signature
    /// sized like a module lattice signature, so the block bytes and the shard bytes
    /// are the real thing rather than a toy.
    fn sample_block(count: usize) -> ChainBlock {
        let mut body = Vec::with_capacity(count);
        for i in 0..count {
            let call = Call::new(format!("account-{i}"), vec![(i % 251) as u8; 64]);
            let inner = Body::new(format!("sender-{i}"), i as u64, 21_000, 1, call);
            // A signature the size of a module lattice signature, distinct per wrapper.
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
        // Gather the sixteen parity shards, the subset that shares no byte with the
        // data shards, and reconstruct from them alone.
        let pieces: Vec<(Shard, ShardProof)> = (16..32).map(|i| coded.piece(i)).collect();
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
        let pieces: Vec<(Shard, ShardProof)> = picks.iter().map(|&i| coded.piece(i)).collect();
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

        // A single corrupted shard fails the commitment on its own.
        let (mut shard, proof) = coded.piece(3);
        shard.bytes[0] ^= 255;
        assert!(!coded.commitment().verify_shard(&shard, &proof));

        // A set that mixes the corrupted shard with enough clean shards drops the
        // corrupted one and still reconstructs from the clean k.
        let mut pieces: Vec<(Shard, ShardProof)> = vec![(shard, proof)];
        for i in (0..32).filter(|&i| i != 3).take(16) {
            pieces.push(coded.piece(i));
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
        let pieces: Vec<(Shard, ShardProof)> = (0..16).map(|i| coded.piece(i)).collect();

        // A different header does not match the block the shards reconstruct.
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

    /// A block proposal at a view, its header committing to the body, ready to be
    /// coded and disseminated.
    fn sample_proposal(count: usize, view: u64) -> Proposal {
        let block = sample_block(count);
        Proposal {
            view,
            header: block.header().clone(),
            body: block.body().to_vec(),
            justification: Vec::new(),
        }
    }

    /// Assert two proposals carry the same view, header, and ordered body, the byte
    /// exact identity a reassembled proposal must hold against the coded one.
    fn same_proposal(rebuilt: &Proposal, original: &Proposal) {
        assert_eq!(rebuilt.view, original.view, "the view differed");
        assert_eq!(rebuilt.header, original.header, "the header differed");
        assert_eq!(rebuilt.body.len(), original.body.len(), "the body length differed");
        for (a, b) in rebuilt.body.iter().zip(original.body.iter()) {
            assert_eq!(a.id(), b.id(), "a body transaction differed");
        }
    }

    #[test]
    fn a_coded_proposal_reassembles_byte_for_byte_from_any_k() {
        let proposal = sample_proposal(64, 3);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let k = shards[0].commitment.k;
        let n = shards[0].commitment.n;
        // A half rate code: the shard count is twice the data shard count.
        assert_eq!(n, 2 * k);
        assert_eq!(shards.len(), n);

        // Feed the parity shards alone, the k shards that share no byte with the data
        // shards, the hardest subset. Reassembly completes on exactly the k th shard.
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
        same_proposal(&rebuilt.expect("k shards reconstruct the proposal"), &proposal);
    }

    #[test]
    fn a_wrong_proposal_shard_is_refused_and_a_clean_set_still_reassembles() {
        let proposal = sample_proposal(48, 0);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let k = shards[0].commitment.k;
        let mut assembler = ProposalAssembler::new();

        // A shard with a flipped byte fails its commitment and is dropped, never
        // entering the reassembly.
        let mut corrupt = shards[0].clone();
        corrupt.shard.bytes[0] ^= 255;
        assert!(
            assembler.admit(corrupt).is_none(),
            "a corrupted shard was admitted"
        );

        // A clean set of k still reconstructs the proposal, so a wrong shard neither
        // corrupts nor blocks the block.
        let mut rebuilt = None;
        for coded in shards.iter().take(k).cloned() {
            if let Some(result) = assembler.admit(coded) {
                rebuilt = Some(result.expect("the clean k reconstruct"));
            }
        }
        same_proposal(&rebuilt.expect("the clean k reconstruct the proposal"), &proposal);
    }

    #[test]
    fn each_coded_proposal_shard_fits_one_record() {
        // A block wider than one qtv-net record, the case the old single record
        // proposal could not carry.
        let proposal = sample_proposal(800, 0);
        let block = ChainBlock::new(
            proposal.header.clone(),
            Vec::new(),
            proposal.body.clone(),
        );
        let block_len = to_bytes(&block).len();
        let record_bound = 1usize << 20;
        assert!(
            block_len > record_bound,
            "the sample block {block_len} did not exceed one record, so the test is not meaningful"
        );

        // Every shard travels as its own gossip message, and each stays within the
        // record bound, so a block the single record path would refuse disseminates.
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
        // Shards whose commitment codes one block cannot be passed off under another
        // header: reassembly rebuilds the block the shards code, and the header check
        // refuses it. This exercises the refusal path a malicious disperser would hit.
        let proposal = sample_proposal(32, 0);
        let shards = code_proposal(&proposal).expect("code the proposal");
        let k = shards[0].commitment.k;

        // Rewrite each shard to advertise a different header while keeping the true
        // commitment and shards, the mismatch a disperser could attempt.
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
    fn coding_params_keep_a_shard_within_the_record_bound() {
        let record_bound = 1usize << 20;
        // Across a wide span of payload sizes the data shard stays a fraction of a
        // record, so the shard plus its metadata never approaches the bound.
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
}
