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

use qtv_block::{transaction_root, Block as ChainBlock, Header};
use qtv_codec::{to_bytes, Decoder, Encoder};
use qtv_crypto::sha3::sha3_256;
use qtv_net::erasure::{self, Commitment, Shard, ShardProof, DIGEST_LEN};

use crate::wire::chain_block_from_bytes;

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
        shard.bytes[0] ^= 0xff;
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
}
