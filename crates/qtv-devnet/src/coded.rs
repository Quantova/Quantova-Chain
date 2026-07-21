
use std::collections::HashMap;

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

    pub fn piece(&self, index: usize) -> (Shard, ShardProof) {
        (self.coded.shard(index).clone(), self.coded.proof(index))
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
    let rederived = erasure::encode(&bytes, commitment.k, commitment.n)?;
    if rederived.commitment() != commitment {
        return Err(CodedError::CommitmentMismatch);
    }
    Ok(block)
}

pub const SHARD_TARGET: usize = 1 << 18;

pub fn coding_params(payload_len: usize) -> (usize, usize) {
    let k = payload_len.div_ceil(SHARD_TARGET).clamp(2, erasure::MAX_SHARDS / 2);
    let n = (2 * k).min(erasure::MAX_SHARDS);
    (k, n)
}

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

type ProposalKey = (u64, [u8; DIGEST_LEN]);

#[derive(Clone, Default)]
pub struct ProposalAssembler {
    pending: HashMap<ProposalKey, Pending>,
    done: HashMap<ProposalKey, u64>,
    horizon: u64,
}

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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn admit(&mut self, coded: CodedProposal) -> Option<Result<Proposal, CodedError>> {
        let key: ProposalKey = (coded.view, coded.commitment.root);
        if self.done.contains_key(&key) {
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
        } = coded;
        let entry = self.pending.entry(key).or_insert_with(|| Pending {
            height,
            view,
            header: header.clone(),
            commitment: commitment.clone(),
            justification,
            pieces: Vec::new(),
        });
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

    fn sample_block(count: usize) -> ChainBlock {
        let mut body = Vec::with_capacity(count);
        for i in 0..count {
            let call = Call::new(format!("account-{i}"), vec![(i % 251) as u8; 64]);
            let inner = Body::new(format!("sender-{i}"), i as u64, 21_000, 1, call);
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

        let (mut shard, proof) = coded.piece(3);
        shard.bytes[0] ^= 255;
        assert!(!coded.commitment().verify_shard(&shard, &proof));

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

    fn sample_proposal(count: usize, view: u64) -> Proposal {
        let block = sample_block(count);
        Proposal {
            view,
            header: block.header().clone(),
            body: block.body().to_vec(),
            justification: Vec::new(),
        }
    }

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
        same_proposal(&rebuilt.expect("k shards reconstruct the proposal"), &proposal);
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
        same_proposal(&rebuilt.expect("the clean k reconstruct the proposal"), &proposal);
    }

    #[test]
    fn each_coded_proposal_shard_fits_one_record() {
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
}
