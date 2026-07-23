
use qtv_attest::{Attestation, Block, Certificate, Envelope, Parent};
use qtv_block::{Block as ChainBlock, Header};
use qtv_codec::{Decoder, Encode, Encoder, Error as CodecError};
use qtv_crypto::ml_dsa::{Signature, SIGNATURE_BYTES};
use qtv_crypto::sha3::sha3_256;
use qtv_net::erasure::{Commitment, Shard, ShardProof, DIGEST_LEN};
use qtv_sampler::onetime::{MerklePath, Root, NODE_BYTES, PREIMAGE_BYTES};
use qtv_sampler::sortition::Credential;
use qtv_tx::{Body, Call, Wrapper};

use crate::discovery::{PeerEntry, KEY_BYTES};

const TAG_TX: u8 = 1;
const TAG_PROPOSAL: u8 = 2;
const TAG_ATTEST: u8 = 3;
const TAG_PEERS: u8 = 4;
const TAG_STATUS: u8 = 5;
const TAG_GET_BLOCKS: u8 = 6;
const TAG_BLOCKS: u8 = 7;
const TAG_VIEW_CHANGE: u8 = 8;
const TAG_CODED_PROPOSAL: u8 = 9;
const TAG_REVEAL: u8 = 10;
const TAG_REGISTER: u8 = 11;

const PARENT_GENESIS: u8 = 0;
const PARENT_VALUE: u8 = 1;

const STAGE_ONE: u8 = 1;

const PREALLOC_LIMIT: usize = 4096;
const MIN_WRAPPER: usize = 65;
const MIN_VIEW_CHANGE: usize = 32;
const MIN_CHAIN_BLOCK: usize = 16;
const MIN_PEER: usize = 16;
const MIN_ATTESTATION: usize = 32;
const MIN_SIBLING: usize = 8;

fn bounded_capacity(remaining: usize, count: u64, min_element: usize) -> Result<usize, DecodeError> {
    let ceiling = (remaining / min_element.max(1)) as u64;
    if count > ceiling {
        return Err(DecodeError::BadLength);
    }
    Ok((count as usize).min(PREALLOC_LIMIT))
}

#[derive(Clone)]
pub struct Proposal {
    pub view: u64,
    pub header: Header,
    pub body: Vec<Wrapper>,
    pub justification: Vec<ViewChange>,
}

#[derive(Clone)]
pub struct CodedProposal {
    pub view: u64,
    pub header: Header,
    pub commitment: Commitment,
    pub justification: Vec<ViewChange>,
    pub shard: Shard,
    pub proof: ShardProof,
}

#[derive(Clone)]
pub struct LockedBlock {
    pub header: Header,
    pub body: Vec<Wrapper>,
}

#[derive(Clone)]
pub struct ViewChange {
    pub height: u64,
    pub target_view: u64,
    pub lock_view: u64,
    pub locked: Option<LockedBlock>,
    pub att: Attestation,
}

/// A validator's own sortition reveal for a height, its height, author id, and
/// credential, published so peers admit it to the committee.
#[derive(Clone)]
pub struct RevealNote {
    pub height: u64,
    pub id: u64,
    pub credential: Credential,
}

/// A validator's signed re registration of its rotated one time sortition root for an
/// epoch. The signature is over the id, epoch, and root under the validator's stable
/// attestation key, so a peer admits the new root without holding the validator's secret.
#[derive(Clone)]
pub struct RegisterNote {
    pub height: u64,
    pub id: u64,
    pub epoch: u64,
    pub root: Root,
    pub sig: Signature,
}

#[derive(Clone)]
pub enum Message {
    Tx(Wrapper),
    Proposal(Proposal),
    CodedProposal(Box<CodedProposal>),
    Attest(Box<Attestation>),
    Peers(Vec<PeerEntry>),
    Status(u64),
    GetBlocks { from: u64, to: u64 },
    Blocks(Vec<ChainBlock>),
    ViewChange(Box<ViewChange>),
    Reveal(Box<RevealNote>),
    Register(Box<RegisterNote>),
}

#[derive(Debug)]
pub enum DecodeError {
    Codec(CodecError),
    Header(qtv_block::Error),
    UnknownTag(u8),
    BadParent(u8),
    BadStage(u8),
    BadLength,
    Utf8,
}

impl From<CodecError> for DecodeError {
    fn from(error: CodecError) -> Self {
        DecodeError::Codec(error)
    }
}

impl From<qtv_block::Error> for DecodeError {
    fn from(error: qtv_block::Error) -> Self {
        DecodeError::Header(error)
    }
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        match self {
            Message::Tx(wrapper) => {
                encoder.put_tag(TAG_TX);
                wrapper.encode(&mut encoder);
            }
            Message::Proposal(proposal) => {
                encoder.put_tag(TAG_PROPOSAL);
                encoder.put_u64(proposal.view);
                proposal.header.encode(&mut encoder);
                encoder.put_u64(proposal.body.len() as u64);
                for wrapper in &proposal.body {
                    wrapper.encode(&mut encoder);
                }
                encoder.put_u64(proposal.justification.len() as u64);
                for record in &proposal.justification {
                    encode_view_change(&mut encoder, record);
                }
            }
            Message::CodedProposal(coded) => {
                encoder.put_tag(TAG_CODED_PROPOSAL);
                encode_coded_proposal(&mut encoder, coded);
            }
            Message::Attest(attestation) => {
                encoder.put_tag(TAG_ATTEST);
                encode_attestation(&mut encoder, attestation);
            }
            Message::Peers(peers) => {
                encoder.put_tag(TAG_PEERS);
                encoder.put_u64(peers.len() as u64);
                for entry in peers {
                    encoder.put_bytes(entry.key());
                    encoder.put_bytes(entry.address().as_bytes());
                }
            }
            Message::Status(height) => {
                encoder.put_tag(TAG_STATUS);
                encoder.put_u64(*height);
            }
            Message::GetBlocks { from, to } => {
                encoder.put_tag(TAG_GET_BLOCKS);
                encoder.put_u64(*from);
                encoder.put_u64(*to);
            }
            Message::Blocks(blocks) => {
                encoder.put_tag(TAG_BLOCKS);
                encoder.put_u64(blocks.len() as u64);
                for block in blocks {
                    encode_chain_block(&mut encoder, block);
                }
            }
            Message::ViewChange(record) => {
                encoder.put_tag(TAG_VIEW_CHANGE);
                encode_view_change(&mut encoder, record);
            }
            Message::Reveal(note) => {
                encoder.put_tag(TAG_REVEAL);
                encoder.put_u64(note.height);
                encoder.put_u64(note.id);
                encode_credential(&mut encoder, &note.credential);
            }
            Message::Register(note) => {
                encoder.put_tag(TAG_REGISTER);
                encoder.put_u64(note.height);
                encoder.put_u64(note.id);
                encoder.put_u64(note.epoch);
                encoder.put_bytes(&note.root.digest);
                encoder.put_u64(note.root.slots);
                encoder.put_bytes(&note.sig);
            }
        }
        encoder.into_bytes()
    }

    pub fn id(&self) -> [u8; 32] {
        gossip_id(&self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let message = match decoder.get_tag()? {
            TAG_TX => Message::Tx(decode_wrapper(&mut decoder)?),
            TAG_PROPOSAL => {
                let view = decoder.get_u64()?;
                let header = Header::decode(&mut decoder)?;
                let count = decoder.get_u64()?;
                let mut body =
                    Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_WRAPPER)?);
                for _ in 0..count {
                    body.push(decode_wrapper(&mut decoder)?);
                }
                let just_count = decoder.get_u64()?;
                let mut justification = Vec::with_capacity(bounded_capacity(
                    decoder.remaining(),
                    just_count,
                    MIN_VIEW_CHANGE,
                )?);
                for _ in 0..just_count {
                    justification.push(decode_view_change(&mut decoder)?);
                }
                Message::Proposal(Proposal {
                    view,
                    header,
                    body,
                    justification,
                })
            }
            TAG_CODED_PROPOSAL => {
                Message::CodedProposal(Box::new(decode_coded_proposal(&mut decoder)?))
            }
            TAG_ATTEST => Message::Attest(Box::new(decode_attestation(&mut decoder)?)),
            TAG_PEERS => {
                let count = decoder.get_u64()?;
                let mut peers =
                    Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_PEER)?);
                for _ in 0..count {
                    let key: [u8; KEY_BYTES] = read_fixed(&mut decoder)?;
                    let address = read_text(&mut decoder)?;
                    peers.push(PeerEntry::new(key, address));
                }
                Message::Peers(peers)
            }
            TAG_STATUS => Message::Status(decoder.get_u64()?),
            TAG_GET_BLOCKS => {
                let from = decoder.get_u64()?;
                let to = decoder.get_u64()?;
                Message::GetBlocks { from, to }
            }
            TAG_BLOCKS => {
                let count = decoder.get_u64()?;
                let mut blocks = Vec::with_capacity(bounded_capacity(
                    decoder.remaining(),
                    count,
                    MIN_CHAIN_BLOCK,
                )?);
                for _ in 0..count {
                    blocks.push(decode_chain_block(&mut decoder)?);
                }
                Message::Blocks(blocks)
            }
            TAG_VIEW_CHANGE => Message::ViewChange(Box::new(decode_view_change(&mut decoder)?)),
            TAG_REVEAL => {
                let height = decoder.get_u64()?;
                let id = decoder.get_u64()?;
                let credential = decode_credential(&mut decoder)?;
                Message::Reveal(Box::new(RevealNote {
                    height,
                    id,
                    credential,
                }))
            }
            TAG_REGISTER => {
                let height = decoder.get_u64()?;
                let id = decoder.get_u64()?;
                let epoch = decoder.get_u64()?;
                let digest: [u8; NODE_BYTES] = read_fixed(&mut decoder)?;
                let slots = decoder.get_u64()?;
                let sig: [u8; SIGNATURE_BYTES] = read_fixed(&mut decoder)?;
                Message::Register(Box::new(RegisterNote {
                    height,
                    id,
                    epoch,
                    root: Root { digest, slots },
                    sig,
                }))
            }
            tag => return Err(DecodeError::UnknownTag(tag)),
        };
        decoder.finish()?;
        Ok(message)
    }
}

pub fn gossip_id(bytes: &[u8]) -> [u8; 32] {
    sha3_256(bytes)
}

pub fn encode_register_note(note: &RegisterNote) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.put_u64(note.height);
    encoder.put_u64(note.id);
    encoder.put_u64(note.epoch);
    encoder.put_bytes(&note.root.digest);
    encoder.put_u64(note.root.slots);
    encoder.put_bytes(&note.sig);
    encoder.into_bytes()
}

pub fn decode_register_note(bytes: &[u8]) -> Result<RegisterNote, DecodeError> {
    let mut decoder = Decoder::new(bytes);
    let height = decoder.get_u64()?;
    let id = decoder.get_u64()?;
    let epoch = decoder.get_u64()?;
    let digest: [u8; NODE_BYTES] = read_fixed(&mut decoder)?;
    let slots = decoder.get_u64()?;
    let sig: [u8; SIGNATURE_BYTES] = read_fixed(&mut decoder)?;
    decoder.finish()?;
    Ok(RegisterNote {
        height,
        id,
        epoch,
        root: Root { digest, slots },
        sig,
    })
}

fn read_text(decoder: &mut Decoder<'_>) -> Result<String, DecodeError> {
    let bytes = decoder.get_bytes()?;
    String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Utf8)
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], DecodeError> {
    let bytes = decoder.get_bytes()?;
    bytes.try_into().map_err(|_| DecodeError::BadLength)
}

fn decode_wrapper(decoder: &mut Decoder<'_>) -> Result<Wrapper, DecodeError> {
    let sender = read_text(decoder)?;
    let nonce = decoder.get_u64()?;
    let meter_limit = decoder.get_u64()?;
    let fee = decoder.get_u128()?;
    let target = read_text(decoder)?;
    let args = decoder.get_bytes()?.to_vec();
    let value = decoder.get_u64()?;
    let chain_id = decoder.get_u64()?;
    let scheme = decoder.get_u8()?;
    let signature = decoder.get_bytes()?.to_vec();
    let body = Body::with_context(
        sender,
        nonce,
        meter_limit,
        fee,
        Call::new(target, args),
        value,
        chain_id,
    );
    Ok(Wrapper::new(body, scheme, signature))
}

fn encode_attestation(encoder: &mut Encoder, attestation: &Attestation) {
    encoder.put_u64(attestation.from);
    encoder.put_u64(attestation.height);
    encoder.put_u64(attestation.slot);
    encode_block(encoder, &attestation.block);
    encode_credential(encoder, &attestation.membership);
    encoder.put_bytes(&attestation.sig);
}

fn decode_attestation(decoder: &mut Decoder<'_>) -> Result<Attestation, DecodeError> {
    let from = decoder.get_u64()?;
    let height = decoder.get_u64()?;
    let slot = decoder.get_u64()?;
    let block = decode_block(decoder)?;
    let membership = decode_credential(decoder)?;
    let sig: [u8; SIGNATURE_BYTES] = read_fixed(decoder)?;
    Ok(Attestation {
        from,
        height,
        slot,
        block,
        membership,
        sig,
    })
}

fn encode_credential(encoder: &mut Encoder, credential: &Credential) {
    encoder.put_u64(credential.position);
    encoder.put_bytes(&credential.preimage);
    encoder.put_u64(credential.path.siblings.len() as u64);
    for sibling in &credential.path.siblings {
        encoder.put_bytes(sibling);
    }
}

fn decode_credential(decoder: &mut Decoder<'_>) -> Result<Credential, DecodeError> {
    let position = decoder.get_u64()?;
    let preimage: [u8; PREIMAGE_BYTES] = read_fixed(decoder)?;
    let count = decoder.get_u64()?;
    let mut siblings = Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_SIBLING)?);
    for _ in 0..count {
        let sibling: [u8; NODE_BYTES] = read_fixed(decoder)?;
        siblings.push(sibling);
    }
    Ok(Credential {
        position,
        preimage,
        path: MerklePath { siblings },
    })
}

fn encode_view_change(encoder: &mut Encoder, record: &ViewChange) {
    encoder.put_u64(record.height);
    encoder.put_u64(record.target_view);
    encoder.put_u64(record.lock_view);
    match &record.locked {
        Some(locked) => {
            encoder.put_u8(1);
            locked.header.encode(encoder);
            encoder.put_u64(locked.body.len() as u64);
            for wrapper in &locked.body {
                wrapper.encode(encoder);
            }
        }
        None => encoder.put_u8(0),
    }
    encode_attestation(encoder, &record.att);
}

fn decode_view_change(decoder: &mut Decoder<'_>) -> Result<ViewChange, DecodeError> {
    let height = decoder.get_u64()?;
    let target_view = decoder.get_u64()?;
    let lock_view = decoder.get_u64()?;
    let locked = match decoder.get_u8()? {
        0 => None,
        1 => {
            let header = Header::decode(decoder)?;
            let count = decoder.get_u64()?;
            let mut body =
                Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_WRAPPER)?);
            for _ in 0..count {
                body.push(decode_wrapper(decoder)?);
            }
            Some(LockedBlock { header, body })
        }
        other => return Err(DecodeError::BadParent(other)),
    };
    let att = decode_attestation(decoder)?;
    Ok(ViewChange {
        height,
        target_view,
        lock_view,
        locked,
        att,
    })
}

fn encode_coded_proposal(encoder: &mut Encoder, coded: &CodedProposal) {
    encoder.put_u64(coded.view);
    coded.header.encode(encoder);
    encode_commitment(encoder, &coded.commitment);
    encoder.put_u64(coded.justification.len() as u64);
    for record in &coded.justification {
        encode_view_change(encoder, record);
    }
    encoder.put_u64(coded.shard.index as u64);
    encoder.put_bytes(&coded.shard.bytes);
    encoder.put_u64(coded.proof.siblings.len() as u64);
    for sibling in &coded.proof.siblings {
        encoder.put_bytes(sibling);
    }
}

fn decode_coded_proposal(decoder: &mut Decoder<'_>) -> Result<CodedProposal, DecodeError> {
    let view = decoder.get_u64()?;
    let header = Header::decode(decoder)?;
    let commitment = decode_commitment(decoder)?;
    let just_count = decoder.get_u64()?;
    let mut justification = Vec::with_capacity(bounded_capacity(
        decoder.remaining(),
        just_count,
        MIN_VIEW_CHANGE,
    )?);
    for _ in 0..just_count {
        justification.push(decode_view_change(decoder)?);
    }
    let index = decoder.get_u64()? as usize;
    let bytes = decoder.get_bytes()?.to_vec();
    let sibling_count = decoder.get_u64()?;
    let mut siblings = Vec::with_capacity(bounded_capacity(
        decoder.remaining(),
        sibling_count,
        MIN_SIBLING,
    )?);
    for _ in 0..sibling_count {
        let sibling: [u8; DIGEST_LEN] = read_fixed(decoder)?;
        siblings.push(sibling);
    }
    Ok(CodedProposal {
        view,
        header,
        commitment,
        justification,
        shard: Shard { index, bytes },
        proof: ShardProof { siblings },
    })
}

fn encode_commitment(encoder: &mut Encoder, commitment: &Commitment) {
    encoder.put_bytes(&commitment.root);
    encoder.put_u64(commitment.k as u64);
    encoder.put_u64(commitment.n as u64);
    encoder.put_u64(commitment.shard_len as u64);
    encoder.put_u64(commitment.data_len as u64);
}

fn decode_commitment(decoder: &mut Decoder<'_>) -> Result<Commitment, DecodeError> {
    let root: [u8; DIGEST_LEN] = read_fixed(decoder)?;
    let k = decoder.get_u64()? as usize;
    let n = decoder.get_u64()? as usize;
    let shard_len = decoder.get_u64()? as usize;
    let data_len = decoder.get_u64()? as usize;
    Ok(Commitment {
        root,
        k,
        n,
        shard_len,
        data_len,
    })
}

fn put_value(encoder: &mut Encoder, value: &[u8; 32]) {
    for &byte in value {
        encoder.put_u8(byte);
    }
}

fn get_value(decoder: &mut Decoder<'_>) -> Result<[u8; 32], DecodeError> {
    let mut value = [0u8; 32];
    for slot in value.iter_mut() {
        *slot = decoder.get_u8()?;
    }
    Ok(value)
}

fn encode_block(encoder: &mut Encoder, block: &Block) {
    encoder.put_u64(block.height);
    put_value(encoder, &block.val);
    match block.parent {
        Parent::Genesis => {
            encoder.put_u8(PARENT_GENESIS);
            put_value(encoder, &[0u8; 32]);
        }
        Parent::Value(value) => {
            encoder.put_u8(PARENT_VALUE);
            put_value(encoder, &value);
        }
    }
    encoder.put_u64(block.cost);
}

fn decode_block(decoder: &mut Decoder<'_>) -> Result<Block, DecodeError> {
    let height = decoder.get_u64()?;
    let val = get_value(decoder)?;
    let parent_tag = decoder.get_u8()?;
    let parent_value = get_value(decoder)?;
    let parent = match parent_tag {
        PARENT_GENESIS => Parent::Genesis,
        PARENT_VALUE => Parent::Value(parent_value),
        other => return Err(DecodeError::BadParent(other)),
    };
    let cost = decoder.get_u64()?;
    Ok(Block {
        height,
        val,
        parent,
        cost,
    })
}

pub fn certificate_to_bytes(certificate: &Certificate) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encode_envelope(&mut encoder, &certificate.envelope);
    encoder.put_u8(STAGE_ONE);
    encoder.put_u64(certificate.attestations.len() as u64);
    for attestation in &certificate.attestations {
        encode_attestation(&mut encoder, attestation);
    }
    encoder.into_bytes()
}

pub fn certificate_from_bytes(bytes: &[u8]) -> Result<Certificate, DecodeError> {
    let mut decoder = Decoder::new(bytes);
    let envelope = decode_envelope(&mut decoder)?;
    let certificate = match decoder.get_u8()? {
        STAGE_ONE => {
            let count = decoder.get_u64()?;
            let mut attestations = Vec::with_capacity(bounded_capacity(
                decoder.remaining(),
                count,
                MIN_ATTESTATION,
            )?);
            for _ in 0..count {
                attestations.push(decode_attestation(&mut decoder)?);
            }
            Certificate::new(envelope, attestations)
        }
        stage => return Err(DecodeError::BadStage(stage)),
    };
    decoder.finish()?;
    Ok(certificate)
}

fn encode_envelope(encoder: &mut Encoder, envelope: &Envelope) {
    encoder.put_u64(envelope.height);
    encoder.put_u64(envelope.slot);
    encode_block(encoder, &envelope.block);
    encoder.put_bytes(&envelope.committee);
}

fn decode_envelope(decoder: &mut Decoder<'_>) -> Result<Envelope, DecodeError> {
    let height = decoder.get_u64()?;
    let slot = decoder.get_u64()?;
    let block = decode_block(decoder)?;
    let committee: [u8; 32] = read_fixed(decoder)?;
    Ok(Envelope {
        height,
        slot,
        block,
        committee,
    })
}

fn encode_chain_block(encoder: &mut Encoder, block: &ChainBlock) {
    block.header().encode(encoder);
    encoder.put_bytes(block.certificate());
    encoder.put_u64(block.body().len() as u64);
    for wrapper in block.body() {
        wrapper.encode(encoder);
    }
}

pub fn chain_block_from_bytes(bytes: &[u8]) -> Result<ChainBlock, DecodeError> {
    let mut decoder = Decoder::new(bytes);
    let block = decode_chain_block(&mut decoder)?;
    decoder.finish()?;
    Ok(block)
}

pub fn wrapper_from_bytes(bytes: &[u8]) -> Result<Wrapper, DecodeError> {
    let mut decoder = Decoder::new(bytes);
    let wrapper = decode_wrapper(&mut decoder)?;
    decoder.finish()?;
    Ok(wrapper)
}

fn decode_chain_block(decoder: &mut Decoder<'_>) -> Result<ChainBlock, DecodeError> {
    let header = Header::decode(decoder)?;
    let certificate = decoder.get_bytes()?.to_vec();
    let count = decoder.get_u64()?;
    let mut body =
        Vec::with_capacity(bounded_capacity(decoder.remaining(), count, MIN_WRAPPER)?);
    for _ in 0..count {
        body.push(decode_wrapper(decoder)?);
    }
    Ok(ChainBlock::new(header, certificate, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_frame_with_a_huge_count_and_a_tiny_body_is_rejected() {
        let mut bytes = vec![TAG_PEERS];
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(Message::decode(&bytes), Err(DecodeError::BadLength)));
    }

    #[test]
    fn a_blocks_frame_with_a_huge_count_and_a_tiny_body_is_rejected() {
        let mut bytes = vec![TAG_BLOCKS];
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(Message::decode(&bytes), Err(DecodeError::BadLength)));
    }

    #[test]
    fn bounded_capacity_rejects_a_count_that_overruns_the_remaining_bytes() {
        assert!(matches!(
            bounded_capacity(0, u64::MAX, MIN_WRAPPER),
            Err(DecodeError::BadLength)
        ));
        assert!(matches!(
            bounded_capacity(16, 100, MIN_PEER),
            Err(DecodeError::BadLength)
        ));
    }

    #[test]
    fn bounded_capacity_admits_a_plausible_count_and_caps_the_reservation() {
        assert_eq!(bounded_capacity(1_000_000, 3, MIN_WRAPPER).unwrap(), 3);
        assert_eq!(
            bounded_capacity(1_000_000_000, 100_000, MIN_SIBLING).unwrap(),
            PREALLOC_LIMIT
        );
    }

    #[test]
    fn a_registration_note_round_trips_through_the_carried_encoding() {
        let note = RegisterNote {
            height: 7,
            id: 3,
            epoch: 2,
            root: Root {
                digest: [9u8; NODE_BYTES],
                slots: 4,
            },
            sig: [5u8; SIGNATURE_BYTES],
        };
        let decoded = decode_register_note(&encode_register_note(&note)).expect("round trip");
        assert_eq!(decoded.height, note.height);
        assert_eq!(decoded.id, note.id);
        assert_eq!(decoded.epoch, note.epoch);
        assert_eq!(decoded.root.digest, note.root.digest);
        assert_eq!(decoded.root.slots, note.root.slots);
        assert_eq!(decoded.sig, note.sig);
        assert!(
            decode_register_note(&[0u8; 3]).is_err(),
            "a truncated record is refused"
        );
    }
}
