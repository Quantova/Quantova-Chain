//! The gossip messages nodes exchange over the channels, and their canonical
//! codec.
//!
//! Three things travel the wire: a submitted transaction, a block proposal that
//! carries the real header and the ordered body, and a committee attestation that
//! carries the sampler membership draw and the module lattice signature. Every
//! message enters and leaves the wire through the qtv-codec canonical encoding, so
//! a message has exactly one encoded form and a message that does not parse is
//! dropped at the edge, which is where a classical or malformed artifact is
//! refused.

use qtv_attest::{Attestation, Block, Parent};
use qtv_block::Header;
use qtv_codec::{Decoder, Encode, Encoder, Error as CodecError};
use qtv_crypto::ml_dsa::SIGNATURE_BYTES;
use qtv_crypto::vrf::{OUTPUT_BYTES, PROOF_BYTES};
use qtv_sampler::sortition::Draw;
use qtv_tx::{Body, Call, Wrapper};

/// The tag that selects a transaction message.
const TAG_TX: u8 = 1;
/// The tag that selects a block proposal message.
const TAG_PROPOSAL: u8 = 2;
/// The tag that selects an attestation message.
const TAG_ATTEST: u8 = 3;

/// The tag that marks a genesis parent link.
const PARENT_GENESIS: u8 = 0;
/// The tag that marks a value parent link.
const PARENT_VALUE: u8 = 1;

/// A block proposal: the view it is offered in, the real chain header the
/// committee attests over, and the ordered body the header commits to. The view
/// names which leader in the rotation proposed it, so a receiver checks the
/// proposal against the leader of that view and never against a stale one.
#[derive(Clone, Debug)]
pub struct Proposal {
    pub view: u64,
    pub header: Header,
    pub body: Vec<Wrapper>,
}

/// A gossip message. A node forwards a transaction it admitted, a leader forwards
/// its proposal, and a committee member forwards its attestation.
#[derive(Clone)]
pub enum Message {
    /// A submitted transaction spreading toward the leader mempools.
    Tx(Wrapper),
    /// A leader block proposal for the current height.
    Proposal(Proposal),
    /// One committee member attestation over a proposed block.
    Attest(Box<Attestation>),
}

/// A reason a wire message failed to parse. Any of these drops the message.
#[derive(Debug)]
pub enum DecodeError {
    /// A codec step refused the bytes.
    Codec(CodecError),
    /// The header inside a proposal did not decode.
    Header(qtv_block::Error),
    /// A message tag named no message.
    UnknownTag(u8),
    /// A parent link tag named neither genesis nor a value.
    BadParent(u8),
    /// A fixed width crypto field was not its expected length.
    BadLength,
    /// A text field did not hold valid text.
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
    /// The canonical encoding of the message, a tag byte then the variant.
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
            }
            Message::Attest(attestation) => {
                encoder.put_tag(TAG_ATTEST);
                encode_attestation(&mut encoder, attestation);
            }
        }
        encoder.into_bytes()
    }

    /// Read a message from a whole payload in canonical form, refusing trailing
    /// bytes.
    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let message = match decoder.get_tag()? {
            TAG_TX => Message::Tx(decode_wrapper(&mut decoder)?),
            TAG_PROPOSAL => {
                let view = decoder.get_u64()?;
                let header = Header::decode(&mut decoder)?;
                let count = decoder.get_u64()?;
                let mut body = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    body.push(decode_wrapper(&mut decoder)?);
                }
                Message::Proposal(Proposal { view, header, body })
            }
            TAG_ATTEST => Message::Attest(Box::new(decode_attestation(&mut decoder)?)),
            tag => return Err(DecodeError::UnknownTag(tag)),
        };
        decoder.finish()?;
        Ok(message)
    }
}

/// Read a length delimited byte string as text.
fn read_text(decoder: &mut Decoder<'_>) -> Result<String, DecodeError> {
    let bytes = decoder.get_bytes()?;
    String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Utf8)
}

/// Read a length delimited byte string into a fixed width array.
fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], DecodeError> {
    let bytes = decoder.get_bytes()?;
    bytes.try_into().map_err(|_| DecodeError::BadLength)
}

/// Read a transaction wrapper field by field, the mirror of its canonical
/// encoding.
fn decode_wrapper(decoder: &mut Decoder<'_>) -> Result<Wrapper, DecodeError> {
    let sender = read_text(decoder)?;
    let nonce = decoder.get_u64()?;
    let gas_limit = decoder.get_u64()?;
    let fee = decoder.get_u128()?;
    let target = read_text(decoder)?;
    let args = decoder.get_bytes()?.to_vec();
    let scheme = decoder.get_u8()?;
    let signature = decoder.get_bytes()?.to_vec();
    let body = Body::new(sender, nonce, gas_limit, fee, Call::new(target, args));
    Ok(Wrapper::new(body, scheme, signature))
}

/// Append the canonical encoding of an attestation: its subject, the consensus
/// block, the sampler membership draw, and the module lattice signature.
fn encode_attestation(encoder: &mut Encoder, attestation: &Attestation) {
    encoder.put_u64(attestation.from);
    encoder.put_u64(attestation.height);
    encoder.put_u64(attestation.slot);
    encode_block(encoder, &attestation.block);
    encoder.put_bytes(&attestation.membership.output);
    encoder.put_bytes(&attestation.membership.proof);
    encoder.put_bytes(&attestation.sig);
}

/// Read an attestation, reconstructing the sampler draw and the signature from
/// their fixed width fields.
fn decode_attestation(decoder: &mut Decoder<'_>) -> Result<Attestation, DecodeError> {
    let from = decoder.get_u64()?;
    let height = decoder.get_u64()?;
    let slot = decoder.get_u64()?;
    let block = decode_block(decoder)?;
    let output: [u8; OUTPUT_BYTES] = read_fixed(decoder)?;
    let proof: [u8; PROOF_BYTES] = read_fixed(decoder)?;
    let sig: [u8; SIGNATURE_BYTES] = read_fixed(decoder)?;
    Ok(Attestation {
        from,
        height,
        slot,
        block,
        membership: Draw { output, proof },
        sig,
    })
}

/// Append the canonical encoding of a consensus block.
fn encode_block(encoder: &mut Encoder, block: &Block) {
    encoder.put_u64(block.height);
    encoder.put_u64(block.val);
    match block.parent {
        Parent::Genesis => {
            encoder.put_u8(PARENT_GENESIS);
            encoder.put_u64(0);
        }
        Parent::Value(value) => {
            encoder.put_u8(PARENT_VALUE);
            encoder.put_u64(value);
        }
    }
    encoder.put_u64(block.cost);
}

/// Read a consensus block, refusing a parent tag that names neither genesis nor a
/// value.
fn decode_block(decoder: &mut Decoder<'_>) -> Result<Block, DecodeError> {
    let height = decoder.get_u64()?;
    let val = decoder.get_u64()?;
    let parent_tag = decoder.get_u8()?;
    let parent_value = decoder.get_u64()?;
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
