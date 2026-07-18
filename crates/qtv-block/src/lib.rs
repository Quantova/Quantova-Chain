//! The block model for the Quantova stack.
//!
//! A block is a header, a certificate slot, and a body. The header fixes the
//! position of the block and commits to its contents. It holds the height, the
//! hash of the parent header, the state root, the transaction root over the
//! transactions in order, the event root over the emitted events, the beacon
//! seed, the proposer, the time, and a short arbitrary data field the proposer
//! may set, the equivalent of a coinbase note. The parent hash, each root, and
//! the beacon seed are thirty two byte values. Every field enters the encoding
//! through the canonical codec, so one header has exactly one encoded form, and
//! the arbitrary data field folds into the header hash like every other field.
//!
//! The certificate slot is a variable length byte field that carries the
//! aggregated certificate over the header. It sits outside the header so that
//! the header hash stays fixed while the certificate is gathered. The body is
//! the ordered list of transaction wrappers.
//!
//! The transaction root is a sha3 256 Merkle root over the canonical encodings
//! of the transactions in order. Each transaction contributes a leaf that is the
//! sha3 256 hash of its canonical encoding, and the leaves reduce in pairs under
//! sha3 256 until one value remains. When a level of the tree holds an odd
//! number of nodes the last node pairs with a copy of itself. An empty body has
//! the empty transaction root, the sha3 256 hash of the empty input. The header
//! hash is the sha3 256 hash of the canonical header encoding, and the block id
//! is the identifier format render under the block prefix of that hash.

#![forbid(unsafe_code)]

use std::fmt;

use qtv_codec::{to_bytes, Decode, Decoder, Encode, Encoder};
use qtv_crypto::sha3;
use qtv_tx::Wrapper;

/// The length in bytes of a header field that holds a hash, a root, or the
/// beacon seed.
pub const ROOT_LEN: usize = 32;

/// The most bytes the header's arbitrary data field may carry. Held small on
/// purpose, the field is a short note and not a place to park data, so a proposer
/// cannot bloat a header with it. A coinbase style line fits well inside this.
pub const MAX_EXTRA_DATA: usize = 32;

/// A reason a header decode refused its input, or a value it refused to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A codec step refused the input.
    Codec(qtv_codec::Error),
    /// The proposer field did not hold valid text.
    Proposer,
    /// The arbitrary data field was longer than the header allows.
    ExtraDataTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Codec(error) => {
                write!(f, "a codec step refused the header and reported {error}")
            }
            Error::Proposer => write!(f, "the proposer field did not hold valid text"),
            Error::ExtraDataTooLong => write!(
                f,
                "the header arbitrary data field is longer than {MAX_EXTRA_DATA} bytes"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<qtv_codec::Error> for Error {
    fn from(error: qtv_codec::Error) -> Self {
        Error::Codec(error)
    }
}

/// Append a thirty two byte value as its raw bytes in order.
fn put_root(encoder: &mut Encoder, root: &[u8; ROOT_LEN]) {
    for &byte in root.iter() {
        encoder.put_u8(byte);
    }
}

/// Read a thirty two byte value as its raw bytes in order.
fn get_root(decoder: &mut Decoder<'_>) -> Result<[u8; ROOT_LEN], Error> {
    let mut root = [0u8; ROOT_LEN];
    for slot in root.iter_mut() {
        *slot = decoder.get_u8()?;
    }
    Ok(root)
}

/// The header of a block. It fixes the height and the time, names the proposer
/// and the beacon seed, and commits to the parent header, the state, the
/// transactions, and the events through their thirty two byte values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    height: u64,
    parent_hash: [u8; ROOT_LEN],
    state_root: [u8; ROOT_LEN],
    transaction_root: [u8; ROOT_LEN],
    event_root: [u8; ROOT_LEN],
    beacon_seed: [u8; ROOT_LEN],
    proposer: String,
    time: u64,
    /// A short arbitrary note the proposer may set, empty by default. It commits
    /// into the header hash like every other field. Bounded by MAX_EXTRA_DATA.
    extra_data: Vec<u8>,
}

impl Header {
    /// Assemble a header from the height, the parent header hash, the state
    /// root, the transaction root, the event root, the beacon seed, the
    /// proposer, and the time.
    pub fn new(
        height: u64,
        parent_hash: [u8; ROOT_LEN],
        state_root: [u8; ROOT_LEN],
        transaction_root: [u8; ROOT_LEN],
        event_root: [u8; ROOT_LEN],
        beacon_seed: [u8; ROOT_LEN],
        proposer: String,
        time: u64,
    ) -> Self {
        Header {
            height,
            parent_hash,
            state_root,
            transaction_root,
            event_root,
            beacon_seed,
            proposer,
            time,
            extra_data: Vec::new(),
        }
    }

    /// The height of the block in the chain.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// The hash of the parent header.
    pub fn parent_hash(&self) -> &[u8; ROOT_LEN] {
        &self.parent_hash
    }

    /// The state root the block commits to.
    pub fn state_root(&self) -> &[u8; ROOT_LEN] {
        &self.state_root
    }

    /// The transaction root over the transactions in order.
    pub fn transaction_root(&self) -> &[u8; ROOT_LEN] {
        &self.transaction_root
    }

    /// The event root over the emitted events.
    pub fn event_root(&self) -> &[u8; ROOT_LEN] {
        &self.event_root
    }

    /// The beacon seed the block carries.
    pub fn beacon_seed(&self) -> &[u8; ROOT_LEN] {
        &self.beacon_seed
    }

    /// The proposer of the block.
    pub fn proposer(&self) -> &str {
        &self.proposer
    }

    /// The time of the block.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// The arbitrary data the proposer set on this header, empty when none.
    pub fn extra_data(&self) -> &[u8] {
        &self.extra_data
    }

    /// Set the arbitrary data note, refusing anything past MAX_EXTRA_DATA so a
    /// proposer cannot bloat the header. The bytes go in exactly as given.
    pub fn set_extra_data(&mut self, data: Vec<u8>) -> Result<(), Error> {
        if data.len() > MAX_EXTRA_DATA {
            return Err(Error::ExtraDataTooLong);
        }
        self.extra_data = data;
        Ok(())
    }

    /// The header hash, the sha3 256 hash of the canonical header encoding.
    pub fn hash(&self) -> [u8; ROOT_LEN] {
        sha3::sha3_256(&to_bytes(self))
    }

    /// Read a header from a decoder in canonical form.
    pub fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let height = u64::decode(decoder)?;
        let parent_hash = get_root(decoder)?;
        let state_root = get_root(decoder)?;
        let transaction_root = get_root(decoder)?;
        let event_root = get_root(decoder)?;
        let beacon_seed = get_root(decoder)?;
        let proposer_bytes = decoder.get_bytes()?;
        let proposer = String::from_utf8(proposer_bytes.to_vec()).map_err(|_| Error::Proposer)?;
        let time = u64::decode(decoder)?;
        let extra_data = decoder.get_bytes()?.to_vec();
        if extra_data.len() > MAX_EXTRA_DATA {
            return Err(Error::ExtraDataTooLong);
        }
        Ok(Header {
            height,
            parent_hash,
            state_root,
            transaction_root,
            event_root,
            beacon_seed,
            proposer,
            time,
            extra_data,
        })
    }
}

impl Encode for Header {
    fn encode(&self, encoder: &mut Encoder) {
        self.height.encode(encoder);
        put_root(encoder, &self.parent_hash);
        put_root(encoder, &self.state_root);
        put_root(encoder, &self.transaction_root);
        put_root(encoder, &self.event_root);
        put_root(encoder, &self.beacon_seed);
        encoder.put_bytes(self.proposer.as_bytes());
        self.time.encode(encoder);
        encoder.put_bytes(&self.extra_data);
    }
}

/// Read a header from a whole byte slice, refusing any trailing bytes.
pub fn header_from_bytes(bytes: &[u8]) -> Result<Header, Error> {
    let mut decoder = Decoder::new(bytes);
    let header = Header::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(header)
}

/// The transaction root of an empty body. It is the sha3 256 hash of the empty
/// input, the fixed value that stands for a block that carries no transactions.
pub fn empty_transaction_root() -> [u8; ROOT_LEN] {
    sha3::sha3_256(&[])
}

/// The sha3 256 hash of a left node followed by a right node.
fn pair_hash(left: &[u8; ROOT_LEN], right: &[u8; ROOT_LEN]) -> [u8; ROOT_LEN] {
    let mut input = [0u8; ROOT_LEN * 2];
    input[..ROOT_LEN].copy_from_slice(left);
    input[ROOT_LEN..].copy_from_slice(right);
    sha3::sha3_256(&input)
}

/// The transaction root over an ordered list of transactions. Each transaction
/// contributes a leaf that is the sha3 256 hash of its canonical encoding. The
/// leaves reduce in pairs under sha3 256 until one value remains. When a level
/// holds an odd number of nodes the last node pairs with a copy of itself. An
/// empty list has the empty transaction root.
pub fn transaction_root(transactions: &[Wrapper]) -> [u8; ROOT_LEN] {
    if transactions.is_empty() {
        return empty_transaction_root();
    }
    let mut level: Vec<[u8; ROOT_LEN]> = transactions
        .iter()
        .map(|transaction| sha3::sha3_256(&to_bytes(transaction)))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut index = 0;
        while index < level.len() {
            let left = level[index];
            let right = if index + 1 < level.len() {
                level[index + 1]
            } else {
                left
            };
            next.push(pair_hash(&left, &right));
            index += 2;
        }
        level = next;
    }
    level[0]
}

/// A block, the header together with the certificate slot and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    header: Header,
    certificate: Vec<u8>,
    body: Vec<Wrapper>,
}

impl Block {
    /// Assemble a block from a header, a certificate slot, and a body.
    pub fn new(header: Header, certificate: Vec<u8>, body: Vec<Wrapper>) -> Self {
        Block {
            header,
            certificate,
            body,
        }
    }

    /// The header of the block.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The aggregated certificate slot, a variable length byte field over the
    /// header.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The body, the ordered list of transaction wrappers.
    pub fn body(&self) -> &[Wrapper] {
        &self.body
    }

    /// The header hash of the block.
    pub fn header_hash(&self) -> [u8; ROOT_LEN] {
        self.header.hash()
    }

    /// The block id, the identifier format render under the block prefix of the
    /// header hash.
    pub fn id(&self) -> String {
        qtv_idfmt::render_block(&self.header.hash())
            .expect("a sha3 256 hash is the fixed digest length")
    }
}

impl Encode for Block {
    fn encode(&self, encoder: &mut Encoder) {
        self.header.encode(encoder);
        encoder.put_bytes(&self.certificate);
        encoder.put_u64(self.body.len() as u64);
        for transaction in &self.body {
            transaction.encode(encoder);
        }
    }
}
