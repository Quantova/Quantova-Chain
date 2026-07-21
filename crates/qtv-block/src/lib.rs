
#![forbid(unsafe_code)]

use std::fmt;

use qtv_codec::{to_bytes, Decode, Decoder, Encode, Encoder};
use qtv_crypto::sha3;
use qtv_tx::Wrapper;

pub const ROOT_LEN: usize = 32;

pub const MAX_EXTRA_DATA: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Codec(qtv_codec::Error),
    Proposer,
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

fn put_root(encoder: &mut Encoder, root: &[u8; ROOT_LEN]) {
    for &byte in root.iter() {
        encoder.put_u8(byte);
    }
}

fn get_root(decoder: &mut Decoder<'_>) -> Result<[u8; ROOT_LEN], Error> {
    let mut root = [0u8; ROOT_LEN];
    for slot in root.iter_mut() {
        *slot = decoder.get_u8()?;
    }
    Ok(root)
}

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
    extra_data: Vec<u8>,
}

impl Header {
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

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn parent_hash(&self) -> &[u8; ROOT_LEN] {
        &self.parent_hash
    }

    pub fn state_root(&self) -> &[u8; ROOT_LEN] {
        &self.state_root
    }

    pub fn transaction_root(&self) -> &[u8; ROOT_LEN] {
        &self.transaction_root
    }

    pub fn event_root(&self) -> &[u8; ROOT_LEN] {
        &self.event_root
    }

    pub fn beacon_seed(&self) -> &[u8; ROOT_LEN] {
        &self.beacon_seed
    }

    pub fn proposer(&self) -> &str {
        &self.proposer
    }

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn extra_data(&self) -> &[u8] {
        &self.extra_data
    }

    pub fn set_extra_data(&mut self, data: Vec<u8>) -> Result<(), Error> {
        if data.len() > MAX_EXTRA_DATA {
            return Err(Error::ExtraDataTooLong);
        }
        self.extra_data = data;
        Ok(())
    }

    pub fn hash(&self) -> [u8; ROOT_LEN] {
        sha3::sha3_256(&to_bytes(self))
    }

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

pub fn header_from_bytes(bytes: &[u8]) -> Result<Header, Error> {
    let mut decoder = Decoder::new(bytes);
    let header = Header::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(header)
}

pub fn empty_transaction_root() -> [u8; ROOT_LEN] {
    sha3::sha3_256(&[])
}

pub fn event_root(events: &[Vec<u8>]) -> [u8; ROOT_LEN] {
    if events.is_empty() {
        return empty_transaction_root();
    }
    let mut level: Vec<[u8; ROOT_LEN]> = events.iter().map(|event| sha3::sha3_256(event)).collect();
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

fn pair_hash(left: &[u8; ROOT_LEN], right: &[u8; ROOT_LEN]) -> [u8; ROOT_LEN] {
    let mut input = [0u8; ROOT_LEN * 2];
    input[..ROOT_LEN].copy_from_slice(left);
    input[ROOT_LEN..].copy_from_slice(right);
    sha3::sha3_256(&input)
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    header: Header,
    certificate: Vec<u8>,
    body: Vec<Wrapper>,
}

impl Block {
    pub fn new(header: Header, certificate: Vec<u8>, body: Vec<Wrapper>) -> Self {
        Block {
            header,
            certificate,
            body,
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    pub fn body(&self) -> &[Wrapper] {
        &self.body
    }

    pub fn header_hash(&self) -> [u8; ROOT_LEN] {
        self.header.hash()
    }

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
