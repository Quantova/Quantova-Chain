// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


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
    q_root: [u8; ROOT_LEN],
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
        q_root: [u8; ROOT_LEN],
        transaction_root: [u8; ROOT_LEN],
        event_root: [u8; ROOT_LEN],
        beacon_seed: [u8; ROOT_LEN],
        proposer: String,
        time: u64,
    ) -> Self {
        Header {
            height,
            parent_hash,
            q_root,
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

    pub fn q_root(&self) -> &[u8; ROOT_LEN] {
        &self.q_root
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
        let q_root = get_root(decoder)?;
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
            q_root,
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
        put_root(encoder, &self.q_root);
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

const MERKLE_LEAF_DOMAIN: u8 = 0x00;
const MERKLE_NODE_DOMAIN: u8 = 0x01;

pub fn event_root(events: &[Vec<u8>]) -> [u8; ROOT_LEN] {
    if events.is_empty() {
        return empty_transaction_root();
    }
    let leaves: Vec<[u8; ROOT_LEN]> = events.iter().map(|event| leaf_hash(event)).collect();
    merkle_root(&leaves)
}

pub fn transaction_root(transactions: &[Wrapper]) -> [u8; ROOT_LEN] {
    if transactions.is_empty() {
        return empty_transaction_root();
    }
    let leaves: Vec<[u8; ROOT_LEN]> = transactions
        .iter()
        .map(|transaction| leaf_hash(&to_bytes(transaction)))
        .collect();
    merkle_root(&leaves)
}

// A leaf hash carries a leading leaf domain byte and an internal node a leading
// node domain byte, so no leaf hash can ever equal an internal node hash and a
// crafted transaction can never be reinterpreted as a subtree of two children.
fn leaf_hash(data: &[u8]) -> [u8; ROOT_LEN] {
    let mut input = Vec::with_capacity(1 + data.len());
    input.push(MERKLE_LEAF_DOMAIN);
    input.extend_from_slice(data);
    sha3::sha3_256(&input)
}

fn pair_hash(left: &[u8; ROOT_LEN], right: &[u8; ROOT_LEN]) -> [u8; ROOT_LEN] {
    let mut input = [0u8; 1 + ROOT_LEN * 2];
    input[0] = MERKLE_NODE_DOMAIN;
    input[1..1 + ROOT_LEN].copy_from_slice(left);
    input[1 + ROOT_LEN..].copy_from_slice(right);
    sha3::sha3_256(&input)
}

// The tree splits at the largest power of two below the leaf count, the RFC 6962
// rule, so its shape is fixed by the count alone. A leaf left without a sibling is
// carried up as a subtree of its own rather than paired with a copy of itself, so
// repeating the final leaf can no longer forge a second body with the same root.
fn merkle_root(leaves: &[[u8; ROOT_LEN]]) -> [u8; ROOT_LEN] {
    match leaves.len() {
        0 => empty_transaction_root(),
        1 => leaves[0],
        n => {
            let split = largest_power_of_two_below(n);
            let left = merkle_root(&leaves[..split]);
            let right = merkle_root(&leaves[split..]);
            pair_hash(&left, &right)
        }
    }
}

fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n >= 2, "the split rule is only called on two or more leaves");
    let mut split = 1;
    while split << 1 < n {
        split <<= 1;
    }
    split
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleStep {
    pub sibling: [u8; ROOT_LEN],
    pub sibling_on_left: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MerkleProof {
    pub steps: Vec<MerkleStep>,
}

impl MerkleProof {
    pub fn encode(&self, encoder: &mut Encoder) {
        encoder.put_u64(self.steps.len() as u64);
        for step in &self.steps {
            put_root(encoder, &step.sibling);
            encoder.put_u8(u8::from(step.sibling_on_left));
        }
    }

    pub fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let count = u64::decode(decoder)?;
        let mut steps = Vec::new();
        for _ in 0..count {
            let sibling = get_root(decoder)?;
            let sibling_on_left = match decoder.get_u8()? {
                0 => false,
                1 => true,
                byte => return Err(Error::Codec(qtv_codec::Error::InvalidOption { byte })),
            };
            steps.push(MerkleStep {
                sibling,
                sibling_on_left,
            });
        }
        Ok(MerkleProof { steps })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder);
        encoder.into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        let proof = MerkleProof::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(proof)
    }
}

pub fn prove_inclusion(events: &[Vec<u8>], index: usize) -> Option<MerkleProof> {
    if index >= events.len() {
        return None;
    }
    let leaves: Vec<[u8; ROOT_LEN]> = events.iter().map(|event| leaf_hash(event)).collect();
    let mut steps = Vec::new();
    collect_steps(&leaves, index, &mut steps);
    Some(MerkleProof { steps })
}

fn collect_steps(leaves: &[[u8; ROOT_LEN]], index: usize, steps: &mut Vec<MerkleStep>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let split = largest_power_of_two_below(n);
    if index < split {
        collect_steps(&leaves[..split], index, steps);
        steps.push(MerkleStep {
            sibling: merkle_root(&leaves[split..]),
            sibling_on_left: false,
        });
    } else {
        collect_steps(&leaves[split..], index - split, steps);
        steps.push(MerkleStep {
            sibling: merkle_root(&leaves[..split]),
            sibling_on_left: true,
        });
    }
}

pub fn verify_inclusion(root: &[u8; ROOT_LEN], event: &[u8], proof: &MerkleProof) -> bool {
    let mut acc = leaf_hash(event);
    for step in &proof.steps {
        acc = if step.sibling_on_left {
            pair_hash(&step.sibling, &acc)
        } else {
            pair_hash(&acc, &step.sibling)
        };
    }
    &acc == root
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

#[cfg(test)]
mod merkle_tests {
    use super::*;

    fn event(byte: u8) -> Vec<u8> {
        vec![byte; 8]
    }

    #[test]
    fn duplicating_the_final_event_no_longer_reproduces_the_root() {
        let three = vec![event(1), event(2), event(3)];
        let with_repeat = vec![event(1), event(2), event(3), event(3)];
        assert_ne!(event_root(&three), event_root(&with_repeat));
    }

    #[test]
    fn a_leaf_preimage_can_never_equal_an_internal_node() {
        let left = leaf_hash(&event(1));
        let right = leaf_hash(&event(2));
        let node = pair_hash(&left, &right);
        let mut forged = Vec::new();
        forged.extend_from_slice(&left);
        forged.extend_from_slice(&right);
        assert_ne!(leaf_hash(&forged), node);
    }

    #[test]
    fn reordering_the_events_changes_the_root() {
        let forward = vec![event(1), event(2), event(3)];
        let reversed = vec![event(3), event(2), event(1)];
        assert_ne!(event_root(&forward), event_root(&reversed));
    }

    #[test]
    fn the_root_is_deterministic_for_a_fixed_ordered_set() {
        let events = vec![event(9), event(8), event(7), event(6), event(5)];
        assert_eq!(event_root(&events), event_root(&events));
    }

    #[test]
    fn the_empty_root_differs_from_every_leaf_and_every_node() {
        let empty = empty_transaction_root();
        let left = leaf_hash(&event(1));
        let right = leaf_hash(&event(2));
        assert_ne!(empty, left);
        assert_ne!(empty, pair_hash(&left, &right));
    }

    #[test]
    fn the_split_falls_on_the_largest_power_of_two_below_the_count() {
        assert_eq!(largest_power_of_two_below(2), 1);
        assert_eq!(largest_power_of_two_below(3), 2);
        assert_eq!(largest_power_of_two_below(4), 2);
        assert_eq!(largest_power_of_two_below(5), 4);
        assert_eq!(largest_power_of_two_below(9), 8);
    }

    #[test]
    fn every_leaf_proves_inclusion_under_the_root_at_each_count() {
        for count in 1..=9usize {
            let events: Vec<Vec<u8>> = (0..count).map(|i| event(i as u8)).collect();
            let root = event_root(&events);
            for index in 0..count {
                let proof = prove_inclusion(&events, index).expect("a present leaf proves");
                assert!(
                    verify_inclusion(&root, &events[index], &proof),
                    "leaf {index} of {count} verifies under the event root"
                );
            }
        }
    }

    #[test]
    fn a_tampered_leaf_does_not_verify() {
        let events = vec![event(1), event(2), event(3), event(4), event(5)];
        let root = event_root(&events);
        let proof = prove_inclusion(&events, 2).unwrap();
        let mut tampered = events[2].clone();
        tampered[0] ^= 0xff;
        assert!(!verify_inclusion(&root, &tampered, &proof));
    }

    #[test]
    fn a_wrong_branch_does_not_verify() {
        let events = vec![event(1), event(2), event(3), event(4), event(5)];
        let root = event_root(&events);
        let mut proof = prove_inclusion(&events, 2).unwrap();
        proof.steps[0].sibling[0] ^= 0xff;
        assert!(!verify_inclusion(&root, &events[2], &proof));
    }

    #[test]
    fn a_flipped_side_does_not_verify() {
        let events = vec![event(1), event(2), event(3), event(4), event(5)];
        let root = event_root(&events);
        let mut proof = prove_inclusion(&events, 1).unwrap();
        proof.steps[0].sibling_on_left = !proof.steps[0].sibling_on_left;
        assert!(!verify_inclusion(&root, &events[1], &proof));
    }

    #[test]
    fn a_proof_for_one_leaf_does_not_carry_another() {
        let events = vec![event(1), event(2), event(3), event(4), event(5)];
        let root = event_root(&events);
        let proof = prove_inclusion(&events, 2).unwrap();
        assert!(!verify_inclusion(&root, &events[3], &proof));
    }

    #[test]
    fn a_single_leaf_tree_proves_with_an_empty_path() {
        let events = vec![event(7)];
        let root = event_root(&events);
        let proof = prove_inclusion(&events, 0).unwrap();
        assert!(proof.steps.is_empty());
        assert!(verify_inclusion(&root, &events[0], &proof));
    }

    #[test]
    fn an_out_of_range_index_has_no_proof() {
        let events = vec![event(1), event(2)];
        assert!(prove_inclusion(&events, 2).is_none());
    }

    #[test]
    fn the_proof_round_trips_through_its_codec() {
        let events = vec![event(1), event(2), event(3), event(4), event(5)];
        let proof = prove_inclusion(&events, 3).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(MerkleProof::from_bytes(&bytes).unwrap(), proof);
    }
}
