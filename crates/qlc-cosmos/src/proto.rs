// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub const PRECOMMIT_TYPE: u32 = 2;

pub fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
}

fn field_varint(out: &mut Vec<u8>, tag: u8, value: u64) {
    out.push(tag);
    put_varint(out, value);
}

fn field_fixed64(out: &mut Vec<u8>, tag: u8, value: u64) {
    out.push(tag);
    out.extend_from_slice(&value.to_le_bytes());
}

fn field_len_delim(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockId {
    pub hash: Vec<u8>,
    pub part_total: u32,
    pub part_hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalVote {
    pub vote_type: u32,
    pub height: i64,
    pub round: i64,
    pub block_id: BlockId,
    pub timestamp: Timestamp,
    pub chain_id: String,
}

pub fn encode_timestamp(ts: &Timestamp) -> Vec<u8> {
    let mut b = Vec::new();
    if ts.seconds != 0 {
        field_varint(&mut b, 0x08, ts.seconds as u64);
    }
    if ts.nanos != 0 {
        field_varint(&mut b, 0x10, ts.nanos as u64);
    }
    b
}

fn encode_part_set_header(total: u32, hash: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    if total != 0 {
        field_varint(&mut b, 0x08, total as u64);
    }
    if !hash.is_empty() {
        field_len_delim(&mut b, 0x12, hash);
    }
    b
}

pub fn encode_block_id(bid: &BlockId) -> Vec<u8> {
    let mut b = Vec::new();
    if !bid.hash.is_empty() {
        field_len_delim(&mut b, 0x0a, &bid.hash);
    }
    let psh = encode_part_set_header(bid.part_total, &bid.part_hash);
    field_len_delim(&mut b, 0x12, &psh);
    b
}

pub fn encode_canonical_vote(vote: &CanonicalVote) -> Vec<u8> {
    let mut b = Vec::new();
    if vote.vote_type != 0 {
        field_varint(&mut b, 0x08, vote.vote_type as u64);
    }
    if vote.height != 0 {
        field_fixed64(&mut b, 0x11, vote.height as u64);
    }
    if vote.round != 0 {
        field_fixed64(&mut b, 0x19, vote.round as u64);
    }
    let bid = encode_block_id(&vote.block_id);
    field_len_delim(&mut b, 0x22, &bid);
    let ts = encode_timestamp(&vote.timestamp);
    field_len_delim(&mut b, 0x2a, &ts);
    if !vote.chain_id.is_empty() {
        field_len_delim(&mut b, 0x32, vote.chain_id.as_bytes());
    }
    b
}

pub fn vote_sign_bytes(vote: &CanonicalVote) -> Vec<u8> {
    let inner = encode_canonical_vote(vote);
    let mut out = Vec::with_capacity(inner.len() + 2);
    put_varint(&mut out, inner.len() as u64);
    out.extend_from_slice(&inner);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CanonicalVote {
        CanonicalVote {
            vote_type: PRECOMMIT_TYPE,
            height: 9_000_000,
            round: 0,
            block_id: BlockId {
                hash: vec![0x11u8; 32],
                part_total: 1,
                part_hash: vec![0x22u8; 32],
            },
            timestamp: Timestamp {
                seconds: 1_600_000_000,
                nanos: 12345,
            },
            chain_id: "cosmoshub-4".to_string(),
        }
    }

    #[test]
    fn varints_match_the_protobuf_vectors() {
        let mut a = Vec::new();
        put_varint(&mut a, 1);
        assert_eq!(a, vec![0x01]);
        let mut b = Vec::new();
        put_varint(&mut b, 127);
        assert_eq!(b, vec![0x7f]);
        let mut c = Vec::new();
        put_varint(&mut c, 128);
        assert_eq!(c, vec![0x80, 0x01]);
        let mut d = Vec::new();
        put_varint(&mut d, 300);
        assert_eq!(d, vec![0xac, 0x02]);
    }

    #[test]
    fn the_sign_bytes_are_length_prefixed() {
        let v = sample();
        let inner = encode_canonical_vote(&v);
        let signed = vote_sign_bytes(&v);
        let mut expect = Vec::new();
        put_varint(&mut expect, inner.len() as u64);
        expect.extend_from_slice(&inner);
        assert_eq!(signed, expect);
    }

    #[test]
    fn height_is_carried_as_eight_little_endian_bytes() {
        let v = sample();
        let bytes = encode_canonical_vote(&v);
        let mut needle = vec![0x11u8];
        needle.extend_from_slice(&9_000_000u64.to_le_bytes());
        assert!(bytes.windows(needle.len()).any(|w| w == needle.as_slice()));
    }

    #[test]
    fn a_zero_round_is_omitted_but_a_nonzero_round_is_present() {
        let mut v = sample();
        let without = encode_canonical_vote(&v);
        v.round = 3;
        let with = encode_canonical_vote(&v);
        assert!(with.len() > without.len());
        assert!(!without.contains(&0x19));
        assert!(with.contains(&0x19));
    }

    #[test]
    fn every_signed_field_changes_the_sign_bytes() {
        let base = vote_sign_bytes(&sample());

        let mut a = sample();
        a.height += 1;
        assert_ne!(vote_sign_bytes(&a), base);

        let mut b = sample();
        b.block_id.hash[0] ^= 0xff;
        assert_ne!(vote_sign_bytes(&b), base);

        let mut c = sample();
        c.chain_id = "osmosis-1".to_string();
        assert_ne!(vote_sign_bytes(&c), base);

        let mut d = sample();
        d.timestamp.nanos += 1;
        assert_ne!(vote_sign_bytes(&d), base);

        let mut e = sample();
        e.vote_type = 1;
        assert_ne!(vote_sign_bytes(&e), base);
    }
}
