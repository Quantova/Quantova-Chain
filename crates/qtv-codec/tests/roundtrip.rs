// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_codec::{from_bytes, to_bytes, Decode, Decoder, Encode, Encoder, Error};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Header {
    version: u8,
    height: u32,
    weight: u128,
    label: Vec<u8>,
    parent: Option<u64>,
}

impl Encode for Header {
    fn encode(&self, encoder: &mut Encoder) {
        self.version.encode(encoder);
        self.height.encode(encoder);
        self.weight.encode(encoder);
        self.label.encode(encoder);
        self.parent.encode(encoder);
    }
}

impl Decode for Header {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Header {
            version: u8::decode(decoder)?,
            height: u32::decode(decoder)?,
            weight: u128::decode(decoder)?,
            label: Vec::<u8>::decode(decoder)?,
            parent: Option::<u64>::decode(decoder)?,
        })
    }
}

const TAG_PING: u8 = 0;
const TAG_ECHO: u8 = 1;
const TAG_SEQ: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    Ping,
    Echo(Vec<u8>),
    Seq(u64),
}

impl Encode for Frame {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Frame::Ping => encoder.put_tag(TAG_PING),
            Frame::Echo(data) => {
                encoder.put_tag(TAG_ECHO);
                data.encode(encoder);
            }
            Frame::Seq(seq) => {
                encoder.put_tag(TAG_SEQ);
                seq.encode(encoder);
            }
        }
    }
}

impl Decode for Frame {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        match decoder.get_tag()? {
            TAG_PING => Ok(Frame::Ping),
            TAG_ECHO => Ok(Frame::Echo(Vec::<u8>::decode(decoder)?)),
            TAG_SEQ => Ok(Frame::Seq(u64::decode(decoder)?)),
            tag => Err(Error::UnknownTag { tag }),
        }
    }
}

fn sample_header() -> Header {
    Header {
        version: 7,
        height: 4_294_000_111,
        weight: 340_282_000_000_000_000_000_000_000_000_000_009,
        label: vec![9, 8, 7, 6, 5],
        parent: Some(18_446_744_073_709_551_000),
    }
}

#[test]
fn round_trip_u8() {
    let value = 165u8;
    let bytes = to_bytes(&value);
    assert_eq!(bytes.len(), 1);
    assert_eq!(from_bytes::<u8>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_u16() {
    let value = 48879u16;
    let bytes = to_bytes(&value);
    assert_eq!(bytes.len(), 2);
    assert_eq!(from_bytes::<u16>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_u32() {
    let value = 16909060u32;
    let bytes = to_bytes(&value);
    assert_eq!(bytes.len(), 4);
    assert_eq!(from_bytes::<u32>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_u64() {
    let value = 72623859790382856u64;
    let bytes = to_bytes(&value);
    assert_eq!(bytes.len(), 8);
    assert_eq!(from_bytes::<u64>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_u128() {
    let value = 1339673755198158349044581307228491536u128;
    let bytes = to_bytes(&value);
    assert_eq!(bytes.len(), 16);
    assert_eq!(from_bytes::<u128>(&bytes).unwrap(), value);
}

#[test]
fn little_endian_layout() {
    assert_eq!(to_bytes(&258u16), vec![2, 1]);
    assert_eq!(to_bytes(&16909060u32), vec![4, 3, 2, 1]);
}

#[test]
fn round_trip_byte_string() {
    let value = vec![1u8, 2, 3, 4, 5];
    let bytes = to_bytes(&value);
    assert_eq!(bytes.len(), 8 + value.len());
    assert_eq!(from_bytes::<Vec<u8>>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_empty_byte_string() {
    let value = Vec::<u8>::new();
    let bytes = to_bytes(&value);
    assert_eq!(bytes, vec![0u8; 8]);
    assert_eq!(from_bytes::<Vec<u8>>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_option_present() {
    let value = Some(287454020u32);
    let bytes = to_bytes(&value);
    assert_eq!(bytes[0], 1);
    assert_eq!(from_bytes::<Option<u32>>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_option_absent() {
    let value: Option<u32> = None;
    let bytes = to_bytes(&value);
    assert_eq!(bytes, vec![0u8]);
    assert_eq!(from_bytes::<Option<u32>>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_structure() {
    let value = sample_header();
    let bytes = to_bytes(&value);
    assert_eq!(from_bytes::<Header>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_tagged_ping() {
    let value = Frame::Ping;
    let bytes = to_bytes(&value);
    assert_eq!(bytes, vec![TAG_PING]);
    assert_eq!(from_bytes::<Frame>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_tagged_echo() {
    let value = Frame::Echo(vec![222, 173, 190, 239]);
    let bytes = to_bytes(&value);
    assert_eq!(bytes[0], TAG_ECHO);
    assert_eq!(from_bytes::<Frame>(&bytes).unwrap(), value);
}

#[test]
fn round_trip_tagged_seq() {
    let value = Frame::Seq(987_654_321);
    let bytes = to_bytes(&value);
    assert_eq!(bytes[0], TAG_SEQ);
    assert_eq!(from_bytes::<Frame>(&bytes).unwrap(), value);
}

#[test]
fn reject_truncated_integer() {
    let bytes = [1u8, 2];
    assert_eq!(
        from_bytes::<u32>(&bytes),
        Err(Error::Truncated {
            needed: 4,
            found: 2,
        })
    );
}

#[test]
fn reject_truncated_length() {
    let full = to_bytes(&vec![1u8, 2, 3, 4, 5]);
    let cut = &full[..full.len() - 3];
    assert_eq!(
        from_bytes::<Vec<u8>>(cut),
        Err(Error::LengthOverrun {
            length: 5,
            found: 2,
        })
    );
}

#[test]
fn reject_trailing_bytes() {
    let mut bytes = to_bytes(&66u8);
    bytes.push(153);
    assert_eq!(
        from_bytes::<u8>(&bytes),
        Err(Error::TrailingBytes { count: 1 })
    );
}

#[test]
fn reject_option_byte_of_two() {
    let bytes = [2u8];
    assert_eq!(
        from_bytes::<Option<u8>>(&bytes),
        Err(Error::InvalidOption { byte: 2 })
    );
}

#[test]
fn reject_unknown_tag() {
    let bytes = [9u8];
    assert_eq!(
        from_bytes::<Frame>(&bytes),
        Err(Error::UnknownTag { tag: 9 })
    );
}

#[test]
fn encoding_is_byte_identical() {
    let value = sample_header();
    let first = to_bytes(&value);
    let second = to_bytes(&value);
    assert_eq!(first, second);
}

#[test]
fn encoder_appends_onto_a_buffer() {
    let mut encoder = Encoder::with_buffer(vec![170, 187]);
    encoder.put_u8(204);
    assert_eq!(encoder.into_bytes(), vec![170, 187, 204]);
}
