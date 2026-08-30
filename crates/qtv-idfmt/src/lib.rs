// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::fmt;

pub const HRP_ADDRESS: &str = "Q";
pub const HRP_SECRET: &str = "Q2";
pub const HRP_TX: &str = "QTX";
pub const HRP_BLOCK: &str = "QBK";
pub const HRP_STATE: &str = "QST";
pub const HRP_CID: &str = "QCID";
pub const HRP_PROOF: &str = "QPF";

pub const KEY_FLOOR: usize = 32;
pub const DIGEST_LEN: usize = 32;

const MAX_ENCODED: usize = 128;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 734539939;
const GENERATOR: [u32; 5] = [996825010, 642813549, 513874426, 1027748829, 705979059];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooShort { min: usize, got: usize },
    BadLength { expected: usize, got: usize },
    WrongPrefix,
    BadChecksum,
    BadChar,
    MixedCase,
    NoSeparator,
    BadData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooShort { min, got } => {
                write!(
                    f,
                    "payload of {got} bytes falls below the floor of {min} bytes"
                )
            }
            Error::BadLength { expected, got } => {
                write!(
                    f,
                    "payload of {got} bytes is not the required {expected} bytes"
                )
            }
            Error::WrongPrefix => write!(f, "the string carries the wrong prefix"),
            Error::BadChecksum => write!(f, "the checksum does not verify"),
            Error::BadChar => write!(f, "the string holds a character outside the alphabet"),
            Error::MixedCase => write!(f, "the string mixes upper and lower case"),
            Error::NoSeparator => write!(f, "the string lacks a separator"),
            Error::BadData => write!(f, "the data section does not decode to whole bytes"),
        }
    }
}

impl std::error::Error for Error {}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 33554431) << 5) ^ u32::from(value);
        for (bit, coefficient) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                chk ^= coefficient;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let lowered = hrp.to_ascii_lowercase();
    let bytes = lowered.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    for &byte in bytes {
        out.push(byte >> 5);
    }
    out.push(0);
    for &byte in bytes {
        out.push(byte & 31);
    }
    out
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max_value: u32 = (1 << to) - 1;
    let max_acc: u32 = (1 << (from + to - 1)) - 1;
    let mut out = Vec::new();
    for &byte in data {
        let value = u32::from(byte);
        if (value >> from) != 0 {
            return None;
        }
        acc = ((acc << from) | value) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max_value) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max_value) != 0 {
        return None;
    }
    Some(out)
}

fn encode(hrp: &str, data: &[u8]) -> String {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let residue = polymod(&values) ^ BECH32M_CONST;

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &group in data {
        out.push(CHARSET[group as usize] as char);
    }
    for slot in 0..6 {
        let group = (residue >> (5 * (5 - slot))) & 31;
        out.push(CHARSET[group as usize] as char);
    }
    out
}

fn render(hrp: &str, payload: &[u8]) -> String {
    let groups =
        convert_bits(payload, 8, 5, true).expect("eight to five padded regrouping is total");
    encode(hrp, &groups).to_ascii_uppercase()
}

fn decode(text: &str) -> Result<(String, Vec<u8>), Error> {
    if text.len() > MAX_ENCODED {
        return Err(Error::BadLength {
            expected: MAX_ENCODED,
            got: text.len(),
        });
    }
    let has_lower = text.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = text.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Error::MixedCase);
    }

    let lowered = text.to_ascii_lowercase();
    let separator = lowered.rfind('1').ok_or(Error::NoSeparator)?;
    if separator < 1 || separator + 7 > lowered.len() {
        return Err(Error::NoSeparator);
    }

    let hrp = &lowered[..separator];
    for &byte in hrp.as_bytes() {
        if !(33..=126).contains(&byte) {
            return Err(Error::BadChar);
        }
    }

    let body = &lowered[separator + 1..];
    let mut groups = Vec::with_capacity(body.len());
    for byte in body.bytes() {
        let index = CHARSET
            .iter()
            .position(|&symbol| symbol == byte)
            .ok_or(Error::BadChar)?;
        groups.push(index as u8);
    }

    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&groups);
    if polymod(&values) != BECH32M_CONST {
        return Err(Error::BadChecksum);
    }

    let payload_groups = &groups[..groups.len() - 6];
    let payload = convert_bits(payload_groups, 5, 8, false).ok_or(Error::BadData)?;
    Ok((hrp.to_string(), payload))
}

fn parse(expected: &str, text: &str) -> Result<Vec<u8>, Error> {
    let (hrp, payload) = decode(text)?;
    if !hrp.eq_ignore_ascii_case(expected) {
        return Err(Error::WrongPrefix);
    }
    Ok(payload)
}

fn check_floor(len: usize) -> Result<(), Error> {
    if len < KEY_FLOOR {
        Err(Error::TooShort {
            min: KEY_FLOOR,
            got: len,
        })
    } else {
        Ok(())
    }
}

fn check_digest(len: usize) -> Result<(), Error> {
    if len != DIGEST_LEN {
        Err(Error::BadLength {
            expected: DIGEST_LEN,
            got: len,
        })
    } else {
        Ok(())
    }
}

macro_rules! key_family {
    ($render:ident, $parse:ident, $hrp:ident, $what:literal) => {
        #[doc = concat!("Render ", $what, " as a Bech32m string, holding the key floor.")]
        pub fn $render(bytes: &[u8]) -> Result<String, Error> {
            check_floor(bytes.len())?;
            Ok(render($hrp, bytes))
        }

        #[doc = concat!("Parse ", $what, " from a Bech32m string, holding the key floor.")]
        pub fn $parse(text: &str) -> Result<Vec<u8>, Error> {
            let bytes = parse($hrp, text)?;
            check_floor(bytes.len())?;
            Ok(bytes)
        }
    };
}

macro_rules! digest_family {
    ($render:ident, $parse:ident, $hrp:ident, $what:literal) => {
        #[doc = concat!("Render ", $what, " as a Bech32m string over a fixed digest.")]
        pub fn $render(bytes: &[u8]) -> Result<String, Error> {
            check_digest(bytes.len())?;
            Ok(render($hrp, bytes))
        }

        #[doc = concat!("Parse ", $what, " from a Bech32m string over a fixed digest.")]
        pub fn $parse(text: &str) -> Result<Vec<u8>, Error> {
            let bytes = parse($hrp, text)?;
            check_digest(bytes.len())?;
            Ok(bytes)
        }
    };
}

digest_family!(
    render_address,
    parse_address,
    HRP_ADDRESS,
    "an account or contract address"
);
key_family!(render_secret, parse_secret, HRP_SECRET, "a secret seed");
digest_family!(render_tx, parse_tx, HRP_TX, "a transaction id");
digest_family!(render_block, parse_block, HRP_BLOCK, "a block hash");
digest_family!(render_state, parse_state, HRP_STATE, "a state root");
digest_family!(
    render_cid,
    parse_cid,
    HRP_CID,
    "a contract interface digest"
);
digest_family!(render_proof, parse_proof, HRP_PROOF, "a proof digest");
