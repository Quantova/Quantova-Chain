//! The single formatting path for every identifier in the Quantova stack.
//!
//! Raw bytes become a Bech32m string carrying a role prefix. Nothing here ever
//! emits Ethereum style hex. Encoding and decoding follow the modern Bech32m
//! standard, meaning the Bech32 base 32 alphabet paired with the Bech32m
//! checksum constant.
//!
//! Each family exposes a render function and a parse function. Render takes the
//! raw bytes and returns the checked string. Parse takes the string and returns
//! the raw bytes, verifying both the checksum and the prefix.

#![forbid(unsafe_code)]

use std::fmt;

/// Human readable part for an account or contract address. The separator that
/// follows a human readable part is the digit one, so an address reads as q1.
pub const HRP_ADDRESS: &str = "q";
/// Human readable part for a secret seed.
pub const HRP_SECRET: &str = "q2";
/// Human readable part for a transaction id.
pub const HRP_TX: &str = "qtx";
/// Human readable part for a block hash.
pub const HRP_BLOCK: &str = "qbk";
/// Human readable part for a state root.
pub const HRP_STATE: &str = "qst";
/// Human readable part for a contract interface digest.
pub const HRP_CID: &str = "qcid";
/// Human readable part for a proof digest.
pub const HRP_PROOF: &str = "qpf";

/// The security floor in bytes for the address and secret families. Every
/// payload is the full 256-bit width, and a shorter one is refused.
pub const KEY_FLOOR: usize = 32;
/// The fixed digest length in bytes for the transaction, block, state,
/// interface, and proof families.
pub const DIGEST_LEN: usize = 32;

/// The Bech32 base 32 alphabet.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// The Bech32m checksum constant from the modern standard.
const BECH32M_CONST: u32 = 0x2bc8_30a3;
/// The five generator coefficients of the Bech32 checksum polynomial.
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// A reason a render or parse step refused its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The payload is shorter than the security floor.
    TooShort {
        /// The floor in bytes.
        min: usize,
        /// The length that was offered.
        got: usize,
    },
    /// The payload is not the required fixed length.
    BadLength {
        /// The required length in bytes.
        expected: usize,
        /// The length that was offered.
        got: usize,
    },
    /// The string carries a prefix other than the one expected.
    WrongPrefix,
    /// The checksum does not verify.
    BadChecksum,
    /// The string holds a character outside the Bech32 alphabet.
    BadChar,
    /// The string mixes upper and lower case.
    MixedCase,
    /// The string lacks a separator.
    NoSeparator,
    /// The data section does not decode to whole bytes.
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

/// The Bech32 checksum polynomial over a run of five bit groups.
fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (bit, coefficient) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                chk ^= coefficient;
            }
        }
    }
    chk
}

/// Expand a human readable part into the five bit groups the checksum folds in.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
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

/// Regroup a byte stream from one bit width to another. When padding is on the
/// tail is zero filled. When padding is off a nonzero tail returns nothing.
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

/// Assemble a Bech32m string from a human readable part and five bit groups.
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

/// Render a payload under a human readable part. The regrouping from eight to
/// five bits with padding is total, so this never fails.
fn render(hrp: &str, payload: &[u8]) -> String {
    let groups =
        convert_bits(payload, 8, 5, true).expect("eight to five padded regrouping is total");
    encode(hrp, &groups)
}

/// Split a Bech32m string, verify its checksum, and return the raw bytes with
/// the human readable part.
fn decode(text: &str) -> Result<(String, Vec<u8>), Error> {
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

/// Parse a Bech32m string and confirm it carries the expected prefix.
fn parse(expected: &str, text: &str) -> Result<Vec<u8>, Error> {
    let (hrp, payload) = decode(text)?;
    if hrp != expected {
        return Err(Error::WrongPrefix);
    }
    Ok(payload)
}

/// Confirm a payload length reaches the key floor.
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

/// Confirm a payload length is exactly the fixed digest length.
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

key_family!(
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
