// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rlp {
    Bytes(Vec<u8>),
    List(Vec<Rlp>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpError {
    Empty,
    Truncated,
    LeadingZeroLength,
    Trailing,
    OversizeLength,
    NestingTooDeep,
}

pub const MAX_DEPTH: usize = 32;

impl Rlp {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Rlp::Bytes(b) => Some(b),
            Rlp::List(_) => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Rlp]> {
        match self {
            Rlp::List(items) => Some(items),
            Rlp::Bytes(_) => None,
        }
    }
}

fn encode_length(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let be = len.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let len_bytes = &be[start..];
        out.push(offset + 55 + len_bytes.len() as u8);
        out.extend_from_slice(len_bytes);
    }
}

pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        encode_length(bytes.len(), 0x80, &mut out);
        out.extend_from_slice(bytes);
    }
    out
}

pub fn encode_uint(value: u64) -> Vec<u8> {
    if value == 0 {
        return encode_bytes(&[]);
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap();
    encode_bytes(&be[start..])
}

pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    let mut out = Vec::new();
    encode_length(body.len(), 0xc0, &mut out);
    out.extend_from_slice(&body);
    out
}

fn read_length(bytes: &[u8], of_len: usize) -> Result<usize, RlpError> {
    if of_len == 0 || of_len > 8 || of_len > bytes.len() {
        return Err(RlpError::Truncated);
    }
    if bytes[0] == 0 {
        return Err(RlpError::LeadingZeroLength);
    }
    let mut value = 0usize;
    for &b in &bytes[0..of_len] {
        value = value.checked_shl(8).ok_or(RlpError::OversizeLength)? | b as usize;
    }
    Ok(value)
}

fn decode_item(bytes: &[u8], depth: usize) -> Result<(Rlp, usize), RlpError> {
    if bytes.is_empty() {
        return Err(RlpError::Empty);
    }
    let prefix = bytes[0];
    if prefix < 0x80 {
        Ok((Rlp::Bytes(vec![prefix]), 1))
    } else if prefix < 0xb8 {
        let len = (prefix - 0x80) as usize;
        let end = 1 + len;
        if end > bytes.len() {
            return Err(RlpError::Truncated);
        }
        Ok((Rlp::Bytes(bytes[1..end].to_vec()), end))
    } else if prefix < 0xc0 {
        let of_len = (prefix - 0xb7) as usize;
        let len = read_length(&bytes[1..], of_len)?;
        let start = 1 + of_len;
        let end = start.checked_add(len).ok_or(RlpError::OversizeLength)?;
        if end > bytes.len() {
            return Err(RlpError::Truncated);
        }
        Ok((Rlp::Bytes(bytes[start..end].to_vec()), end))
    } else if prefix < 0xf8 {
        let len = (prefix - 0xc0) as usize;
        let start = 1;
        let end = start + len;
        if end > bytes.len() {
            return Err(RlpError::Truncated);
        }
        let items = decode_list_body(&bytes[start..end], depth)?;
        Ok((Rlp::List(items), end))
    } else {
        let of_len = (prefix - 0xf7) as usize;
        let len = read_length(&bytes[1..], of_len)?;
        let start = 1 + of_len;
        let end = start.checked_add(len).ok_or(RlpError::OversizeLength)?;
        if end > bytes.len() {
            return Err(RlpError::Truncated);
        }
        let items = decode_list_body(&bytes[start..end], depth)?;
        Ok((Rlp::List(items), end))
    }
}

fn decode_list_body(mut bytes: &[u8], depth: usize) -> Result<Vec<Rlp>, RlpError> {
    if depth >= MAX_DEPTH {
        return Err(RlpError::NestingTooDeep);
    }
    let mut items = Vec::new();
    while !bytes.is_empty() {
        let (item, used) = decode_item(bytes, depth + 1)?;
        items.push(item);
        bytes = &bytes[used..];
    }
    Ok(items)
}

pub fn decode(bytes: &[u8]) -> Result<Rlp, RlpError> {
    let (item, used) = decode_item(bytes, 0)?;
    if used != bytes.len() {
        return Err(RlpError::Trailing);
    }
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_past_the_limit_is_refused_rather_than_overflowing_the_stack() {
        let mut deep = encode_bytes(&[0u8]);
        for _ in 0..MAX_DEPTH + 8 {
            deep = encode_list(&[deep]);
        }
        assert!(
            matches!(decode(&deep), Err(RlpError::NestingTooDeep)),
            "a validly encoded but over deep list must be refused, not recurse into a stack overflow"
        );
    }

    #[test]
    fn decode_never_panics_on_hostile_bytes() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut rng = || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        for _ in 0..200_000 {
            let len = (rng() % 500) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((rng() & 0xff) as u8);
            }
            let _ = decode(&buf);
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn a_short_string_encodes_with_the_known_prefix() {
        assert_eq!(to_hex(&encode_bytes(b"dog")), "83646f67");
    }

    #[test]
    fn an_empty_string_is_a_single_byte() {
        assert_eq!(to_hex(&encode_bytes(b"")), "80");
    }

    #[test]
    fn a_single_low_byte_is_itself() {
        assert_eq!(to_hex(&encode_bytes(&[0x0f])), "0f");
    }

    #[test]
    fn a_two_element_list_matches_the_known_vector() {
        let cat = encode_bytes(b"cat");
        let dog = encode_bytes(b"dog");
        assert_eq!(to_hex(&encode_list(&[cat, dog])), "c88363617483646f67");
    }

    #[test]
    fn the_index_zero_key_encodes_to_the_empty_string_byte() {
        assert_eq!(to_hex(&encode_uint(0)), "80");
        assert_eq!(to_hex(&encode_uint(1)), "01");
        assert_eq!(to_hex(&encode_uint(127)), "7f");
        assert_eq!(to_hex(&encode_uint(128)), "8180");
        assert_eq!(to_hex(&encode_uint(1024)), "820400");
    }

    #[test]
    fn a_long_string_uses_a_length_prefix() {
        let data = vec![0x61u8; 60];
        let encoded = encode_bytes(&data);
        assert_eq!(encoded[0], 0xb8);
        assert_eq!(encoded[1], 60);
        assert_eq!(decode(&encoded).unwrap(), Rlp::Bytes(data));
    }

    #[test]
    fn decode_round_trips_a_nested_list() {
        let inner = encode_list(&[encode_bytes(b"a"), encode_bytes(b"bb")]);
        let outer = encode_list(&[inner, encode_bytes(&[0xff])]);
        let decoded = decode(&outer).unwrap();
        let items = decoded.as_list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_list().unwrap().len(), 2);
        assert_eq!(items[1].as_bytes().unwrap(), &[0xff]);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = encode_bytes(b"dog");
        encoded.push(0x00);
        assert_eq!(decode(&encoded), Err(RlpError::Trailing));
    }

    #[test]
    fn a_truncated_string_is_rejected() {
        assert_eq!(decode(&[0x83, 0x64, 0x6f]), Err(RlpError::Truncated));
    }

    #[test]
    fn deeply_nested_lists_are_refused_rather_than_overflowing_the_stack() {
        let mut deep = encode_bytes(b"");
        for _ in 0..MAX_DEPTH + 64 {
            deep = encode_list(&[deep]);
        }
        assert_eq!(
            decode(&deep),
            Err(RlpError::NestingTooDeep),
            "a nesting past the depth bound must be refused, not recursed"
        );
    }

    #[test]
    fn nesting_up_to_the_bound_still_decodes() {
        let mut encoded = encode_bytes(b"leaf");
        for _ in 0..MAX_DEPTH - 1 {
            encoded = encode_list(&[encoded]);
        }
        assert!(
            decode(&encoded).is_ok(),
            "real receipt and trie nesting sits far under the bound"
        );
    }
}
