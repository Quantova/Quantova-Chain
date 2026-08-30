// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::fmt;

pub const LENGTH_WIDTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated { needed: usize, found: usize },
    LengthOverrun { length: u64, found: usize },
    TrailingBytes { count: usize },
    InvalidOption { byte: u8 },
    UnknownTag { tag: u8 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { needed, found } => {
                write!(
                    f,
                    "a read of {needed} bytes ran past the {found} bytes that remain"
                )
            }
            Error::LengthOverrun { length, found } => {
                write!(
                    f,
                    "a byte string of {length} bytes overruns the {found} bytes that remain"
                )
            }
            Error::TrailingBytes { count } => {
                write!(f, "the input held {count} bytes after the last field")
            }
            Error::InvalidOption { byte } => {
                write!(f, "an optional value carried the leading byte {byte}")
            }
            Error::UnknownTag { tag } => {
                write!(f, "a tagged value carried the unknown tag {tag}")
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Encoder { buf: Vec::new() }
    }

    pub fn with_buffer(buf: Vec<u8>) -> Self {
        Encoder { buf }
    }

    pub fn put_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn put_u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn put_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn put_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn put_u128(&mut self, value: u128) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn put_bytes(&mut self, bytes: &[u8]) {
        self.put_u64(bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
    }

    pub fn put_tag(&mut self, tag: u8) {
        self.buf.push(tag);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Decoder { input, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated {
            needed: n,
            found: self.remaining(),
        })?;
        if end > self.input.len() {
            return Err(Error::Truncated {
                needed: n,
                found: self.remaining(),
            });
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn get_u8(&mut self) -> Result<u8, Error> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    pub fn get_u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes(
            bytes.try_into().expect("take yields two bytes"),
        ))
    }

    pub fn get_u32(&mut self) -> Result<u32, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("take yields four bytes"),
        ))
    }

    pub fn get_u64(&mut self) -> Result<u64, Error> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("take yields eight bytes"),
        ))
    }

    pub fn get_u128(&mut self) -> Result<u128, Error> {
        let bytes = self.take(16)?;
        Ok(u128::from_le_bytes(
            bytes.try_into().expect("take yields sixteen bytes"),
        ))
    }

    pub fn get_bytes(&mut self) -> Result<&'a [u8], Error> {
        let length = self.get_u64()?;
        if length > self.remaining() as u64 {
            return Err(Error::LengthOverrun {
                length,
                found: self.remaining(),
            });
        }
        self.take(length as usize)
    }

    pub fn get_tag(&mut self) -> Result<u8, Error> {
        self.get_u8()
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes {
                count: self.remaining(),
            })
        }
    }
}

pub trait Encode {
    fn encode(&self, encoder: &mut Encoder);
}

pub trait Decode: Sized {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error>;
}

macro_rules! integer_codec {
    ($ty:ty, $put:ident, $get:ident) => {
        impl Encode for $ty {
            fn encode(&self, encoder: &mut Encoder) {
                encoder.$put(*self);
            }
        }

        impl Decode for $ty {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
                decoder.$get()
            }
        }
    };
}

integer_codec!(u8, put_u8, get_u8);
integer_codec!(u16, put_u16, get_u16);
integer_codec!(u32, put_u32, get_u32);
integer_codec!(u64, put_u64, get_u64);
integer_codec!(u128, put_u128, get_u128);

impl Encode for Vec<u8> {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_bytes(self);
    }
}

impl Decode for Vec<u8> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(decoder.get_bytes()?.to_vec())
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            None => encoder.put_u8(0),
            Some(value) => {
                encoder.put_u8(1);
                value.encode(encoder);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        match decoder.get_u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(decoder)?)),
            byte => Err(Error::InvalidOption { byte }),
        }
    }
}

pub fn to_bytes<T: Encode>(value: &T) -> Vec<u8> {
    let mut encoder = Encoder::new();
    value.encode(&mut encoder);
    encoder.into_bytes()
}

pub fn from_bytes<T: Decode>(input: &[u8]) -> Result<T, Error> {
    let mut decoder = Decoder::new(input);
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}
