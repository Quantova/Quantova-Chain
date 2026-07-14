//! The canonical codec for the Quantova stack.
//!
//! Every value has exactly one valid encoding. The encoding is deterministic
//! and length delimited. Unsigned integers are fixed width and little endian in
//! their natural width. A byte string carries an explicit fixed width length
//! ahead of its bytes. A structure is the concatenation of its fields in order.
//! An optional value is a single leading byte that is zero for absent or one for
//! present, followed by the value when present. A tagged value is a single tag
//! byte that selects the variant, followed by the variant.
//!
//! A decoder rejects any input that is not the canonical form. It refuses a
//! length that overruns the input, trailing bytes after the last field, an
//! optional leading byte above one, and an unknown tag.

#![forbid(unsafe_code)]

use std::fmt;

/// The fixed width in bytes of the length that prefixes a byte string. The
/// length itself is an unsigned eight byte little endian integer, so any byte
/// string that a machine can hold has a length that fits.
pub const LENGTH_WIDTH: usize = 8;

/// A reason a decode step refused its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A fixed width read reached past the end of the input.
    Truncated {
        /// The number of bytes the read wanted.
        needed: usize,
        /// The number of bytes that were left.
        found: usize,
    },
    /// A byte string declared a length larger than the bytes that remain.
    LengthOverrun {
        /// The length the input declared.
        length: u64,
        /// The number of bytes that were left after the length field.
        found: usize,
    },
    /// The input held more bytes after the last field was read.
    TrailingBytes {
        /// The number of bytes left over.
        count: usize,
    },
    /// An optional value carried a leading byte other than zero or one.
    InvalidOption {
        /// The leading byte that was read.
        byte: u8,
    },
    /// A tagged value carried a tag that names no variant.
    UnknownTag {
        /// The tag byte that was read.
        tag: u8,
    },
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

/// A growing byte buffer that appended encodings write into.
#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Start an encoder over an empty buffer.
    pub fn new() -> Self {
        Encoder { buf: Vec::new() }
    }

    /// Start an encoder that appends onto an existing buffer.
    pub fn with_buffer(buf: Vec<u8>) -> Self {
        Encoder { buf }
    }

    /// Append an unsigned one byte integer.
    pub fn put_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Append an unsigned two byte integer in little endian order.
    pub fn put_u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Append an unsigned four byte integer in little endian order.
    pub fn put_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Append an unsigned eight byte integer in little endian order.
    pub fn put_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Append an unsigned sixteen byte integer in little endian order.
    pub fn put_u128(&mut self, value: u128) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a byte string as a fixed width length followed by its bytes.
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        self.put_u64(bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
    }

    /// Append the tag byte that selects a variant.
    pub fn put_tag(&mut self, tag: u8) {
        self.buf.push(tag);
    }

    /// Borrow the bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Take the buffer that holds the finished encoding.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// A cursor over a byte slice that reads one field at a time.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Start a decoder at the front of an input slice.
    pub fn new(input: &'a [u8]) -> Self {
        Decoder { input, pos: 0 }
    }

    /// The number of bytes that have not been read.
    pub fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Advance over a fixed run of bytes, refusing a run that overruns.
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

    /// Read an unsigned one byte integer.
    pub fn get_u8(&mut self) -> Result<u8, Error> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    /// Read an unsigned two byte integer in little endian order.
    pub fn get_u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes(
            bytes.try_into().expect("take yields two bytes"),
        ))
    }

    /// Read an unsigned four byte integer in little endian order.
    pub fn get_u32(&mut self) -> Result<u32, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("take yields four bytes"),
        ))
    }

    /// Read an unsigned eight byte integer in little endian order.
    pub fn get_u64(&mut self) -> Result<u64, Error> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("take yields eight bytes"),
        ))
    }

    /// Read an unsigned sixteen byte integer in little endian order.
    pub fn get_u128(&mut self) -> Result<u128, Error> {
        let bytes = self.take(16)?;
        Ok(u128::from_le_bytes(
            bytes.try_into().expect("take yields sixteen bytes"),
        ))
    }

    /// Read a byte string, refusing a declared length that overruns the input.
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

    /// Read the tag byte that selects a variant.
    pub fn get_tag(&mut self) -> Result<u8, Error> {
        self.get_u8()
    }

    /// Confirm the whole input was read, refusing any trailing bytes.
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

/// A value that appends its canonical encoding onto an encoder.
pub trait Encode {
    /// Append the canonical encoding of this value.
    fn encode(&self, encoder: &mut Encoder);
}

/// A value that reads its canonical encoding from a decoder.
pub trait Decode: Sized {
    /// Read one value in canonical form, returning an error on any other input.
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

/// Encode one value into a fresh byte buffer.
pub fn to_bytes<T: Encode>(value: &T) -> Vec<u8> {
    let mut encoder = Encoder::new();
    value.encode(&mut encoder);
    encoder.into_bytes()
}

/// Decode one value from a whole byte slice, refusing any trailing bytes.
pub fn from_bytes<T: Decode>(input: &[u8]) -> Result<T, Error> {
    let mut decoder = Decoder::new(input);
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}
