//! Small shared helpers: lowercase hex, a strict hex decode, and timestamped
//! logging to standard error. The daemon carries no serialization or logging
//! dependency, so these are written here to keep the whole chain graph free of
//! outside crates.

use std::time::{SystemTime, UNIX_EPOCH};

/// Lowercase hex of a byte slice, used for logging state roots and block ids and
/// for the genesis hash a chain id is reported under.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("a nibble is a hex digit"));
        s.push(char::from_digit((b & 0xf) as u32, 16).expect("a nibble is a hex digit"));
    }
    s
}

/// Decode a lowercase or uppercase hex string into bytes, rejecting an odd length
/// or a non hex character with a message rather than a silent truncation, so a
/// mistyped public key in a genesis file is caught at load and never funds the
/// wrong account.
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex has an odd length of {} characters", s.len()));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// One hex digit to its value, or a message naming the offending character.
fn nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("'{}' is not a hex digit", c as char)),
    }
}

/// Log a line to standard error, prefixed with the daemon name and the wall clock
/// seconds since the epoch. The daemon runs unattended, so every material step,
/// each finalised height, a refused peer, a clean shutdown, is written where an
/// operator watching the process can read it.
pub fn log(message: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("[quantovad t={secs}] {message}");
}
