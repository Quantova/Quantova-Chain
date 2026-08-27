// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use qtv_crypto::ml_dsa;
use qtv_crypto::sha3::shake256;

pub const SECRET_LEN: usize = 32;

const VALIDATOR_ACCOUNT_DOMAIN: &[u8] = b"QORUS/validator-keying/v1/ledger-bond-account";

const P2P_IDENTITY_DOMAIN: &[u8] = b"QORUS/validator-keying/v1/p2p-identity";

pub fn generate() -> [u8; SECRET_LEN] {
    let mut secret = [0u8; SECRET_LEN];
    fill_random(&mut secret).expect("the operating system CSPRNG is available");
    secret
}

pub fn load_or_generate(path: &Path) -> io::Result<[u8; SECRET_LEN]> {
    match fs::read_to_string(path) {
        Ok(text) => parse_hex32(text.trim()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "keystore {} must hold exactly 64 hex characters",
                    path.display()
                ),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let secret = generate();
            write_keystore(path, &secret)?;
            Ok(secret)
        }
        Err(error) => Err(error),
    }
}

fn write_keystore(path: &Path, secret: &[u8; SECRET_LEN]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let mut file = open_private(path)?;
    file.write_all(to_hex(secret).as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(unix)]
fn open_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    let mut file = File::open("/dev/urandom")?;
    file.read_exact(buf)
}

pub fn validator_account_seed(secret: &[u8; SECRET_LEN]) -> [u8; SECRET_LEN] {
    const D: usize = VALIDATOR_ACCOUNT_DOMAIN.len();
    let mut buf = [0u8; D + SECRET_LEN];
    buf[..D].copy_from_slice(VALIDATOR_ACCOUNT_DOMAIN);
    buf[D..].copy_from_slice(secret);
    let mut out = [0u8; SECRET_LEN];
    shake256(&buf, &mut out);
    out
}

pub fn validator_account(secret: &[u8; SECRET_LEN]) -> qtv_account::Account {
    qtv_account::derive(&validator_account_seed(secret), 0)
}

pub fn validator_address(secret: &[u8; SECRET_LEN]) -> String {
    validator_account(secret).address()
}

pub fn p2p_identity_seed(secret: &[u8; SECRET_LEN]) -> [u8; SECRET_LEN] {
    const D: usize = P2P_IDENTITY_DOMAIN.len();
    let mut buf = [0u8; D + SECRET_LEN];
    buf[..D].copy_from_slice(P2P_IDENTITY_DOMAIN);
    buf[D..].copy_from_slice(secret);
    let mut out = [0u8; SECRET_LEN];
    shake256(&buf, &mut out);
    out
}

pub fn p2p_public(secret: &[u8; SECRET_LEN]) -> ml_dsa::PublicKey {
    ml_dsa::keygen(&p2p_identity_seed(secret)).0
}

fn parse_hex32(hex: &str) -> Option<[u8; SECRET_LEN]> {
    let hex = hex.trim();
    if hex.len() != SECRET_LEN * 2 {
        return None;
    }
    let mut out = [0u8; SECRET_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn to_hex(bytes: &[u8; SECRET_LEN]) -> String {
    let mut out = String::with_capacity(SECRET_LEN * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(any(test, feature = "test-fixtures"))]
const FIXTURE_SECRET_DOMAIN: &[u8] = b"QORUS/TEST-ONLY/insecure-node-fixture-secret/v1";

#[cfg(any(test, feature = "test-fixtures"))]
pub fn fixture_secret(index: u64) -> [u8; SECRET_LEN] {
    const D: usize = FIXTURE_SECRET_DOMAIN.len();
    let mut buf = [0u8; D + 8];
    buf[..D].copy_from_slice(FIXTURE_SECRET_DOMAIN);
    buf[D..].copy_from_slice(&index.to_le_bytes());
    let mut out = [0u8; SECRET_LEN];
    shake256(&buf, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_secret_is_not_all_zero_and_two_draws_differ() {
        let a = generate();
        let b = generate();
        assert_ne!(a, [0u8; SECRET_LEN], "the CSPRNG returned all zero");
        assert_ne!(a, b, "two independent draws collided");
    }

    #[test]
    fn a_keystore_round_trips_and_is_generated_on_first_run() {
        let dir = std::env::temp_dir().join(format!("qtv-keystore-{}", std::process::id()));
        let path = dir.join("keystore");
        let _ = fs::remove_file(&path);
        let first = load_or_generate(&path).expect("first run generates");
        let second = load_or_generate(&path).expect("second run loads");
        assert_eq!(first, second, "the keystore did not persist the secret");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn the_account_seed_is_not_the_secret_and_is_bound_to_it() {
        let secret = [9u8; SECRET_LEN];
        assert_ne!(validator_account_seed(&secret), secret);
        let other = [10u8; SECRET_LEN];
        assert_ne!(
            validator_account_seed(&secret),
            validator_account_seed(&other)
        );
    }

    #[test]
    fn two_secrets_commit_two_bond_addresses() {
        assert_ne!(
            validator_address(&[1u8; SECRET_LEN]),
            validator_address(&[2u8; SECRET_LEN])
        );
    }

    #[test]
    fn hex_round_trips() {
        let secret = [0xabu8; SECRET_LEN];
        assert_eq!(parse_hex32(&to_hex(&secret)), Some(secret));
        assert_eq!(parse_hex32("zz"), None);
    }
}
