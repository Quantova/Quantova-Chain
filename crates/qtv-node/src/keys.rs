// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use qtv_crypto::ml_dsa;
use qtv_crypto::sha3::shake256;

pub const SECRET_LEN: usize = 32;

const VALIDATOR_ACCOUNT_DOMAIN: &[u8] = b"QORUS/validator-keying/v1/ledger-bond-account";

const P2P_IDENTITY_DOMAIN: &[u8] = b"QORUS/validator-keying/v1/p2p-identity";

pub fn generate() -> io::Result<qtv_wipe::Zeroizing<[u8; SECRET_LEN]>> {
    let mut secret = qtv_wipe::Zeroizing::new([0u8; SECRET_LEN]);
    fill_random(&mut secret[..])?;
    Ok(secret)
}

fn wipe(bytes: &mut [u8]) {
    for slot in bytes.iter_mut() {
        *slot = 0;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let _ = core::hint::black_box(&*bytes);
}

pub const KEYSTORE_PASSPHRASE_ENV: &str = "QTV_KEYSTORE_PASSPHRASE";

pub const KEYSTORE_PASSPHRASE_FILE_ENV: &str = "QTV_KEYSTORE_PASSPHRASE_FILE";

const SEALED_PREFIX: &str = "qks1:";

const SEALED_AAD: &[u8] = b"QORUS/validator-keystore/v1";

const KDF_ROUNDS: u32 = 200_000;

const SALT_LEN: usize = 16;

fn configured_passphrase() -> io::Result<Option<qtv_wipe::Zeroizing<Vec<u8>>>> {
    if let Ok(file) = std::env::var(KEYSTORE_PASSPHRASE_FILE_ENV) {
        let mut raw = fs::read(&file)?;
        let trimmed = raw
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map_or(0, |end| end + 1);
        let pass = qtv_wipe::Zeroizing::new(raw[..trimmed].to_vec());
        wipe(&mut raw);
        return Ok((!pass.is_empty()).then_some(pass));
    }
    Ok(std::env::var(KEYSTORE_PASSPHRASE_ENV)
        .ok()
        .filter(|pass| !pass.is_empty())
        .map(|pass| qtv_wipe::Zeroizing::new(pass.into_bytes())))
}

fn sealing_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> qtv_wipe::Zeroizing<[u8; 32]> {
    let mut input = Vec::with_capacity(SEALED_AAD.len() + SALT_LEN + passphrase.len());
    input.extend_from_slice(SEALED_AAD);
    input.extend_from_slice(salt);
    input.extend_from_slice(passphrase);
    let mut state = qtv_wipe::Zeroizing::new([0u8; 32]);
    qtv_crypto::sha3::shake256(&input, &mut state[..]);
    wipe(&mut input);
    let mut round = [0u8; 32 + SALT_LEN];
    for _ in 0..KDF_ROUNDS {
        round[..32].copy_from_slice(&state[..]);
        round[32..].copy_from_slice(salt);
        qtv_crypto::sha3::shake256(&round, &mut state[..]);
    }
    wipe(&mut round);
    state
}

fn seal_secret(secret: &[u8; SECRET_LEN], passphrase: &[u8]) -> io::Result<String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; qtv_crypto::chacha20poly1305::NONCE_BYTES];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;
    let key = sealing_key(passphrase, &salt);
    let (ciphertext, tag) = qtv_crypto::chacha20poly1305::seal(&key, &nonce, SEALED_AAD, secret)
        .ok_or_else(|| io::Error::other("the keystore could not be sealed"))?;
    let mut blob = Vec::with_capacity(SALT_LEN + nonce.len() + ciphertext.len() + tag.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob.extend_from_slice(&tag);
    let mut text = String::with_capacity(SEALED_PREFIX.len() + blob.len() * 2);
    text.push_str(SEALED_PREFIX);
    for byte in &blob {
        text.push_str(&format!("{byte:02x}"));
    }
    Ok(text)
}

fn open_sealed(hex: &str, passphrase: &[u8]) -> Option<qtv_wipe::Zeroizing<[u8; SECRET_LEN]>> {
    use qtv_crypto::chacha20poly1305::{NONCE_BYTES, TAG_BYTES};
    if hex.len() != 2 * (SALT_LEN + NONCE_BYTES + SECRET_LEN + TAG_BYTES) || !hex.is_ascii() {
        return None;
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    let salt: [u8; SALT_LEN] = bytes[..SALT_LEN].try_into().ok()?;
    let nonce: [u8; NONCE_BYTES] = bytes[SALT_LEN..SALT_LEN + NONCE_BYTES].try_into().ok()?;
    let body = &bytes[SALT_LEN + NONCE_BYTES..bytes.len() - TAG_BYTES];
    let tag: [u8; TAG_BYTES] = bytes[bytes.len() - TAG_BYTES..].try_into().ok()?;
    let key = sealing_key(passphrase, &salt);
    let mut plain = qtv_crypto::chacha20poly1305::open(&key, &nonce, SEALED_AAD, body, &tag)?;
    let secret = <[u8; SECRET_LEN]>::try_from(plain.as_slice())
        .ok()
        .map(qtv_wipe::Zeroizing::new);
    wipe(&mut plain);
    secret
}

pub fn load_or_generate(path: &Path) -> io::Result<qtv_wipe::Zeroizing<[u8; SECRET_LEN]>> {
    let passphrase = configured_passphrase()?;
    load_or_generate_with(path, passphrase.as_deref().map(|p| p.as_slice()))
}

pub fn load_or_generate_with(
    path: &Path,
    passphrase: Option<&[u8]>,
) -> io::Result<qtv_wipe::Zeroizing<[u8; SECRET_LEN]>> {
    match fs::read(path) {
        Ok(mut raw) => {
            if let Err(error) = refuse_shared(path) {
                wipe(&mut raw);
                return Err(error);
            }
            let text = std::str::from_utf8(&raw).ok().map(str::trim);
            if let Some(sealed) = text.and_then(|t| t.strip_prefix(SEALED_PREFIX)) {
                let opened = passphrase.and_then(|pass| open_sealed(sealed, pass));
                wipe(&mut raw);
                return opened.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "keystore {} is sealed and {} or {} does not open it",
                            path.display(),
                            KEYSTORE_PASSPHRASE_ENV,
                            KEYSTORE_PASSPHRASE_FILE_ENV
                        ),
                    )
                });
            }
            let parsed = text.and_then(parse_hex32).map(qtv_wipe::Zeroizing::new);
            wipe(&mut raw);
            parsed.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "keystore {} must hold exactly 64 hex characters",
                        path.display()
                    ),
                )
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let secret = generate()?;
            write_keystore(path, &secret, passphrase)?;
            Ok(secret)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn refuse_shared(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "keystore {} is readable by group or others, restrict it with chmod 600",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_shared(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn write_keystore(
    path: &Path,
    secret: &[u8; SECRET_LEN],
    passphrase: Option<&[u8]>,
) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let mut file = open_private(path)?;
    let mut rendered = match passphrase {
        Some(pass) => seal_secret(secret, pass)?,
        None => to_hex(secret),
    };
    let result = file
        .write_all(rendered.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());
    qtv_wipe::Zeroize::zeroize(&mut rendered);
    result?;
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::File::open(dir)?.sync_all()?;
        }
    }
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
    qtv_crypto::rng::try_fill_random(buf)?;
    Ok(())
}

pub fn validator_account_seed(secret: &[u8; SECRET_LEN]) -> [u8; SECRET_LEN] {
    const D: usize = VALIDATOR_ACCOUNT_DOMAIN.len();
    let mut buf = [0u8; D + SECRET_LEN];
    buf[..D].copy_from_slice(VALIDATOR_ACCOUNT_DOMAIN);
    buf[D..].copy_from_slice(secret);
    let mut out = [0u8; SECRET_LEN];
    shake256(&buf, &mut out);
    wipe(&mut buf);
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
    wipe(&mut buf);
    out
}

pub fn p2p_public(secret: &[u8; SECRET_LEN]) -> ml_dsa::PublicKey {
    ml_dsa::keygen(&p2p_identity_seed(secret)).0
}

fn parse_hex32(hex: &str) -> Option<[u8; SECRET_LEN]> {
    let hex = hex.trim();
    if hex.len() != SECRET_LEN * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; SECRET_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn to_hex(bytes: &[u8; SECRET_LEN]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(SECRET_LEN * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
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
        let a = generate().expect("the operating system CSPRNG is available");
        let b = generate().expect("the operating system CSPRNG is available");
        assert_ne!(*a, [0u8; SECRET_LEN], "the CSPRNG returned all zero");
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

    #[cfg(unix)]
    #[test]
    fn a_keystore_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("qtv-keystore-shared-{}", std::process::id()));
        let path = dir.join("keystore");
        let _ = fs::remove_file(&path);
        load_or_generate(&path).expect("first run generates");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let refused = load_or_generate(&path).expect_err("a shared keystore is refused");
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(load_or_generate(&path).is_ok());
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

    #[test]
    fn a_keystore_with_a_multibyte_character_is_refused_without_a_panic() {
        let text = format!("{}é{}", "a".repeat(31), "b".repeat(31));
        assert_eq!(text.len(), SECRET_LEN * 2);
        assert_eq!(parse_hex32(&text), None);
    }

    #[test]
    fn a_keystore_with_a_sign_character_is_refused() {
        let text = format!("+a{}", "b".repeat(62));
        assert_eq!(parse_hex32(&text), None);
    }
}
