//! Per validator secret material for the node.
//!
//! Every private key a validator uses, its one time sortition tree, its ML-DSA-65
//! attestation signing key, its peer to peer network identity, and its ledger bond
//! and reward account, is derived from one 32 byte secret through domain separated
//! derivations. Nothing is derived from the public validator id, and there is no
//! shared master.
//!
//! The secret is high entropy material the operator generates on their own machine
//! from the operating system CSPRNG and holds in a keystore file they own. It is read
//! on startup and generated on first run when the file is absent. There is no path by
//! which a second party can derive or hold a validator's secret; only the commitments
//! (the sortition Merkle root, the ML-DSA public key, the peer id, and the bond
//! account address) are ever published.
//!
//! FOUNDER DECISION, still open: the mainnet keystore backend, where and how the
//! keystore file is protected at rest (an HSM, an encrypted store, an operator
//! passphrase). This module is the single seam that backend plugs into; today it
//! reads and writes a plain 0600 file, which is the developer default and not the
//! mainnet answer.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use qtv_crypto::sha3::shake256;

/// The length of a validator's root secret in bytes.
pub const SECRET_LEN: usize = 32;

// Domain tag under which the one secret a validator holds is expanded into the seed
// of its ledger bond and reward account. It is distinct from the sortition tree, the
// signing key, and the peer identity domains, so the one secret yields four
// independent derived keys and no derived key or public commitment reveals the
// others or the secret.
const VALIDATOR_ACCOUNT_DOMAIN: &[u8] = b"QORUS/validator-keying/v1/ledger-bond-account";

/// A freshly generated 32 byte secret from the operating system CSPRNG. This is how a
/// validator's secret comes into being on first run: a real random draw the operator
/// alone holds, never a function of any public value.
pub fn generate() -> [u8; SECRET_LEN] {
    let mut secret = [0u8; SECRET_LEN];
    fill_random(&mut secret).expect("the operating system CSPRNG is available");
    secret
}

/// Read the node's own secret from its keystore file, generating it on first run when
/// the file is absent. The secret never leaves the machine that holds this file; a
/// party without the file cannot derive it. This is the whole of a validator's key
/// custody: one file the operator owns, read here and nowhere else.
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

/// Expand a validator's 32 byte secret into the seed of its ledger bond and reward
/// account. The secret is material the validator alone holds; the account seed
/// follows from it by a domain separated SHAKE and never leaves the validator. Only
/// the account address is published, and it reveals neither this seed nor the secret.
pub fn validator_account_seed(secret: &[u8; SECRET_LEN]) -> [u8; SECRET_LEN] {
    const D: usize = VALIDATOR_ACCOUNT_DOMAIN.len();
    let mut buf = [0u8; D + SECRET_LEN];
    buf[..D].copy_from_slice(VALIDATOR_ACCOUNT_DOMAIN);
    buf[D..].copy_from_slice(secret);
    let mut out = [0u8; SECRET_LEN];
    shake256(&buf, &mut out);
    out
}

/// The validator's ledger bond and reward account, derived from its one secret. The
/// account holds the bond genesis seeds and the rewards the validator claims; its
/// signing key follows from the secret alone, so a party knowing only the public id
/// or the public address cannot spend from it.
pub fn validator_account(secret: &[u8; SECRET_LEN]) -> qtv_account::Account {
    qtv_account::derive(&validator_account_seed(secret), 0)
}

/// The published address of the validator's bond and reward account. This is a
/// commitment: it goes into genesis, the roster, and the gateway view, and it carries
/// no secret and cannot be turned back into the seed or the secret behind it.
pub fn validator_address(secret: &[u8; SECRET_LEN]) -> String {
    validator_account(secret).address()
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

// Test and simulation fixtures. A single process that simulates the whole validator
// set, the devnet, the single process node, and the local load test binaries, needs
// every node's secret at once. These helpers hand it a deterministic per index secret
// so a run is reproducible. They are compiled only under `cfg(test)` or the
// `test-fixtures` feature and are absent from a default node build, so no key material
// is ever derived from the public id on any default path. Each fixture secret is an
// independent image of its index, never a shared master expanded by an id.
#[cfg(any(test, feature = "test-fixtures"))]
const FIXTURE_SECRET_DOMAIN: &[u8] = b"QORUS/TEST-ONLY/insecure-node-fixture-secret/v1";

/// A deterministic, per index secret for tests and the single process simulation
/// only. It is a clearly test only fixture, not a production derivation, and cannot be
/// reached from a default node build.
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
