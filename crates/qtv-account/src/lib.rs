// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


#![forbid(unsafe_code)]

use qtv_crypto::{ml_dsa, sha3, slh_dsa};
use zeroize::Zeroize;

pub const SCHEME_LATTICE: u8 = 1;

pub const SCHEME_HASH: u8 = 2;

pub const SCHEME_FALCON: u8 = 3;

pub const MASTER_SEED_LEN: usize = 32;
pub const SEED_LEN: usize = 32;
pub const CANONICAL_LEN: usize = 32;

pub fn account_seed(master_seed: &[u8; MASTER_SEED_LEN], scheme: u8, index: u64) -> [u8; SEED_LEN] {
    let mut input = Vec::with_capacity(MASTER_SEED_LEN + 1 + 8);
    input.extend_from_slice(master_seed);
    input.push(scheme);
    input.extend_from_slice(&index.to_le_bytes());
    let mut seed = [0u8; SEED_LEN];
    sha3::shake256(&input, &mut seed);
    seed
}

const HASH_SEED_LEN: usize = slh_dsa::PUBLIC_KEY_BYTES / 2;

pub fn hash_keypair(
    seed: &[u8; SEED_LEN],
) -> (
    [u8; slh_dsa::SECRET_KEY_BYTES],
    [u8; slh_dsa::PUBLIC_KEY_BYTES],
) {
    let mut material = [0u8; 3 * HASH_SEED_LEN];
    sha3::shake256(seed, &mut material);
    let mut sk_seed = [0u8; HASH_SEED_LEN];
    let mut sk_prf = [0u8; HASH_SEED_LEN];
    let mut pk_seed = [0u8; HASH_SEED_LEN];
    sk_seed.copy_from_slice(&material[..HASH_SEED_LEN]);
    sk_prf.copy_from_slice(&material[HASH_SEED_LEN..2 * HASH_SEED_LEN]);
    pk_seed.copy_from_slice(&material[2 * HASH_SEED_LEN..]);
    slh_dsa::keygen(&sk_seed, &sk_prf, &pk_seed)
}

fn address_hash(scheme: u8, public_key: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + public_key.len());
    input.push(scheme);
    input.extend_from_slice(public_key);
    sha3::sha3_256(&input)
}

pub fn address_for_key(scheme: u8, public_key: &[u8]) -> String {
    let hash = address_hash(scheme, public_key);
    qtv_idfmt::render_address(&hash).expect("a full address hash reaches the key floor")
}

#[derive(Clone)]
pub struct Account {
    scheme: u8,
    index: u64,
    seed: [u8; SEED_LEN],
    public_key: Vec<u8>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("scheme", &self.scheme)
            .field("index", &self.index)
            .field("seed", &"[redacted]")
            .field("public_key_len", &self.public_key.len())
            .finish()
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        // The per account seed is the one secret this type holds, so wipe it when the
        // account goes out of scope rather than leave it in freed memory for a later read.
        // The scheme, the index, and the public key are not secret and are left alone.
        self.seed.zeroize();
    }
}

impl Account {
    pub fn scheme(&self) -> u8 {
        self.scheme
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn address(&self) -> String {
        address_for_key(self.scheme, &self.public_key)
    }

    pub fn secret_export(&self) -> String {
        qtv_idfmt::render_secret(&self.seed).expect("an account seed reaches the key floor")
    }
}

pub fn derive(master_seed: &[u8; MASTER_SEED_LEN], index: u64) -> Account {
    derive_with_scheme(master_seed, SCHEME_LATTICE, index)
}

pub fn derive_with_scheme(master_seed: &[u8; MASTER_SEED_LEN], scheme: u8, index: u64) -> Account {
    let seed = account_seed(master_seed, scheme, index);
    let public_key = match scheme {
        SCHEME_LATTICE => {
            let (public_key, _expanded) = ml_dsa::keygen(&seed);
            public_key.to_vec()
        }
        SCHEME_HASH => {
            let (_secret, public_key) = hash_keypair(&seed);
            public_key.to_vec()
        }
        #[cfg(feature = "fn-dsa")]
        SCHEME_FALCON => {
            #[allow(unused_imports)]
            use qtv_crypto::fn_dsa;
            unimplemented!("fn_dsa key derivation is gated until the standard is final")
        }
        _ => panic!("derive was handed an unknown scheme identifier"),
    };
    Account {
        scheme,
        index,
        seed,
        public_key,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    from: String,
    to: String,
}

impl Binding {
    pub fn from(&self) -> &str {
        &self.from
    }

    pub fn to(&self) -> &str {
        &self.to
    }
}

#[derive(Debug, Clone)]
pub struct Rotation {
    next: Account,
    binding: Binding,
}

impl Rotation {
    pub fn next(&self) -> &Account {
        &self.next
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }
}

pub fn rotate(master_seed: &[u8; MASTER_SEED_LEN], current: &Account, next_index: u64) -> Rotation {
    let next = derive(master_seed, next_index);
    let binding = Binding {
        from: current.address(),
        to: next.address(),
    };
    Rotation { next, binding }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_seed() {
        let account = derive(&[7u8; MASTER_SEED_LEN], 0);
        let shown = format!("{account:?}");
        assert!(shown.contains("[redacted]"), "seed must be redacted: {shown}");
        assert!(!shown.contains("seed: ["), "seed must never print as bytes: {shown}");
    }
}
