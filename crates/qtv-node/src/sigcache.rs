// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, OnceLock};

use qtv_crypto::sha3;
use qtv_tx::Wrapper;

const GENERATION: usize = 131_072;

#[derive(Default)]
struct Verified {
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
}

fn verified() -> MutexGuard<'static, Verified> {
    static VERIFIED: OnceLock<Mutex<Verified>> = OnceLock::new();
    VERIFIED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn entry(wrapper: &Wrapper, public_key: &[u8]) -> [u8; 32] {
    let id = wrapper.id_str().as_bytes();
    let mut input = Vec::with_capacity(16 + id.len() + public_key.len());
    input.extend_from_slice(&(id.len() as u64).to_le_bytes());
    input.extend_from_slice(id);
    input.extend_from_slice(&(public_key.len() as u64).to_le_bytes());
    input.extend_from_slice(public_key);
    sha3::sha3_256(&input)
}

pub(crate) fn verify(wrapper: &Wrapper, public_key: &[u8]) -> bool {
    let key = entry(wrapper, public_key);
    {
        let seen = verified();
        if seen.current.contains(&key) || seen.previous.contains(&key) {
            return true;
        }
    }
    let ok = qtv_tx::verify(wrapper, public_key);
    if ok {
        let mut seen = verified();
        if seen.current.len() >= GENERATION {
            seen.previous = std::mem::take(&mut seen.current);
        }
        seen.current.insert(key);
    }
    ok
}
