// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

pub const RATE: usize = 136;
const DOMAIN_SUFFIX: u8 = 0x06;
const SHAKE_DOMAIN_SUFFIX: u8 = 0x1f;

fn keccak_f(state: &mut [u64; 25]) {
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        let mut current = state[1];
        for i in 0..24 {
            let j = PI[i];
            let temp = state[j];
            state[j] = current.rotate_left(RHO[i]);
            current = temp;
        }

        for y in 0..5 {
            let mut t = [0u64; 5];
            for x in 0..5 {
                t[x] = state[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        state[0] ^= rc;
    }
}

fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    for k in 0..(RATE / 8) {
        let mut lane = [0u8; 8];
        lane.copy_from_slice(&block[k * 8..k * 8 + 8]);
        state[k] ^= u64::from_le_bytes(lane);
    }
    keccak_f(state);
}

pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let mut i = 0;
    while i + RATE <= input.len() {
        absorb_block(&mut state, &input[i..i + RATE]);
        i += RATE;
    }

    let mut block = [0u8; RATE];
    let rem = &input[i..];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] ^= DOMAIN_SUFFIX;
    block[RATE - 1] ^= 0x80;
    absorb_block(&mut state, &block);

    let mut out = [0u8; 32];
    for k in 0..4 {
        out[k * 8..k * 8 + 8].copy_from_slice(&state[k].to_le_bytes());
    }
    out
}

pub fn shake256_256(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let mut i = 0;
    while i + RATE <= input.len() {
        absorb_block(&mut state, &input[i..i + RATE]);
        i += RATE;
    }

    let mut block = [0u8; RATE];
    let rem = &input[i..];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] ^= SHAKE_DOMAIN_SUFFIX;
    block[RATE - 1] ^= 0x80;
    absorb_block(&mut state, &block);

    let mut out = [0u8; 32];
    for k in 0..4 {
        out[k * 8..k * 8 + 8].copy_from_slice(&state[k].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn empty_input_matches_the_nist_known_answer() {
        assert_eq!(
            to_hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn abc_matches_the_nist_known_answer() {
        assert_eq!(
            to_hex(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn a_rate_boundary_length_matches_the_nist_known_answer() {
        let full = vec![0x61u8; RATE];
        assert_eq!(
            to_hex(&sha3_256(&full)),
            "3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1"
        );
        let short = vec![0x61u8; RATE - 1];
        assert_eq!(
            to_hex(&sha3_256(&short)),
            "8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9"
        );
    }

    #[test]
    fn the_digest_is_deterministic() {
        let a = sha3_256(b"quantova");
        let b = sha3_256(b"quantova");
        assert_eq!(a, b);
    }

    #[test]
    fn a_single_flipped_input_bit_changes_the_digest() {
        let a = sha3_256(b"quantova");
        let b = sha3_256(b"quantovb");
        assert_ne!(a, b);
    }

    #[test]
    fn the_domain_suffix_separates_sha3_from_bare_keccak() {
        let input = b"quantova";
        let mut state = [0u64; 25];
        let mut block = [0u8; RATE];
        block[..input.len()].copy_from_slice(input);
        block[input.len()] ^= 0x01;
        block[RATE - 1] ^= 0x80;
        absorb_block(&mut state, &block);
        let mut keccak_variant = [0u8; 32];
        for k in 0..4 {
            keccak_variant[k * 8..k * 8 + 8].copy_from_slice(&state[k].to_le_bytes());
        }
        assert_ne!(sha3_256(input), keccak_variant);
    }

    #[test]
    fn shake256_256_empty_matches_the_known_answer() {
        assert_eq!(
            to_hex(&shake256_256(b"")),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn shake256_256_abc_matches_the_known_answer() {
        assert_eq!(
            to_hex(&shake256_256(b"abc")),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        );
    }

    #[test]
    fn shake256_256_is_distinct_from_sha3_256() {
        assert_ne!(shake256_256(b"quantova"), sha3_256(b"quantova"));
    }
}
