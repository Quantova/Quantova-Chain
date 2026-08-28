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

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let mut i = 0;
    while i + RATE <= input.len() {
        absorb_block(&mut state, &input[i..i + RATE]);
        i += RATE;
    }

    let mut block = [0u8; RATE];
    let rem = &input[i..];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] ^= 0x01;
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
    fn empty_string_matches_the_known_answer() {
        assert_eq!(
            to_hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn abc_matches_the_known_answer() {
        assert_eq!(
            to_hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn a_block_boundary_length_still_pads_correctly() {
        let long = vec![0x61u8; RATE];
        let once = keccak256(&long);
        let again = keccak256(&long);
        assert_eq!(once, again);
        assert_ne!(to_hex(&once), to_hex(&keccak256(&[0x61u8; RATE - 1])));
    }

    #[test]
    fn a_single_flipped_input_bit_changes_the_digest() {
        let a = keccak256(b"quantova");
        let b = keccak256(b"quantovb");
        assert_ne!(a, b);
    }
}
