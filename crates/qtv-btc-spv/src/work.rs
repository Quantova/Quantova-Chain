// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256 {
    limbs: [u64; 4],
}

impl U256 {
    pub const ZERO: U256 = U256 { limbs: [0, 0, 0, 0] };
    pub const ONE: U256 = U256 { limbs: [1, 0, 0, 0] };

    pub fn from_u64(x: u64) -> U256 {
        U256 {
            limbs: [x, 0, 0, 0],
        }
    }

    pub fn from_be_bytes(bytes: &[u8; 32]) -> U256 {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v = (v << 8) | bytes[i * 8 + j] as u64;
            }
            limbs[3 - i] = v;
        }
        U256 { limbs }
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            let v = self.limbs[3 - i];
            for j in 0..8 {
                out[i * 8 + j] = (v >> (56 - j * 8)) as u8;
            }
        }
        out
    }

    pub fn from_compact(bits: u32) -> U256 {
        U256::from_be_bytes(&crate::compact_to_target(bits))
    }

    pub fn to_compact(&self) -> u32 {
        let bytes = self.to_be_bytes();
        let mut first = 0usize;
        while first < 32 && bytes[first] == 0 {
            first += 1;
        }
        if first == 32 {
            return 0;
        }
        let size = (32 - first) as u32;
        let b0 = bytes[first] as u32;
        let b1 = if first + 1 < 32 {
            bytes[first + 1] as u32
        } else {
            0
        };
        let b2 = if first + 2 < 32 {
            bytes[first + 2] as u32
        } else {
            0
        };
        let mut mant = (b0 << 16) | (b1 << 8) | b2;
        let mut exp = size;
        if mant & 0x0080_0000 != 0 {
            mant >>= 8;
            exp += 1;
        }
        (exp << 24) | (mant & 0x007f_ffff)
    }

    pub fn is_zero(&self) -> bool {
        self.limbs == [0, 0, 0, 0]
    }

    pub fn not(&self) -> U256 {
        U256 {
            limbs: [
                !self.limbs[0],
                !self.limbs[1],
                !self.limbs[2],
                !self.limbs[3],
            ],
        }
    }

    pub fn wrapping_add(&self, other: &U256) -> U256 {
        let mut limbs = [0u64; 4];
        let mut carry = 0u128;
        for (out, (a, b)) in limbs.iter_mut().zip(self.limbs.iter().zip(other.limbs.iter())) {
            let s = *a as u128 + *b as u128 + carry;
            *out = s as u64;
            carry = s >> 64;
        }
        U256 { limbs }
    }

    pub fn wrapping_sub(&self, other: &U256) -> U256 {
        let mut limbs = [0u64; 4];
        let mut borrow = 0i128;
        for (out, (a, b)) in limbs.iter_mut().zip(self.limbs.iter().zip(other.limbs.iter())) {
            let d = *a as i128 - *b as i128 - borrow;
            if d < 0 {
                *out = (d + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                *out = d as u64;
                borrow = 0;
            }
        }
        U256 { limbs }
    }

    pub fn mul_u64(&self, x: u64) -> U256 {
        let mut limbs = [0u64; 4];
        let mut carry = 0u128;
        for (out, a) in limbs.iter_mut().zip(self.limbs.iter()) {
            let p = *a as u128 * x as u128 + carry;
            *out = p as u64;
            carry = p >> 64;
        }
        U256 { limbs }
    }

    pub fn div_u64(&self, x: u64) -> U256 {
        let mut rem = 0u128;
        let mut q = [0u64; 4];
        for i in (0..4).rev() {
            let cur = (rem << 64) | self.limbs[i] as u128;
            q[i] = (cur / x as u128) as u64;
            rem = cur % x as u128;
        }
        U256 { limbs: q }
    }

    fn shl1(&self) -> U256 {
        let mut limbs = [0u64; 4];
        let mut carry = 0u64;
        for (out, a) in limbs.iter_mut().zip(self.limbs.iter()) {
            let next = *a >> 63;
            *out = (*a << 1) | carry;
            carry = next;
        }
        U256 { limbs }
    }

    fn bit(&self, i: usize) -> bool {
        (self.limbs[i / 64] >> (i % 64)) & 1 == 1
    }

    fn set_bit(&mut self, i: usize) {
        self.limbs[i / 64] |= 1u64 << (i % 64);
    }

    pub fn div(&self, divisor: &U256) -> U256 {
        if divisor.is_zero() || self < divisor {
            return U256::ZERO;
        }
        let mut quotient = U256::ZERO;
        let mut rem = U256::ZERO;
        for i in (0..256).rev() {
            rem = rem.shl1();
            if self.bit(i) {
                rem.limbs[0] |= 1;
            }
            if rem >= *divisor {
                rem = rem.wrapping_sub(divisor);
                quotient.set_bit(i);
            }
        }
        quotient
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn block_work(bits: u32) -> U256 {
    let target = U256::from_compact(bits);
    if target.is_zero() {
        return U256::ZERO;
    }
    let divisor = target.wrapping_add(&U256::ONE);
    if divisor.is_zero() {
        return U256::ZERO;
    }
    target.not().div(&divisor).wrapping_add(&U256::ONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_one_block_work_is_the_known_chain_constant() {
        assert_eq!(block_work(0x1d00ffff), U256::from_u64(4_295_032_833));
    }

    #[test]
    fn a_harder_block_carries_more_work_than_difficulty_one() {
        assert!(block_work(0x1d00d86a) > block_work(0x1d00ffff));
    }

    #[test]
    fn the_pow_limit_compact_round_trips() {
        assert_eq!(U256::from_compact(0x1d00ffff).to_compact(), 0x1d00ffff);
        assert_eq!(U256::from_compact(0x1d00d86a).to_compact(), 0x1d00d86a);
    }

    #[test]
    fn big_endian_bytes_round_trip() {
        let x = U256::from_u64(0x0102_0304_0506_0708);
        assert_eq!(U256::from_be_bytes(&x.to_be_bytes()), x);
    }

    #[test]
    fn multiply_then_divide_recovers_the_value() {
        let x = U256::from_compact(0x1d00ffff);
        assert_eq!(x.mul_u64(7).div_u64(7), x);
    }

    #[test]
    fn full_division_matches_a_known_quotient() {
        assert_eq!(
            U256::from_u64(1_000_000).div(&U256::from_u64(7)),
            U256::from_u64(142_857)
        );
    }

    #[test]
    fn ordering_is_by_magnitude_across_limbs() {
        let small = U256::from_u64(u64::MAX);
        let big = small.wrapping_add(&U256::ONE);
        assert!(big > small);
    }

    #[test]
    fn accumulating_seven_difficulty_one_blocks_sums_the_work() {
        let mut total = U256::ZERO;
        for _ in 0..7 {
            total = total.wrapping_add(&block_work(0x1d00ffff));
        }
        assert_eq!(total, U256::from_u64(7 * 4_295_032_833));
    }
}
