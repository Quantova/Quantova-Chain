// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

const P: [u64; 4] = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

const P_MINUS_2: [u8; 32] = [
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

const P_MINUS_5_DIV_8: [u8; 32] = [
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fe {
    limbs: [u64; 4],
}

fn add_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let t = (a[i] as u128) + (b[i] as u128) + carry;
        r[i] = t as u64;
        carry = t >> 64;
    }
    (r, carry as u64)
}

fn sub_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut borrow: i128 = 0;
    for i in 0..4 {
        let t = (a[i] as i128) - (b[i] as i128) - borrow;
        if t < 0 {
            r[i] = (t + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = t as u64;
            borrow = 0;
        }
    }
    (r, borrow as u64)
}

fn ge_p(a: [u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > P[i] {
            return true;
        }
        if a[i] < P[i] {
            return false;
        }
    }
    true
}

fn canonicalize(mut a: [u64; 4]) -> [u64; 4] {
    for _ in 0..2 {
        if ge_p(a) {
            a = sub_limbs(a, P).0;
        }
    }
    a
}

fn mul_limbs(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let t = (a[i] as u128) * (b[j] as u128) + (r[i + j] as u128) + carry;
            r[i + j] = t as u64;
            carry = t >> 64;
        }
        r[i + 4] = carry as u64;
    }
    r
}

fn reduce_wide(w: [u64; 8]) -> [u64; 4] {
    let lo = [w[0], w[1], w[2], w[3]];
    let hi = [w[4], w[5], w[6], w[7]];

    let mut t = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let x = (hi[i] as u128) * 38 + carry;
        t[i] = x as u64;
        carry = x >> 64;
    }
    t[4] = carry as u64;

    let mut s = [0u64; 5];
    let mut c: u128 = 0;
    for i in 0..4 {
        let x = (t[i] as u128) + (lo[i] as u128) + c;
        s[i] = x as u64;
        c = x >> 64;
    }
    s[4] = t[4].wrapping_add(c as u64);

    let mut r = [0u64; 4];
    let mut carry2: u128 = 38u128 * (s[4] as u128);
    for i in 0..4 {
        let x = (s[i] as u128) + carry2;
        r[i] = x as u64;
        carry2 = x >> 64;
    }
    if carry2 == 1 {
        let mut c2: u128 = 38;
        for i in 0..4 {
            let x = (r[i] as u128) + c2;
            r[i] = x as u64;
            c2 = x >> 64;
        }
    }
    canonicalize(r)
}

impl Fe {
    pub const fn zero() -> Fe {
        Fe { limbs: [0, 0, 0, 0] }
    }

    pub const fn one() -> Fe {
        Fe { limbs: [1, 0, 0, 0] }
    }

    pub const fn from_limbs(limbs: [u64; 4]) -> Fe {
        Fe { limbs }
    }

    pub fn from_u64(n: u64) -> Fe {
        Fe {
            limbs: canonicalize([n, 0, 0, 0]),
        }
    }

    pub fn from_bytes_le(bytes: &[u8; 32]) -> Fe {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(word);
        }
        Fe {
            limbs: canonicalize(limbs),
        }
    }

    pub fn from_bytes_le_strict(bytes: &[u8; 32]) -> Option<Fe> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(word);
        }
        if ge_p(limbs) {
            return None;
        }
        Some(Fe { limbs })
    }

    pub fn to_bytes_le(&self) -> [u8; 32] {
        let canon = canonicalize(self.limbs);
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&canon[i].to_le_bytes());
        }
        out
    }

    pub fn is_odd(&self) -> bool {
        canonicalize(self.limbs)[0] & 1 == 1
    }

    pub fn is_zero(&self) -> bool {
        canonicalize(self.limbs) == [0, 0, 0, 0]
    }

    pub fn add(&self, other: &Fe) -> Fe {
        let (s, _carry) = add_limbs(self.limbs, other.limbs);
        Fe {
            limbs: canonicalize(s),
        }
    }

    pub fn sub(&self, other: &Fe) -> Fe {
        let (d, borrow) = sub_limbs(self.limbs, other.limbs);
        if borrow == 1 {
            Fe {
                limbs: canonicalize(add_limbs(d, P).0),
            }
        } else {
            Fe {
                limbs: canonicalize(d),
            }
        }
    }

    pub fn neg(&self) -> Fe {
        Fe::zero().sub(self)
    }

    pub fn mul(&self, other: &Fe) -> Fe {
        Fe {
            limbs: reduce_wide(mul_limbs(self.limbs, other.limbs)),
        }
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    pub fn pow(&self, exp_le: &[u8; 32]) -> Fe {
        let mut result = Fe::one();
        for i in (0..32).rev() {
            let byte = exp_le[i];
            for b in (0..8).rev() {
                result = result.square();
                if (byte >> b) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    pub fn invert(&self) -> Fe {
        self.pow(&P_MINUS_2)
    }

    pub fn pow_p5_8(&self) -> Fe {
        self.pow(&P_MINUS_5_DIV_8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_is_the_multiplicative_identity() {
        let a = Fe::from_u64(123456789);
        assert_eq!(a.mul(&Fe::one()), a);
    }

    #[test]
    fn adding_the_negation_gives_zero() {
        let a = Fe::from_u64(0xdead_beef);
        assert!(a.add(&a.neg()).is_zero());
    }

    #[test]
    fn small_products_are_exact() {
        assert_eq!(Fe::from_u64(6), Fe::from_u64(2).mul(&Fe::from_u64(3)));
        assert_eq!(
            Fe::from_u64(0xffff_ffff).square(),
            Fe::from_u64(0xffff_fffe_0000_0001)
        );
    }

    #[test]
    fn inverse_times_value_is_one() {
        let a = Fe::from_u64(0x0123_4567_89ab_cdef);
        assert_eq!(a.mul(&a.invert()), Fe::one());
    }

    #[test]
    fn the_modulus_reduces_to_zero_and_is_not_canonical() {
        let p_bytes = {
            let mut b = [0u8; 32];
            for i in 0..4 {
                b[i * 8..i * 8 + 8].copy_from_slice(&P[i].to_le_bytes());
            }
            b
        };
        assert!(Fe::from_bytes_le_strict(&p_bytes).is_none());
        assert!(Fe::from_bytes_le(&p_bytes).is_zero());
    }

    #[test]
    fn reduction_wraps_two_to_the_255_to_nineteen() {
        let mut b = [0u8; 32];
        b[31] = 0x80;
        let two_255 = Fe::from_bytes_le(&b);
        assert_eq!(two_255, Fe::from_u64(19));
    }

    #[test]
    fn byte_round_trip_is_stable() {
        let a = Fe::from_u64(0x7766_5544_3322_1100);
        assert_eq!(Fe::from_bytes_le(&a.to_bytes_le()), a);
    }

    #[test]
    fn parity_tracks_the_low_bit() {
        assert!(Fe::from_u64(7).is_odd());
        assert!(!Fe::from_u64(8).is_odd());
    }
}
