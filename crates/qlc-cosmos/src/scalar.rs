// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scalar {
    limbs: [u64; 4],
}

fn geq_l(a: [u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > L[i] {
            return true;
        }
        if a[i] < L[i] {
            return false;
        }
    }
    true
}

fn sub_l(a: [u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow: i128 = 0;
    for i in 0..4 {
        let t = (a[i] as i128) - (L[i] as i128) - borrow;
        if t < 0 {
            r[i] = (t + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = t as u64;
            borrow = 0;
        }
    }
    r
}

fn shl1_add_bit(a: [u64; 4], bit: u64) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry = bit;
    for i in 0..4 {
        let next = a[i] >> 63;
        r[i] = (a[i] << 1) | carry;
        carry = next;
    }
    r
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

fn reduce_bits(bytes_le: &[u8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for byte_index in (0..bytes_le.len()).rev() {
        let byte = bytes_le[byte_index];
        for b in (0..8).rev() {
            let bit = ((byte >> b) & 1) as u64;
            r = shl1_add_bit(r, bit);
            if geq_l(r) {
                r = sub_l(r);
            }
        }
    }
    r
}

impl Scalar {
    pub const fn zero() -> Scalar {
        Scalar { limbs: [0, 0, 0, 0] }
    }

    pub fn from_u64(n: u64) -> Scalar {
        let mut s = [n, 0, 0, 0];
        if geq_l(s) {
            s = sub_l(s);
        }
        Scalar { limbs: s }
    }

    pub fn reduce_wide(bytes_le: &[u8]) -> Scalar {
        Scalar {
            limbs: reduce_bits(bytes_le),
        }
    }

    pub fn from_wide_64(bytes: &[u8; 64]) -> Scalar {
        Scalar::reduce_wide(bytes)
    }

    pub fn from_canonical_32(bytes: &[u8; 32]) -> Option<Scalar> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(word);
        }
        if geq_l(limbs) {
            return None;
        }
        Some(Scalar { limbs })
    }

    pub fn to_bytes_le(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        out
    }

    pub fn bit(&self, index: usize) -> u8 {
        ((self.limbs[index / 64] >> (index % 64)) & 1) as u8
    }

    pub fn is_zero(&self) -> bool {
        self.limbs == [0, 0, 0, 0]
    }

    pub fn add(&self, other: &Scalar) -> Scalar {
        let mut r = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let t = (self.limbs[i] as u128) + (other.limbs[i] as u128) + carry;
            r[i] = t as u64;
            carry = t >> 64;
        }
        let mut bytes = [0u8; 40];
        for i in 0..4 {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&r[i].to_le_bytes());
        }
        bytes[32] = carry as u8;
        Scalar::reduce_wide(&bytes)
    }

    pub fn mul(&self, other: &Scalar) -> Scalar {
        let wide = mul_limbs(self.limbs, other.limbs);
        let mut bytes = [0u8; 64];
        for i in 0..8 {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&wide[i].to_le_bytes());
        }
        Scalar::from_wide_64(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order_bytes() -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..4 {
            b[i * 8..i * 8 + 8].copy_from_slice(&L[i].to_le_bytes());
        }
        b
    }

    #[test]
    fn small_values_are_left_alone() {
        let mut b = [0u8; 64];
        b[0] = 5;
        assert_eq!(Scalar::from_wide_64(&b).to_bytes_le()[0], 5);
    }

    #[test]
    fn the_order_reduces_to_zero() {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&order_bytes());
        assert!(Scalar::from_wide_64(&wide).is_zero());
    }

    #[test]
    fn the_order_is_not_a_canonical_scalar() {
        assert!(Scalar::from_canonical_32(&order_bytes()).is_none());
        let mut minus_one = order_bytes();
        minus_one[0] -= 1;
        assert!(Scalar::from_canonical_32(&minus_one).is_some());
    }

    #[test]
    fn order_plus_seven_reduces_to_seven() {
        let mut wide = [0u8; 64];
        let mut ob = order_bytes();
        let (v, _) = ob[0].overflowing_add(7);
        ob[0] = v;
        wide[..32].copy_from_slice(&ob);
        assert_eq!(Scalar::from_wide_64(&wide).to_bytes_le()[0], 7);
    }

    #[test]
    fn addition_wraps_at_the_order() {
        let mut minus_one = order_bytes();
        minus_one[0] -= 1;
        let a = Scalar::from_canonical_32(&minus_one).unwrap();
        assert!(a.add(&Scalar::from_u64(1)).is_zero());
    }

    #[test]
    fn multiplication_matches_a_small_product() {
        let a = Scalar::from_u64(1_000_000);
        let b = Scalar::from_u64(1_000_003);
        assert_eq!(a.mul(&b), Scalar::from_u64(1_000_003_000_000));
    }

    #[test]
    fn bits_are_read_little_endian() {
        let s = Scalar::from_u64(0b1010);
        assert_eq!(s.bit(0), 0);
        assert_eq!(s.bit(1), 1);
        assert_eq!(s.bit(2), 0);
        assert_eq!(s.bit(3), 1);
    }
}
