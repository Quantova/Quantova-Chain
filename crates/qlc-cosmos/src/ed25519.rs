// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::field25519::Fe;
use crate::scalar::Scalar;
use crate::sha512::sha512;

const D: Fe = Fe::from_limbs([
    0x75eb_4dca_1359_78a3,
    0x0070_0a4d_4141_d8ab,
    0x8cc7_4079_7779_e898,
    0x5203_6cee_2b6f_fe73,
]);

const D2: Fe = Fe::from_limbs([
    0xebd6_9b94_26b2_f159,
    0x00e0_149a_8283_b156,
    0x198e_80f2_eef3_d130,
    0x2406_d9dc_56df_fce7,
]);

const SQRT_M1: Fe = Fe::from_limbs([
    0xc4ee_1b27_4a0e_a0b0,
    0x2f43_1806_ad2f_e478,
    0x2b4d_0099_3dfb_d7a7,
    0x2b83_2480_4fc1_df0b,
]);

const BX: Fe = Fe::from_limbs([
    0xc956_2d60_8f25_d51a,
    0x692c_c760_9525_a7b2,
    0xc0a4_e231_fdd6_dc5c,
    0x2169_36d3_cd6e_53fe,
]);

const BY: Fe = Fe::from_limbs([
    0x6666_6666_6666_6658,
    0x6666_6666_6666_6666,
    0x6666_6666_6666_6666,
    0x6666_6666_6666_6666,
]);

#[derive(Debug, Clone, Copy)]
pub struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    fn identity() -> Point {
        Point {
            x: Fe::zero(),
            y: Fe::one(),
            z: Fe::one(),
            t: Fe::zero(),
        }
    }

    fn from_affine(x: Fe, y: Fe) -> Point {
        Point {
            x,
            y,
            z: Fe::one(),
            t: x.mul(&y),
        }
    }

    fn negate(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    fn add(&self, other: &Point) -> Point {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&D2).mul(&other.t);
        let d = self.z.mul(&other.z);
        let d = d.add(&d);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let d = a.neg();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    fn compress(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut bytes = y.to_bytes_le();
        if x.is_odd() {
            bytes[31] |= 0x80;
        }
        bytes
    }

    fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.sub(&self.z).is_zero()
    }

    fn is_small_order(&self) -> bool {
        self.double().double().double().is_identity()
    }
}

fn base() -> Point {
    Point::from_affine(BX, BY)
}

fn scalar_mul(scalar: &Scalar, point: &Point) -> Point {
    let mut result = Point::identity();
    for i in (0..256).rev() {
        result = result.double();
        if scalar.bit(i) == 1 {
            result = result.add(point);
        }
    }
    result
}

fn decompress(bytes: &[u8; 32]) -> Option<Point> {
    let sign = (bytes[31] >> 7) & 1;
    let mut y_bytes = *bytes;
    y_bytes[31] &= 0x7f;
    let y = Fe::from_bytes_le_strict(&y_bytes)?;

    let yy = y.square();
    let u = yy.sub(&Fe::one());
    let v = D.mul(&yy).add(&Fe::one());

    let v3 = v.square().mul(&v);
    let v7 = v3.square().mul(&v);
    let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p5_8());

    let vxx = v.mul(&x.square());
    if vxx == u.neg() {
        x = x.mul(&SQRT_M1);
    } else if vxx != u {
        return None;
    }

    if x.is_zero() && sign == 1 {
        return None;
    }
    if (x.is_odd() as u8) != sign {
        x = x.neg();
    }

    Some(Point::from_affine(x, y))
}

#[cfg(any(test, feature = "test-util"))]
fn clamp(scalar_bytes: &mut [u8; 32]) {
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
}

#[cfg(any(test, feature = "test-util"))]
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let h = sha512(seed);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&h[0..32]);
    clamp(&mut a_bytes);
    let a = Scalar::reduce_wide(&a_bytes);
    scalar_mul(&a, &base()).compress()
}

#[cfg(any(test, feature = "test-util"))]
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let h = sha512(seed);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&h[0..32]);
    clamp(&mut a_bytes);
    let a = Scalar::reduce_wide(&a_bytes);
    let public_key = scalar_mul(&a, &base()).compress();

    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..64]);

    let mut r_input = Vec::with_capacity(32 + message.len());
    r_input.extend_from_slice(&prefix);
    r_input.extend_from_slice(message);
    let r = Scalar::reduce_wide(&sha512(&r_input));
    let r_point = scalar_mul(&r, &base()).compress();

    let mut k_input = Vec::with_capacity(64 + message.len());
    k_input.extend_from_slice(&r_point);
    k_input.extend_from_slice(&public_key);
    k_input.extend_from_slice(message);
    let k = Scalar::reduce_wide(&sha512(&k_input));

    let s = r.add(&k.mul(&a));

    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(&r_point);
    signature[32..64].copy_from_slice(&s.to_bytes_le());
    signature
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let a_point = match decompress(public_key) {
        Some(p) => p,
        None => return false,
    };
    if a_point.is_small_order() {
        return false;
    }
    let neg_a = a_point.negate();

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[0..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..64]);

    match decompress(&r_bytes) {
        Some(r_point) if r_point.is_small_order() => return false,
        Some(_) => {}
        None => return false,
    }

    let s = match Scalar::from_canonical_32(&s_bytes) {
        Some(s) => s,
        None => return false,
    };

    let mut k_input = Vec::with_capacity(64 + message.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(public_key);
    k_input.extend_from_slice(message);
    let k = Scalar::reduce_wide(&sha512(&k_input));

    let sb = scalar_mul(&s, &base());
    let ka = scalar_mul(&k, &neg_a);
    let check = sb.add(&ka);

    check.compress() == r_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn arr32(s: &str) -> [u8; 32] {
        let v = from_hex(s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    fn arr64(s: &str) -> [u8; 64] {
        let v = from_hex(s);
        let mut a = [0u8; 64];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn curve_constant_d_is_minus_121665_over_121666() {
        let d = Fe::from_u64(121665).neg().mul(&Fe::from_u64(121666).invert());
        assert_eq!(d, D);
        assert_eq!(D.add(&D), D2);
    }

    #[test]
    fn sqrt_of_minus_one_squares_to_minus_one() {
        assert_eq!(SQRT_M1.square(), Fe::one().neg());
    }

    #[test]
    fn the_base_point_lies_on_the_curve() {
        let xx = BX.square();
        let yy = BY.square();
        let lhs = xx.neg().add(&yy);
        let rhs = Fe::one().add(&D.mul(&xx).mul(&yy));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn compress_then_decompress_returns_the_base_point() {
        let b = base();
        let bytes = b.compress();
        let back = decompress(&bytes).unwrap();
        assert_eq!(back.compress(), bytes);
    }

    #[test]
    fn clamp_follows_the_specified_bit_pattern() {
        let mut bytes = [0xffu8; 32];
        clamp(&mut bytes);
        assert_eq!(bytes[0] & 0b0000_0111, 0);
        assert_eq!(bytes[31] & 0b1000_0000, 0);
        assert_eq!(bytes[31] & 0b0100_0000, 0b0100_0000);
    }

    #[test]
    fn rfc8032_test_1_verifies() {
        let pk = arr32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = arr64("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assert!(verify(&pk, &[], &sig));
    }

    #[test]
    fn rfc8032_test_2_verifies() {
        let pk = arr32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let msg = from_hex("72");
        let sig = arr64("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assert!(verify(&pk, &msg, &sig));
    }

    #[test]
    fn rfc8032_test_3_verifies() {
        let pk = arr32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let msg = from_hex("af82");
        let sig = arr64("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
        assert!(verify(&pk, &msg, &sig));
    }

    #[test]
    fn a_tampered_message_does_not_verify() {
        let pk = arr32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let sig = arr64("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assert!(!verify(&pk, &[0x73], &sig));
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let pk = arr32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let msg = from_hex("72");
        let mut sig = arr64("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        sig[10] ^= 0x01;
        assert!(!verify(&pk, &msg, &sig));
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let seed = arr32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let pk = public_key_from_seed(&seed);
        let msg = b"quantova cosmos corridor";
        let sig = sign(&seed, msg);
        assert!(verify(&pk, msg, &sig));
    }

    #[test]
    fn a_signature_from_a_different_key_does_not_verify() {
        let seed_a = arr32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let seed_b = arr32("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let pk_b = public_key_from_seed(&seed_b);
        let msg = b"quantova cosmos corridor";
        let sig = sign(&seed_a, msg);
        assert!(!verify(&pk_b, msg, &sig));
    }

    #[test]
    fn signing_is_deterministic() {
        let seed = arr32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let msg = b"same message same signature";
        assert_eq!(sign(&seed, msg), sign(&seed, msg));
    }

    #[test]
    fn an_identity_public_key_forgery_is_rejected() {
        let mut a = [0u8; 32];
        a[0] = 1;
        let identity = decompress(&a).unwrap();
        assert!(identity.is_small_order());

        let s = Scalar::from_u64(12345);
        let r_point = scalar_mul(&s, &base());
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(&r_point.compress());
        sig[32..64].copy_from_slice(&s.to_bytes_le());

        assert!(!verify(&a, b"forge anything under an identity key", &sig));
    }

    fn order_bytes_le() -> [u8; 32] {
        arr32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
    }

    fn add_bytes_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let t = a[i] as u16 + b[i] as u16 + carry;
            out[i] = t as u8;
            carry = t >> 8;
        }
        out
    }

    fn valid_signature() -> ([u8; 32], Vec<u8>, [u8; 64]) {
        let seed = arr32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let pk = public_key_from_seed(&seed);
        let msg = b"quantova cosmos corridor".to_vec();
        let sig = sign(&seed, &msg);
        assert!(verify(&pk, &msg, &sig));
        (pk, msg, sig)
    }

    #[test]
    fn a_scalar_equal_to_the_group_order_is_rejected() {
        let (pk, msg, mut sig) = valid_signature();
        sig[32..64].copy_from_slice(&order_bytes_le());
        assert!(!verify(&pk, &msg, &sig));
    }

    #[test]
    fn a_scalar_plus_the_group_order_is_rejected() {
        let (pk, msg, mut sig) = valid_signature();
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..64]);
        let malleated = add_bytes_le(&s, &order_bytes_le());
        sig[32..64].copy_from_slice(&malleated);
        assert!(!verify(&pk, &msg, &sig));
    }

    #[test]
    fn a_non_canonical_public_key_y_is_rejected() {
        let (_pk, msg, sig) = valid_signature();
        let non_canonical =
            arr32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(decompress(&non_canonical).is_none());
        assert!(!verify(&non_canonical, &msg, &sig));
    }

    #[test]
    fn a_zero_x_with_the_sign_bit_set_is_rejected() {
        let (_pk, msg, sig) = valid_signature();
        let mut a = [0u8; 32];
        a[0] = 1;
        a[31] |= 0x80;
        assert!(decompress(&a).is_none());
        assert!(!verify(&a, &msg, &sig));
    }

    #[test]
    fn a_small_order_public_key_is_rejected() {
        let (_pk, msg, sig) = valid_signature();
        let small_order =
            arr32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(decompress(&small_order).unwrap().is_small_order());
        assert!(!verify(&small_order, &msg, &sig));
    }

    #[test]
    fn a_small_order_r_is_rejected() {
        let (pk, msg, mut sig) = valid_signature();
        let small_order =
            arr32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        sig[0..32].copy_from_slice(&small_order);
        sig[32..64].copy_from_slice(&Scalar::from_u64(9).to_bytes_le());
        assert!(!verify(&pk, &msg, &sig));
    }
}
