// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::sync::atomic::{compiler_fence, Ordering};

pub trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        for slot in self.iter_mut() {
            unsafe { core::ptr::write_volatile(slot, 0) }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        self[..].zeroize();
    }
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Zeroize for String {
    fn zeroize(&mut self) {
        unsafe { self.as_mut_vec() }.zeroize();
    }
}

pub struct Zeroizing<T: Zeroize> {
    value: T,
}

impl<T: Zeroize> Zeroizing<T> {
    pub fn new(value: T) -> Self {
        Zeroizing { value }
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T: Zeroize + Clone> Clone for Zeroizing<T> {
    fn clone(&self) -> Self {
        Zeroizing {
            value: self.value.clone(),
        }
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Zeroizing<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Zeroize + Eq> Eq for Zeroizing<T> {}

impl<T: Zeroize> core::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Zeroizing(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slice_clears_every_byte() {
        let mut buffer = [7u8; 64];
        buffer.zeroize();
        assert!(buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn a_vec_clears_every_byte() {
        let mut buffer = vec![9u8; 40];
        buffer.zeroize();
        assert!(buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn a_string_clears_every_byte() {
        let mut secret = "correct horse battery staple".to_string();
        secret.zeroize();
        assert!(secret.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn a_wrapper_exposes_and_fills_the_inner_bytes() {
        let mut holder = Zeroizing::new([0u8; 4]);
        holder.copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(&holder[..], &[1u8, 2, 3, 4][..]);
    }

    #[test]
    fn a_wrapper_debug_hides_the_bytes() {
        let holder = Zeroizing::new([200u8; 8]);
        assert_eq!(format!("{:?}", holder), "Zeroizing(redacted)");
    }
}
