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

pub struct Zeroizing<T: AsMut<[u8]>> {
    value: T,
}

impl<T: AsMut<[u8]>> Zeroizing<T> {
    pub fn new(value: T) -> Self {
        Zeroizing { value }
    }
}

impl<T: AsMut<[u8]>> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.value.as_mut().zeroize();
    }
}

impl<T: AsMut<[u8]>> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: AsMut<[u8]>> core::fmt::Debug for Zeroizing<T> {
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
    fn a_wrapper_exposes_the_inner_bytes() {
        let holder = Zeroizing::new([9u8; 16]);
        assert_eq!(&holder[..], &[9u8; 16][..]);
    }

    #[test]
    fn a_wrapper_debug_hides_the_bytes() {
        let holder = Zeroizing::new([200u8; 8]);
        assert_eq!(format!("{:?}", holder), "Zeroizing(redacted)");
    }
}
