// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::sha3;

pub const LABEL: &[u8] = b"qtv-net/handshake/v1";

pub struct Transcript {
    buffer: Vec<u8>,
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            buffer: LABEL.to_vec(),
        }
    }

    pub fn absorb(&mut self, field: &[u8]) {
        self.buffer.extend_from_slice(field);
    }

    pub fn hash(&self) -> [u8; 32] {
        sha3::sha3_256(&self.buffer)
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
