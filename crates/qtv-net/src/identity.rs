// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt;

use qtv_crypto::{ml_dsa, sha3};

use crate::{fill_random, Error, Result};

#[derive(Clone)]
pub struct Identity {
    public: ml_dsa::PublicKey,
    secret: ml_dsa::SecretKey,
}

impl Identity {
    pub fn from_seed(seed: &[u8; ml_dsa::SEED_BYTES]) -> Self {
        let (public, secret) = ml_dsa::keygen(seed);
        Self { public, secret }
    }

    pub fn public(&self) -> &ml_dsa::PublicKey {
        &self.public
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public(&self.public)
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<ml_dsa::Signature> {
        let mut randomizer = [0u8; 32];
        fill_random(&mut randomizer)?;
        ml_dsa::sign(&self.secret, message, context, &randomizer).ok_or(Error::Handshake(
            "signature context exceeds the length bound",
        ))
    }
}

#[derive(Clone)]
pub struct PeerId {
    public: ml_dsa::PublicKey,
    fingerprint: [u8; 32],
}

impl PeerId {
    pub fn from_public(public: &ml_dsa::PublicKey) -> Self {
        Self {
            public: *public,
            fingerprint: sha3::sha3_256(public),
        }
    }

    pub fn public(&self) -> &ml_dsa::PublicKey {
        &self.public
    }

    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint && self.public == other.public
    }
}

impl Eq for PeerId {}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId(")?;
        for byte in &self.fingerprint[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_derivation_is_stable() {
        let one = Identity::from_seed(&[7u8; 32]);
        let two = Identity::from_seed(&[7u8; 32]);
        assert_eq!(one.public(), two.public());
        assert_eq!(one.peer_id(), two.peer_id());
    }

    #[test]
    fn distinct_seeds_are_distinct_peers() {
        let one = Identity::from_seed(&[1u8; 32]);
        let two = Identity::from_seed(&[2u8; 32]);
        assert_ne!(one.peer_id(), two.peer_id());
        assert_ne!(one.peer_id().fingerprint(), two.peer_id().fingerprint());
    }

    #[test]
    fn signature_verifies_under_the_signer_public_key() {
        let signer = Identity::from_seed(&[3u8; 32]);
        let context = b"qtv-net test";
        let signature = signer.sign(b"transcript", context).unwrap();
        assert!(qtv_crypto::ml_dsa::verify(
            signer.public(),
            b"transcript",
            &signature,
            context
        ));
        let other = Identity::from_seed(&[4u8; 32]);
        assert!(!qtv_crypto::ml_dsa::verify(
            other.public(),
            b"transcript",
            &signature,
            context
        ));
    }
}
