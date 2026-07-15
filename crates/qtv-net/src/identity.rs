//! Peer identity backed by an ML-DSA key pair.

use std::fmt;

use qtv_crypto::{ml_dsa, sha3};

use crate::{fill_random, Error, Result};

/// A peer long term identity. The ML-DSA public key is the peer identity and the
/// secret key signs the handshake transcript so the far side can authenticate it.
#[derive(Clone)]
pub struct Identity {
    public: ml_dsa::PublicKey,
    secret: ml_dsa::SecretKey,
}

impl Identity {
    /// Derive an identity from a thirty two byte seed. The same seed always
    /// yields the same key pair, so a peer identity is stable across restarts.
    pub fn from_seed(seed: &[u8; ml_dsa::SEED_BYTES]) -> Self {
        let (public, secret) = ml_dsa::keygen(seed);
        Self { public, secret }
    }

    /// The ML-DSA public key that names this peer.
    pub fn public(&self) -> &ml_dsa::PublicKey {
        &self.public
    }

    /// The peer identity that other peers see.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public(&self.public)
    }

    /// Sign `message` under `context` with this identity key. The handshake signs
    /// the transcript hash under a role context so the far side authenticates
    /// this peer. The signing randomness is drawn from the operating system.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<ml_dsa::Signature> {
        let mut randomizer = [0u8; 32];
        fill_random(&mut randomizer)?;
        ml_dsa::sign(&self.secret, message, context, &randomizer).ok_or(Error::Handshake(
            "signature context exceeds the length bound",
        ))
    }
}

/// A peer identity, the ML-DSA public key addressed by its SHA3-256 fingerprint.
#[derive(Clone)]
pub struct PeerId {
    public: ml_dsa::PublicKey,
    fingerprint: [u8; 32],
}

impl PeerId {
    /// Build a peer identity from an ML-DSA public key.
    pub fn from_public(public: &ml_dsa::PublicKey) -> Self {
        Self {
            public: *public,
            fingerprint: sha3::sha3_256(public),
        }
    }

    /// The ML-DSA public key of this peer.
    pub fn public(&self) -> &ml_dsa::PublicKey {
        &self.public
    }

    /// The SHA3-256 fingerprint of the public key, a compact peer handle.
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
