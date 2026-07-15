//! The SHAKE key schedule.
//!
//! Both peers finish the handshake holding the same ML-KEM shared secret and the
//! same handshake transcript hash. They feed both into SHAKE-256 under a fixed
//! label and split the output stream the same way, so they agree on a key and a
//! starting nonce for each direction and on an exporter value without any
//! further exchange. Because the schedule binds the transcript, a peer that saw a
//! different transcript derives different keys and cannot open the other side
//! records.

use qtv_crypto::chacha20poly1305::{KEY_BYTES, NONCE_BYTES};
use qtv_crypto::sha3;

const KEY_SCHEDULE_LABEL: &[u8] = b"qtv-net/key-schedule/v1";

/// The channel cipher key and the starting nonce for one direction.
#[derive(Clone)]
pub struct DirKey {
    /// The ChaCha20-Poly1305 key that seals or opens this direction.
    pub key: [u8; KEY_BYTES],
    /// The starting nonce the record counter is offset from.
    pub iv: [u8; NONCE_BYTES],
}

/// The directional session keys and the exporter both peers derive alike.
pub struct SessionKeys {
    /// The key and nonce the initiator seals with and the responder opens with.
    pub initiator_to_responder: DirKey,
    /// The key and nonce the responder seals with and the initiator opens with.
    pub responder_to_initiator: DirKey,
    /// A value both peers derive alike, a channel binding over the handshake.
    pub exporter: [u8; 32],
}

/// Derive the session keys from the ML-KEM shared secret and the handshake
/// transcript hash with SHAKE-256.
pub fn derive(shared_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> SessionKeys {
    let mut input = Vec::with_capacity(KEY_SCHEDULE_LABEL.len() + 64);
    input.extend_from_slice(KEY_SCHEDULE_LABEL);
    input.extend_from_slice(shared_secret);
    input.extend_from_slice(transcript_hash);

    let mut stream = [0u8; 2 * KEY_BYTES + 2 * NONCE_BYTES + 32];
    sha3::shake256(&input, &mut stream);

    let mut i2r_key = [0u8; KEY_BYTES];
    i2r_key.copy_from_slice(&stream[0..KEY_BYTES]);
    let mut r2i_key = [0u8; KEY_BYTES];
    r2i_key.copy_from_slice(&stream[KEY_BYTES..2 * KEY_BYTES]);

    let iv_base = 2 * KEY_BYTES;
    let mut i2r_iv = [0u8; NONCE_BYTES];
    i2r_iv.copy_from_slice(&stream[iv_base..iv_base + NONCE_BYTES]);
    let mut r2i_iv = [0u8; NONCE_BYTES];
    r2i_iv.copy_from_slice(&stream[iv_base + NONCE_BYTES..iv_base + 2 * NONCE_BYTES]);

    let mut exporter = [0u8; 32];
    exporter.copy_from_slice(&stream[iv_base + 2 * NONCE_BYTES..]);

    SessionKeys {
        initiator_to_responder: DirKey {
            key: i2r_key,
            iv: i2r_iv,
        },
        responder_to_initiator: DirKey {
            key: r2i_key,
            iv: r2i_iv,
        },
        exporter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let shared = [9u8; 32];
        let transcript = [5u8; 32];
        let first = derive(&shared, &transcript);
        let second = derive(&shared, &transcript);
        assert_eq!(
            first.initiator_to_responder.key,
            second.initiator_to_responder.key
        );
        assert_eq!(
            first.responder_to_initiator.iv,
            second.responder_to_initiator.iv
        );
        assert_eq!(first.exporter, second.exporter);
    }

    #[test]
    fn directions_and_transcripts_separate_the_keys() {
        let shared = [9u8; 32];
        let keys = derive(&shared, &[5u8; 32]);
        assert_ne!(
            keys.initiator_to_responder.key,
            keys.responder_to_initiator.key
        );
        assert_ne!(
            keys.initiator_to_responder.iv,
            keys.responder_to_initiator.iv
        );

        let other = derive(&shared, &[6u8; 32]);
        assert_ne!(
            keys.initiator_to_responder.key,
            other.initiator_to_responder.key
        );
        assert_ne!(keys.exporter, other.exporter);
    }
}
