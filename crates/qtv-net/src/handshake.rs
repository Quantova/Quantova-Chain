//! The post-quantum authenticated handshake.
//!
//! The initiator sends its identity public key and a random nonce. The responder
//! generates an ephemeral ML-KEM key pair, sends its identity public key, the
//! ephemeral encapsulation key, and a nonce, and signs the transcript so far with
//! its identity key. The initiator verifies that signature, encapsulates to the
//! ephemeral key to fix the shared secret, and signs the transcript including the
//! ciphertext with its identity key. The responder verifies that signature and
//! decapsulates to the same shared secret. Both sides derive the session keys
//! from the shared secret and the transcript hash. A signature that does not
//! verify, over a transcript either peer tampered with, aborts the handshake.

use std::io::{Read, Write};

use qtv_crypto::{ml_dsa, ml_kem};

use crate::channel::{Channel, Role};
use crate::identity::{Identity, PeerId};
use crate::keyschedule;
use crate::transcript::Transcript;
use crate::{fill_random, Error, Result};

/// The signature context that binds a signature to the initiator role.
const INITIATOR_CONTEXT: &[u8] = b"qtv-net initiator";

/// The signature context that binds a signature to the responder role.
const RESPONDER_CONTEXT: &[u8] = b"qtv-net responder";

impl<S: Read + Write> Channel<S> {
    /// Run the handshake as the initiator over `stream`.
    pub fn connect(stream: S, identity: &Identity) -> Result<Self> {
        initiate(stream, identity, None)
    }

    /// Run the handshake as the initiator and require the authenticated peer to
    /// be `peer`, so a man in the middle without that identity key is rejected.
    pub fn connect_pinned(stream: S, identity: &Identity, peer: &PeerId) -> Result<Self> {
        initiate(stream, identity, Some(peer))
    }

    /// Run the handshake as the responder over `stream`.
    pub fn accept(stream: S, identity: &Identity) -> Result<Self> {
        respond(stream, identity, None)
    }

    /// Run the handshake as the responder and require the authenticated peer to
    /// be `peer`.
    pub fn accept_pinned(stream: S, identity: &Identity, peer: &PeerId) -> Result<Self> {
        respond(stream, identity, Some(peer))
    }
}

fn read_array<const N: usize, R: Read>(reader: &mut R) -> Result<[u8; N]> {
    let mut buffer = [0u8; N];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn initiate<S: Read + Write>(
    mut stream: S,
    identity: &Identity,
    expected: Option<&PeerId>,
) -> Result<Channel<S>> {
    let mut client_random = [0u8; 32];
    fill_random(&mut client_random)?;

    let mut transcript = Transcript::new();
    transcript.absorb(identity.public());
    transcript.absorb(&client_random);

    let mut hello = Vec::with_capacity(ml_dsa::PUBLIC_KEY_BYTES + client_random.len());
    hello.extend_from_slice(identity.public());
    hello.extend_from_slice(&client_random);
    stream.write_all(&hello)?;
    stream.flush()?;

    let responder_public: ml_dsa::PublicKey = read_array(&mut stream)?;
    let encaps_key: ml_kem::EncapsKey = read_array(&mut stream)?;
    let server_random: [u8; 32] = read_array(&mut stream)?;
    let responder_signature: ml_dsa::Signature = read_array(&mut stream)?;

    transcript.absorb(&responder_public);
    transcript.absorb(&encaps_key);
    transcript.absorb(&server_random);
    let server_bound = transcript.hash();
    if !ml_dsa::verify(
        &responder_public,
        &server_bound,
        &responder_signature,
        RESPONDER_CONTEXT,
    ) {
        return Err(Error::Authentication);
    }

    let peer = PeerId::from_public(&responder_public);
    if expected.is_some_and(|pin| &peer != pin) {
        return Err(Error::UnexpectedPeer);
    }

    let mut kem_random = [0u8; 32];
    fill_random(&mut kem_random)?;
    let (shared_secret, ciphertext) = ml_kem::encaps(&encaps_key, &kem_random);
    transcript.absorb(&ciphertext);
    let final_bound = transcript.hash();

    let initiator_signature = identity.sign(&final_bound, INITIATOR_CONTEXT)?;

    let mut finish = Vec::with_capacity(ml_kem::CIPHERTEXT_BYTES + ml_dsa::SIGNATURE_BYTES);
    finish.extend_from_slice(&ciphertext);
    finish.extend_from_slice(&initiator_signature);
    stream.write_all(&finish)?;
    stream.flush()?;

    let keys = keyschedule::derive(&shared_secret, &final_bound);
    Ok(Channel::new(stream, Role::Initiator, peer, keys))
}

fn respond<S: Read + Write>(
    mut stream: S,
    identity: &Identity,
    expected: Option<&PeerId>,
) -> Result<Channel<S>> {
    let mut kem_seed = [0u8; 32];
    let mut kem_z = [0u8; 32];
    fill_random(&mut kem_seed)?;
    fill_random(&mut kem_z)?;
    let (encaps_key, decaps_key) = ml_kem::keygen(&kem_seed, &kem_z);

    let initiator_public: ml_dsa::PublicKey = read_array(&mut stream)?;
    let client_random: [u8; 32] = read_array(&mut stream)?;

    let peer = PeerId::from_public(&initiator_public);
    if expected.is_some_and(|pin| &peer != pin) {
        return Err(Error::UnexpectedPeer);
    }

    let mut transcript = Transcript::new();
    transcript.absorb(&initiator_public);
    transcript.absorb(&client_random);

    let mut server_random = [0u8; 32];
    fill_random(&mut server_random)?;
    transcript.absorb(identity.public());
    transcript.absorb(&encaps_key);
    transcript.absorb(&server_random);
    let server_bound = transcript.hash();
    let responder_signature = identity.sign(&server_bound, RESPONDER_CONTEXT)?;

    let mut hello = Vec::with_capacity(
        ml_dsa::PUBLIC_KEY_BYTES
            + ml_kem::ENCAPS_KEY_BYTES
            + server_random.len()
            + ml_dsa::SIGNATURE_BYTES,
    );
    hello.extend_from_slice(identity.public());
    hello.extend_from_slice(&encaps_key);
    hello.extend_from_slice(&server_random);
    hello.extend_from_slice(&responder_signature);
    stream.write_all(&hello)?;
    stream.flush()?;

    let ciphertext: ml_kem::Ciphertext = read_array(&mut stream)?;
    let initiator_signature: ml_dsa::Signature = read_array(&mut stream)?;
    transcript.absorb(&ciphertext);
    let final_bound = transcript.hash();
    if !ml_dsa::verify(
        &initiator_public,
        &final_bound,
        &initiator_signature,
        INITIATOR_CONTEXT,
    ) {
        return Err(Error::Authentication);
    }

    let shared_secret = ml_kem::decaps(&decaps_key, &ciphertext);
    let keys = keyschedule::derive(&shared_secret, &final_bound);
    Ok(Channel::new(stream, Role::Responder, peer, keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duplex;
    use std::thread;

    #[test]
    fn peers_complete_the_handshake_and_agree() {
        let (client_stream, server_stream) = duplex();
        let initiator = Identity::from_seed(&[11u8; 32]);
        let responder = Identity::from_seed(&[22u8; 32]);
        let responder_for_thread = responder.clone();

        let server =
            thread::spawn(move || Channel::accept(server_stream, &responder_for_thread).unwrap());
        let client = Channel::connect(client_stream, &initiator).unwrap();
        let server = server.join().unwrap();

        assert_eq!(client.channel_binding(), server.channel_binding());
        assert_eq!(client.peer_id(), &responder.peer_id());
        assert_eq!(server.peer_id(), &initiator.peer_id());
    }
}
