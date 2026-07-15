# qtv-net scope

This crate is the post-quantum secure channel that peers talk over. It is the
handshake and the encrypted record layer, and nothing else. It runs over any
standard library stream, so an in memory duplex for tests and a TCP stream for a
real link.

## What is in this crate

- A handshake where each peer holds a long term ML-DSA identity key. The
  initiator encapsulates to the responder ephemeral ML-KEM public key to
  establish a shared secret, both peers sign the handshake transcript with their
  ML-DSA identity key so each authenticates the other, and both derive
  directional session keys and starting nonces from the shared secret and the
  transcript with SHAKE. A peer whose identity signature over the transcript does
  not verify is rejected, and a tampered transcript aborts the handshake.
- A record layer of ChaCha20-Poly1305 over the derived directional key, a
  monotonic per direction nonce counter started from the derived nonce, length
  framed records, and the sequence number bound as associated data so a
  reordered, replayed, or tampered record fails to open and tears down the
  channel.

## The cryptographic law honored here

The only cryptographic dependency is qtv-crypto. The key exchange is ML-KEM, the
authentication is ML-DSA, the key schedule is SHAKE, and the channel cipher is
ChaCha20-Poly1305. There is no classical cryptography and no X25519, on devnets
or anywhere. The no_classical test asserts the crate stays qtv-crypto only, and
the workspace deny list refuses a classical crate anywhere in the tree.

## What is deferred to the full QUIC transport

This is honestly not a full QUIC stack. The parts a QUIC transport still needs
are named here and are not built yet.

- The UDP datagram layer. This channel runs over an in order reliable byte
  stream, not over datagrams.
- Multiplexed streams. This channel carries one ordered record stream per
  direction, not many independent streams over one connection.
- Congestion control. There is no sender rate control and no window.
- Loss recovery. The channel relies on the underlying stream for retransmission
  and does not recover lost packets itself.
- Peer discovery, gossip, and sync from SPEC-p2p, and the session key rotation
  schedule, all of which sit above this channel.
