//! A multi node devnet for the Quantova stack.
//!
//! The first node ran a state transition and finalization loop in one process
//! over direct calls. This crate turns that loop into several real nodes that
//! talk over qtv-net and reach finality over the wire, following SPEC-p2p.md and
//! SPEC-consensus-qorus.md.
//!
//! Each node holds its own identity, its own state and store, and a bounded set of
//! overlay neighbors rather than a channel to every peer. A node discovers the
//! network from a small set of bootstrap peers, then gossips three things to its
//! neighbors and relays what it hears onward: submitted transactions, block
//! proposals, and attestations. The committee is chosen by the sampler, the leader
//! proposes the block over the overlay, the online members attest over the overlay
//! with their module lattice key, an entitled supermajority aggregates into one
//! finality certificate, and every node commits the same finalized block and
//! persists it through qtv-store before advancing.
//!
//! The execution, the mempool, the committee selection, the attestation, and the
//! certificate aggregation are the same chain crates the in process loop used,
//! reused rather than forked. What is new here is the transport: peer discovery,
//! the bounded gossip overlay, the wire codec, the secure channels, and the per
//! node loop that drives the round over it.
//!
//! Every overlay link is a qtv-net channel, an ML-KEM and ML-DSA handshake with a
//! ChaCha20-Poly1305 record layer, and a discovered peer is authenticated by that
//! pinned handshake before it is trusted. There is no X25519 and no classical
//! cryptography anywhere. NOTES.md states the scope and the deferred networking
//! work.

#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod devnet;
pub mod discovery;
pub mod network;
pub mod node;
pub mod overlay;
pub mod transport;
pub mod wire;

pub use clock::{Clock, Event, Time};
pub use config::{DevnetConfig, NodeConfig};
pub use devnet::Devnet;
pub use discovery::{PeerEntry, PeerTable};
pub use network::Network;
pub use node::{leader_for, DevNode, FinalizedBlock, Height, SyncError, View};
pub use overlay::Seen;
pub use transport::{connect_duplex_mesh, connect_duplex_overlay, connect_duplex_pair, Mesh};
pub use wire::Message;
