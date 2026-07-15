//! A multi node devnet for the Quantova stack.
//!
//! The first node ran a state transition and finalization loop in one process
//! over direct calls. This crate turns that loop into several real nodes that
//! talk over qtv-net and reach finality over the wire, following SPEC-p2p.md and
//! SPEC-consensus-qorus.md.
//!
//! Each node holds its own identity, its own state and store, and a secure
//! channel to every peer. A node gossips three things over the channels:
//! submitted transactions, block proposals, and attestations. The committee is
//! chosen by the sampler, the leader proposes the block over the wire, the online
//! members attest over the wire with their module lattice key, an entitled
//! supermajority aggregates into one finality certificate, and every node commits
//! the same finalized block and persists it through qtv-store before advancing.
//!
//! The execution, the mempool, the committee selection, the attestation, and the
//! certificate aggregation are the same chain crates the in process loop used,
//! reused rather than forked. What is new here is the transport: the wire codec,
//! the secure channel mesh, and the per node loop that drives the round over it.
//!
//! The transport is qtv-net, an ML-KEM and ML-DSA handshake with a
//! ChaCha20-Poly1305 record layer. There is no X25519 and no classical
//! cryptography anywhere. NOTES.md states the scope and the deferred networking
//! work.

#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod devnet;
pub mod node;
pub mod transport;
pub mod wire;

pub use config::{DevnetConfig, NodeConfig};
pub use devnet::Devnet;
pub use node::{DevNode, FinalizedBlock, Height};
pub use transport::{connect_duplex_mesh, Mesh};
pub use wire::Message;
