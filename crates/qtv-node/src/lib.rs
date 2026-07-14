//! The first in process node for the Quantova stack.
//!
//! This crate is the first vertical slice of the node. It composes the chain
//! crates, the virtual machine, and the consensus core into a single state
//! transition and finalization loop that runs a small committee in one process.
//! It holds chain state in a sparse Merkle trie, accepts signed transactions
//! into a mempool, executes each transaction through the virtual machine so a
//! block carries a real post execution state root, and drives a sampler selected
//! committee through attestation and aggregation into a finality certificate.
//!
//! The slice is honest about its bounds. There is no real networking, no QUIC
//! transport, no peer discovery, and no disk persistence. The committee runs
//! over direct calls, not over a wire. NOTES.md states what is in this slice and
//! what is deferred to later node work.

#![forbid(unsafe_code)]

pub mod execution;
pub mod fee;
pub mod ledger;
pub mod mempool;
