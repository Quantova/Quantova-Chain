//! The first disk backed persistence for the Quantova stack.
//!
//! The node runs a state transition and finalization loop in memory. This crate
//! gives it two file backed stores so the chain survives a restart. A block store
//! appends each finalized block and indexes it by height and by hash. A state
//! store persists the account state, the leaves of the qtv-state sparse Merkle
//! trie keyed by their thirty two byte hash, and records the root a state was
//! committed under. Every record enters disk through the qtv-codec canonical
//! encoding, so a value has exactly one stored form.
//!
//! Each store is an append log plus an in memory index. A write appends one
//! canonical record and updates the index. On open the log is scanned once and
//! the index is rebuilt from it, so a reopen sees exactly what was committed. An
//! append that was interrupted leaves a torn tail; the scan stops at the last
//! whole record and the file is truncated back to it, so the store stays append
//! only and nothing torn is ever read. An absent or truncated file opens as an
//! empty store.
//!
//! This is a first persistence layer. A hardened embedded store, with checksummed
//! pages, atomic multi record commits, and compaction, is later work. NOTES.md
//! states the scope and the deferred hardening.

#![forbid(unsafe_code)]

mod block_store;
mod log;

pub use block_store::BlockStore;
