// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg_attr(test, allow(deprecated))]
#![forbid(unsafe_code)]

#[cfg(all(feature = "test-fixtures", not(any(test, debug_assertions))))]
compile_error!("the test-fixtures feature exposes deterministic validator identities and must never be enabled in a release build");

pub mod clock;
pub mod coded;
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
pub use node::{leader_for, Checkpoint, DevNode, Fatal, FinalizedBlock, Height, SyncError, View};
pub use overlay::Seen;
pub use qtv_governance::GuardianSet;
pub use transport::{connect_duplex_mesh, connect_duplex_overlay, connect_duplex_pair, Mesh};
pub use wire::Message;
