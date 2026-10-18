// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg_attr(test, allow(deprecated))]
#![forbid(unsafe_code)]

#[cfg(all(feature = "test-fixtures", not(any(test, debug_assertions))))]
compile_error!("the test-fixtures feature exposes deterministic account secrets and must never be enabled in a release build");

pub const TEST_FIXTURES_LINKED: bool = cfg!(feature = "test-fixtures");

pub mod bridge;
pub mod consensus;
pub mod evidence;
pub mod execution;
pub mod fee;
pub mod keys;
pub mod ledger;
pub mod mempool;
pub mod node;
pub mod parallel;
pub mod provenance;
mod sigcache;

pub use sigcache::{bind_genesis, genesis as bound_genesis};
pub mod upgrades;
pub mod watermark;
