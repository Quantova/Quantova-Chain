#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod chain;
pub mod commit;
pub mod ed25519;
pub mod field25519;
pub mod light;
pub mod merkle;
pub mod proof;
pub mod proto;
pub mod scalar;
pub mod sha256;
pub mod sha512;
pub mod statement;
pub mod validator;
pub mod witness;

pub use chain::{by_chain_id, ChainConfig, CELESTIA, COSMOS_HUB, FAMILY, INJECTIVE, OSMOSIS, SEI};
pub use statement::{verify_trustless_deposit, CorridorError, TrustlessDeposit};
