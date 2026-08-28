#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod beacon;
pub mod bls;
pub mod config;
pub mod engine;
pub mod keccak;
pub mod mpt;
pub mod receipt;
pub mod rlp;
pub mod ssz;
pub mod witness;

pub use config::EvmChainConfig;
pub use engine::{
    advance_period, apply_sync_committee_update, bootstrap, lower_to_stark, public_input_digest,
    to_verified_event, verify_deposit_update, verify_trustless_deposit, DepositProof, EthError,
    ExecutionCommit, LightClientStore, LightClientUpdate, SyncCommitteeUpdate, TrustlessDeposit,
};
pub use witness::{prove_ready_witness, EthereumCheckedFacts, ProveReadyWitness};
