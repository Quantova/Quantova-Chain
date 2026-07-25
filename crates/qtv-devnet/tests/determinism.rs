// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The same inputs give the same finalized chain across a run.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, encoded_chain, transfer, unique_base, user};

/// Run one fixed script over a fresh devnet and return the finalized chain bytes
/// and the final state root every node ends on.
fn run_scripted(name: &str, params: &FeeParams) -> (Vec<Vec<u8>>, [u8; 32]) {
    let base = unique_base(name);
    let alice = user(0);
    let carol = user(1);
    let dave = user(2);
    let accounts = vec![
        GenesisAccount::from_account(&alice, 1_000_000),
        GenesisAccount::from_account(&carol, 500_000),
    ];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let script = [
        (&alice, dave.address(), 3_000u64, 0u64),
        (&carol, dave.address(), 1_500u64, 0u64),
    ];
    for (index, (from, to, amount, nonce)) in script.iter().enumerate() {
        let tx = transfer(from, to, *amount, *nonce, params);
        // Submit each to a different node to exercise propagation.
        devnet.submit(index % devnet.len(), tx).expect("admitted");
        devnet.step().expect("finalized");
    }

    (
        encoded_chain(devnet.node(0)),
        devnet.node(0).ledger().state_root(),
    )
}

#[test]
fn the_same_inputs_give_the_same_finalized_chain() {
    let params = FeeParams::devnet();
    let one = run_scripted("determinism-one", &params);
    let two = run_scripted("determinism-two", &params);
    assert_eq!(one.0, two.0, "the finalized chains differ across runs");
    assert_eq!(one.1, two.1, "the final state roots differ across runs");
}
