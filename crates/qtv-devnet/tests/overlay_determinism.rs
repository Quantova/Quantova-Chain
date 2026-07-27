// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Determinism over the overlay. The same logical schedule over the same bounded
//! overlay gives the same finalized chain and the same state every run, so a run
//! replays identically rather than racing.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config_with_fanout, encoded_chain, transfer, unique_base, user};

const NODES: usize = 5;
const FANOUT: usize = 2;

/// Run one fixed script over a fresh bounded overlay and return the finalized chain
/// and the final state root.
fn run_scripted(name: &str, params: &FeeParams) -> (Vec<Vec<u8>>, [u8; 32]) {
    let base = unique_base(name);
    let alice = user(0);
    let carol = user(1);
    let dave = user(2);
    let accounts = vec![
        GenesisAccount::from_account(&alice, 1_000_000),
        GenesisAccount::from_account(&carol, 500_000),
    ];
    let online = vec![true; NODES];
    let mut devnet =
        Devnet::over_duplex(config_with_fanout(&base, &online, accounts, FANOUT)).expect("devnet");

    let script = [
        (&alice, dave.address(), 3_000u64, 0u64),
        (&carol, dave.address(), 1_500u64, 0u64),
        (&alice, carol.address(), 2_000u64, 1u64),
    ];
    for (index, (from, to, amount, nonce)) in script.iter().enumerate() {
        let tx = transfer(from, to, *amount, *nonce, params);
        devnet.submit(index % devnet.len(), tx).expect("admitted");
        devnet.step().expect("finalized");
    }

    (
        encoded_chain(devnet.node(0)),
        devnet.node(0).ledger().q_root(),
    )
}

#[test]
fn the_same_schedule_over_the_overlay_gives_the_same_chain() {
    let params = FeeParams::devnet();
    let one = run_scripted("overlay-determinism-one", &params);
    let two = run_scripted("overlay-determinism-two", &params);
    assert_eq!(one.0, two.0, "the finalized chains differ across runs");
    assert_eq!(one.1, two.1, "the final state roots differ across runs");
    assert_eq!(
        one.0.len(),
        3,
        "every scripted height finalized over the overlay"
    );
}
