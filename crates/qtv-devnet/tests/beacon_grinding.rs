// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

fn beacon_track(
    name: &str,
    params: &FeeParams,
    script: impl Fn(usize) -> u64,
    rounds: usize,
) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let base = unique_base(name);
    let alice = user(0);
    let bob = user(1);
    let sink = user(2);
    let accounts = vec![
        GenesisAccount::from_account(&alice, 100_000_000),
        GenesisAccount::from_account(&bob, 100_000_000),
    ];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    for round in 0..rounds {
        let tx = transfer(&alice, &sink.address(), script(round), round as u64, params);
        devnet.submit(round % devnet.len(), tx).expect("admitted");
        devnet.step().expect("finalized");
    }

    let seeds = devnet
        .node(0)
        .chain()
        .iter()
        .map(|b| *b.header().beacon_seed())
        .collect();
    let hashes = devnet
        .node(0)
        .chain()
        .iter()
        .map(|b| b.header_hash())
        .collect();
    (seeds, hashes)
}

#[test]
fn block_content_cannot_shift_the_next_beacon() {
    let params = FeeParams::devnet();
    let rounds = 8;

    let (seeds_a, hashes_a) = beacon_track("grind-a", &params, |round| 1_000 + round as u64, rounds);
    let (seeds_b, hashes_b) =
        beacon_track("grind-b", &params, |round| 7_777 + 3 * round as u64, rounds);

    assert_eq!(seeds_a.len(), rounds, "run a finalized every round");
    assert_eq!(seeds_b.len(), rounds, "run b finalized every round");

    assert_ne!(
        hashes_a, hashes_b,
        "the two runs must commit different blocks for the check to mean anything"
    );

    assert_eq!(
        seeds_a, seeds_b,
        "block content shifted the beacon, a proposer can grind the validator draw"
    );
}
