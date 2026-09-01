// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::node::GenesisAccount;

use qtv_devnet::node::{DevNode, RoundError};

use support::{config, unique_base, user};

#[test]
fn a_genesis_above_the_ceiling_is_refused_rather_than_bricking_the_mint() {
    let base = unique_base("genesis-over-supply");
    let whale = user(0);
    let accounts = vec![GenesisAccount::from_account(
        &whale,
        qtv_staking::MAX_SUPPLY,
    )];
    let cfg = config(&base, &[true], accounts);
    match DevNode::open(&cfg.nodes[0], &cfg) {
        Err(RoundError::GenesisOverSupply { supply, max }) => {
            assert!(supply > max, "the refusal carries the offending supply");
            assert_eq!(
                max,
                qtv_staking::MAX_SUPPLY,
                "the ceiling is the staking cap"
            );
        }
        Err(other) => panic!("a genesis above the ceiling must be refused, got {other:?}"),
        Ok(_) => panic!("a genesis above the ceiling must be refused, it opened"),
    }
}

#[test]
fn a_genesis_below_the_ceiling_opens_and_keeps_room_to_mint() {
    let base = unique_base("genesis-under-cap");
    let holder = user(0);
    let funded = 400_000 * qtv_staking::NATIVE_UNIT as u64;
    let accounts = vec![GenesisAccount::from_account(&holder, funded)];
    let cfg = config(&base, &[true], accounts);
    let node = DevNode::open(&cfg.nodes[0], &cfg).expect("a genesis below the ceiling opens");
    assert!(
        node.genesis_supply() < qtv_staking::MAX_SUPPLY,
        "a chain that starts at its ceiling can never mint again"
    );
    assert!(
        node.genesis_supply() >= funded,
        "the funded holder counts toward supply"
    );
}
