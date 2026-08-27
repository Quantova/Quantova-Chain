// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

fn run_view_change(name: &str, params: &FeeParams) -> (Vec<[u8; 32]>, [u8; 32]) {
    let base = unique_base(name);
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let silent = devnet.peek_leader().expect("view zero leader");
    let silent_index = devnet.index_of(silent).expect("silent leader is a node");
    devnet.set_silent(silent_index, true);

    let tx = transfer(&alice, &bob.address(), 1_000, 0, params);
    devnet.submit(0, tx).expect("admitted");
    devnet.step().expect("finalized through the view change");

    (
        header_chain(devnet.node(0)),
        devnet.node(0).ledger().q_root(),
    )
}

#[test]
fn a_view_change_replays_to_the_same_chain() {
    let params = FeeParams::devnet();
    let one = run_view_change("vc-determinism-one", &params);
    let two = run_view_change("vc-determinism-two", &params);
    assert_eq!(
        one.0.len(),
        1,
        "the view change did not finalize the height"
    );
    assert_eq!(
        one.0, two.0,
        "the view change finalized different chains across runs"
    );
    assert_eq!(
        one.1, two.1,
        "the view change reached different state roots across runs"
    );
}
