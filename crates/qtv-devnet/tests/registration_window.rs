// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_devnet::config::{DevnetConfig, NodeConfig};
use qtv_devnet::Devnet;
use qtv_node::fee::FeeParams;

use support::{header_chain, unique_base, GENESIS_TIME, VALIDATOR_STAKE};

// Eight heights an epoch, so the window for the next epoch's roots is slots 0 to 5 and the
// last two heights of every epoch carry reveals made after every root was fixed.
const SLOTS: u64 = 8;

fn config(base: &std::path::Path) -> DevnetConfig {
    let nodes = (0..4u64)
        .map(|i| {
            let id = i + 1;
            NodeConfig {
                id,
                stake: VALIDATOR_STAKE,
                online: true,
                store_dir: base.join(format!("node-{id}")),
                bootstrap: if i == 0 { vec![2] } else { vec![1] },
                address: format!("mem://{id}"),
                secret: qtv_node::keys::fixture_secret(id),
            }
        })
        .collect();
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: vec![],
        nodes,
        genesis_time: GENESIS_TIME,
        fanout: qtv_devnet::config::FULL_FANOUT,
        slots: SLOTS,
        published_roster: None,
        bridge_dest_chain: None,
        guardians: qtv_devnet::GuardianSet::default(),
        bridge_operators: None,
        bridged_assets: vec![],
        bridge_era: None,
        bridge_exit_max_amount: None,
    }
}

fn step_to(devnet: &mut Devnet<qtv_net::DuplexStream>, height: u64, ctx: &str) {
    while devnet.node(0).height() < height {
        devnet
            .step()
            .unwrap_or_else(|e| panic!("{ctx}: stalled at {}: {e:?}", devnet.node(0).height()));
    }
}

fn agreed_root(devnet: &Devnet<qtv_net::DuplexStream>, id: u64) -> qtv_sampler::onetime::Root {
    let root = devnet
        .node(0)
        .roster_root(id)
        .expect("every validator is on the roster");
    for i in 1..devnet.len() {
        assert_eq!(
            devnet.node(i).roster_root(id),
            Some(root),
            "node {i} holds a different root for validator {id}"
        );
    }
    root
}

#[test]
fn roots_registered_inside_the_window_seat_the_next_epoch_on_every_node() {
    let mut devnet = Devnet::over_duplex(config(&unique_base("reg-window-all"))).expect("devnet");
    step_to(&mut devnet, SLOTS + 1, "into epoch one");
    for i in 0..devnet.len() {
        assert_eq!(devnet.node(i).epoch(), 1);
    }
    for j in 0..devnet.len() {
        let id = j as u64 + 1;
        assert_eq!(
            agreed_root(&devnet, id),
            devnet.node(j).own_rotated_root(1),
            "validator {id} registered in time and must be seated at its rotated root"
        );
    }
}

#[test]
fn a_validator_offline_through_the_window_sits_out_one_epoch_on_every_node_then_returns() {
    let mut devnet = Devnet::over_duplex(config(&unique_base("reg-window-miss"))).expect("devnet");
    let late = 3usize;
    let late_id = late as u64 + 1;
    let unseated = qtv_sampler::onetime::Root {
        digest: [0u8; 32],
        slots: 0,
    };

    devnet.set_active(late, false);
    // Heights 1 to 5 are the window for epoch one. Past them, a root can no longer count.
    step_to(
        &mut devnet,
        SLOTS - 2,
        "through the window without the late validator",
    );
    devnet.set_active(late, true);
    devnet.sync().expect("the late validator catches up");
    assert!(
        devnet.node(late).own_registration_note().is_none(),
        "the window is closed, so the late validator has nothing it may register"
    );

    step_to(&mut devnet, SLOTS + 1, "into epoch one");
    // Every node, the late one included, agrees it holds no seat this epoch. Its genesis
    // tree is not reused: leaves revealed in epoch zero are public and would replay.
    assert_eq!(agreed_root(&devnet, late_id), unseated);
    for j in 0..late {
        let id = j as u64 + 1;
        assert_eq!(agreed_root(&devnet, id), devnet.node(j).own_rotated_root(1));
    }
    let selection = devnet.node(0).select().expect("the other three are drawn");
    assert!(
        !selection.members.contains(&late_id),
        "an unseated validator is never drawn"
    );

    // The other three carry the epoch, and the late validator follows and registers
    // inside this epoch's window, so it is seated again from epoch two.
    step_to(&mut devnet, 2 * SLOTS + 1, "into epoch two");
    assert_eq!(
        agreed_root(&devnet, late_id),
        devnet.node(late).own_rotated_root(2),
        "the late validator registered inside the next window and is seated at its new root"
    );
    let reference = header_chain(devnet.node(0));
    for i in 0..devnet.len() {
        assert_eq!(header_chain(devnet.node(i)), reference, "node {i} diverged");
    }
}

#[test]
fn a_note_that_arrives_after_the_window_closes_is_refused() {
    let mut devnet = Devnet::over_duplex(config(&unique_base("reg-window-late"))).expect("devnet");
    let late = 3usize;
    devnet.set_active(late, false);
    // Built while the late validator still sits inside the window, then held back.
    let held = devnet
        .node(late)
        .own_registration_note()
        .expect("height one is inside the window");
    step_to(&mut devnet, SLOTS - 2, "past the window");
    assert!(
        !devnet.node_mut(0).collect_registration(held),
        "a root offered once its owner could already predict the next beacon is refused"
    );
}
