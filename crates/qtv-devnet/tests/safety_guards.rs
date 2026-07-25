// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The running node consults the persistent anti double sign watermark before every
//! signature and the finality ledger on every certificate, and treats a refusal or a
//! finality violation as a fatal halt.

mod support;

use qtv_devnet::{DevNode, Fatal};

use support::{config, unique_base};

#[test]
fn a_restarted_devnode_refuses_to_re_sign_a_height_it_already_signed() {
    let base = unique_base("resign-guard");
    let cfg = config(&base, &[true], vec![]);

    {
        let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");
        let selection = node.select().expect("a committee is selected");
        let _ = node.enter_round(&selection, true);
        assert_eq!(node.height(), 1, "the node signed height one but did not finalise it");
        assert!(node.fatal().is_none(), "signing the first height is permitted");
        // Drop the node without finalising, so nothing lands in the block store but the
        // sign watermark is persisted at height one.
    }

    let mut restarted = DevNode::open(&cfg.nodes[0], &cfg).expect("reopen");
    assert_eq!(
        restarted.height(),
        1,
        "an empty block store brings the restarted node back to genesis height"
    );
    let selection = restarted.select().expect("a committee is selected");
    let _ = restarted.enter_round(&selection, true);
    assert!(
        matches!(restarted.fatal(), Some(Fatal::DoubleSignRefused { height: 1, .. })),
        "the persisted watermark did not refuse re signing a height already signed, got {:?}",
        restarted.fatal()
    );
}

#[test]
fn a_conflicting_certificate_halts_the_running_devnode() {
    let base = unique_base("finality-halt");
    let cfg = config(&base, &[true], vec![]);
    let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");

    let selection = node.select().expect("a committee is selected");
    let _ = node.enter_round(&selection, true);
    assert!(
        node.try_finalize(&selection).expect("finalize"),
        "the single member committee finalises height one"
    );
    assert_eq!(node.height(), 2);
    assert!(node.fatal().is_none());

    let finalized = node.chain().last().expect("a finalised block");
    let value = qtv_node::consensus::header_value(&finalized.header_hash());

    assert!(
        node.observe_certificate(1, value).is_none(),
        "the same certificate re confirms without alarm"
    );
    assert!(node.fatal().is_none());

    let mut conflicting = value;
    conflicting[0] ^= 0xFF;
    let fatal = node
        .observe_certificate(1, conflicting)
        .expect("a conflicting certificate at a finalised height halts the node");
    assert!(
        matches!(fatal, Fatal::FinalityViolation { height: 1, .. }),
        "expected a finality violation, got {fatal:?}"
    );
    assert!(node.fatal().is_some(), "the node stays halted after the violation");
}
