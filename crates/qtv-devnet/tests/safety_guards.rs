// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_devnet::{DevNode, Fatal};

use support::{config, unique_base};

#[test]
fn a_restarted_devnode_refuses_to_re_sign_a_height_it_already_signed() {
    let base = unique_base("resign-guard");
    let cfg = config(&base, &[true], vec![]);

    let watermark = cfg.nodes[0].store_dir.join("sign.watermark");
    {
        let mut node = DevNode::open(&cfg.nodes[0], &cfg).expect("open");
        // Entering a round only signs when this node leads the view, and the draw is not
        // something the test controls. Drive rounds until it has signed, so the restart
        // below is always testing the guard rather than an empty watermark.
        for _ in 0..16 {
            let selection = node.select().expect("a committee is selected");
            let _ = node.enter_round(&selection, true);
            if watermark.exists() {
                break;
            }
        }
        assert_eq!(
            node.height(),
            1,
            "the node signed height one but did not finalise it"
        );
        assert!(
            node.fatal().is_none(),
            "signing the first height is permitted"
        );
    }

    // Without a watermark the reopen below finds nothing to refuse, which looks identical
    // to the guard being broken. Height one is also the starting height, so it cannot
    // stand in for this.
    assert!(
        watermark.exists(),
        "sixteen rounds wrote no signing watermark, so the restart below would prove \
         nothing about the double sign guard"
    );

    let mut restarted = DevNode::open(&cfg.nodes[0], &cfg).expect("reopen");
    assert_eq!(
        restarted.height(),
        1,
        "an empty block store brings the restarted node back to genesis height"
    );
    let selection = restarted.select().expect("a committee is selected");
    let _ = restarted.enter_round(&selection, true);
    assert!(
        matches!(
            restarted.fatal(),
            Some(Fatal::DoubleSignRefused { height: 1, .. })
        ),
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
    assert!(
        node.fatal().is_some(),
        "the node stays halted after the violation"
    );
}
