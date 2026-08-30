// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::DevNode;
use qtv_devnet::wire::RevealNote;
use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

fn open_nodes(config: &DevnetConfig) -> Vec<DevNode> {
    config
        .nodes
        .iter()
        .map(|node| DevNode::open(node, config).expect("node opens"))
        .collect()
}

#[test]
fn a_node_forms_the_committee_from_published_reveals_and_verifies_them() {
    let base = unique_base("published-reveal");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let cfg = config(&base, &[true, true, true, true], accounts);
    let nodes = open_nodes(&cfg);

    let notes: Vec<RevealNote> = nodes
        .iter()
        .map(|node| {
            node.own_reveal_note()
                .expect("a selected validator publishes")
        })
        .collect();
    assert_eq!(notes.len(), 4);

    let mut node1 = open_nodes(&cfg).into_iter().next().expect("node one");
    for note in &notes {
        node1.collect_reveal(note.clone());
    }
    let full = node1.select().expect("committee");
    assert_eq!(full.members, vec![1, 2, 3, 4]);

    let mut mislabeller = open_nodes(&cfg).into_iter().next().expect("node one");
    let three = notes.iter().find(|n| n.id == 3).unwrap().clone();
    let two_note = notes.iter().find(|n| n.id == 2).unwrap();
    let mislabelled = RevealNote {
        height: two_note.height,
        id: 2,
        credential: three.credential.clone(),
    };
    mislabeller.collect_reveal(notes.iter().find(|n| n.id == 1).unwrap().clone());
    mislabeller.collect_reveal(mislabelled);
    let after = mislabeller
        .select()
        .expect("committee of the ones that authenticate");
    assert!(after.members.contains(&1));
    assert!(!after.members.contains(&2));

    let mut liveness = open_nodes(&cfg).into_iter().next().expect("node one");
    for note in notes.iter().filter(|n| n.id != 2) {
        liveness.collect_reveal(note.clone());
    }
    let without_two = liveness.select().expect("committee");
    assert!(without_two.members.contains(&1));
    assert!(without_two.members.contains(&3));
    assert!(without_two.members.contains(&4));
    assert!(!without_two.members.contains(&2));
}

#[test]
fn a_multi_node_run_holding_only_own_secrets_finalises() {
    let base = unique_base("published-reveal-run");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let heights = 3u64;
    for nonce in 0..heights {
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted at the origin node");
        devnet
            .step()
            .expect("the committee finalised the height from published reveals");
    }

    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len(), heights as usize);
    for i in 0..devnet.len() {
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "node {i} finalised a different chain"
        );
        for finalized in devnet.node(i).chain() {
            assert!(
                finalized.attesters.len() >= 3,
                "at least a two thirds quorum attested"
            );
            assert!(
                finalized
                    .attesters
                    .iter()
                    .all(|a| [1u64, 2, 3, 4].contains(a)),
                "every attester is a committee member"
            );
        }
    }
    assert_eq!(
        devnet.node(0).ledger().balance(&bob.address()),
        heights * 1_000
    );
}

#[test]
fn a_fresh_reveal_forwards_once_and_a_duplicate_or_forgery_does_not() {
    let base = unique_base("reveal-regossip");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let cfg = config(&base, &[true, true, true, true], accounts);
    let nodes = open_nodes(&cfg);
    let notes: Vec<RevealNote> = nodes
        .iter()
        .map(|node| {
            node.own_reveal_note()
                .expect("a selected validator publishes")
        })
        .collect();

    let mut node1 = open_nodes(&cfg).into_iter().next().expect("node one");
    let peer = notes.iter().find(|n| n.id == 2).unwrap().clone();
    assert!(
        node1.collect_reveal(peer.clone()),
        "a fresh reveal is accepted, so a node re gossips it exactly once"
    );
    assert!(
        !node1.collect_reveal(peer),
        "a duplicate reveal is dropped, so the re gossip can never loop"
    );

    let three = notes.iter().find(|n| n.id == 3).unwrap();
    let forged = RevealNote {
        height: three.height,
        id: 4,
        credential: three.credential.clone(),
    };
    assert!(
        !node1.collect_reveal(forged),
        "a reveal that does not authenticate is refused, so it is never forwarded"
    );
}
