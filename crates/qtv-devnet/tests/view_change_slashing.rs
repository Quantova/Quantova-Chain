// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::consensus::{
    equivocation_offenders, roster_of, ConsensusValidator, ValidatorRegistration, DEFAULT_SLOTS,
};
use qtv_node::evidence::Equivocation;

use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};

use support::{config, unique_base, VALIDATOR_STAKE};

fn open_nodes(config: &DevnetConfig) -> Vec<DevNode> {
    let mut nodes: Vec<DevNode> = config
        .nodes
        .iter()
        .map(|node| DevNode::open(node, config).expect("node opens"))
        .collect();
    let notes: Vec<_> = nodes
        .iter()
        .filter_map(|node| node.own_reveal_note())
        .collect();
    for node in &mut nodes {
        for note in &notes {
            node.collect_reveal(note.clone());
        }
    }
    nodes
}

fn index_of(config: &DevnetConfig, id: u64) -> usize {
    config
        .nodes
        .iter()
        .position(|node| node.id == id)
        .expect("a node holds the id")
}

#[test]
fn an_honest_view_change_is_not_a_slashable_equivocation() {
    let base = unique_base("view-change-slashing");
    let config = config(&base, &[true, true, true, true], vec![]);
    let chain_id = config.fee_params.chain_id;
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let leader0 = leader_for(&selection, 0);
    let leader0_idx = index_of(&config, leader0);
    let victim_idx = (0..nodes.len())
        .find(|&i| i != leader0_idx)
        .expect("a non leader member");
    let victim_id = config.nodes[victim_idx].id;

    let proposal = nodes[leader0_idx].build_proposal(&selection);
    let out = nodes[victim_idx].on_proposal(&selection, leader0, proposal.clone());
    let victim_prevote = out
        .into_iter()
        .find_map(|m| match m {
            qtv_devnet::wire::Message::Prevote(att) => Some(*att),
            _ => None,
        })
        .expect("the victim prevotes the proposal");
    let mut polka = vec![victim_prevote.clone()];
    for i in 0..nodes.len() {
        if i == victim_idx {
            continue;
        }
        if let Some(qtv_devnet::wire::Message::Prevote(att)) = nodes[i]
            .on_proposal(&selection, leader0, proposal.clone())
            .into_iter()
            .next()
        {
            polka.push(*att);
        }
    }
    for prevote in &polka {
        nodes[victim_idx].on_prevote(&selection, prevote.clone());
    }
    assert_eq!(
        nodes[victim_idx].staged_view(),
        Some(0),
        "locked at view zero"
    );

    let record = nodes[victim_idx].make_view_change(2);
    assert!(record.polka.is_some(), "the view change carries the polka");
    let lock_att = victim_prevote;
    let vote = record.att.clone();

    assert_eq!(
        vote.view, lock_att.view,
        "the view change vote and the prevote share the view the victim locked in"
    );
    assert_ne!(
        vote.block, lock_att.block,
        "the view change subject and the prevote subject are two different subjects"
    );

    let roster: Vec<ValidatorRegistration> = roster_of(
        &(1..=config.nodes.len() as u64)
            .map(|id| {
                ConsensusValidator::from_secret(
                    id,
                    VALIDATOR_STAKE,
                    true,
                    qtv_node::keys::fixture_secret(id),
                )
            })
            .collect::<Vec<_>>(),
        DEFAULT_SLOTS,
    );
    let victim = roster
        .iter()
        .find(|r| r.id == victim_id)
        .expect("the victim is in the roster");

    assert!(
        equivocation_offenders(chain_id, &[vote.clone(), lock_att.clone()], &roster).is_empty(),
        "an honest view change was read as an equivocation and the signer would be slashed"
    );

    let framed = Equivocation {
        offender: victim.bond_address.clone(),
        height: vote.height,
        view_a: vote.view,
        view_b: lock_att.view,
        slot_a: vote.slot,
        slot_b: vote.slot,
        committee_a: [0u8; 32],
        committee_b: [0u8; 32],
        block_a: vote.block.to_bytes(),
        sig_a: vote.sig.to_vec(),
        block_b: lock_att.block.to_bytes(),
        sig_b: lock_att.sig.to_vec(),
    };
    assert!(
        !framed.attributes(chain_id, &victim.attest_pk),
        "the on chain slasher attributed an honest view change and would ban the signer"
    );
}
