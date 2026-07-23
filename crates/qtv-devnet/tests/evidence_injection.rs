//! The block leader carries the equivocation it attributed into the block it produces, so
//! every node that executes the block slashes the offender from the block alone.

mod support;

use qtv_attest::Attester;
use qtv_devnet::config::DEFAULT_SLOTS;
use qtv_devnet::node::DevNode;
use qtv_node::consensus::{genesis_beacon, Block, Parent};
use qtv_node::ledger::evidence_address;
use qtv_node::node::{day_of_height, execute_ordered};

use support::{config, unique_base, VALIDATOR_STAKE};

#[test]
fn the_leader_carries_attributed_evidence_into_the_block_it_produces() {
    let base = unique_base("evidence-injection");
    let cfg = config(&base, &[true, true, true, true], vec![]);

    let open = || {
        cfg.nodes
            .iter()
            .map(|node| DevNode::open(node, &cfg).expect("node opens"))
            .collect::<Vec<_>>()
    };

    // The leader collects every peer's reveal so it draws a full committee.
    let reveals: Vec<_> = open()
        .iter()
        .map(|node| node.own_reveal_note().expect("a selected validator publishes"))
        .collect();
    let mut leader = open().into_iter().next().expect("the leader node");
    for note in &reveals {
        leader.collect_reveal(note.clone());
    }

    let offender_id = 2u64;
    let offender = qtv_node::keys::validator_address(&qtv_node::keys::fixture_secret(offender_id));
    assert!(
        leader.ledger().staked_weight(&offender) > 0,
        "the offender starts bonded"
    );
    assert!(!leader.ledger().is_validator_banned(&offender));

    // Feed the leader the two conflicting attestations the offender signed at this height.
    let secret = qtv_node::keys::fixture_secret(offender_id);
    let attester =
        Attester::from_secret_with_slots(offender_id, &secret, VALIDATOR_STAKE, DEFAULT_SLOTS);
    let beacon = genesis_beacon();
    let height = leader.height();
    let block_a = Block::new(height, [1u8; 32], Parent::Genesis);
    let block_b = Block::new(height, [2u8; 32], Parent::Genesis);
    leader.on_attestation(attester.attest(height, 1, block_a, &beacon));
    leader.on_attestation(attester.attest(height, 1, block_b, &beacon));

    let selection = leader.select().expect("a committee forms from the reveals");
    let proposal = leader.build_proposal(&selection);

    let carried: usize = proposal
        .body
        .iter()
        .filter(|w| w.body().call().target() == evidence_address())
        .count();
    assert_eq!(carried, 1, "the produced block carries the attributed evidence");

    // Any node that executes the produced body reaches the same slash from the block alone.
    let fresh = open().into_iter().next().expect("a node that saw no attestation");
    assert!(!fresh.ledger().is_validator_banned(&offender));
    let mut ledger = fresh.ledger().clone();
    let included = execute_ordered(&mut ledger, &proposal.body, &cfg.fee_params, day_of_height(height));
    assert_eq!(included.len(), proposal.body.len(), "the whole body is included");
    assert!(
        ledger.is_validator_banned(&offender),
        "the offender is slashed by the carried evidence"
    );
    assert_eq!(ledger.staked_weight(&offender), 0, "the offender's stake is slashed");
}
