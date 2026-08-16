// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Genesis assembled from independently generated registrations. Each node draws its
//! own secret into its own keystore, publishes only its public registration, and the
//! committee forms and finalises from those published registrations. No node holds or
//! reproduces a peer secret, and no registration is a function of the validator id.

mod support;

use qtv_devnet::config::{DevnetConfig, NodeConfig, DEFAULT_SLOTS, FULL_FANOUT};
use qtv_devnet::Devnet;
use qtv_node::consensus::ValidatorRegistration;
use qtv_node::fee::FeeParams;
use qtv_node::node::{GenesisAccount, ValidatorSpec};

use support::{header_chain, transfer, unique_base, user, GENESIS_TIME, VALIDATOR_STAKE};

#[test]
fn a_genesis_of_independent_registrations_finalises_and_reproduces_no_peer_secret() {
    let base = unique_base("genesis-registration");
    let n = 4usize;

    let secrets: Vec<[u8; 32]> = (1..=n as u64)
        .map(|id| {
            let keystore = base.join(format!("node-{id}")).join("keystore");
            qtv_node::keys::load_or_generate(&keystore).expect("each node draws its own secret")
        })
        .collect();

    for i in 0..n {
        for j in (i + 1)..n {
            assert_ne!(secrets[i], secrets[j], "two nodes drew the same secret");
        }
    }

    let specs: Vec<ValidatorSpec> = (0..n)
        .map(|i| {
            ValidatorSpec::from_secret(i as u64 + 1, VALIDATOR_STAKE, true, &secrets[i], DEFAULT_SLOTS)
        })
        .collect();

    for spec in &specs {
        let id_derived =
            qtv_node::keys::validator_address(&qtv_node::keys::fixture_secret(spec.id));
        assert_ne!(
            spec.bond_address, id_derived,
            "the registration is the id derived fixture, not an independently generated secret"
        );
    }

    let roster: Vec<ValidatorRegistration> =
        specs.iter().map(ValidatorRegistration::from_spec).collect();

    let alice = user(0);
    let bob = user(1);
    let nodes: Vec<NodeConfig> = (0..n)
        .map(|i| {
            let id = i as u64 + 1;
            let bootstrap = if id == 1 { vec![2] } else { vec![1] };
            NodeConfig {
                id,
                stake: VALIDATOR_STAKE,
                online: true,
                store_dir: base.join(format!("node-{id}")),
                bootstrap,
                address: format!("mem://{id}"),
                secret: secrets[i],
            }
        })
        .collect();

    let config = DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: vec![GenesisAccount::from_account(&alice, 1_000_000)],
        nodes,
        genesis_time: GENESIS_TIME,
        fanout: FULL_FANOUT,
        slots: DEFAULT_SLOTS,
        published_roster: Some(roster),
    };

    let mut devnet =
        Devnet::over_duplex(config).expect("the devnet stands up on the published roster");

    let params = FeeParams::devnet();
    for nonce in 0..3u64 {
        devnet
            .submit(0, transfer(&alice, &bob.address(), 1_000, nonce, &params))
            .expect("admitted at the origin");
        devnet
            .step()
            .expect("the committee finalised the height from published reveals");
    }

    let reference = header_chain(devnet.node(0));
    assert_eq!(reference.len(), 3);
    for i in 0..devnet.len() {
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "node {i} finalised a different chain"
        );
        for finalized in devnet.node(i).chain() {
            assert!(finalized.attesters.len() >= 3, "at least a two thirds quorum attested"); assert!(finalized.attesters.iter().all(|a| [1u64, 2, 3, 4].contains(a)), "every attester is a committee member");
        }
    }
    assert_eq!(devnet.node(0).ledger().balance(&bob.address()), 3 * 1_000);

    let _ = std::fs::remove_dir_all(&base);
}
