// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

#[test]
fn an_offline_node_does_not_stall_a_supermajority_and_is_never_slashed() {
    let base = unique_base("offline");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let first_leader = devnet.peek_leader().expect("leader");
    let offline_index = (0..devnet.len())
        .rev()
        .find(|&i| devnet.node(i).id() != first_leader)
        .expect("a validator that does not lead the first height");
    let offline_id = devnet.node(offline_index).id();
    devnet.set_active(offline_index, false);

    let mut online_ids: Vec<u64> = (0..devnet.len())
        .map(|i| devnet.node(i).id())
        .filter(|&id| id != offline_id)
        .collect();
    online_ids.sort_unstable();

    let target = 2u64;
    let mut finalized = 0u64;
    let mut nonce = 0u64;
    while finalized < target {
        if devnet.peek_leader().expect("leader") == offline_id {
            break;
        }
        let tx = transfer(&alice, &bob.address(), 1_000, nonce, &params);
        devnet.submit(0, tx).expect("admitted");
        devnet
            .step()
            .expect("the online supermajority finalized despite an absence");
        finalized += 1;
        nonce += 1;
    }
    assert!(
        finalized >= 1,
        "the online nodes finalized at least one height while a node was offline"
    );

    let online: Vec<usize> = (0..devnet.len()).filter(|&i| i != offline_index).collect();
    let reference = header_chain(devnet.node(online[0]));
    for &i in &online {
        assert_eq!(
            header_chain(devnet.node(i)),
            reference,
            "an online node diverged"
        );
        for block in devnet.node(i).chain() {
            assert_eq!(block.attesters, online_ids);
            assert!(!block.attesters.contains(&offline_id));
        }
        assert!(devnet.node(i).slashed().is_empty());
    }

    assert!(devnet.node(offline_index).chain().is_empty());
    assert!(devnet.node(offline_index).slashed().is_empty());
}
