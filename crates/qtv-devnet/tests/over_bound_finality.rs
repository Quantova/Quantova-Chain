// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_codec::to_bytes;
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::Wrapper;

use qtv_bft::params::is_quorum;
use qtv_devnet::wire::{Message, Proposal};
use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

const RECORD_BOUND: usize = 1 << 20;

#[test]
fn an_over_bound_block_finalizes_over_the_coded_path() {
    let base = unique_base("over-bound-finality");
    let params = FeeParams::devnet();

    let recipient = user(0);
    let probe = transfer(&user(1), &recipient.address(), 1_000, 0, &params);
    let per_tx = to_bytes(&probe).len();
    let sender_count = (RECORD_BOUND + RECORD_BOUND / 8) / per_tx + 1;

    let senders: Vec<_> = (0..sender_count).map(|i| user(i as u64 + 1)).collect();
    let mut accounts = vec![GenesisAccount::from_account(&recipient, 0)];
    for account in &senders {
        accounts.push(GenesisAccount::from_account(account, 1_000_000));
    }

    let online = [true, true, true, false];
    let online_count = online.iter().filter(|&&on| on).count();
    let verifier = online.len() - 1;
    let mut devnet = Devnet::over_duplex(config(&base, &online, accounts)).expect("devnet");

    let committee = devnet
        .node(0)
        .select()
        .expect("a committee is selected")
        .members
        .len();

    let mut submitted: Vec<String> = Vec::with_capacity(senders.len());
    for (i, account) in senders.iter().enumerate() {
        let tx = transfer(account, &recipient.address(), 1_000 + i as u64, 0, &params);
        submitted.push(tx.id());
        devnet.submit(i % online_count, tx).expect("admitted");
    }

    devnet
        .step()
        .expect("the committee finalized the over bound height over the coded path");

    let chain = header_chain(devnet.node(0));
    assert_eq!(chain.len(), 1, "the over bound height did not finalize");
    for i in 1..online_count {
        assert_eq!(
            header_chain(devnet.node(i)),
            chain,
            "node {i} finalized a different chain over the coded path"
        );
    }

    let finalized = devnet.node(0).chain().last().expect("a finalized block");
    let block = &finalized.block;

    let whole_block = to_bytes(block).len();
    assert!(
        whole_block > RECORD_BOUND,
        "the finalized block {whole_block} did not exceed the record bound {RECORD_BOUND}"
    );
    let whole_proposal = Message::Proposal(Proposal {
        view: 0,
        header: block.header().clone(),
        body: block.body().to_vec(),
        justification: Vec::new(),
    })
    .encode()
    .len();
    assert!(
        whole_proposal > RECORD_BOUND,
        "the whole proposal record {whole_proposal} did not exceed the record bound {RECORD_BOUND}, \
         so the block would have fit one record and the test is not meaningful"
    );

    assert!(
        is_quorum(finalized.attesters.len(), committee),
        "the finalized block carried {} attesters, not a supermajority of the committee {committee}",
        finalized.attesters.len()
    );

    for i in 0..online_count {
        let node_block = &devnet.node(i).chain().last().expect("a finalized block").block;
        let ids: std::collections::HashSet<String> =
            node_block.body().iter().map(Wrapper::id).collect();
        assert_eq!(
            node_block.body().len(),
            submitted.len(),
            "node {i} finalized a different transaction count than was submitted"
        );
        for id in &submitted {
            assert!(
                ids.contains(id),
                "node {i} did not finalize a submitted transaction"
            );
        }
    }

    let expected_credit: u64 = (0..sender_count as u64).map(|i| 1_000 + i).sum();
    for i in 0..online_count {
        assert_eq!(
            devnet.node(i).ledger().balance(&recipient.address()),
            expected_credit,
            "node {i} did not execute the over bound block to the expected state"
        );
    }

    let height = block.header().height();
    let served = devnet.served_blocks(0, height, height);
    let over_bound = served
        .into_iter()
        .next()
        .expect("the finalized over bound block is served");
    assert!(
        to_bytes(&over_bound).len() > RECORD_BOUND,
        "the served block was not the over bound block"
    );
    devnet
        .apply_synced(verifier, over_bound)
        .expect("the offline node verified the aggregated certificate over the whole over bound block");
    assert_eq!(
        header_chain(devnet.node(verifier)),
        chain,
        "the offline node did not verify and reproduce the over bound block"
    );
    assert_eq!(
        devnet.node(verifier).ledger().balance(&recipient.address()),
        expected_credit,
        "the offline node did not reach the same state after verifying the over bound block"
    );
}
