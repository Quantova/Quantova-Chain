// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An over bound block finalizes end to end over the coded dissemination path.
//!
//! An over bound block is one whose body exceeds the one mebibyte qtv-net record
//! plaintext bound, so it cannot travel as a single sealed record. The old whole
//! proposal path could not carry such a block; the coded dissemination path codes the
//! block into k data shards and n minus k parity shards under a SHA3 commitment,
//! disperses the shards over the overlay each within the record bound, and rebuilds
//! the block on receipt from any k shards against the header. This test drives a real
//! over bound block through the real devnet all the way to a finalized block: the
//! block is proposed as coded shards, reassembled, attested, and finalized under a
//! real aggregated certificate, and a node that took no part in the round verifies
//! that certificate over the whole reconstructed block through the trustless sync
//! verifier. It is the committed end to end demonstration that dropping the block
//! width cap holds in a finalized chain, not only in the coding units: the over bound
//! block finalizes, its transactions are in the finalized chain on every node, and the
//! block could not have traveled as a single record.

mod support;

use qtv_codec::to_bytes;
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::Wrapper;

use qtv_bft::params::is_quorum;
use qtv_devnet::wire::{Message, Proposal};
use qtv_devnet::Devnet;

use support::{config, header_chain, transfer, unique_base, user};

/// The qtv-net record plaintext bound, one mebibyte. A whole proposal record above
/// this cannot be sealed by the transport, so a block wider than it can only reach
/// the committee coded into shards.
const RECORD_BOUND: usize = 1 << 20;

#[test]
fn an_over_bound_block_finalizes_over_the_coded_path() {
    let base = unique_base("over-bound-finality");
    let params = FeeParams::devnet();

    // The mempool admits a sender's next nonce only, so a wide block comes from many
    // distinct senders each sending one transfer at nonce zero, not one sender many
    // times. Measure one real signed transfer to size the sender set, then take enough
    // senders that the body runs an eighth past the record bound, comfortably over
    // bound after the header and the coding round trip rather than a hair above it.
    let recipient = user(0);
    let probe = transfer(&user(1), &recipient.address(), 1_000, 0, &params);
    let per_tx = to_bytes(&probe).len();
    let sender_count = (RECORD_BOUND + RECORD_BOUND / 8) / per_tx + 1;

    // Fund every sender and the recipient at genesis. Sender indices start at one so
    // none collides with the recipient at index zero.
    let senders: Vec<_> = (0..sender_count).map(|i| user(i as u64 + 1)).collect();
    let mut accounts = vec![GenesisAccount::from_account(&recipient, 0)];
    for account in &senders {
        accounts.push(GenesisAccount::from_account(account, 1_000_000));
    }

    // Three online validators build and finalize the height. A fourth stays offline
    // from genesis and takes no part in the round; it verifies the finalized block
    // afterward as an independent node that neither proposed nor attested it.
    let online = [true, true, true, false];
    let online_count = online.iter().filter(|&&on| on).count();
    let verifier = online.len() - 1;
    let mut devnet = Devnet::over_duplex(config(&base, &online, accounts)).expect("devnet");

    // The committee is drawn from the validators alone, fixed before the round, so a
    // real supermajority certificate can be checked against its size afterward.
    let committee = devnet
        .node(0)
        .select()
        .expect("a committee is selected")
        .members
        .len();

    // Submit one transfer from each sender, spread across the online nodes so they
    // reach the leader over the overlay rather than a direct link. Every submitted id
    // is recorded so the finalized body can be checked against the whole set.
    let mut submitted: Vec<String> = Vec::with_capacity(senders.len());
    for (i, account) in senders.iter().enumerate() {
        let tx = transfer(account, &recipient.address(), 1_000 + i as u64, 0, &params);
        submitted.push(tx.id());
        devnet.submit(i % online_count, tx).expect("admitted");
    }

    // Finalize exactly one height. The proposal for this height is over bound, so the
    // round drives the coded dissemination path end to end; a whole record proposal
    // could not have been sealed.
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

    // The finalized block is over bound. Its whole canonical encoding exceeds the
    // record bound, and the whole proposal record the pre coding path would have sealed
    // for it, its header and ordered body, exceeds the bound too, so it could not have
    // traveled as a single sealed record and only the coded shard path carries it.
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

    // A real aggregated certificate finalized the block: it names a supermajority of
    // the committee as attesters over this exact block.
    assert!(
        is_quorum(finalized.attesters.len(), committee),
        "the finalized block carried {} attesters, not a supermajority of the committee {committee}",
        finalized.attesters.len()
    );

    // Every submitted transaction is in the finalized body, on every online node, and
    // the body carries the whole set and nothing else, so no transaction was dropped
    // in the coding round trip.
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

    // The recipient balance reflects every finalized transfer, so the over bound block
    // executed to the same state on every online node.
    let expected_credit: u64 = (0..sender_count as u64).map(|i| 1_000 + i).sum();
    for i in 0..online_count {
        assert_eq!(
            devnet.node(i).ledger().balance(&recipient.address()),
            expected_credit,
            "node {i} did not execute the over bound block to the expected state"
        );
    }

    // The offline node took no part in the round. It receives the finalized over bound
    // block and verifies it through the same trustless verifier a light client uses:
    // the aggregated certificate over the whole reconstructed block under the committee
    // commitment and the beacon, the parent link, and the re executed state root, all
    // checked by the node itself before it accepts the block. It ends byte identical to
    // the nodes that built it.
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
