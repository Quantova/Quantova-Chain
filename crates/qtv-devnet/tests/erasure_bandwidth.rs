// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_block::{empty_transaction_root, transaction_root, Block as ChainBlock, Header};
use qtv_codec::to_bytes;
use qtv_node::fee::FeeParams;
use qtv_tx::Wrapper;

use qtv_devnet::coded::{code_block, per_node_bandwidth, reconstruct_block};

use support::{transfer, user};

const K: usize = 16;
const N: usize = 32;

const NODES: usize = 32;

fn realistic_block(count: usize) -> (ChainBlock, usize) {
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let mut body: Vec<Wrapper> = Vec::with_capacity(count);
    for i in 0..count {
        body.push(transfer(
            &alice,
            &bob.address(),
            1_000 + i as u64,
            i as u64,
            &params,
        ));
    }
    let per_tx = to_bytes(&body[0]).len();
    let header = Header::new(
        7,
        [1u8; 32],
        [2u8; 32],
        transaction_root(&body),
        empty_transaction_root(),
        [3u8; 32],
        alice.address(),
        1_700_000_000_000,
    );
    let block = ChainBlock::new(header, vec![90u8; 4096], body);
    (block, per_tx)
}

#[test]
fn erasure_coding_cuts_the_per_node_block_download() {
    let (block, per_tx) = realistic_block(200);
    let whole_block = to_bytes(&block).len();

    let coded = code_block(&block, K, N).expect("code the block");
    let bandwidth = per_node_bandwidth(&coded, whole_block, NODES);

    assert!(
        bandwidth.erasure_coded < whole_block,
        "erasure coded download {} was not below the whole block {}",
        bandwidth.erasure_coded,
        whole_block
    );

    let pieces: Vec<_> = (N - K..N).map(|i| coded.piece(i).expect("index within shard_count")).collect();
    let rebuilt = reconstruct_block(
        coded.header(),
        &coded.header_hash(),
        coded.commitment(),
        &pieces,
    )
    .expect("reconstruct from k shards");
    assert_eq!(
        rebuilt, block,
        "the reconstructed block was not byte identical"
    );

    let factor = bandwidth.saving_factor();
    assert!(
        factor > 12.0,
        "the per node saving factor {factor:.2} fell short of the expected range"
    );

    let projected_txs = 15_000usize;
    let projected_block = projected_txs * per_tx;
    let projected_shard = projected_block.div_ceil(K);
    let metadata = to_bytes(block.header()).len() + 64 + 5 * 32;
    let projected_per_node = projected_shard + metadata;
    let projected_factor = projected_block as f64 / projected_per_node as f64;

    println!("--- erasure coded block propagation, k {K} of n {N} ---");
    println!("measured on a real {}-transaction block", 200);
    println!("  per transaction bytes      {per_tx}");
    println!("  whole block bytes          {whole_block}");
    println!(
        "  per node erasure coded     {} (header + commitment + one shard)",
        bandwidth.erasure_coded
    );
    println!("  per node saving factor     {factor:.2}x");
    println!("projected onto a {projected_txs}-transaction block at the throughput target");
    println!("  whole block bytes          {projected_block}");
    println!("  per node erasure coded     {projected_per_node}");
    println!("  per node saving factor     {projected_factor:.2}x");

    assert!(projected_factor > 15.0);
}
