// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The per node bandwidth an erasure coded block costs against downloading the
//! whole block.
//!
//! Today a block spreads whole, so every node downloads every byte of it. This
//! measures the alternative on a real block: the block is coded into k data shards
//! and n minus k parity shards, committed under a SHA3 Merkle root, and dispersed
//! over the overlay so each node holds one shard. The per node download is that
//! shard, the header, and the commitment, each counted from its real canonical
//! encoding, against the whole block every node downloads today. The measurement
//! reconstructs the block from a subset of k shards and checks it byte for byte
//! against the header, so the saving is measured on genuine coding and genuine
//! reconstruction, not an estimate.

mod support;

use qtv_block::{empty_transaction_root, transaction_root, Block as ChainBlock, Header};
use qtv_codec::to_bytes;
use qtv_node::fee::FeeParams;
use qtv_tx::Wrapper;

use qtv_devnet::coded::{code_block, per_node_bandwidth, reconstruct_block};

use support::{transfer, user};

/// The coding rate, sixteen data shards extended to thirty two, so any sixteen of
/// the thirty two reconstruct the block and up to sixteen shards may be lost. This is
/// a half rate code, the redundancy a data availability layer commonly runs.
const K: usize = 16;
const N: usize = 32;

/// The number of nodes the shards disperse across, one custodian per shard, so each
/// node holds exactly one of the thirty two shards.
const NODES: usize = 32;

/// A block whose body holds `count` real signed transfers and a header that commits
/// to that body through the transaction root. Each transfer carries a real module
/// lattice signature, so the block bytes and the shard bytes are the genuine size a
/// block runs to, not a toy.
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
    // A certificate slot the size of a finality certificate, so the coded block is
    // the whole finalized block, not only its body.
    let block = ChainBlock::new(header, vec![90u8; 4096], body);
    (block, per_tx)
}

#[test]
fn erasure_coding_cuts_the_per_node_block_download() {
    // A block of two hundred real transfers, enough that a shard dwarfs the header
    // and the commitment, so the measured saving is not flattered by a tiny block.
    let (block, per_tx) = realistic_block(200);
    let whole_block = to_bytes(&block).len();

    let coded = code_block(&block, K, N).expect("code the block");
    let bandwidth = per_node_bandwidth(&coded, whole_block, NODES);

    // No node downloads the whole block: the per node figure is well under it.
    assert!(
        bandwidth.erasure_coded < whole_block,
        "erasure coded download {} was not below the whole block {}",
        bandwidth.erasure_coded,
        whole_block
    );

    // The block reconstructs byte for byte from a subset of k shards and verifies
    // against the header, so the saving rests on genuine reconstruction.
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
    // A half rate code over sixteen data shards saves close to a factor of k. The
    // header, the commitment, and the proof cost a little, so the realized factor
    // sits a touch under k rather than exactly at it.
    assert!(
        factor > 12.0,
        "the per node saving factor {factor:.2} fell short of the expected range"
    );

    // Project the same coding onto a block at the throughput target: a hundred
    // thousand transactions a second over a hundred and fifty millisecond slot is
    // fifteen thousand transactions a block. The per transaction size is measured, so
    // the projected block bytes are real.
    let projected_txs = 15_000usize;
    let projected_block = projected_txs * per_tx;
    let projected_shard = projected_block.div_ceil(K);
    // The metadata a node still downloads at scale: the header and the commitment are
    // fixed, the proof grows with the log of the shard count.
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
