// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::time::Instant;

use qtv_account::{derive, Account as KeyAccount};
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{Account, Ledger};
use qtv_node::mempool::{Mempool, DEFAULT_MEMPOOL_CAP, DEFAULT_PER_SENDER_CAP};
use qtv_tx::{sign, Body, Wrapper};

const SEED: [u8; 32] = [77u8; 32];
const BATCH: u64 = 4_000;
const ROUNDS: u64 = 8;

fn keypair(index: u64) -> KeyAccount {
    derive(&SEED, index)
}

fn fund(ledger: &mut Ledger, account: &KeyAccount, balance: u64) {
    ledger.set_account(
        &account.address(),
        &Account::funded(balance, account.scheme(), account.public_key().to_vec()),
    );
}

fn transfer(from: &KeyAccount, to: &str, fee: u128) -> Wrapper {
    let body = Body::new(from.address(), 0, TRANSFER_METER, fee, transfer_call(to, 100));
    sign(from, &body)
}

fn main() {
    let params = FeeParams::devnet();
    let fee = u128::from(params.transfer_fee());
    let mut ledger = Ledger::new();
    let mut pool = Mempool::with_limits(DEFAULT_MEMPOOL_CAP, DEFAULT_PER_SENDER_CAP, 512);
    let recipient = keypair(9_999_999);

    let mut batches = Vec::new();
    for round in 0..ROUNDS {
        let mut batch = Vec::new();
        for i in 0..BATCH {
            let sender = keypair(round * BATCH + i);
            fund(&mut ledger, &sender, 10_000_000_000);
            batch.push(transfer(&sender, &recipient.address(), fee));
        }
        batches.push(batch);
    }

    println!("admission cost against pool depth, cap {DEFAULT_MEMPOOL_CAP}");
    for batch in batches {
        let before = pool.pending_len();
        let start = Instant::now();
        for wrapper in batch {
            let _ = pool.admit(wrapper, &ledger, &params);
        }
        let micros = start.elapsed().as_micros() / BATCH as u128;
        println!(
            "depth {before:>6} -> {:>6}   {micros:>6} us/tx",
            pool.pending_len()
        );
    }
}
