// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_account::derive;
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_tx::{sign, Body};

const SEED: [u8; 32] = [11u8; 32];

fn arg(n: usize, default: u64) -> u64 {
    std::env::args()
        .nth(n)
        .and_then(|a| a.parse().ok())
        .unwrap_or(default)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 15) as u32, 16).unwrap());
    }
    s
}

fn main() {
    let sender_index = arg(1, 0);
    let recipient_index = arg(2, 1);
    let nonce = arg(3, 0);
    let amount = arg(4, 1_000);

    let sender = derive(&SEED, sender_index);
    let recipient = derive(&SEED, recipient_index);

    let fee = FeeParams::devnet().transfer_fee();
    let call = transfer_call(&recipient.address(), amount);
    let body = Body::new(sender.address(), nonce, TRANSFER_METER, u128::from(fee), call);
    let wrapper = sign(&sender, &body);

    let encoded = qtv_codec::to_bytes(&wrapper);

    println!("sender_address={}", sender.address());
    println!("sender_scheme={}", sender.scheme());
    println!("sender_pubkey_hex={}", hex(sender.public_key()));
    println!("recipient_address={}", recipient.address());
    println!("amount={amount}");
    println!("fee_qgas={fee}");
    println!("tx_id={}", wrapper.id());
    println!("tx_hex={}", hex(&encoded));
}
