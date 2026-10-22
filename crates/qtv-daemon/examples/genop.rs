// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
use qtv_crypto::{ml_dsa, sha3};

fn urandom(out: &mut [u8]) {
    if qtv_crypto::rng::try_fill_random(out).is_err() {
        eprintln!("the operating system random source is unavailable");
        std::process::exit(1);
    }
}

fn chain_binding(name: &str) -> u64 {
    u64::from_be_bytes(
        sha3::sha3_256(name.as_bytes())[..8]
            .try_into()
            .expect("eight"),
    )
}

use qtv_wipe::Zeroize;

fn main() {
    let name = std::env::args().nth(1).expect("chain name");
    let id: u32 = std::env::args()
        .nth(2)
        .expect("operator id")
        .parse()
        .expect("the operator id is a number");
    let out = std::env::args().nth(3).expect("secret out path");
    let cid = chain_binding(&name);
    let mut secrets = String::with_capacity(256);
    {
        let mut seed = [0u8; 32];
        urandom(&mut seed);
        let (pk, mut sk) = ml_dsa::keygen(&seed);
        let pop = ml_dsa::sign(
            &sk,
            &qtv_node::bridge::operator_pop_challenge(id, &pk, cid),
            qtv_node::bridge::POP_DOMAIN,
            &[0u8; 32],
        )
        .expect("pop signs");
        println!("bridge_operator = {id} {} {}", hex(&pk), hex(&pop));
        let mut rendered = hex(&seed);
        secrets.push_str("operator ");
        secrets.push_str(&id.to_string());
        secrets.push_str(" seed ");
        secrets.push_str(&rendered);
        secrets.push('\n');
        rendered.zeroize();
        sk.zeroize();
        seed.zeroize();
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&out)
            .expect("create the secrets file, owner only; an existing file is never overwritten");
        file.write_all(secrets.as_bytes()).expect("write secrets");
    }
    #[cfg(not(unix))]
    std::fs::write(&out, &secrets).expect("write secrets");
    secrets.zeroize();
    eprintln!("secrets written to {out}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
