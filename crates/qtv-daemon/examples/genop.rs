// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
use qtv_crypto::{ml_dsa, sha3};
use std::io::Read;

/// Operator secrets come from the operating system's entropy, never from anything
/// derivable. Seeding these from the chain name meant every secret key could be
/// recomputed by anyone who knew the name, which is public, so the whole operator
/// quorum was forgeable by any observer.
fn urandom(n: usize) -> Vec<u8> {
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    let mut b = vec![0u8; n];
    f.read_exact(&mut b).expect("read /dev/urandom");
    b
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
    let out = std::env::args().nth(2).expect("secret out path");
    let cid = chain_binding(&name);
    let mut secrets = String::new();
    for id in 0u32..3 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&urandom(32));
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
        secrets.push_str(&format!("operator {id} seed {rendered}\n"));
        rendered.zeroize();
        sk.zeroize();
        seed.zeroize();
    }
    // Owner only, not the process umask.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&out)
            .expect("open the secrets file owner only");
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
