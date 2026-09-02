use qtv_crypto::{ml_dsa, sha3};

fn chain_binding(name: &str) -> u64 {
    u64::from_be_bytes(
        sha3::sha3_256(name.as_bytes())[..8]
            .try_into()
            .expect("eight"),
    )
}

fn main() {
    let name = std::env::args().nth(1).expect("chain name");
    let out = std::env::args().nth(2).expect("secret out path");
    let cid = chain_binding(&name);
    let mut secrets = String::new();
    for id in 0u32..3 {
        let mut seed = [0u8; 32];
        let base = sha3::sha3_256(format!("{name}/bridge/operator/{id}").as_bytes());
        seed.copy_from_slice(&base);
        let (pk, sk) = ml_dsa::keygen(&seed);
        let pop = ml_dsa::sign(
            &sk,
            &qtv_node::bridge::operator_pop_challenge(id, &pk, cid),
            qtv_node::bridge::POP_DOMAIN,
            &[0u8; 32],
        )
        .expect("pop signs");
        println!("bridge_operator = {id} {} {}", hex(&pk), hex(&pop));
        secrets.push_str(&format!("operator {id} seed {}\n", hex(&seed)));
    }
    std::fs::write(&out, secrets).expect("write secrets");
    eprintln!("secrets written to {out}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
