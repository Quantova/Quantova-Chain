#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::env;
use std::fs;

use qtv_account::{address_for_key, derive};
use qtv_codec::to_bytes;
use qtv_crypto::ml_dsa::{self, SECRET_KEY_BYTES};
use qtv_governance::Action;
use qtv_node::bridge::{
    attest_context, operator_pop_challenge, quorum_attests, Attestation, Direction, Fact,
    MintArtifact, OperatorSet, SignerSig, FACT_VERSION, POP_DOMAIN,
};
use qtv_node::ledger::bridge_mint_address;
use qtv_node::node::{build_guardian_enact_tx, guardian_enact_challenge};
use qtv_tx::{sign, Body, Call};
use qtv_wipe::{Zeroize, Zeroizing};

const MINT_METER: u64 = 5_000_000;
const GUARDIAN_DOMAIN: &[u8] = b"QUANTOVA/Q/BRIDGE-GUARDIAN/v1";

fn urandom(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    qtv_crypto::rng::fill_random(&mut b);
    b
}

fn push_hex(out: &mut String, b: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for x in b {
        out.push(DIGITS[(x >> 4) as usize] as char);
        out.push(DIGITS[(x & 15) as usize] as char);
    }
}

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    push_hex(&mut s, b);
    s
}

fn write_private(path: &str, contents: &[u8]) {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create the secret file, owner only; an existing file is never overwritten");
        file.write_all(contents).expect("write the secret file");
    }
    #[cfg(not(unix))]
    fs::write(path, contents).expect("write the secret file");
}

fn fact_from(a: &[String]) -> Fact {
    Fact {
        version: FACT_VERSION,
        source_chain: a[0].parse().expect("source_chain"),
        dest_chain: a[1].parse().expect("dest_chain"),
        route_id: a[2].parse().expect("route_id"),
        direction: Direction::Deposit,
        nonce: a[3].parse().expect("nonce"),
        source_ref: unhex(&a[4]).try_into().expect("source_ref 32 bytes"),
        asset_id: unhex(&a[5]).try_into().expect("asset 16 bytes"),
        amount: a[6].parse().expect("amount"),
        recipient: unhex(&a[7]).try_into().expect("recipient 32 bytes"),
        finality_depth: 0,
        observed_height: a[9].parse().expect("observed"),
        expiry_height: a[8].parse().expect("expiry"),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) || !s.len().is_multiple_of(2) {
        fail("a hex argument has an odd length or a non hex character");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .unwrap_or_else(|_| fail("a hex argument has a non hex character"))
        })
        .collect()
}

fn fail(msg: &str) -> ! {
    eprintln!("qtv-oracle: {msg}");
    std::process::exit(1);
}

fn private_text(path: &str) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(|e| format!("reading {path}: {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "the secret file {path} is readable by group or others, restrict it with chmod 600"
            ));
        }
    }
    fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))
}

fn read_private(path: &str) -> Zeroizing<String> {
    Zeroizing::new(private_text(path).unwrap_or_else(|e| fail(&e)))
}

fn read_seed(path: &str) -> [u8; 32] {
    let text = read_private(path);
    let mut bytes = unhex(text.trim());
    if bytes.len() != 32 {
        bytes.zeroize();
        fail("the relayer seed file must hold 32 bytes as hex");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.zeroize();
    seed
}

fn keygen(a: &[String]) {
    if a.len() != 4 {
        fail("keygen <n> <threshold> <chain_id> <out_prefix>");
    }
    let n: u32 = a[0].parse().expect("n");
    let threshold: u32 = a[1].parse().expect("threshold");
    let chain_id: u64 = a[2].parse().expect("chain_id");
    let prefix = &a[3];
    if n == 0 {
        fail("keygen needs at least one operator");
    }
    if threshold == 0 || threshold > n {
        fail("the threshold must be at least one and at most the operator count");
    }
    if threshold * 2 <= n {
        fail("the threshold must be more than half the operators, otherwise two quorums can disagree");
    }
    let mut committee = format!("{threshold}\n");
    for id in 0..n {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&urandom(32));
        let (pk, mut sk) = ml_dsa::keygen(&seed);
        let pop = ml_dsa::sign(
            &sk,
            &operator_pop_challenge(id, &pk, chain_id),
            POP_DOMAIN,
            &[0u8; 32],
        )
        .expect("pop");
        let mut secret = Zeroizing::new(String::with_capacity(2 * SECRET_KEY_BYTES + 32));
        secret.push_str(&format!("{id} {chain_id} "));
        push_hex(&mut secret, &sk);
        secret.push('\n');
        write_private(&format!("{prefix}.{id}.secret"), secret.as_bytes());
        sk.zeroize();
        seed.zeroize();
        committee.push_str(&format!("{id} {} {}\n", hexs(&pk), hexs(&pop)));
    }
    fs::write(format!("{prefix}.committee"), committee).expect("write committee");
    eprintln!("wrote {prefix}.<id>.secret for each of {n} operators + {prefix}.committee (threshold {threshold}, chain {chain_id})");
}

fn attest(a: &[String]) {
    if a.len() != 13 {
        fail("attest <operator_secret> <chain_id> <source_chain> <dest_chain> <route_id> <nonce> <source_ref_hex> <asset_hex> <amount> <recipient_hex> <expiry> <observed> <era_hex>");
    }
    let secret = read_private(&a[0]);
    let parts: Vec<&str> = secret.split_whitespace().collect();
    if parts.len() != 3 {
        fail("an operator secret file holds an operator id, a chain id and one secret key");
    }
    let id: u32 = parts[0].parse().expect("operator id");
    let key_chain: u64 = parts[1].parse().expect("key chain id");
    let chain_id: u64 = a[1].parse().expect("chain_id");
    if key_chain != chain_id {
        fail("this operator key was made for another chain");
    }
    let fact = fact_from(&a[2..12]);
    let era: [u8; 32] = unhex(&a[12]).try_into().expect("era 32 bytes");
    let mut sk: [u8; SECRET_KEY_BYTES] = unhex(parts[2]).try_into().expect("secret key length");
    let sig = ml_dsa::sign(
        &sk,
        &fact.attest_preimage(chain_id),
        &attest_context(&era),
        &[0u8; 32],
    )
    .expect("attest sign");
    sk.zeroize();
    println!("{id} {}", hexs(&sig));
}

fn mint(a: &[String]) {
    if a.len() != 18 {
        fail("mint <signatures> <chain_id> <source_chain> <dest_chain> <route_id> <nonce> <source_ref_hex> <asset_hex> <amount> <recipient_hex> <expiry> <observed> <relayer_seed_file> <relayer_index> <fee> <era_hex> <tx_nonce> <valid_until>");
    }
    let collected = fs::read_to_string(&a[0]).expect("read the collected signatures");
    let chain_id: u64 = a[1].parse().expect("chain_id");
    let fact = fact_from(&a[2..12]);
    let relayer_seed: [u8; 32] = read_seed(&a[12]);
    let relayer_index: u64 = a[13].parse().expect("relayer_index");
    let fee: u128 = a[14].parse().expect("fee");
    let tx_nonce: u64 = a[16].parse().expect("tx_nonce");
    let valid_until: u64 = a[17].parse().expect("valid_until");
    let mut signatures = Vec::new();
    for line in collected.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.is_empty() {
            continue;
        }
        if p.len() != 2 {
            fail("each signature line is an operator id and a signature");
        }
        signatures.push(SignerSig {
            operator_id: p[0].parse().expect("operator id"),
            signature: unhex(p[1]),
        });
    }
    let artifact = MintArtifact {
        attestation: Attestation { fact, signatures },
        stark: None,
    };
    let artifact_bytes = artifact.encode();
    eprintln!("ARTIFACT {}", hexs(&artifact_bytes));
    let relayer = derive(&relayer_seed, relayer_index);
    let call = Call::new(bridge_mint_address(), artifact_bytes);
    let body = Body::with_context(
        relayer.address(),
        tx_nonce,
        MINT_METER,
        fee,
        call,
        0,
        chain_id,
    )
    .valid_until(valid_until);
    let wrapper = sign(&relayer, &body);
    println!("{}", hexs(&to_bytes(&wrapper)));
}

fn check(a: &[String]) {
    if a.len() != 5 {
        fail("check <committee> <artifact_hex> <dest_chain> <chain_id> <era_hex>");
    }
    let committee = fs::read_to_string(&a[0]).expect("read committee");
    let artifact = MintArtifact::decode(&unhex(&a[1])).expect("decode artifact");
    let dest_chain: u32 = a[2].parse().expect("dest_chain");
    let chain_id: u64 = a[3].parse().expect("chain_id");
    let era: [u8; 32] = unhex(&a[4]).try_into().expect("era 32 bytes");
    let mut lines = committee.lines();
    let threshold: u32 = lines
        .next()
        .expect("threshold")
        .trim()
        .parse()
        .expect("threshold");
    let mut operators: Vec<(u32, Vec<u8>)> = Vec::new();
    for line in lines {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() < 2 {
            continue;
        }
        operators.push((p[0].parse().expect("id"), unhex(p[1])));
    }
    let set = OperatorSet::new(operators, threshold);
    let ok = quorum_attests(&set, &artifact.attestation, dest_chain, chain_id, &era);
    println!("quorum_attests = {ok}");
    if !ok {
        std::process::exit(2);
    }
}

fn guardian_member_id_hex(pk: &[u8]) -> String {
    let address = address_for_key(1, pk);
    let payload = qtv_idfmt::parse_address(&address).expect("guardian address");
    hexs(&payload)
}

fn guardian_keygen(a: &[String]) {
    if a.len() != 1 {
        fail("guardian-keygen <out_prefix>");
    }
    let prefix = &a[0];
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&urandom(32));
    let (pk, mut sk) = ml_dsa::keygen(&seed);
    let mut rendered = Zeroizing::new(String::with_capacity(2 * (pk.len() + sk.len()) + 2));
    push_hex(&mut rendered, &pk);
    rendered.push(' ');
    push_hex(&mut rendered, &sk);
    rendered.push('\n');
    write_private(&format!("{prefix}.gsecret"), rendered.as_bytes());
    sk.zeroize();
    seed.zeroize();
    let mid = guardian_member_id_hex(&pk);
    fs::write(
        format!("{prefix}.gpub"),
        format!("scheme 1\nmember_id {mid}\npubkey {}\n", hexs(&pk)),
    )
    .expect("write gpub");
    eprintln!("wrote {prefix}.gsecret + {prefix}.gpub  (member_id {mid})");
}

fn anchor_action(corridor: &str, anchor_hex: &str) -> Action {
    let corridor: u8 = corridor.parse().expect("corridor");
    if corridor > 2 {
        fail("the corridor is 0 for bitcoin, 1 for ethereum or 2 for cosmos");
    }
    Action::BridgeAnchorSet {
        corridor,
        anchor: unhex(anchor_hex),
    }
}

fn guardian_sign(a: &[String]) {
    if a.len() != 6 {
        fail("guardian-sign <gsecret> <chain_id> <enact_nonce> <corridor 0|1|2> <anchor_hex> <era_hex32>");
    }
    let gsecret = read_private(&a[0]);
    let parts: Vec<&str> = gsecret.split_whitespace().collect();
    if parts.len() != 2 {
        fail("a guardian secret file holds a public key and a secret key");
    }
    let chain_id: u64 = a[1].parse().expect("chain_id");
    let enact_nonce: u64 = a[2].parse().expect("enact_nonce");
    let action = anchor_action(&a[3], &a[4]);
    let era: [u8; 32] = unhex(&a[5]).try_into().expect("era 32 bytes");
    let challenge = guardian_enact_challenge(chain_id, &era, enact_nonce, &action);
    let mut sk: [u8; SECRET_KEY_BYTES] = unhex(parts[1]).try_into().expect("secret key length");
    let sig = ml_dsa::sign(&sk, &challenge, GUARDIAN_DOMAIN, &[0u8; 32]).expect("guardian sign");
    sk.zeroize();
    println!("{} {}", parts[0], hexs(&sig));
}

fn guardian_enact_anchor(a: &[String]) {
    if a.len() != 9 {
        fail("guardian-enact-anchor <approvals> <chain_id> <enact_nonce> <corridor 0|1|2> <anchor_hex> <relayer_seed_file> <relayer_index> <fee> <era_hex32>");
    }
    let collected = fs::read_to_string(&a[0]).expect("read the collected approvals");
    let chain_id: u64 = a[1].parse().expect("chain_id");
    let enact_nonce: u64 = a[2].parse().expect("enact_nonce");
    let action = anchor_action(&a[3], &a[4]);
    let relayer_seed: [u8; 32] = read_seed(&a[5]);
    let relayer_index: u64 = a[6].parse().expect("relayer_index");
    let fee: u128 = a[7].parse().expect("fee");
    let mut approvals: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::new();
    for line in collected.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.is_empty() {
            continue;
        }
        if p.len() != 2 {
            fail("each approval line is a guardian public key and a signature");
        }
        approvals.push((1, unhex(p[0]), unhex(p[1])));
    }
    let relayer = derive(&relayer_seed, relayer_index);
    let tx = build_guardian_enact_tx(
        &action,
        chain_id,
        enact_nonce,
        approvals,
        &relayer,
        0,
        MINT_METER,
        fee,
    );
    println!("{}", hexs(&to_bytes(&tx)));
}

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("keygen") => keygen(&argv[1..]),
        Some("attest") => attest(&argv[1..]),
        Some("mint") => mint(&argv[1..]),
        Some("check") => check(&argv[1..]),
        Some("guardian-keygen") => guardian_keygen(&argv[1..]),
        Some("guardian-sign") => guardian_sign(&argv[1..]),
        Some("guardian-enact-anchor") => guardian_enact_anchor(&argv[1..]),
        _ => {
            fail("usage: qtv-oracle <keygen|mint|check|guardian-keygen|guardian-enact-anchor> ...")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_secret_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("qtv-oracle-secret-{}", std::process::id()));
        fs::write(&path, "1 2 3\n").unwrap();
        let text = path.to_str().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_text(text).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(private_text(text).unwrap(), "1 2 3\n");
        let _ = fs::remove_file(&path);
    }
}
