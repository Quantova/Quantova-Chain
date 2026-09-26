#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::env;
use std::fs;

use qtv_account::{address_for_key, derive};
use qtv_codec::to_bytes;
use qtv_crypto::ml_dsa::{self, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES};
use qtv_node::bridge::{
    attest_context, operator_pop_challenge, operator_pop_ok, quorum_attests, Attestation,
    Direction, Fact, MintArtifact, OperatorSet, SignerSig, FACT_VERSION, POP_DOMAIN,
};
use qtv_node::ledger::bridge_mint_address;
use qtv_tx::{sign, Body, Call};
use qtv_wipe::Zeroizing;

const MINT_METER: u64 = 5_000_000;

fn urandom32() -> Zeroizing<[u8; 32]> {
    let mut b = Zeroizing::new([0u8; 32]);
    qtv_crypto::rng::fill_random(&mut b[..]);
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
            .unwrap_or_else(|e| {
                fail(&format!(
                    "creating {path} owner only, never overwriting: {e}"
                ))
            });
        file.write_all(contents)
            .unwrap_or_else(|e| fail(&format!("writing {path}: {e}")));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, contents);
        fail("secret files are only written on unix, where owner only permissions can be set");
    }
}

fn arg<T: std::str::FromStr>(value: &str, name: &str) -> T {
    value
        .trim()
        .parse()
        .unwrap_or_else(|_| fail(&format!("{name} is not a valid number")))
}

fn fixed<const N: usize>(value: &str, name: &str) -> [u8; N] {
    let bytes = unhex(value);
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| fail(&format!("{name} must be {N} bytes of hex")))
}

fn fact_from(a: &[String]) -> Fact {
    let fact = Fact {
        version: FACT_VERSION,
        source_chain: arg(&a[0], "source_chain"),
        dest_chain: arg(&a[1], "dest_chain"),
        route_id: arg(&a[2], "route_id"),
        direction: Direction::Deposit,
        nonce: arg(&a[3], "nonce"),
        source_ref: fixed(&a[4], "source_ref"),
        asset_id: fixed(&a[5], "asset"),
        amount: arg(&a[6], "amount"),
        recipient: fixed(&a[7], "recipient"),
        finality_depth: 0,
        observed_height: arg(&a[9], "observed"),
        expiry_height: arg(&a[8], "expiry"),
    };
    if fact.source_chain == 0
        || fact.dest_chain == 0
        || fact.amount == 0
        || fact.asset_id == [0u8; 16]
        || fact.recipient == [0u8; 32]
        || fact.source_ref == [0u8; 32]
    {
        fail("the fact has a zero chain, amount, asset, recipient or source reference");
    }
    if fact.expiry_height <= fact.observed_height {
        fail("the fact expires at or before the height it was observed");
    }
    fact
}

fn describe(fact: &Fact) -> String {
    format!(
        "source_chain {} dest_chain {} route {} nonce {} source_ref {} asset {} amount {} recipient {} observed {} expiry {}",
        fact.source_chain,
        fact.dest_chain,
        fact.route_id,
        fact.nonce,
        hexs(&fact.source_ref),
        hexs(&fact.asset_id),
        fact.amount,
        hexs(&fact.recipient),
        fact.observed_height,
        fact.expiry_height
    )
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

fn secret_key(hex: &str) -> Zeroizing<[u8; SECRET_KEY_BYTES]> {
    let bytes = Zeroizing::new(unhex(hex));
    if bytes.len() != SECRET_KEY_BYTES {
        fail("the secret key has the wrong length for this build; it was not printed");
    }
    let mut key = Zeroizing::new([0u8; SECRET_KEY_BYTES]);
    key.copy_from_slice(&bytes);
    key
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

fn read_seed(path: &str) -> Zeroizing<[u8; 32]> {
    let text = read_private(path);
    let bytes = Zeroizing::new(unhex(text.trim()));
    if bytes.len() != 32 {
        fail("the relayer seed file must hold 32 bytes as hex");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    seed
}

struct Committee {
    threshold: u32,
    operators: Vec<(u32, Vec<u8>)>,
}

impl Committee {
    fn load(path: &str, chain_id: u64) -> Committee {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|e| fail(&format!("reading the committee {path}: {e}")));
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let threshold: u32 = arg(lines.next().unwrap_or(""), "the committee threshold");
        let mut operators: Vec<(u32, Vec<u8>)> = Vec::new();
        for line in lines {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() != 3 {
                fail(
                    "each committee line is an operator id, a public key and a proof of possession",
                );
            }
            let id: u32 = arg(p[0], "operator id");
            let pk = unhex(p[1]);
            if !operator_pop_ok(id, &pk, &unhex(p[2]), chain_id) {
                fail(&format!(
                    "operator {id} has no valid proof of possession for this chain"
                ));
            }
            if operators.iter().any(|(oid, opk)| *oid == id || *opk == pk) {
                fail(&format!(
                    "operator {id} or its key appears twice in the committee"
                ));
            }
            operators.push((id, pk));
        }
        check_threshold(threshold, operators.len());
        Committee {
            threshold,
            operators,
        }
    }

    fn key(&self, id: u32) -> Option<&[u8]> {
        self.operators
            .iter()
            .find(|(oid, _)| *oid == id)
            .map(|(_, pk)| pk.as_slice())
    }
}

fn check_threshold(threshold: u32, n: usize) {
    if threshold < 2 {
        fail("the threshold must be at least 2");
    }
    if threshold as usize > n {
        fail("the threshold exceeds the committee size");
    }
    if (threshold as usize) * 3 < n * 2 {
        fail(
            "the threshold is below two thirds of the committee, the same rule the chain enforces",
        );
    }
}

fn keygen(a: &[String]) {
    if a.len() != 3 {
        fail("keygen <chain_id> <operator_id> <out_prefix>   (run once per operator, on that operator's own machine)");
    }
    let chain_id: u64 = arg(&a[0], "chain_id");
    let id: u32 = arg(&a[1], "operator_id");
    let prefix = &a[2];
    let seed = urandom32();
    let (pk, sk) = ml_dsa::keygen(&seed);
    let sk = Zeroizing::new(sk);
    let pop = ml_dsa::sign(
        &sk,
        &operator_pop_challenge(id, &pk, chain_id),
        POP_DOMAIN,
        &urandom32(),
    )
    .unwrap_or_else(|| fail("signing the proof of possession"));
    let mut secret = Zeroizing::new(String::with_capacity(2 * SECRET_KEY_BYTES + 32));
    secret.push_str(&format!("{id} {chain_id} "));
    push_hex(&mut secret, &sk[..]);
    secret.push('\n');
    write_private(&format!("{prefix}.{id}.secret"), secret.as_bytes());
    let public = format!("{id} {} {}\n", hexs(&pk), hexs(&pop));
    fs::write(format!("{prefix}.{id}.pub"), &public)
        .unwrap_or_else(|e| fail(&format!("writing {prefix}.{id}.pub: {e}")));
    print!("{public}");
    eprintln!("wrote {prefix}.{id}.secret (keep it on this machine) and {prefix}.{id}.pub (send it to the coordinator)");
}

fn committee(a: &[String]) {
    if a.len() < 4 {
        fail("committee <threshold> <chain_id> <out_file> <operator.pub>...");
    }
    let threshold: u32 = arg(&a[0], "threshold");
    let chain_id: u64 = arg(&a[1], "chain_id");
    let mut text = format!("{threshold}\n");
    for path in &a[3..] {
        let line =
            fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("reading {path}: {e}")));
        text.push_str(line.trim());
        text.push('\n');
    }
    let tmp = format!("{}.checking", a[2]);
    fs::write(&tmp, &text).unwrap_or_else(|e| fail(&format!("writing {tmp}: {e}")));
    let checked = Committee::load(&tmp, chain_id);
    fs::rename(&tmp, &a[2]).unwrap_or_else(|e| fail(&format!("writing {}: {e}", a[2])));
    eprintln!(
        "wrote {} with {} operators, threshold {}",
        a[2],
        checked.operators.len(),
        checked.threshold
    );
}

fn attest(a: &[String]) {
    if a.len() != 14 {
        fail("attest <operator_secret> <committee> <chain_id> <source_chain> <dest_chain> <route_id> <nonce> <source_ref_hex> <asset_hex> <amount> <recipient_hex> <expiry> <observed> <era_hex>");
    }
    let secret = read_private(&a[0]);
    let parts: Vec<&str> = secret.split_whitespace().collect();
    if parts.len() != 3 {
        fail("an operator secret file holds an operator id, a chain id and one secret key");
    }
    let id: u32 = arg(parts[0], "operator id");
    let key_chain: u64 = arg(parts[1], "key chain id");
    let chain_id: u64 = arg(&a[2], "chain_id");
    if key_chain != chain_id {
        fail("this operator key was made for another chain");
    }
    let committee = Committee::load(&a[1], chain_id);
    let expected = committee
        .key(id)
        .unwrap_or_else(|| fail("this operator is not in the committee"));
    let fact = fact_from(&a[3..13]);
    let era: [u8; 32] = fixed(&a[13], "era");
    let sk = secret_key(parts[2]);
    let message = fact.attest_preimage(chain_id);
    let sig = ml_dsa::sign(&sk, &message, &attest_context(&era), &urandom32())
        .unwrap_or_else(|| fail("signing the fact"));
    let pk: &[u8; PUBLIC_KEY_BYTES] = expected
        .try_into()
        .unwrap_or_else(|_| fail("the committee key has the wrong length"));
    if !ml_dsa::verify(pk, &message, &sig, &attest_context(&era)) {
        fail("this secret key does not match the committee key for this operator");
    }
    eprintln!("signing as operator {id}: {}", describe(&fact));
    println!("{id} {}", hexs(&sig));
}

fn collect_signatures(
    path: &str,
    committee: &Committee,
    fact: &Fact,
    chain_id: u64,
    era: &[u8; 32],
) -> Vec<SignerSig> {
    let collected = fs::read_to_string(path)
        .unwrap_or_else(|e| fail(&format!("reading the signatures {path}: {e}")));
    let message = fact.attest_preimage(chain_id);
    let context = attest_context(era);
    let mut signatures: Vec<SignerSig> = Vec::new();
    for line in collected.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.is_empty() {
            continue;
        }
        if p.len() != 2 {
            fail("each signature line is an operator id and a signature");
        }
        let id: u32 = arg(p[0], "operator id");
        if signatures.iter().any(|s| s.operator_id == id) {
            eprintln!("skipping a second signature from operator {id}");
            continue;
        }
        let Some(key) = committee.key(id) else {
            eprintln!("skipping operator {id}, which is not in the committee");
            continue;
        };
        let signature = unhex(p[1]);
        let valid = match (
            <&[u8; PUBLIC_KEY_BYTES]>::try_from(key),
            <&[u8; SIGNATURE_BYTES]>::try_from(signature.as_slice()),
        ) {
            (Ok(pk), Ok(sig)) => ml_dsa::verify(pk, &message, sig, &context),
            _ => false,
        };
        if !valid {
            eprintln!("skipping operator {id}, whose signature does not verify for this fact");
            continue;
        }
        signatures.push(SignerSig {
            operator_id: id,
            signature,
        });
    }
    if (signatures.len() as u32) < committee.threshold {
        fail(&format!(
            "only {} valid signatures, the committee needs {}",
            signatures.len(),
            committee.threshold
        ));
    }
    signatures
}

fn mint(a: &[String]) {
    if a.len() != 19 {
        fail("mint <signatures> <committee> <chain_id> <source_chain> <dest_chain> <route_id> <nonce> <source_ref_hex> <asset_hex> <amount> <recipient_hex> <expiry> <observed> <relayer_seed_file> <relayer_index> <fee> <era_hex> <tx_nonce> <valid_until>");
    }
    let chain_id: u64 = arg(&a[2], "chain_id");
    let committee = Committee::load(&a[1], chain_id);
    let fact = fact_from(&a[3..13]);
    let relayer_seed = read_seed(&a[13]);
    let relayer_index: u64 = arg(&a[14], "relayer_index");
    let fee: u128 = arg(&a[15], "fee");
    let era: [u8; 32] = fixed(&a[16], "era");
    let tx_nonce: u64 = arg(&a[17], "tx_nonce");
    let valid_until: u64 = arg(&a[18], "valid_until");
    let signatures = collect_signatures(&a[0], &committee, &fact, chain_id, &era);
    let set = OperatorSet::new(committee.operators.clone(), committee.threshold);
    let attestation = Attestation { fact, signatures };
    if !quorum_attests(
        &set,
        &attestation,
        attestation.fact.dest_chain,
        chain_id,
        &era,
    ) {
        fail("the collected signatures do not reach the committee quorum");
    }
    let artifact = MintArtifact {
        attestation,
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
    let chain_id: u64 = arg(&a[3], "chain_id");
    let committee = Committee::load(&a[0], chain_id);
    let artifact =
        MintArtifact::decode(&unhex(&a[1])).unwrap_or_else(|| fail("the artifact does not decode"));
    let dest_chain: u32 = arg(&a[2], "dest_chain");
    let era: [u8; 32] = fixed(&a[4], "era");
    let set = OperatorSet::new(committee.operators, committee.threshold);
    let ok = quorum_attests(&set, &artifact.attestation, dest_chain, chain_id, &era);
    println!("quorum_attests = {ok}");
    if !ok {
        std::process::exit(2);
    }
}

fn guardian_member_id_hex(pk: &[u8]) -> String {
    let address = address_for_key(1, pk);
    let payload = qtv_idfmt::parse_address(&address)
        .unwrap_or_else(|_| fail("the guardian key does not form an address"));
    hexs(&payload)
}

fn guardian_keygen(a: &[String]) {
    if a.len() != 1 {
        fail("guardian-keygen <out_prefix>");
    }
    let prefix = &a[0];
    let seed = urandom32();
    let (pk, sk) = ml_dsa::keygen(&seed);
    let sk = Zeroizing::new(sk);
    let mut rendered = Zeroizing::new(String::with_capacity(2 * (pk.len() + sk.len()) + 2));
    push_hex(&mut rendered, &pk);
    rendered.push(' ');
    push_hex(&mut rendered, &sk[..]);
    rendered.push('\n');
    write_private(&format!("{prefix}.gsecret"), rendered.as_bytes());
    let mid = guardian_member_id_hex(&pk);
    fs::write(
        format!("{prefix}.gpub"),
        format!("scheme 1\nmember_id {mid}\npubkey {}\n", hexs(&pk)),
    )
    .unwrap_or_else(|e| fail(&format!("writing {prefix}.gpub: {e}")));
    eprintln!("wrote {prefix}.gsecret + {prefix}.gpub  (member_id {mid})");
}

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("keygen") => keygen(&argv[1..]),
        Some("committee") => committee(&argv[1..]),
        Some("attest") => attest(&argv[1..]),
        Some("mint") => mint(&argv[1..]),
        Some("check") => check(&argv[1..]),
        Some("guardian-keygen") => guardian_keygen(&argv[1..]),
        _ => fail("usage: qtv-oracle <keygen|committee|attest|mint|check|guardian-keygen> ..."),
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
