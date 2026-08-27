use std::env;
use std::fs;
use std::io::Read;

use qtv_account::{address_for_key, derive};
use qtv_governance::Action;
use qtv_node::node::{build_guardian_enact_tx, guardian_enact_challenge};
use qtv_crypto::ml_dsa::{self, SECRET_KEY_BYTES};
use qtv_node::bridge::{
    operator_pop_challenge, quorum_attests, Attestation, Direction, Fact, MintArtifact,
    attest_context, OperatorSet, SignerSig, FACT_VERSION, POP_DOMAIN,
};
use qtv_node::ledger::bridge_mint_address;
use qtv_codec::to_bytes;
use qtv_tx::{sign, Body, Call};

const MINT_METER: u64 = 5_000_000;
const GUARDIAN_DOMAIN: &[u8] = b"QUANTOVA/Q/BRIDGE-GUARDIAN/v1";

fn urandom(n: usize) -> Vec<u8> {
    let mut f = fs::File::open("/dev/urandom").expect("open /dev/urandom");
    let mut b = vec![0u8; n];
    f.read_exact(&mut b).expect("read /dev/urandom");
    b
}

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fail(msg: &str) -> ! {
    eprintln!("qtv-oracle: {msg}");
    std::process::exit(1);
}

fn keygen(a: &[String]) {
    if a.len() != 4 {
        fail("keygen <n> <threshold> <chain_id> <out_prefix>");
    }
    let n: u32 = a[0].parse().expect("n");
    let threshold: u32 = a[1].parse().expect("threshold");
    let chain_id: u64 = a[2].parse().expect("chain_id");
    let prefix = &a[3];
    let mut secrets = format!("{n} {threshold} {chain_id}\n");
    let mut committee = format!("{threshold}\n");
    for id in 0..n {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&urandom(32));
        let (pk, sk) = ml_dsa::keygen(&seed);
        let pop = ml_dsa::sign(&sk, &operator_pop_challenge(id, &pk, chain_id), POP_DOMAIN, &[0u8; 32])
            .expect("pop");
        secrets.push_str(&format!("{id} {}\n", hexs(&sk)));
        committee.push_str(&format!("{id} {} {}\n", hexs(&pk), hexs(&pop)));
    }
    fs::write(format!("{prefix}.secrets"), secrets).expect("write secrets");
    fs::write(format!("{prefix}.committee"), committee).expect("write committee");
    eprintln!("wrote {prefix}.secrets + {prefix}.committee ({n} operators, threshold {threshold}, chain {chain_id})");
}

fn mint(a: &[String]) {
    if a.len() != 16 {
        fail("mint <secrets> <chain_id> <source_chain> <dest_chain> <route_id> <nonce> <source_ref_hex> <asset_hex> <amount> <recipient_hex> <expiry> <observed> <relayer_seed_hex> <relayer_index> <fee> <era_hex>");
    }
    let secrets = fs::read_to_string(&a[0]).expect("read secrets");
    let chain_id: u64 = a[1].parse().expect("chain_id");
    let source_chain: u32 = a[2].parse().expect("source_chain");
    let dest_chain: u32 = a[3].parse().expect("dest_chain");
    let route_id: u32 = a[4].parse().expect("route_id");
    let nonce: u64 = a[5].parse().expect("nonce");
    let source_ref: [u8; 32] = unhex(&a[6]).try_into().expect("source_ref 32 bytes");
    let asset_id: [u8; 16] = unhex(&a[7]).try_into().expect("asset 16 bytes");
    let amount: u128 = a[8].parse().expect("amount");
    let recipient: [u8; 32] = unhex(&a[9]).try_into().expect("recipient 32 bytes");
    let expiry: u64 = a[10].parse().expect("expiry");
    let observed: u64 = a[11].parse().expect("observed");
    let relayer_seed: [u8; 32] = unhex(&a[12]).try_into().expect("relayer seed 32 bytes");
    let relayer_index: u64 = a[13].parse().expect("relayer_index");
    let fee: u128 = a[14].parse().expect("fee");
    let era: [u8; 32] = unhex(&a[15]).try_into().expect("era 32 bytes");

    let fact = Fact {
        version: FACT_VERSION,
        source_chain,
        dest_chain,
        route_id,
        direction: Direction::Deposit,
        nonce,
        source_ref,
        asset_id,
        amount,
        recipient,
        finality_depth: 0,
        observed_height: observed,
        expiry_height: expiry,
    };
    let preimage = fact.attest_preimage(chain_id);
    let mut signatures = Vec::new();
    for (i, line) in secrets.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() < 2 {
            continue;
        }
        let id: u32 = p[0].parse().expect("operator id");
        let sk: [u8; SECRET_KEY_BYTES] = unhex(p[1]).try_into().expect("secret key length");
        let sig = ml_dsa::sign(&sk, &preimage, &attest_context(&era), &[0u8; 32]).expect("attest sign");
        signatures.push(SignerSig {
            operator_id: id,
            signature: sig.to_vec(),
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
    let body = Body::with_context(relayer.address(), nonce, MINT_METER, fee, call, 0, chain_id);
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
    let threshold: u32 = lines.next().expect("threshold").trim().parse().expect("threshold");
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
    let (pk, sk) = ml_dsa::keygen(&seed);
    fs::write(format!("{prefix}.gsecret"), format!("{} {}\n", hexs(&pk), hexs(&sk))).expect("write gsecret");
    let mid = guardian_member_id_hex(&pk);
    fs::write(format!("{prefix}.gpub"), format!("scheme 1\nmember_id {mid}\npubkey {}\n", hexs(&pk))).expect("write gpub");
    eprintln!("wrote {prefix}.gsecret + {prefix}.gpub  (member_id {mid})");
}

fn guardian_enact_asset(a: &[String]) {
    if a.len() != 11 {
        fail("guardian-enact-asset <gsecrets_comma_sep> <chain_id> <enact_nonce> <asset_hex16> <cap> <epoch_cap> <stark 0|1> <relayer_seed_hex> <relayer_index> <fee> <era_hex32>");
    }
    let chain_id: u64 = a[1].parse().expect("chain_id");
    let enact_nonce: u64 = a[2].parse().expect("enact_nonce");
    let asset_id: [u8; 16] = unhex(&a[3]).try_into().expect("asset 16 bytes");
    let cap: u128 = a[4].parse().expect("cap");
    let epoch_cap: u128 = a[5].parse().expect("epoch_cap");
    let requires_stark = a[6] == "1";
    let relayer_seed: [u8; 32] = unhex(&a[7]).try_into().expect("relayer seed");
    let relayer_index: u64 = a[8].parse().expect("relayer_index");
    let fee: u128 = a[9].parse().expect("fee");
    let era: [u8; 32] = unhex(&a[10]).try_into().expect("era 32 bytes");
    let action = Action::AssetRegister { asset_id, cap, epoch_cap, requires_stark };
    let challenge = guardian_enact_challenge(chain_id, &era, enact_nonce, &action);
    let mut approvals: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::new();
    for path in a[0].split(',') {
        let gsecret = fs::read_to_string(path.trim()).expect("read gsecret");
        let parts: Vec<&str> = gsecret.split_whitespace().collect();
        let pk = unhex(parts[0]);
        let sk: [u8; SECRET_KEY_BYTES] = unhex(parts[1]).try_into().expect("secret key length");
        let sig = ml_dsa::sign(&sk, &challenge, GUARDIAN_DOMAIN, &[0u8; 32]).expect("guardian sign");
        approvals.push((1, pk, sig.to_vec()));
    }
    let relayer = derive(&relayer_seed, relayer_index);
    let tx = build_guardian_enact_tx(&action, chain_id, enact_nonce, approvals, &relayer, 0, MINT_METER, fee);
    println!("{}", hexs(&to_bytes(&tx)));
}

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("keygen") => keygen(&argv[1..]),
        Some("mint") => mint(&argv[1..]),
        Some("check") => check(&argv[1..]),
        Some("guardian-keygen") => guardian_keygen(&argv[1..]),
        Some("guardian-enact-asset") => guardian_enact_asset(&argv[1..]),
        _ => fail("usage: qtv-oracle <keygen|mint> ..."),
    }
}
