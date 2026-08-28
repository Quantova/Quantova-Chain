// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::Read;

use qtv_bridge_relay::{Corridor, Relay, RELAY_METER, SEED_LEN};

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let clean = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    if clean.len() % 2 != 0 {
        return Err("the hex payload has an odd length".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| format!("bad hex, {e}")))
        .collect()
}

fn corridor_from(name: &str) -> Result<Corridor, String> {
    match name.to_ascii_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(Corridor::Bitcoin),
        "ethereum" | "eth" => Ok(Corridor::Ethereum),
        "cosmos" | "atom" => Ok(Corridor::Cosmos),
        other => Err(format!("unknown corridor {other}, expected bitcoin ethereum or cosmos")),
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let gateway = args.next().ok_or("usage qtv-bridge-relay <gateway-url> <corridor> [proof-hex]")?;
    let corridor = corridor_from(&args.next().ok_or("missing corridor")?)?;

    let proof_hex = match args.next() {
        Some(hex) => hex,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("reading proof from stdin, {e}"))?;
            buf
        }
    };
    let proof_bytes = parse_hex(&proof_hex)?;

    let seed_hex = std::env::var("QTV_RELAY_SEED")
        .map_err(|_| "set QTV_RELAY_SEED to the relayer seed as hex".to_string())?;
    let seed_bytes = parse_hex(&seed_hex)?;
    if seed_bytes.len() != SEED_LEN {
        return Err(format!("the relayer seed must be {SEED_LEN} bytes"));
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&seed_bytes);

    let index = std::env::var("QTV_RELAY_INDEX")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let max_fee = std::env::var("QTV_RELAY_MAX_FEE")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(1_000);

    let relay = Relay::new(gateway, seed, index, RELAY_METER, max_fee);
    let (signed, outcome) = relay.submit(corridor, proof_bytes)?;
    println!("submitted {} outcome {outcome:?}", signed.tx_id);
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("relay error: {err}");
        std::process::exit(1);
    }
}
