// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::Read;

use qtv_bridge_relay::{Corridor, Relay, RELAY_METER, SEED_LEN};
use qtv_wipe::{Zeroize, Zeroizing};

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let clean = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    if !clean.len().is_multiple_of(2) {
        return Err("the hex payload has an odd length".to_string());
    }
    if !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the hex payload holds a non hex character".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| format!("bad hex, {e}")))
        .collect()
}

fn private_text(path: &str) -> Result<Zeroizing<String>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("reading {path}, {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "the seed file {path} is readable by group or others, restrict it with chmod 600"
            ));
        }
    }
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("reading {path}, {e}"))
}

fn env_number<T: std::str::FromStr>(
    name: &str,
    value: Option<String>,
    default: T,
) -> Result<T, String> {
    match value {
        Some(text) => text
            .trim()
            .parse::<T>()
            .map_err(|_| format!("{name} is not a whole number")),
        None => Ok(default),
    }
}

fn corridor_from(name: &str) -> Result<Corridor, String> {
    match name.to_ascii_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(Corridor::Bitcoin),
        "ethereum" | "eth" => Ok(Corridor::Ethereum),
        "cosmos" | "atom" => Ok(Corridor::Cosmos),
        other => Err(format!(
            "unknown corridor {other}, expected bitcoin ethereum or cosmos"
        )),
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let gateway = args
        .next()
        .ok_or("usage qtv-bridge-relay <gateway-url> <corridor> [proof-hex]")?;
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

    let seed_path = std::env::var("QTV_RELAY_SEED_FILE").map_err(|_| {
        "set QTV_RELAY_SEED_FILE to a file holding the relayer seed as hex, readable by its \
         owner only (chmod 600). A seed in an environment variable is readable by every process \
         sharing the uid and lands in service files and crash dumps."
            .to_string()
    })?;
    let seed_hex = private_text(&seed_path)?;
    let mut seed_bytes = parse_hex(seed_hex.trim())?;
    if seed_bytes.len() != SEED_LEN {
        seed_bytes.zeroize();
        return Err(format!("the relayer seed must be {SEED_LEN} bytes"));
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&seed_bytes);
    seed_bytes.zeroize();

    let index = env_number(
        "QTV_RELAY_INDEX",
        std::env::var("QTV_RELAY_INDEX").ok(),
        0u64,
    )?;
    let max_fee = env_number(
        "QTV_RELAY_MAX_FEE",
        std::env::var("QTV_RELAY_MAX_FEE").ok(),
        1_000u128,
    )?;

    let chain = std::env::var("QTV_RELAY_CHAIN")
        .map_err(|_| "set QTV_RELAY_CHAIN to the chain name the relay signs for".to_string())?;
    let acknowledge_mainnet = std::env::var("QTV_RELAY_ACK_MAINNET").as_deref() == Ok("1");

    let relay = Relay::new(
        gateway,
        chain,
        acknowledge_mainnet,
        seed,
        index,
        RELAY_METER,
        max_fee,
    )?;
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

#[cfg(test)]
mod hex_tests {
    use super::*;

    #[test]
    fn a_payload_with_a_sign_character_is_refused() {
        assert!(parse_hex("+a+b").is_err());
        assert_eq!(parse_hex("0x0aff").unwrap(), vec![0x0a, 0xff]);
    }

    #[test]
    fn a_malformed_number_in_the_environment_is_refused() {
        assert!(env_number("QTV_RELAY_MAX_FEE", Some("5000x".to_string()), 1_000u128).is_err());
        assert_eq!(
            env_number("QTV_RELAY_MAX_FEE", Some(" 5000 ".to_string()), 1_000u128),
            Ok(5_000)
        );
        assert_eq!(env_number("QTV_RELAY_INDEX", None, 0u64), Ok(0));
    }
}
