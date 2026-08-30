// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use qtv_bridge_relay::{Corridor, Relay, RELAY_METER};
use qtv_devnet::wire::wrapper_from_bytes;

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]);
            let content_len = head
                .lines()
                .find_map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().to_string())
                })
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() - (pos + 4) >= content_len {
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn extract_tx_hex(body: &str) -> Option<String> {
    let start = body.find("\"tx\":\"")? + "\"tx\":\"".len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn parse_hex(text: &str) -> Vec<u8> {
    let clean = text.strip_prefix("0x").unwrap_or(text);
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

fn spawn_gateway(captured: Arc<Mutex<Option<String>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let mut stream = match conn {
                Ok(s) => s,
                Err(_) => continue,
            };
            let request = read_request(&mut stream);
            let path = request
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("");
            let body = match path {
                "/v1/node_info" => "{\"chain_id\":\"Q-test-net-1\",\"genesis_hash\":\"Qgen\",\
                     \"head_height\":10,\"denomination\":\"Quon\",\
                     \"fee\":{\"transfer_quon\":\"100\"},\"version\":\"test\"}"
                    .to_string(),
                "/v1/get_account" => "{\"address\":\"Q1acct\",\"nonce\":4,\"balance\":\"0\",\
                     \"scheme\":1,\"has_key\":true}"
                    .to_string(),
                "/v1/submit_transaction" => {
                    if let Some(hex) = extract_tx_hex(&request) {
                        *captured.lock().unwrap() = Some(hex);
                    }
                    "{\"verdict\":\"accepted\",\"state\":\"fresh\",\"tx_id\":\"Qtxabc\"}"
                        .to_string()
                }
                _ => "{\"error\":\"unknown_method\",\"message\":\"x\"}".to_string(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

#[test]
fn the_relay_submits_a_bitcoin_mint_over_the_gateway_wire_targeting_the_mint_address() {
    let captured = Arc::new(Mutex::new(None));
    let port = spawn_gateway(captured.clone());
    let base = format!("http://127.0.0.1:{port}");

    let relay = Relay::new(base, [0x2a; 32], 0, RELAY_METER, 1_000);
    let proof = vec![0xde, 0xad, 0xbe, 0xef];
    let (signed, outcome) = relay
        .submit(Corridor::Bitcoin, proof.clone())
        .expect("the relay submits over the gateway");

    assert!(
        matches!(outcome, qcore::Submit::Accepted { .. }),
        "the gateway accepted the trustless mint submission"
    );

    let hex = captured
        .lock()
        .unwrap()
        .clone()
        .expect("the gateway received a submission");
    let bytes = parse_hex(&hex);
    let wrapper = wrapper_from_bytes(&bytes).expect("the submitted bytes decode on the wire");
    assert_eq!(
        wrapper.body().call().target(),
        Corridor::Bitcoin.mint_address(),
        "the submitted tx targets the bitcoin mint address"
    );
    assert_eq!(
        wrapper.body().call().args(),
        proof.as_slice(),
        "the raw proof rode untouched"
    );
    assert_eq!(
        wrapper.body().nonce(),
        4,
        "the relay used the gateway reported nonce"
    );
    assert_eq!(signed.from, qcore::account_address(&[0x2a; 32], 0));
}
