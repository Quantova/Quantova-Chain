// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::io::{BufRead, BufReader, Read, Result as IoResult, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::json::{self, object, Json};
use crate::service::build_request;
use crate::GatewayCall;

const MAX_BODY: usize = 2 * 1024 * 1024;

const MAX_HEAD: usize = 16 * 1024;

const IO_TIMEOUT: Duration = Duration::from_secs(15);

const MAX_CONNECTIONS: usize = 512;

pub fn serve(listener: TcpListener, requests: Sender<GatewayCall>) {
    thread::spawn(move || {
        let active = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::SeqCst);
                stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                let _ = write_error(&mut stream, 503, "busy", "the gateway is at its connection limit");
                continue;
            }
            let requests = requests.clone();
            let active = active.clone();
            thread::spawn(move || {
                let _ = handle_connection(stream, requests);
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
}

fn handle_connection(mut stream: TcpStream, requests: Sender<GatewayCall>) -> IoResult<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut head_budget = MAX_HEAD;
    let request_line = match read_capped_line(&mut reader, &mut head_budget) {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(()),
        Err(_) => return write_error(&mut stream, 431, "head_too_large", "the request head is too large"),
    };
    let mut parts = request_line.split_whitespace();
    let verb = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    loop {
        let header = match read_capped_line(&mut reader, &mut head_budget) {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(_) => {
                return write_error(&mut stream, 431, "head_too_large", "the request head is too large")
            }
        };
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = header_value(trimmed, "content-length") {
            content_length = value.parse().unwrap_or(0);
        }
    }

    if verb.eq_ignore_ascii_case("OPTIONS") {
        return write_response(&mut stream, 204, "");
    }
    if !verb.eq_ignore_ascii_case("POST") {
        return write_error(&mut stream, 405, "method_not_allowed", "the RPC accepts POST");
    }
    if content_length > MAX_BODY {
        return write_error(&mut stream, 413, "too_large", "the request body is too large");
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let body_text = String::from_utf8_lossy(&body);

    let Some(method) = path.strip_prefix("/v1/") else {
        return write_error(&mut stream, 404, "unknown_method", "methods live under /v1/");
    };

    let parsed = if body_text.trim().is_empty() {
        Json::Object(Vec::new())
    } else {
        match json::parse(&body_text) {
            Ok(value) => value,
            Err(e) => {
                return write_error(&mut stream, 400, "bad_request", &format!("the body is not JSON, {e}"))
            }
        }
    };

    let request = match build_request(method, &parsed) {
        Ok(request) => request,
        Err(err) => return write_error(&mut stream, err.http, &err.code, &err.message),
    };

    let (reply_tx, reply_rx) = channel();
    if requests
        .send(GatewayCall {
            request,
            reply: reply_tx,
        })
        .is_err()
    {
        return write_error(&mut stream, 503, "unavailable", "the node is not accepting requests");
    }

    match reply_rx.recv() {
        Ok(Ok(value)) => write_response(&mut stream, 200, &value.render()),
        Ok(Err(err)) => write_error(&mut stream, err.http, &err.code, &err.message),
        Err(_) => write_error(&mut stream, 503, "unavailable", "the node dropped the request"),
    }
}

fn read_capped_line<R: BufRead>(reader: &mut R, budget: &mut usize) -> IoResult<Option<String>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if reader.read(&mut byte)? == 0 {
            return Ok(if line.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&line).into_owned())
            });
        }
        if *budget == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the request head exceeded its budget",
            ));
        }
        *budget -= 1;
        if byte[0] == b'\n' {
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        line.push(byte[0]);
    }
}

fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    if key.trim().eq_ignore_ascii_case(name) {
        Some(value.trim())
    } else {
        None
    }
}

fn write_error(stream: &mut TcpStream, code: u16, error: &str, message: &str) -> IoResult<()> {
    let body = object(vec![
        ("error", Json::str(error)),
        ("message", Json::str(message)),
    ])
    .render();
    write_response(stream, code, &body)
}

fn write_response(stream: &mut TcpStream, code: u16, body: &str) -> IoResult<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        reason = reason(code),
        len = body.len(),
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_capped_line_reads_a_normal_line_and_draws_down_the_budget() {
        let raw = b"POST /v1/node_info HTTP/1.1\r\n".to_vec();
        let spent = raw.len();
        let mut reader = Cursor::new(raw);
        let mut budget = MAX_HEAD;
        let line = read_capped_line(&mut reader, &mut budget).unwrap().unwrap();
        assert_eq!(line, "POST /v1/node_info HTTP/1.1\r");
        assert_eq!(budget, MAX_HEAD - spent, "every byte read draws down the budget");
    }

    #[test]
    fn a_capped_line_refuses_a_line_that_exhausts_the_budget() {
        let mut reader = Cursor::new(vec![b'a'; 100]);
        let mut budget = 16usize;
        assert!(
            read_capped_line(&mut reader, &mut budget).is_err(),
            "an endless line is refused once the budget is spent"
        );
    }

    #[test]
    fn a_capped_line_returns_none_at_end_of_stream() {
        let mut reader = Cursor::new(Vec::new());
        let mut budget = MAX_HEAD;
        assert!(read_capped_line(&mut reader, &mut budget).unwrap().is_none());
    }

    #[test]
    fn the_head_budget_is_shared_across_the_lines() {
        let mut reader = Cursor::new(b"aaaaa\nbbbbb\n".to_vec());
        let mut budget = 8usize;
        assert!(read_capped_line(&mut reader, &mut budget).unwrap().is_some());
        assert!(read_capped_line(&mut reader, &mut budget).is_err());
    }

    fn serve_stub() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = channel::<GatewayCall>();
        thread::spawn(move || {
            for call in rx {
                let _ = call.reply.send(Ok(object(vec![("ok", Json::Bool(true))])));
            }
        });
        serve(listener, tx);
        port
    }

    fn round_trip(port: u16, request: &str) -> String {
        use std::io::{Read, Write};
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).ok();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn a_well_formed_post_is_routed_and_answered_over_the_socket() {
        let port = serve_stub();
        let response = round_trip(
            port,
            "POST /v1/node_info HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"ok\""), "{response}");
    }

    #[test]
    fn an_oversized_head_is_refused_over_the_socket() {
        let port = serve_stub();
        let giant = "x".repeat(MAX_HEAD + 1024);
        let response = round_trip(port, &format!("POST /v1/node_info HTTP/1.1\r\nBig: {giant}\r\n\r\n"));
        assert!(response.starts_with("HTTP/1.1 431"), "{response}");
    }

    #[test]
    fn an_oversized_body_is_refused_over_the_socket() {
        let port = serve_stub();
        let response = round_trip(
            port,
            &format!("POST /v1/node_info HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1),
        );
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    }

    #[test]
    fn an_unknown_method_path_is_a_not_found_over_the_socket() {
        let port = serve_stub();
        let response = round_trip(port, "POST /v1/does_not_exist HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}");
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }
}
