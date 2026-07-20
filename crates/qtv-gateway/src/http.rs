//! A small HTTP/1.1 server, written over the standard library so the gateway carries
//! no outside dependency, the same discipline the rest of the stack holds.
//!
//! It accepts a POST to a path under `/v1`, reads a JSON body, turns the path into a
//! typed request, hands that request to the node over the channel, waits for the one
//! reply, and writes it back. Cross origin headers are permissive so a browser served
//! explorer can read the chain, and a preflight is answered directly. Everything a
//! client sends is bounded, so a hostile body cannot exhaust memory.

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

/// The largest request body the gateway reads. A signed transaction is a few kilobytes,
/// so a couple of megabytes is ample and a larger claim is refused rather than allocated.
const MAX_BODY: usize = 2 * 1024 * 1024;

/// The largest request head the gateway reads, the request line and all the headers together. A
/// real request head is a few hundred bytes, so sixteen kilobytes is ample. This is bounded on its
/// own because the head is read before the body limit is ever consulted, so without it a hostile
/// peer could stream an endless request line or header and exhaust memory.
const MAX_HEAD: usize = 16 * 1024;

/// The deadline on reading a request and writing its reply, so a peer that opens a connection and
/// then stalls, the classic slow client, cannot hold a connection thread forever.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// The most connections the gateway serves at once. Each connection is handled on its own thread, so
/// this bounds the threads a connection flood can spawn. A request is small and the node answers it
/// quickly, so a real load stays well under this, and a peer beyond it is turned away rather than
/// letting the process spawn threads without limit.
const MAX_CONNECTIONS: usize = 512;

/// Serve the RPC on a bound listener, sending each request to the node over the channel.
/// Each connection is handled on its own thread, and the node serialises the requests, so
/// concurrency here never reaches the node's state out of order. The number of connections in flight
/// is capped, and a peer past the cap is turned away at once so the flood cannot exhaust threads.
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
    // Bound how long a read or a write may block, so a stalled peer drops off rather than pinning a
    // connection thread. A None deadline would let a slow client hold the thread forever.
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut reader = BufReader::new(stream.try_clone()?);

    // Read the request line and the headers under one shared byte budget, so the whole head is
    // bounded and neither an endless line nor a flood of headers can exhaust memory.
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

/// Read one line ending in a newline, drawing down a shared byte budget so the request line and the
/// headers together can never exceed it. Returns the line without its trailing newline, None if the
/// connection ends before any byte arrives, and an error once the budget is exhausted, which is how
/// an endless line or an endless run of headers is refused before it can exhaust memory.
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

/// The trimmed value of a header by its lowercase name, if the line names it.
fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    if key.trim().eq_ignore_ascii_case(name) {
        Some(value.trim())
    } else {
        None
    }
}

/// Write a JSON error body under a status code.
fn write_error(stream: &mut TcpStream, code: u16, error: &str, message: &str) -> IoResult<()> {
    let body = object(vec![
        ("error", Json::str(error)),
        ("message", Json::str(message)),
    ])
    .render();
    write_response(stream, code, &body)
}

/// Write a full HTTP response with the permissive cross origin headers a browser client
/// needs and a length so the client knows where the body ends.
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

/// The reason phrase for a status code, the small set the gateway returns.
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
        // The two lines together exceed the budget, so the second read fails even though the first
        // fit, which is how a flood of small headers is refused, not only one endless line.
        let mut reader = Cursor::new(b"aaaaa\nbbbbb\n".to_vec());
        let mut budget = 8usize;
        assert!(read_capped_line(&mut reader, &mut budget).unwrap().is_some());
        assert!(read_capped_line(&mut reader, &mut budget).is_err());
    }

    // Stand up the real server on a loopback port with a responder that answers every call with a
    // small canned object, so a request can be driven over a real socket. Returns the port.
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

    // Send a raw request over a real connection and read the whole response back.
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
        // The declared length is above the body cap, so the request is refused before the body is
        // ever read or allocated.
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
