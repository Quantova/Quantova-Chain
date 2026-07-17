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
use std::sync::mpsc::{channel, Sender};
use std::thread;

use crate::json::{self, object, Json};
use crate::service::build_request;
use crate::GatewayCall;

/// The largest request body the gateway reads. A signed transaction is a few kilobytes,
/// so a couple of megabytes is ample and a larger claim is refused rather than allocated.
const MAX_BODY: usize = 2 * 1024 * 1024;

/// Serve the RPC on a bound listener, sending each request to the node over the channel.
/// Each connection is handled on its own thread, and the node serialises the requests, so
/// concurrency here never reaches the node's state out of order.
pub fn serve(listener: TcpListener, requests: Sender<GatewayCall>) {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let requests = requests.clone();
            thread::spawn(move || {
                let _ = handle_connection(stream, requests);
            });
        }
    });
}

fn handle_connection(mut stream: TcpStream, requests: Sender<GatewayCall>) -> IoResult<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let verb = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
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
        503 => "Service Unavailable",
        _ => "OK",
    }
}
