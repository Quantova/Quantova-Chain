// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Result as IoResult, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::json::{self, object, Json};
use crate::service::build_request;
use crate::GatewayCall;

static CORS_ORIGIN: OnceLock<Option<String>> = OnceLock::new();

fn cors_origin() -> Option<&'static str> {
    CORS_ORIGIN.get().and_then(|o| o.as_deref())
}

const MAX_BODY: usize = 1024 * 1024;

const MAX_HEAD: usize = 16 * 1024;

const IO_TIMEOUT: Duration = Duration::from_secs(15);

const REQUEST_DEADLINE: Duration = Duration::from_secs(20);

const MAX_INFLIGHT_BODY: usize = 8 * 1024 * 1024;

const MAX_CONNECTIONS: usize = 512;

const MAX_CONNECTIONS_PER_IP: usize = 32;

const RATE_REFILL_PER_SEC: f64 = 50.0;

const RATE_BURST: f64 = 100.0;

const RATE_TABLE_CAP: usize = 100_000;

const BAN_STRIKES: u32 = 100;

const STRIKE_WINDOW: Duration = Duration::from_secs(10);

const BAN_DURATION: Duration = Duration::from_secs(300);

enum Admit {
    Ok,
    TotalFull,
    IpFull,
    RateLimited,
    Banned,
}

#[derive(Default)]
struct Limiter {
    inner: Mutex<LimiterInner>,
}

#[derive(Default)]
struct LimiterInner {
    total: usize,
    body_bytes: usize,
    per_ip: HashMap<IpAddr, usize>,
    per_forwarded: HashMap<IpAddr, usize>,
    rate: HashMap<IpAddr, Bucket>,
    rate_old: HashMap<IpAddr, Bucket>,
    strikes: HashMap<IpAddr, (u32, Instant)>,
    banned: HashMap<IpAddr, Instant>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl LimiterInner {
    fn spend_rate_token(&mut self, ip: IpAddr, now: Instant) -> bool {
        let mut bucket = match self.rate.remove(&ip) {
            Some(bucket) => bucket,
            None => self.rate_old.remove(&ip).unwrap_or(Bucket {
                tokens: RATE_BURST,
                last: now,
            }),
        };
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * RATE_REFILL_PER_SEC).min(RATE_BURST);
        let allowed = if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        };
        if self.rate.len() >= RATE_TABLE_CAP {
            self.rate_old = std::mem::take(&mut self.rate);
        }
        self.rate.insert(ip, bucket);
        allowed
    }

    fn is_banned(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.banned.get(&ip) {
            Some(&until) if until > now => true,
            Some(_) => {
                self.banned.remove(&ip);
                false
            }
            None => false,
        }
    }

    fn strike(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.strikes.len() >= RATE_TABLE_CAP {
            self.strikes
                .retain(|_, (_, seen)| now.saturating_duration_since(*seen) <= STRIKE_WINDOW);
            if self.strikes.len() >= RATE_TABLE_CAP {
                self.strikes.clear();
            }
        }
        let entry = self.strikes.entry(ip).or_insert((0, now));
        if now.saturating_duration_since(entry.1) > STRIKE_WINDOW {
            *entry = (0, now);
        }
        entry.0 += 1;
        if entry.0 < BAN_STRIKES {
            return false;
        }
        self.strikes.remove(&ip);
        if self.banned.len() >= RATE_TABLE_CAP {
            self.banned.retain(|_, until| *until > now);
            while self.banned.len() >= RATE_TABLE_CAP {
                let soonest = self
                    .banned
                    .iter()
                    .min_by_key(|(_, until)| **until)
                    .map(|(addr, _)| *addr);
                match soonest {
                    Some(addr) => {
                        self.banned.remove(&addr);
                    }
                    None => break,
                }
            }
        }
        self.banned.insert(ip, now + BAN_DURATION);
        eprintln!(
            "gateway: banned {ip} for {}s after {BAN_STRIKES} rate-limited requests within {}s",
            BAN_DURATION.as_secs(),
            STRIKE_WINDOW.as_secs()
        );
        true
    }
}

impl Limiter {
    fn try_admit(&self, ip: IpAddr, total_cap: usize, per_ip_cap: usize, now: Instant) -> Admit {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.is_banned(ip, now) {
            return Admit::Banned;
        }
        if !inner.spend_rate_token(ip, now) {
            return if inner.strike(ip, now) {
                Admit::Banned
            } else {
                Admit::RateLimited
            };
        }
        if inner.total >= total_cap {
            return Admit::TotalFull;
        }
        let count = inner.per_ip.entry(ip).or_insert(0);
        if *count >= per_ip_cap {
            return Admit::IpFull;
        }
        *count += 1;
        inner.total += 1;
        Admit::Ok
    }

    fn try_admit_total_only(&self, total_cap: usize) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.total >= total_cap {
            return false;
        }
        inner.total += 1;
        true
    }

    #[cfg(test)]
    fn admit_forwarded(&self, ip: IpAddr, per_ip_cap: usize, now: Instant) -> Admit {
        self.admit_client(ip, true, per_ip_cap, now)
    }

    fn admit_client(&self, ip: IpAddr, direct: bool, per_ip_cap: usize, now: Instant) -> Admit {
        if direct && ip.is_loopback() {
            return Admit::Ok;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.is_banned(ip, now) {
            return Admit::Banned;
        }
        if !inner.spend_rate_token(ip, now) {
            return if inner.strike(ip, now) {
                Admit::Banned
            } else {
                Admit::RateLimited
            };
        }
        let count = inner.per_forwarded.entry(ip).or_insert(0);
        if *count >= per_ip_cap {
            return Admit::IpFull;
        }
        *count += 1;
        Admit::Ok
    }

    fn release_forwarded(&self, ip: IpAddr) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = inner.per_forwarded.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                inner.per_forwarded.remove(&ip);
            }
        }
    }

    fn try_reserve_body(&self, want: usize) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.body_bytes.saturating_add(want) > MAX_INFLIGHT_BODY {
            return false;
        }
        inner.body_bytes += want;
        true
    }

    fn release_body(&self, held: usize) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.body_bytes = inner.body_bytes.saturating_sub(held);
    }

    fn release(&self, ip: IpAddr) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = inner.per_ip.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                inner.per_ip.remove(&ip);
            }
        }
        inner.total = inner.total.saturating_sub(1);
    }
}

pub fn serve(
    listener: TcpListener,
    requests: Sender<GatewayCall>,
    allow: Vec<IpAddr>,
    cors_origin: Option<String>,
) {
    let _ = CORS_ORIGIN.set(cors_origin.filter(|o| !o.is_empty()));
    let loopback_only = listener
        .local_addr()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false);
    thread::spawn(move || {
        let limiter = Arc::new(Limiter::default());
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let peer = unmapped(
                stream
                    .peer_addr()
                    .map(|addr| addr.ip())
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            );
            let ip = limiter_key(peer);
            if !allow.is_empty() && !allow.contains(&peer) {
                stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                let _ = write_error(
                    &mut stream,
                    403,
                    "forbidden",
                    "this address may not reach the rpc",
                );
                continue;
            }
            if loopback_only {
                if !limiter.try_admit_total_only(MAX_CONNECTIONS) {
                    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                    let _ = write_error(
                        &mut stream,
                        503,
                        "busy",
                        "the gateway is at its connection limit",
                    );
                    continue;
                }
            } else {
                match limiter.try_admit(ip, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, Instant::now())
                {
                    Admit::Ok => {}
                    Admit::TotalFull => {
                        stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                        let _ = write_error(
                            &mut stream,
                            503,
                            "busy",
                            "the gateway is at its connection limit",
                        );
                        continue;
                    }
                    Admit::IpFull => {
                        stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                        let _ = write_error(
                            &mut stream,
                            429,
                            "too_many",
                            "too many open connections from this address",
                        );
                        continue;
                    }
                    Admit::RateLimited => {
                        stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                        let _ = write_error(
                            &mut stream,
                            429,
                            "rate_limited",
                            "too many requests from this address, slow down",
                        );
                        continue;
                    }
                    Admit::Banned => {
                        stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                        let _ = write_error(
                            &mut stream,
                            429,
                            "banned",
                            "address temporarily blocked for excessive requests",
                        );
                        continue;
                    }
                }
            }
            let requests = requests.clone();
            let limiter = limiter.clone();
            let throttle_limiter = limiter.clone();
            thread::spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ =
                        handle_connection(stream, requests, throttle_limiter, loopback_only, ip);
                }));
                limiter.release(ip);
            });
        }
    });
}

fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        IpAddr::V4(_) => ip,
    }
}

fn limiter_key(ip: IpAddr) -> IpAddr {
    let ip = unmapped(ip);
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            for seg in segments.iter_mut().skip(4) {
                *seg = 0;
            }
            IpAddr::V6(Ipv6Addr::from(segments))
        }
    }
}

fn forwarded_client_ip(header: &Option<String>) -> Option<IpAddr> {
    let value = header.as_ref()?;
    let rightmost = value.split(',').next_back()?.trim();
    rightmost.parse::<IpAddr>().ok()
}

struct BodyGuard {
    limiter: Arc<Limiter>,
    held: usize,
}

impl Drop for BodyGuard {
    fn drop(&mut self) {
        self.limiter.release_body(self.held);
    }
}

struct ForwardedGuard {
    limiter: Arc<Limiter>,
    ip: IpAddr,
}

impl Drop for ForwardedGuard {
    fn drop(&mut self) {
        self.limiter.release_forwarded(self.ip);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    requests: Sender<GatewayCall>,
    limiter: Arc<Limiter>,
    loopback_only: bool,
    peer: IpAddr,
) -> IoResult<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let deadline = Instant::now() + REQUEST_DEADLINE;

    let mut head_budget = MAX_HEAD;
    let request_line = match read_capped_line(&mut reader, &mut head_budget, deadline) {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(()),
        Err(_) => {
            return write_error(
                &mut stream,
                431,
                "head_too_large",
                "the request head is too large",
            )
        }
    };
    let mut parts = request_line.split_whitespace();
    let verb = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    let mut seen_length = false;
    let mut forwarded_for: Option<String> = None;
    loop {
        let header = match read_capped_line(&mut reader, &mut head_budget, deadline) {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(_) => {
                return write_error(
                    &mut stream,
                    431,
                    "head_too_large",
                    "the request head is too large",
                )
            }
        };
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = header_value(trimmed, "content-length") {
            if seen_length {
                return write_error(
                    &mut stream,
                    400,
                    "bad_request",
                    "the request carries more than one content-length header",
                );
            }
            seen_length = true;
            match value.trim().parse::<usize>() {
                Ok(n) => content_length = n,
                Err(_) => {
                    return write_error(
                        &mut stream,
                        400,
                        "bad_request",
                        "the content-length header is not a number",
                    );
                }
            }
        }
        if header_value(trimmed, "transfer-encoding").is_some() {
            return write_error(
                &mut stream,
                400,
                "bad_request",
                "transfer-encoding is not supported, send a content-length body",
            );
        }
        if let Some(value) = header_value(trimmed, "x-forwarded-for") {
            forwarded_for = Some(value.to_string());
        }
    }

    let mut _forwarded_guard: Option<ForwardedGuard> = None;
    if loopback_only {
        let forwarded = forwarded_client_ip(&forwarded_for);
        let direct = forwarded_for.is_none();
        let client = limiter_key(forwarded.unwrap_or(peer));
        match limiter.admit_client(client, direct, MAX_CONNECTIONS_PER_IP, Instant::now()) {
            Admit::Ok => {
                _forwarded_guard = Some(ForwardedGuard {
                    limiter: limiter.clone(),
                    ip: client,
                });
            }
            Admit::Banned => {
                return write_error(
                    &mut stream,
                    429,
                    "banned",
                    "address temporarily blocked for excessive requests",
                )
            }
            Admit::IpFull => {
                return write_error(
                    &mut stream,
                    429,
                    "too_many",
                    "too many open connections from this address",
                )
            }
            _ => {
                return write_error(
                    &mut stream,
                    429,
                    "rate_limited",
                    "too many requests from this address, slow down",
                )
            }
        }
    }

    if verb.eq_ignore_ascii_case("OPTIONS") {
        return write_response(&mut stream, 204, "");
    }
    if !verb.eq_ignore_ascii_case("POST") {
        return write_error(
            &mut stream,
            405,
            "method_not_allowed",
            "the RPC accepts POST",
        );
    }
    if content_length > MAX_BODY {
        return write_error(
            &mut stream,
            413,
            "too_large",
            "the request body is too large",
        );
    }

    let _body_guard = if content_length == 0 {
        None
    } else if limiter.try_reserve_body(content_length) {
        Some(BodyGuard {
            limiter: limiter.clone(),
            held: content_length,
        })
    } else {
        return write_error(
            &mut stream,
            503,
            "busy",
            "the gateway is handling too much request data, retry shortly",
        );
    };

    let mut body = Vec::with_capacity(content_length.min(64 * 1024));
    let mut chunk = [0u8; 8192];
    while body.len() < content_length {
        if Instant::now() >= deadline {
            return write_error(
                &mut stream,
                408,
                "timeout",
                "the request body did not arrive in time",
            );
        }
        let want = (content_length - body.len()).min(chunk.len());
        match reader.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(e),
        }
    }
    if body.len() < content_length {
        return write_error(
            &mut stream,
            400,
            "bad_request",
            "the request body was shorter than declared",
        );
    }
    let Ok(body_text) = std::str::from_utf8(&body) else {
        return write_error(
            &mut stream,
            400,
            "bad_request",
            "the request body is not valid UTF-8",
        );
    };

    let Some(method) = path.strip_prefix("/v1/") else {
        return write_error(
            &mut stream,
            404,
            "unknown_method",
            "methods live under /v1/",
        );
    };

    let parsed = if body_text.trim().is_empty() {
        Json::Object(Vec::new())
    } else {
        match json::parse(body_text) {
            Ok(value) => value,
            Err(e) => {
                return write_error(
                    &mut stream,
                    400,
                    "bad_request",
                    &format!("the body is not JSON, {e}"),
                )
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
        return write_error(
            &mut stream,
            503,
            "unavailable",
            "the node is not accepting requests",
        );
    }

    match reply_rx.recv_timeout(REQUEST_DEADLINE) {
        Ok(Ok(value)) => write_response(&mut stream, 200, &value.render()),
        Ok(Err(err)) => write_error(&mut stream, err.http, &err.code, &err.message),
        Err(_) => write_error(
            &mut stream,
            503,
            "unavailable",
            "the node dropped the request",
        ),
    }
}

fn read_capped_line<R: BufRead>(
    reader: &mut R,
    budget: &mut usize,
    deadline: Instant,
) -> IoResult<Option<String>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the request exceeded its deadline",
            ));
        }
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
    let cors = match cors_origin() {
        Some(origin) => format!(
            "Access-Control-Allow-Origin: {origin}\r\n\
             Access-Control-Allow-Methods: POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type\r\n\
             Vary: Origin\r\n"
        ),
        None => String::new(),
    };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Length: {len}\r\n\
         {cors}\
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
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn a_forwarded_header_trusts_the_rightmost_proxy_appended_ip_not_a_spoofed_leftmost() {
        assert_eq!(
            forwarded_client_ip(&Some("9.9.9.9, 10.0.0.1, 198.51.100.7".to_string())),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            "the rightmost entry is the one the trusted proxy appended, a spoofed leftmost is ignored"
        );
        assert_eq!(forwarded_client_ip(&None), None);
        assert_eq!(forwarded_client_ip(&Some("not-an-ip".to_string())), None);
    }

    #[test]
    fn a_direct_loopback_client_is_never_rate_limited_or_banned() {
        let limiter = Limiter::default();
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let t = Instant::now();
        for _ in 0..(RATE_BURST as usize + BAN_STRIKES as usize + 500) {
            assert!(
                matches!(
                    limiter.admit_forwarded(local, MAX_CONNECTIONS_PER_IP, t),
                    Admit::Ok
                ),
                "a trusted local loopback client is exempt from the per address rate limit and ban"
            );
        }
        assert!(
            matches!(
                limiter.admit_forwarded(
                    IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                    MAX_CONNECTIONS_PER_IP,
                    t
                ),
                Admit::Ok
            ),
            "ipv6 loopback is exempt too"
        );
    }

    #[test]
    fn a_forwarded_loopback_address_gets_no_exemption() {
        let limiter = Limiter::default();
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let t = Instant::now();
        let refused = (0..(RATE_BURST as usize + BAN_STRIKES as usize + 500)).any(|_| {
            !matches!(
                limiter.admit_client(local, false, MAX_CONNECTIONS_PER_IP, t),
                Admit::Ok
            )
        });
        assert!(
            refused,
            "a client naming loopback in the header is limited like any other"
        );
    }

    #[test]
    fn a_proxied_client_is_rate_limited_and_banned_by_its_forwarded_ip() {
        let limiter = Limiter::default();
        let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let t = Instant::now();
        let mut rate_limited = false;
        for _ in 0..(RATE_BURST as usize + BAN_STRIKES as usize + 50) {
            match limiter.admit_forwarded(client, MAX_CONNECTIONS_PER_IP, t) {
                Admit::Ok => limiter.release_forwarded(client),
                Admit::RateLimited => rate_limited = true,
                Admit::Banned => rate_limited = true,
                _ => {}
            }
        }
        assert!(
            rate_limited,
            "a proxied client that floods on one forwarded ip is throttled"
        );
        assert!(
            matches!(
                limiter.admit_forwarded(client, MAX_CONNECTIONS_PER_IP, t),
                Admit::Banned
            ),
            "a sustained flood on one forwarded ip is banned even behind the loopback proxy"
        );
        let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        assert!(
            matches!(
                limiter.admit_forwarded(other, MAX_CONNECTIONS_PER_IP, t),
                Admit::Ok
            ),
            "a different proxied client is not collateral banned"
        );
        limiter.release_forwarded(other);
    }

    #[test]
    fn the_forwarded_connection_cap_limits_one_client_and_frees_on_release() {
        let limiter = Limiter::default();
        let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11));
        let t = Instant::now();
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            assert!(matches!(
                limiter.admit_forwarded(client, MAX_CONNECTIONS_PER_IP, t),
                Admit::Ok
            ));
        }
        assert!(
            matches!(limiter.admit_forwarded(client, MAX_CONNECTIONS_PER_IP, t), Admit::IpFull),
            "one proxied client cannot exceed the per forwarded ip connection cap and monopolize the pool"
        );
        limiter.release_forwarded(client);
        assert!(
            matches!(
                limiter.admit_forwarded(client, MAX_CONNECTIONS_PER_IP, t),
                Admit::Ok
            ),
            "a freed slot admits the client again"
        );
    }

    #[test]
    fn the_limiter_caps_connections_per_address_and_frees_them_on_release() {
        let limiter = Limiter::default();
        let peer = ip(7);
        let t = Instant::now();
        for _ in 0..3 {
            assert!(matches!(limiter.try_admit(peer, 100, 3, t), Admit::Ok));
        }
        assert!(
            matches!(limiter.try_admit(peer, 100, 3, t), Admit::IpFull),
            "the fourth connection from one address is refused"
        );
        limiter.release(peer);
        assert!(
            matches!(limiter.try_admit(peer, 100, 3, t), Admit::Ok),
            "a released slot is reusable"
        );
    }

    #[test]
    fn a_sustained_flood_is_banned_then_lifted_when_the_ban_expires() {
        let limiter = Limiter::default();
        let peer = ip(9);
        let t = Instant::now();
        let mut banned = false;
        for _ in 0..(RATE_BURST as usize + BAN_STRIKES as usize + 50) {
            match limiter.try_admit(peer, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, t) {
                Admit::Ok => limiter.release(peer),
                Admit::Banned => {
                    banned = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(banned, "a persistent flood must trip the ban");
        assert!(
            matches!(
                limiter.try_admit(peer, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, t),
                Admit::Banned
            ),
            "a banned address is refused at admission"
        );
        let later = t + BAN_DURATION + Duration::from_secs(1);
        assert!(
            matches!(
                limiter.try_admit(peer, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, later),
                Admit::Ok
            ),
            "the ban lifts after its window"
        );
    }

    #[test]
    fn the_limiter_caps_the_total_across_addresses() {
        let limiter = Limiter::default();
        let t = Instant::now();
        assert!(matches!(limiter.try_admit(ip(1), 2, 10, t), Admit::Ok));
        assert!(matches!(limiter.try_admit(ip(2), 2, 10, t), Admit::Ok));
        assert!(
            matches!(limiter.try_admit(ip(3), 2, 10, t), Admit::TotalFull),
            "the global cap holds even with per address room left"
        );
        limiter.release(ip(1));
        assert!(matches!(limiter.try_admit(ip(3), 2, 10, t), Admit::Ok));
    }

    #[test]
    fn the_limiter_throttles_the_sustained_request_rate_per_address() {
        let limiter = Limiter::default();
        let peer = ip(9);
        let t = Instant::now();
        let mut admitted = 0usize;
        for _ in 0..(RATE_BURST as usize + 16) {
            match limiter.try_admit(peer, 1_000_000, 1_000_000, t) {
                Admit::Ok => {
                    admitted += 1;
                    limiter.release(peer);
                }
                Admit::RateLimited => {}
                _ => panic!("the connection caps are wide open so counts are not the limit here"),
            }
        }
        assert_eq!(
            admitted, RATE_BURST as usize,
            "the burst is the ceiling at one instant"
        );
        assert!(
            matches!(
                limiter.try_admit(peer, 1_000_000, 1_000_000, t),
                Admit::RateLimited
            ),
            "an address over its rate is refused"
        );
        let later = t + Duration::from_secs(1);
        let mut refilled = 0usize;
        for _ in 0..(RATE_REFILL_PER_SEC as usize + 8) {
            if let Admit::Ok = limiter.try_admit(peer, 1_000_000, 1_000_000, later) {
                refilled += 1;
                limiter.release(peer);
            }
        }
        assert_eq!(
            refilled, RATE_REFILL_PER_SEC as usize,
            "one second refills exactly the sustained rate"
        );
    }

    #[test]
    fn the_rate_table_stays_bounded_under_a_flood_of_distinct_addresses() {
        let limiter = Limiter::default();
        let t = Instant::now();
        for i in 0..(RATE_TABLE_CAP as u32 * 3) {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            let _ = limiter.try_admit(ip, 1_000_000, 1_000_000, t);
            limiter.release(ip);
        }
        let inner = limiter
            .inner
            .lock()
            .expect("the gateway limiter lock is not poisoned");
        assert!(
            inner.rate.len() <= RATE_TABLE_CAP,
            "the live generation is capped"
        );
        assert!(
            inner.rate_old.len() <= RATE_TABLE_CAP,
            "the old generation is capped"
        );
        assert!(
            inner.rate.len() + inner.rate_old.len() <= 2 * RATE_TABLE_CAP,
            "the whole rate table is bounded to twice the cap"
        );
    }

    #[test]
    fn a_capped_line_reads_a_normal_line_and_draws_down_the_budget() {
        let raw = b"POST /v1/node_info HTTP/1.1\r\n".to_vec();
        let spent = raw.len();
        let mut reader = Cursor::new(raw);
        let mut budget = MAX_HEAD;
        let line = read_capped_line(
            &mut reader,
            &mut budget,
            Instant::now() + Duration::from_secs(3600),
        )
        .unwrap()
        .unwrap();
        assert_eq!(line, "POST /v1/node_info HTTP/1.1\r");
        assert_eq!(
            budget,
            MAX_HEAD - spent,
            "every byte read draws down the budget"
        );
    }

    #[test]
    fn a_capped_line_refuses_a_line_that_exhausts_the_budget() {
        let mut reader = Cursor::new(vec![b'a'; 100]);
        let mut budget = 16usize;
        assert!(
            read_capped_line(
                &mut reader,
                &mut budget,
                Instant::now() + Duration::from_secs(3600)
            )
            .is_err(),
            "an endless line is refused once the budget is spent"
        );
    }

    #[test]
    fn a_capped_line_returns_none_at_end_of_stream() {
        let mut reader = Cursor::new(Vec::new());
        let mut budget = MAX_HEAD;
        assert!(read_capped_line(
            &mut reader,
            &mut budget,
            Instant::now() + Duration::from_secs(3600)
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn a_capped_line_refuses_a_read_past_its_deadline() {
        let mut reader = Cursor::new(vec![b'a'; 100]);
        let mut budget = MAX_HEAD;
        let past = Instant::now() - Duration::from_secs(1);
        assert!(
            read_capped_line(&mut reader, &mut budget, past).is_err(),
            "a read whose total deadline has passed is refused rather than held open"
        );
    }

    #[test]
    fn the_head_budget_is_shared_across_the_lines() {
        let mut reader = Cursor::new(b"aaaaa\nbbbbb\n".to_vec());
        let mut budget = 8usize;
        assert!(read_capped_line(
            &mut reader,
            &mut budget,
            Instant::now() + Duration::from_secs(3600)
        )
        .unwrap()
        .is_some());
        assert!(read_capped_line(
            &mut reader,
            &mut budget,
            Instant::now() + Duration::from_secs(3600)
        )
        .is_err());
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
        serve(listener, tx, Vec::new(), None);
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
    fn the_default_response_carries_no_wildcard_cors_header() {
        let port = serve_stub();
        let response = round_trip(
            port,
            "POST /v1/node_info HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(
            !response.contains("Access-Control-Allow-Origin"),
            "no CORS origin is advertised unless an operator configures a specific one: {response}"
        );
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
        let response = round_trip(
            port,
            &format!("POST /v1/node_info HTTP/1.1\r\nBig: {giant}\r\n\r\n"),
        );
        assert!(response.starts_with("HTTP/1.1 431"), "{response}");
    }

    #[test]
    fn an_oversized_body_is_refused_over_the_socket() {
        let port = serve_stub();
        let response = round_trip(
            port,
            &format!(
                "POST /v1/node_info HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                MAX_BODY + 1
            ),
        );
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    }

    #[test]
    fn a_malformed_content_length_is_refused_not_read_as_zero() {
        let port = serve_stub();
        let response = round_trip(
            port,
            "POST /v1/node_info HTTP/1.1\r\nHost: x\r\nContent-Length: notanumber\r\n\r\n{}",
        );
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }

    #[test]
    fn a_transfer_encoding_header_is_refused() {
        let port = serve_stub();
        let response = round_trip(
            port,
            "POST /v1/node_info HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }

    #[test]
    fn an_unknown_method_path_is_a_not_found_over_the_socket() {
        let port = serve_stub();
        let response = round_trip(
            port,
            "POST /v1/does_not_exist HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }

    #[test]
    fn an_address_outside_the_allowlist_is_refused_over_the_socket() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, _rx) = channel::<GatewayCall>();
        serve(
            listener,
            tx,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))],
            None,
        );
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let _ = stream.write_all(b"POST /v1/node_info HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}");
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    }
}

#[cfg(test)]
mod ban_table_pressure_tests {
    use super::*;

    fn ip(n: u32) -> IpAddr {
        IpAddr::from(std::net::Ipv4Addr::from(n))
    }

    #[test]
    fn a_live_ban_survives_the_table_filling_up() {
        let mut inner = LimiterInner::default();
        let now = Instant::now();
        let victim = ip(0xC0000201);
        inner.banned.insert(victim, now + BAN_DURATION);

        for i in 0..RATE_TABLE_CAP as u32 {
            inner.banned.insert(ip(i), now + BAN_DURATION);
        }
        let flooder = ip(0xDEADBEEF);
        for _ in 0..BAN_STRIKES {
            inner.strike(flooder, now);
        }

        assert!(
            inner.is_banned(victim, now),
            "a live ban was released when the table filled, so a flood of fresh addresses \
             clears the record of everyone already banned"
        );
    }

    #[test]
    fn expired_bans_are_the_ones_reclaimed() {
        let mut inner = LimiterInner::default();
        let now = Instant::now();
        let stale = ip(1);
        let live = ip(2);
        inner.banned.insert(stale, now);
        inner.banned.insert(live, now + BAN_DURATION);
        for i in 10..(RATE_TABLE_CAP as u32 + 10) {
            inner.banned.insert(ip(i), now);
        }

        let flooder = ip(0xDEADBEEF);
        for _ in 0..BAN_STRIKES {
            inner.strike(flooder, now);
        }

        assert!(inner.is_banned(live, now), "the live ban must be kept");
        assert!(
            inner.is_banned(flooder, now),
            "the flooder that earned a ban must hold one"
        );
    }
}
