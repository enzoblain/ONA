//! Minimal HTTP/1.1 front for the relay: one request per connection, bodies bounded, no keep-alive.
//! It has no TLS because the relay is meant to be reached through an onion service.
//!
//! A connection has one deadline for reading the whole request and one for writing the whole
//! response, so a client sending a byte at a time cannot hold a thread for long. `Pool` keeps
//! connections off the accepting thread, with a bounded number of threads and of waiting connections.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub const MAX_BODY: usize = 128 * 1024;
const MAX_HEADER_LINES: usize = 64;
const MAX_HEADER_BYTES: u64 = 16 * 1024;
const BUSY_DRAIN_READS: usize = 4;

/// How long a connection may take, as a whole, in each direction.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub read: Duration,
    pub write: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { read: Duration::from_secs(30), write: Duration::from_secs(30) }
    }
}

pub struct Request {
    pub method: String,
    /// Path and query string, exactly as received.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn response_bytes(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn time_left(until: Instant) -> std::io::Result<Duration> {
    let left = until.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(ErrorKind::TimedOut.into());
    }
    Ok(left)
}

fn write_before(stream: &mut TcpStream, until: Instant, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(time_left(until)?))?;
        let written = stream.write(bytes)?;
        if written == 0 {
            return Err(ErrorKind::WriteZero.into());
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

/// Each read gets only the time left, so slow data cannot extend the deadline.
struct DeadlineReader<'a> {
    stream: &'a TcpStream,
    until: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(time_left(self.until)?))?;
        let mut stream = self.stream;
        stream.read(buf)
    }
}

fn read_failure(error: std::io::Error, message: &'static str) -> (u16, &'static str) {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => (408, "request timeout"),
        _ => (400, message),
    }
}

fn read_request(stream: &TcpStream, limit: Duration) -> Result<Request, (u16, &'static str)> {
    let source = DeadlineReader { stream, until: Instant::now() + limit };
    let mut reader = BufReader::new(source.take(MAX_BODY as u64 + MAX_HEADER_BYTES));
    let mut first = String::new();
    reader.read_line(&mut first).map_err(|e| read_failure(e, "cannot read request"))?;
    let mut parts = first.split_whitespace();
    let method = parts.next().ok_or((400, "malformed request"))?.to_string();
    let target = parts.next().ok_or((400, "malformed request"))?.to_string();

    let mut headers = Vec::new();
    let mut length: Option<usize> = None;
    for _ in 0..MAX_HEADER_LINES {
        let mut line = String::new();
        let read = reader.read_line(&mut line).map_err(|e| read_failure(e, "cannot read headers"))?;
        if read == 0 {
            return Err((400, "connection closed in the headers"));
        }
        let line = line.trim_end();
        if line.is_empty() {
            let mut body = Vec::new();
            match (method.as_str(), length) {
                ("POST", None) => return Err((400, "missing content length")),
                (_, Some(n)) if n > MAX_BODY => return Err((413, "body too large")),
                (_, Some(n)) => {
                    body = vec![0u8; n];
                    reader.read_exact(&mut body).map_err(|e| read_failure(e, "body shorter than announced"))?;
                }
                _ => {}
            }
            return Ok(Request { method, target, headers, body });
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.parse().map_err(|_| (400, "bad content length"))?);
            }
            headers.push((name.to_string(), value));
        }
    }
    Err((400, "too many headers"))
}

/// Serves one connection within `limits`, for routes that need the method, headers and exact bytes.
pub fn serve_request_with(
    mut stream: TcpStream,
    limits: Limits,
    handler: &mut dyn FnMut(&Request) -> (u16, Vec<u8>),
) {
    let (status, body) = match read_request(&stream, limits.read) {
        Ok(request) => handler(&request),
        Err((status, message)) => (status, json!({"error": message}).to_string().into_bytes()),
    };
    let until = Instant::now() + limits.write;
    let _ = write_before(&mut stream, until, &response_bytes(status, &body));
}

/// Serves one connection with the default limits.
pub fn serve_request(stream: TcpStream, handler: &mut dyn FnMut(&Request) -> (u16, Vec<u8>)) {
    serve_request_with(stream, Limits::default(), handler);
}

/// Serves one connection of the JSON API: POST only, text body.
pub fn serve_connection(stream: TcpStream, handler: &mut dyn FnMut(&str, &str) -> (u16, Value)) {
    serve_request(stream, &mut |request: &Request| {
        let (status, value) = if request.method != "POST" {
            (405, json!({"error": "only POST is accepted"}))
        } else {
            match std::str::from_utf8(&request.body) {
                Ok(body) => handler(&request.target, body),
                Err(_) => (400, json!({"error": "body is not text"})),
            }
        };
        (status, value.to_string().into_bytes())
    });
}

pub type Handler = dyn Fn(&Request) -> (u16, Vec<u8>) + Send + Sync;

/// A fixed set of threads serving connections from a bounded queue.
pub struct Pool {
    queue: SyncSender<TcpStream>,
}

fn worker(queue: &Mutex<Receiver<TcpStream>>, limits: Limits, handler: &Handler) {
    loop {
        let next = match queue.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => return,
        };
        let Ok(stream) = next else {
            return;
        };
        // A bug in one request must not cost the pool a thread for good.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if stream.set_nonblocking(false).is_ok() {
                serve_request_with(stream, limits, &mut |request: &Request| handler(request));
            }
        }));
    }
}

/// Never waits on the client: the short reply fits the socket buffer of a new connection. Closing
/// with unread data would reset the connection and lose the reply, so what already arrived is read
/// first. A request arriving later can still see a reset, which is an acceptable way to be refused.
fn refuse_busy(mut stream: TcpStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let body = json!({"error": "relay is busy"}).to_string();
    let _ = stream.write_all(&response_bytes(503, body.as_bytes()));
    let _ = stream.shutdown(Shutdown::Write);
    let mut unread = [0u8; 4096];
    for _ in 0..BUSY_DRAIN_READS {
        if !matches!(stream.read(&mut unread), Ok(n) if n > 0) {
            break;
        }
    }
}

impl Pool {
    pub fn new(workers: usize, backlog: usize, limits: Limits, handler: Arc<Handler>) -> Self {
        let (queue, receiver) = sync_channel(backlog);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..workers.max(1) {
            let receiver = Arc::clone(&receiver);
            let handler = Arc::clone(&handler);
            std::thread::spawn(move || worker(&receiver, limits, handler.as_ref()));
        }
        Self { queue }
    }

    /// Hands over a connection without blocking. A full queue answers 503 at once.
    pub fn dispatch(&self, stream: TcpStream) {
        match self.queue.try_send(stream) {
            Ok(()) => {}
            Err(TrySendError::Full(stream) | TrySendError::Disconnected(stream)) => refuse_busy(stream),
        }
    }
}
