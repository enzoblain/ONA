//! Minimal HTTP/1.1 front for the relay: one request per connection, bodies bounded, no keep-alive.
//! It has no TLS because the relay is meant to be reached through an onion service.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{json, Value};

pub const MAX_BODY: usize = 128 * 1024;
const MAX_HEADER_LINES: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(120);

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
        409 => "Conflict",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn write_response(stream: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn read_request(stream: &TcpStream) -> Result<Request, (u16, &'static str)> {
    let mut reader = BufReader::new(stream.take(MAX_BODY as u64 + 16 * 1024));
    let mut first = String::new();
    reader.read_line(&mut first).map_err(|_| (400, "cannot read request"))?;
    let mut parts = first.split_whitespace();
    let method = parts.next().ok_or((400, "malformed request"))?.to_string();
    let target = parts.next().ok_or((400, "malformed request"))?.to_string();

    let mut headers = Vec::new();
    let mut length: Option<usize> = None;
    for _ in 0..MAX_HEADER_LINES {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|_| (400, "cannot read headers"))?;
        let line = line.trim_end();
        if line.is_empty() {
            let mut body = Vec::new();
            match (method.as_str(), length) {
                ("POST", None) => return Err((400, "missing content length")),
                (_, Some(n)) if n > MAX_BODY => return Err((413, "body too large")),
                (_, Some(n)) => {
                    body = vec![0u8; n];
                    reader.read_exact(&mut body).map_err(|_| (400, "body shorter than announced"))?;
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

/// Serves one connection, for routes that need the method, headers and exact bytes.
pub fn serve_request(mut stream: TcpStream, handler: &mut dyn FnMut(&Request) -> (u16, Vec<u8>)) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let (status, body) = match read_request(&stream) {
        Ok(request) => handler(&request),
        Err((status, message)) => (status, json!({"error": message}).to_string().into_bytes()),
    };
    let _ = write_response(&mut stream, status, &body);
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
