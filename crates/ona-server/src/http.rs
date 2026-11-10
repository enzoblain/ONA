//! Minimal HTTP/1.1 front for the relay: one request per connection, bodies bounded, no keep-alive.
//! It has no TLS because the relay is meant to be reached through an onion service.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{json, Value};

pub const MAX_BODY: usize = 128 * 1024;
const MAX_HEADER_LINES: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

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

fn write_response(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let text = body.to_string();
    write!(
        stream,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        reason(status),
        text.len()
    )?;
    stream.flush()
}

/// Reads one request. Returns the response to send at once if the request cannot be served.
fn read_request(stream: &TcpStream) -> Result<(String, String), (u16, &'static str)> {
    let mut reader = BufReader::new(stream.take(MAX_BODY as u64 + 16 * 1024));
    let mut first = String::new();
    reader.read_line(&mut first).map_err(|_| (400, "cannot read request"))?;
    let mut parts = first.split_whitespace();
    let method = parts.next().ok_or((400, "malformed request"))?.to_string();
    let path = parts.next().ok_or((400, "malformed request"))?.to_string();

    let mut length: Option<usize> = None;
    for _ in 0..MAX_HEADER_LINES {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|_| (400, "cannot read headers"))?;
        let line = line.trim_end();
        if line.is_empty() {
            if method != "POST" {
                return Err((405, "only POST is accepted"));
            }
            let length = length.ok_or((400, "missing content length"))?;
            if length > MAX_BODY {
                return Err((413, "body too large"));
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).map_err(|_| (400, "body shorter than announced"))?;
            let body = String::from_utf8(body).map_err(|_| (400, "body is not text"))?;
            return Ok((path, body));
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.trim().parse().map_err(|_| (400, "bad content length"))?);
            }
        }
    }
    Err((400, "too many headers"))
}

/// Serves one connection. Network errors are ignored: the client has gone away.
pub fn serve_connection(mut stream: TcpStream, handler: &mut dyn FnMut(&str, &str) -> (u16, Value)) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let (status, body) = match read_request(&stream) {
        Ok((path, body)) => handler(&path, &body),
        Err((status, message)) => (status, json!({"error": message})),
    };
    let _ = write_response(&mut stream, status, &body);
}
