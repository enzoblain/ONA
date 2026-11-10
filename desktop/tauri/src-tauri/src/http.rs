//! A minimal HTTP/1.x reader and writer for the phone protocol: one request per connection, small JSON bodies.

use serde_json::Value;

pub const MAX_HEADER: usize = 16 * 1024;
pub const MAX_BODY: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum Parse {
    /// More bytes are needed.
    Incomplete,
    Request(Request),
    /// HTTP status to answer with before closing.
    Invalid(u16),
}

/// Parses `buffer`, everything received so far on the connection.
pub fn parse(buffer: &[u8]) -> Parse {
    let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buffer.len() > MAX_HEADER { Parse::Invalid(431) } else { Parse::Incomplete };
    };
    if end > MAX_HEADER {
        return Parse::Invalid(431);
    }
    let Ok(head) = std::str::from_utf8(&buffer[..end]) else { return Parse::Invalid(400) };
    let mut lines = head.split("\r\n");
    let request_line: Vec<&str> = lines.next().unwrap_or("").split(' ').collect();
    let [method, path, version] = request_line.as_slice() else { return Parse::Invalid(400) };
    if !version.starts_with("HTTP/1.") || !path.starts_with('/') {
        return Parse::Invalid(400);
    }
    let mut length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        if name.trim().eq_ignore_ascii_case("content-length") {
            let Ok(value) = value.trim().parse::<usize>() else { return Parse::Invalid(400) };
            length = value;
        }
    }
    if length > MAX_BODY {
        return Parse::Invalid(413);
    }
    let start = end + 4;
    if buffer.len() - start < length {
        return Parse::Incomplete;
    }
    Parse::Request(Request { method: method.to_string(), path: path.to_string(), body: buffer[start..start + length].to_vec() })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub status: u16,
    pub json: Value,
}

impl Response {
    pub fn new(status: u16, json: Value) -> Self {
        Self { status, json }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            409 => "Conflict",
            413 => "Payload Too Large",
            431 => "Request Header Fields Too Large",
            _ => "Error",
        };
        let body = self.json.to_string();
        let mut out = format!(
            "HTTP/1.0 {} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\
             Cache-Control: no-store\r\nConnection: close\r\n\r\n",
            self.status,
            body.len()
        ).into_bytes();
        out.extend_from_slice(body.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_request_in_pieces() {
        let raw = b"POST /v0/chats HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse(&raw[..20]), Parse::Incomplete);
        assert_eq!(parse(&raw[..raw.len() - 1]), Parse::Incomplete);
        assert_eq!(parse(raw), Parse::Request(Request { method: "POST".into(), path: "/v0/chats".into(), body: b"{}".to_vec() }));
    }

    #[test]
    fn refuses_oversized_and_malformed_requests() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\nContent-Length: 999999\r\n\r\n"), Parse::Invalid(413));
        assert_eq!(parse(b"GET nowhere HTTP/1.1\r\n\r\n"), Parse::Invalid(400));
        assert_eq!(parse(&vec![b'a'; MAX_HEADER + 1]), Parse::Invalid(431));
    }
}
