use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use ona_server::http::{serve_connection, MAX_BODY};
use serde_json::{json, Value};

/// Starts a server for `count` connections that echoes the path and body.
fn start(count: usize) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().take(count).flatten() {
            serve_connection(stream, &mut |path: &str, body: &str| (200, json!({"path": path, "body": body})));
        }
    });
    port
}

fn send(port: u16, raw: &[u8]) -> (u16, Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(raw).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status: u16 = out.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = out.split_once("\r\n\r\n").unwrap().1;
    (status, serde_json::from_str(body).unwrap())
}

fn post(path: &str, body: &str) -> Vec<u8> {
    format!("POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

#[test]
fn a_post_reaches_the_handler() {
    let port = start(1);
    let (status, body) = send(port, &post("/chat", "{\"a\":1}"));
    assert_eq!(status, 200);
    assert_eq!(body["path"], "/chat");
    assert_eq!(body["body"], "{\"a\":1}");
}

#[test]
fn other_methods_are_refused() {
    let port = start(1);
    assert_eq!(send(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").0, 405);
}

#[test]
fn a_body_too_large_is_refused_before_reading_it() {
    let port = start(1);
    let raw = format!("POST /chat HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
    assert_eq!(send(port, raw.as_bytes()).0, 413);
}

#[test]
fn malformed_requests_are_refused() {
    let port = start(3);
    assert_eq!(send(port, b"POST /chat HTTP/1.1\r\nHost: x\r\n\r\n").0, 400, "no length");
    assert_eq!(send(port, b"POST /chat HTTP/1.1\r\nContent-Length: abc\r\n\r\n").0, 400);
    assert_eq!(send(port, b"\r\n").0, 400, "empty request line");
}

#[test]
fn too_many_headers_are_refused() {
    let port = start(1);
    let mut raw = b"POST /chat HTTP/1.1\r\n".to_vec();
    for i in 0..100 {
        raw.extend_from_slice(format!("X-{i}: y\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    assert_eq!(send(port, &raw).0, 400);
}
