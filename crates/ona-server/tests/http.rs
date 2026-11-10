use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ona_server::http::{serve_connection, serve_request_with, Handler, Limits, Pool, Request, MAX_BODY};
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

fn ok_handler(_: &Request) -> (u16, Vec<u8>) {
    (200, b"{}".to_vec())
}

/// Starts an accepting thread that gives every connection to a pool.
fn start_pool(workers: usize, backlog: usize, limits: Limits, handler: Arc<Handler>) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let pool = Pool::new(workers, backlog, limits, handler);
        for stream in listener.incoming().flatten() {
            pool.dispatch(stream);
        }
    });
    port
}

fn status_within(port: u16, raw: &[u8], limit: Duration) -> u16 {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(limit)).unwrap();
    s.write_all(raw).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).expect("the server answered in time");
    out.split_whitespace().nth(1).unwrap().parse().unwrap()
}

const SIMPLE_GET: &[u8] = b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n";

#[test]
fn a_client_sending_a_byte_at_a_time_is_cut_by_the_global_deadline() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (done, finished) = channel();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let limits = Limits { read: Duration::from_millis(300), write: Duration::from_secs(1) };
        serve_request_with(stream, limits, &mut ok_handler);
        done.send(()).unwrap();
    });

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let started = Instant::now();
    let mut outcome = Err(RecvTimeoutError::Timeout);
    // Each byte arrives well within the time of a single read, so only a global deadline stops this.
    while outcome.is_err() && started.elapsed() < Duration::from_secs(3) {
        let _ = client.write_all(b"G");
        outcome = finished.recv_timeout(Duration::from_millis(50));
    }
    assert!(outcome.is_ok(), "the connection was still being served after 3 s");

    client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut out = String::new();
    let _ = client.read_to_string(&mut out);
    assert_eq!(out.split_whitespace().nth(1), Some("408"));
}

#[test]
fn a_stalled_connection_does_not_stop_the_others() {
    let port = start_pool(2, 4, Limits::default(), Arc::new(ok_handler));
    let _stalled = TcpStream::connect(("127.0.0.1", port)).unwrap();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(status_within(port, SIMPLE_GET, Duration::from_secs(2)), 200);
}

#[test]
fn a_slow_handler_does_not_stop_the_accepting_thread() {
    let (release, wait) = channel::<()>();
    let wait = Arc::new(Mutex::new(wait));
    let handler: Arc<Handler> = Arc::new(move |request: &Request| {
        if request.target == "/slow" {
            let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(5));
        }
        (200, b"{}".to_vec())
    });
    let port = start_pool(2, 4, Limits::default(), handler);

    let mut slow = TcpStream::connect(("127.0.0.1", port)).unwrap();
    slow.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(status_within(port, SIMPLE_GET, Duration::from_secs(2)), 200);
    release.send(()).unwrap();
}

#[test]
fn a_full_queue_is_refused_at_once() {
    let (release, wait) = channel::<()>();
    let wait = Arc::new(Mutex::new(wait));
    let handler: Arc<Handler> = Arc::new(move |_: &Request| {
        let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(5));
        (200, b"{}".to_vec())
    });
    let port = start_pool(1, 1, Limits::default(), handler);

    let mut busy = TcpStream::connect(("127.0.0.1", port)).unwrap();
    busy.write_all(SIMPLE_GET).unwrap();
    thread::sleep(Duration::from_millis(100));
    let mut queued = TcpStream::connect(("127.0.0.1", port)).unwrap();
    queued.write_all(SIMPLE_GET).unwrap();
    thread::sleep(Duration::from_millis(100));

    let started = Instant::now();
    assert_eq!(status_within(port, b"", Duration::from_secs(2)), 503);
    assert!(started.elapsed() < Duration::from_secs(1));
    release.send(()).unwrap();
    release.send(()).unwrap();
}
