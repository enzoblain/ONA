//! The real HTTP transport against local listeners. This binary holds a single test on purpose:
//! it sets proxy variables for the whole process, which must not leak into tests running in
//! parallel.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ona_core::e2ee::{HttpTransport, Transport};

/// Accepts connections, counts them, and answers each request with `response`.
fn server(response: String) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            seen.fetch_add(1, Ordering::SeqCst);
            answer(stream, &response);
        }
    });
    (port, count)
}

fn answer(mut stream: TcpStream, response: &str) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line == "\r\n" {
            break;
        }
        line.clear();
    }
    let _ = stream.write_all(response.as_bytes());
}

#[test]
fn environment_proxies_are_ignored_and_redirects_are_not_followed() {
    let empty = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
    let (proxy_port, proxy_hits) = server(empty.clone());
    let (other_port, other_hits) = server(empty);
    let redirect = format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{other_port}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let (relay_port, relay_hits) = server(redirect);

    let proxy = format!("http://127.0.0.1:{proxy_port}");
    for name in ["ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "http_proxy", "https_proxy"] {
        std::env::set_var(name, &proxy);
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");
    let mut transport = HttpTransport::new(&format!("http://127.0.0.1:{relay_port}"));
    let headers = vec![("X-Ona-Token".to_string(), "secret".to_string())];
    let result = transport.get("/v1/attestation/report", &headers);
    thread::sleep(Duration::from_millis(100));

    assert_eq!(result.unwrap().0, 307, "the redirect is returned, not followed");
    assert_eq!(relay_hits.load(Ordering::SeqCst), 1, "the request went straight to the relay");
    assert_eq!(proxy_hits.load(Ordering::SeqCst), 0, "the proxy of the environment received nothing");
    assert_eq!(other_hits.load(Ordering::SeqCst), 0, "the redirect target received nothing");
}
