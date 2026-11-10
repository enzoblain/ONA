//! Everything runs against a fake SOCKS5 server on localhost. No Tor, no network.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ona_core::e2ee::Transport;
use ona_tor::{near_client, TorProxy, TorTransport};
use serde_json::json;

const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
const ATYP_DOMAIN: u8 = 3;

#[derive(Clone, Copy)]
enum Mode {
    /// Accepts the tunnel and answers one HTTP request with this response.
    Serve(&'static str),
    /// Answers the SOCKS request with this failure code.
    Refuse(u8),
    /// Answers the greeting with bytes that are not SOCKS.
    Garbage,
}

#[derive(Debug, Clone)]
struct Seen {
    atyp: u8,
    host: String,
    port: u16,
    request_head: String,
    body: Vec<u8>,
}

fn read_connect(stream: &mut TcpStream) -> Option<(u8, String, u16)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).ok()?;
    stream.write_all(&[5, 0]).ok()?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).ok()?;
    let atyp = request[3];
    let host = match atyp {
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).ok()?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).ok()?;
            String::from_utf8(name).ok()?
        }
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).ok()?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        _ => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).ok()?;
            format!("{ip:?}")
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).ok()?;
    Some((atyp, host, u16::from_be_bytes(port)))
}

fn read_http(stream: &TcpStream) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
        head.push_str(&line);
    }
    let mut body = vec![0u8; length];
    let _ = reader.read_exact(&mut body);
    (head, body)
}

fn handle(mut stream: TcpStream, mode: Mode, log: &Mutex<Vec<Seen>>) {
    if let Mode::Garbage = mode {
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    }
    let Some((atyp, host, port)) = read_connect(&mut stream) else { return };
    let record = |request_head: String, body: Vec<u8>| {
        log.lock().unwrap().push(Seen { atyp, host: host.clone(), port, request_head, body });
    };
    match mode {
        Mode::Refuse(code) => {
            record(String::new(), Vec::new());
            let _ = stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
        Mode::Serve(response) => {
            let _ = stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            let (head, body) = read_http(&stream);
            record(head, body);
            let _ = stream.write_all(response.as_bytes());
        }
        Mode::Garbage => unreachable!(),
    }
}

fn fake_socks(mode: Mode) -> (TorProxy, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let shared = log.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle(stream, mode, &shared);
        }
    });
    (TorProxy::new(&addr.to_string()).unwrap(), log)
}

/// A listener standing for the real destination. If it ever gets a connection, traffic escaped.
fn canary() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

fn assert_untouched(listener: &TcpListener) {
    thread::sleep(Duration::from_millis(200));
    assert!(listener.accept().is_err(), "a connection bypassed the proxy");
}

fn dead_proxy() -> TorProxy {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    TorProxy::new(&format!("127.0.0.1:{port}")).unwrap()
}

const OK_REPLY: &str = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

#[test]
fn post_reaches_the_onion_through_socks_with_exact_bytes() {
    let (proxy, log) = fake_socks(Mode::Serve(OK_REPLY));
    let mut transport = TorTransport::new(&format!("http://{ONION}:8787/"), &proxy).unwrap();
    let headers = vec![("X-Ona-Token".to_string(), "abc".to_string())];

    let (status, body) = transport.post("/v1/chat/completions", &headers, b"{\"a\":1}").unwrap();

    assert_eq!((status, body.as_slice()), (200, b"hello".as_slice()));
    let seen = log.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!((seen[0].atyp, seen[0].host.as_str(), seen[0].port), (ATYP_DOMAIN, ONION, 8787));
    assert!(seen[0].request_head.starts_with("POST /v1/chat/completions HTTP/1.1"), "{}", seen[0].request_head);
    assert!(seen[0].request_head.to_ascii_lowercase().contains("x-ona-token: abc"));
    assert_eq!(seen[0].body, b"{\"a\":1}");
}

#[test]
fn get_reaches_the_onion_through_socks() {
    let (proxy, log) = fake_socks(Mode::Serve(OK_REPLY));
    let mut transport = TorTransport::new(&format!("http://{ONION}"), &proxy).unwrap();

    let (status, _) = transport.get("/v1/signature/1", &[]).unwrap();

    assert_eq!(status, 200);
    let seen = log.lock().unwrap().clone();
    assert_eq!((seen[0].atyp, seen[0].port), (ATYP_DOMAIN, 80));
    assert!(seen[0].request_head.starts_with("GET /v1/signature/1 HTTP/1.1"));
}

/// `.invalid` never resolves, so reaching the proxy with the name proves no local lookup decided it.
#[test]
fn name_resolution_is_left_to_the_proxy() {
    let (proxy, log) = fake_socks(Mode::Refuse(4));
    let mut transport = TorTransport::new("https://ona-canary.invalid", &proxy).unwrap();

    assert!(transport.get("/", &[]).is_err());

    let seen = log.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!((seen[0].atyp, seen[0].host.as_str(), seen[0].port), (ATYP_DOMAIN, "ona-canary.invalid", 443));
}

#[test]
fn fails_closed_when_tor_is_not_running() {
    let (listener, addr) = canary();
    let mut transport = TorTransport::new(&format!("https://localhost:{}", addr.port()), &dead_proxy()).unwrap();

    assert!(transport.get("/", &[]).is_err());
    assert!(transport.post("/", &[], b"secret").is_err());
    assert_untouched(&listener);
}

#[test]
fn fails_closed_when_tor_refuses_the_connection() {
    let (listener, addr) = canary();
    let (proxy, log) = fake_socks(Mode::Refuse(5));
    let mut transport = TorTransport::new(&format!("https://localhost:{}", addr.port()), &proxy).unwrap();

    assert!(transport.post("/", &[], b"secret").is_err());
    assert_eq!(log.lock().unwrap().len(), 1, "a refusal must not be retried another way");
    assert_untouched(&listener);
}

#[test]
fn fails_closed_when_the_proxy_does_not_speak_socks() {
    let (listener, addr) = canary();
    let (proxy, _) = fake_socks(Mode::Garbage);
    let mut transport = TorTransport::new(&format!("https://localhost:{}", addr.port()), &proxy).unwrap();

    assert!(transport.get("/", &[]).is_err());
    assert_untouched(&listener);
}

#[test]
fn redirects_are_not_followed() {
    let (listener, addr) = canary();
    let redirect: &'static str = Box::leak(
        format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", addr.port())
            .into_boxed_str(),
    );
    let (proxy, log) = fake_socks(Mode::Serve(redirect));
    let mut transport = TorTransport::new(&format!("http://{ONION}"), &proxy).unwrap();

    let (status, _) = transport.get("/", &[]).unwrap();

    assert_eq!(status, 302);
    assert_eq!(log.lock().unwrap().len(), 1);
    assert_untouched(&listener);
}

#[test]
fn near_rpc_goes_through_socks() {
    let (proxy, log) = fake_socks(Mode::Serve(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 27\r\nConnection: close\r\n\r\n{\"result\":{\"height\":12345}}",
    ));
    let client = near_client(&format!("http://{ONION}"), SigningKey::from_bytes(&[7; 32]), &proxy).unwrap();

    let result = client.post("status", json!([])).unwrap();

    assert_eq!(result["height"], 12345);
    let seen = log.lock().unwrap().clone();
    assert_eq!((seen[0].atyp, seen[0].host.as_str()), (ATYP_DOMAIN, ONION));
    let sent: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
    assert_eq!(sent["method"], "status");
}

#[test]
fn near_rpc_fails_closed_when_tor_is_not_running() {
    let (listener, addr) = canary();
    let url = format!("https://localhost:{}", addr.port());
    let client = near_client(&url, SigningKey::from_bytes(&[7; 32]), &dead_proxy()).unwrap();

    assert!(client.post("status", json!([])).is_err());
    assert_untouched(&listener);
}

#[test]
fn remote_or_malformed_proxies_are_refused() {
    for addr in ["8.8.8.8:9050", "192.168.1.2:9050", "localhost:9050", "127.0.0.1", ""] {
        assert!(TorProxy::new(addr).is_err(), "{addr}");
    }
    assert!(TorProxy::new("127.0.0.1:9050").is_ok());
    assert!(TorProxy::new("[::1]:9050").is_ok());
}

#[test]
fn unsafe_destinations_are_refused() {
    let proxy = TorProxy::new("127.0.0.1:9050").unwrap();
    let short = "http://abc.onion".to_string();
    let subdomain = format!("http://foo.{ONION}");
    let userinfo = format!("http://user@{ONION}");
    let bad_port = format!("http://{ONION}:notaport");
    let cases = [
        "http://rpc.testnet.near.org",
        "ftp://rpc.testnet.near.org",
        "rpc.testnet.near.org",
        "https://1.2.3.4",
        "https://[::1]:443",
        "https://",
        "https://a\\b.org",
        short.as_str(),
        subdomain.as_str(),
        userinfo.as_str(),
        bad_port.as_str(),
    ];
    for url in cases {
        assert!(TorTransport::new(url, &proxy).is_err(), "{url}");
        assert!(near_client(url, SigningKey::from_bytes(&[7; 32]), &proxy).is_err(), "{url}");
    }
    assert!(TorTransport::new("https://rpc.testnet.near.org", &proxy).is_ok());
    assert!(TorTransport::new(&format!("http://{ONION}:8787"), &proxy).is_ok());
}

#[test]
fn a_path_cannot_change_the_host() {
    let (proxy, log) = fake_socks(Mode::Serve(OK_REPLY));
    let mut transport = TorTransport::new(&format!("http://{ONION}"), &proxy).unwrap();

    assert!(transport.get(".evil.example/", &[]).is_err());
    assert!(transport.post("@evil.example/", &[], b"x").is_err());
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn onion_service_template_targets_the_relay_on_localhost_only() {
    let text = include_str!("../../../docs/torrc.relay.example");
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty()).collect();

    assert!(lines.contains(&"HiddenServicePort 80 127.0.0.1:8787"), "{lines:?}");
    assert!(lines.contains(&"HiddenServiceVersion 3"), "{lines:?}");
    assert!(lines.contains(&"SocksPort 0"), "{lines:?}");
    for line in lines.iter().filter(|l| l.starts_with("HiddenServicePort")) {
        assert!(line.ends_with("127.0.0.1:8787"), "{line}");
    }
}
