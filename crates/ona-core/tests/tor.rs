//! The client's traffic through Tor, against a fake SOCKS5 server on localhost that asks for a user name and password,
//! as Tor does when `IsolateSOCKSAuth` is on. No Tor, no network.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_core::e2ee::Transport;
use ona_core::pool::{AgentError, DepositorProof, NearPool, PoolAgent, PoolChain, SignedNote};
use ona_core::pool_agent::HttpAgent;
use ona_core::remote::{http_model, RemoteConfig};
use ona_core::tor::{Network, TorProxy};
use serde_json::json;

const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
const ATYP_DOMAIN: u8 = 3;
const METHOD_PASSWORD: u8 = 2;

#[derive(Debug, Clone)]
struct Seen {
    user: String,
    atyp: u8,
    host: String,
    path: String,
}

/// One SOCKS5 connection with user name and password, then one HTTP request answered with `body`.
fn handle(mut s: TcpStream, body: &str, log: &Mutex<Vec<Seen>>) -> Option<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).ok()?;
    let mut methods = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut methods).ok()?;
    if !methods.contains(&METHOD_PASSWORD) {
        s.write_all(&[5, 0xff]).ok()?;
        return None;
    }
    s.write_all(&[5, METHOD_PASSWORD]).ok()?;
    let mut ver_len = [0u8; 2];
    s.read_exact(&mut ver_len).ok()?;
    let mut user = vec![0u8; usize::from(ver_len[1])];
    s.read_exact(&mut user).ok()?;
    let mut plen = [0u8; 1];
    s.read_exact(&mut plen).ok()?;
    let mut password = vec![0u8; usize::from(plen[0])];
    s.read_exact(&mut password).ok()?;
    s.write_all(&[1, 0]).ok()?;

    let mut request = [0u8; 4];
    s.read_exact(&mut request).ok()?;
    let atyp = request[3];
    let host = if atyp == ATYP_DOMAIN {
        let mut len = [0u8; 1];
        s.read_exact(&mut len).ok()?;
        let mut name = vec![0u8; usize::from(len[0])];
        s.read_exact(&mut name).ok()?;
        String::from_utf8(name).ok()?
    } else {
        String::new()
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).ok()?;
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).ok()?;

    let mut reader = BufReader::new(s.try_clone().ok()?);
    let mut first = String::new();
    reader.read_line(&mut first).ok()?;
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut sent = vec![0u8; length];
    reader.read_exact(&mut sent).ok()?;
    let path = first.split_whitespace().nth(1).unwrap_or_default().to_string();
    log.lock().ok()?.push(Seen { user: String::from_utf8_lossy(&user).into(), atyp, host, path });
    let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    s.write_all(reply.as_bytes()).ok()
}

fn fake_tor(body: String) -> (Network, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let shared = log.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = handle(stream, &body, &shared);
        }
    });
    (Network::Tor(TorProxy::new(&addr.to_string()).unwrap()), log)
}

fn dead_tor() -> Network {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    Network::Tor(TorProxy::new(&format!("127.0.0.1:{port}")).unwrap())
}

fn seen(log: &Arc<Mutex<Vec<Seen>>>) -> Vec<Seen> {
    log.lock().unwrap().clone()
}

fn note() -> SignedNote {
    SignedNote { tier: 0, pk: [1; 32], nonce: [2; 32], sig: [3; 48], owner_sig: [4; 64], expires_at: 9 }
}

fn proof() -> DepositorProof {
    DepositorProof { public_key: [5; 32], signature: [6; 64], nonce: [7; 32] }
}

// The cash issue names the account; the entry names the vault. Through Tor they never share a circuit: each goes with
// its own SOCKS credentials, and the onion name goes to Tor unresolved.
#[test]
fn a_cash_issue_and_an_entry_never_share_a_circuit() {
    let (network, log) = fake_tor(json!({"signatures": [B64.encode([1u8; 48])]}).to_string());
    let mut agent = HttpAgent::through(&network, &format!("http://{ONION}/")).unwrap();
    agent.issue_cash("alice.testnet", &[(0, [9u8; 48])], &proof()).unwrap();
    agent.enter(0, &note(), &[(0, 1)], &[[8u8; 48]]).unwrap();
    agent.signatures(&[[8u8; 48]]).unwrap();
    let seen = seen(&log);
    assert_eq!(seen.iter().map(|s| s.path.as_str()).collect::<Vec<_>>(), ["/issue_cash", "/enter", "/signatures"]);
    assert!(seen.iter().all(|s| s.atyp == ATYP_DOMAIN && s.host == ONION), "{seen:?}");
    let users: std::collections::BTreeSet<&str> = seen.iter().map(|s| s.user.as_str()).collect();
    assert_eq!(users.len(), 3, "one circuit per operation: {seen:?}");
}

// Two reads of a recovery, or of two operations, are not tied to one circuit either.
#[test]
fn each_rpc_read_has_its_own_circuit() {
    let view = json!({"jsonrpc": "2.0", "id": "1", "result": {"result": b"true".to_vec(), "block_hash": "h", "block_height": 1, "logs": []}});
    let (network, log) = fake_tor(view.to_string());
    // An onion RPC endpoint: the fake speaks plain HTTP, not TLS.
    let chain = NearPool::through(&network, &format!("http://{ONION}"), "pool.testnet").unwrap();
    assert_eq!(chain.view("is_spent", json!({"nf": "AA=="})).unwrap(), json!(true));
    assert_eq!(chain.view("is_spent", json!({"nf": "AQ=="})).unwrap(), json!(true));
    let seen = seen(&log);
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|s| s.atyp == ATYP_DOMAIN && s.host == ONION));
    assert_ne!(seen[0].user, seen[1].user);
}

// The relay's calls go through Tor too, each request on its own circuit.
#[test]
fn the_relay_is_reached_through_tor_one_circuit_per_request() {
    let (network, log) = fake_tor("{}".into());
    let mut transport = network.transport(&format!("http://{ONION}:8787")).unwrap();
    transport.get("/v1/attestation", &[]).unwrap();
    transport.post("/v1/chat", &[], b"{}").unwrap();
    let seen = seen(&log);
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0].user, seen[1].user);
    let config = RemoteConfig {
        relay_url: format!("http://{ONION}"),
        model: "m".into(),
        max_tokens_per_call: 10,
        total_token_budget: 100,
        request_tokens: vec![],
        request_tokens_file: None,
    };
    assert!(http_model(config.clone(), &network).is_ok(), "an onion relay through Tor");
    assert!(http_model(config, &Network::Direct).is_err(), "an onion relay without Tor is never looked up");
    let local = RemoteConfig { relay_url: "http://127.0.0.1:8787".into(), ..remote_config() };
    assert!(http_model(local.clone(), &network).is_err(), "a local relay cannot be reached through Tor");
    assert!(http_model(local, &Network::Direct).is_ok());
}

fn remote_config() -> RemoteConfig {
    RemoteConfig {
        relay_url: String::new(),
        model: "m".into(),
        max_tokens_per_call: 10,
        total_token_budget: 100,
        request_tokens: vec![],
        request_tokens_file: None,
    }
}

// Tor down: every call fails, as an unknown outcome or a read error, and nothing is tried directly.
#[test]
fn with_tor_down_every_call_fails() {
    let network = dead_tor();
    let mut agent = HttpAgent::through(&network, &format!("http://{ONION}")).unwrap();
    assert!(matches!(agent.issue_cash("alice.testnet", &[(0, [9u8; 48])], &proof()), Err(AgentError::Unknown(_))));
    assert!(agent.pay_exit(&note(), "alice.testnet").is_err());
    let chain = NearPool::through(&network, "https://rpc.testnet.near.org", "pool.testnet").unwrap();
    assert!(chain.view("get_config", json!({})).is_err());
    assert!(chain.block(None).is_err());
    let mut relay = network.transport("https://relay.example.org").unwrap();
    assert!(relay.get("/", &[]).is_err());
}

// Addresses are checked for the network before any operation.
#[test]
fn addresses_are_checked_for_the_network() {
    let tor = Network::Tor(TorProxy::new("127.0.0.1:9050").unwrap());
    assert!(HttpAgent::through(&tor, "http://127.0.0.1:8788").is_err());
    assert!(NearPool::through(&tor, "http://127.0.0.1:3030", "p").is_err());
    assert!(NearPool::through(&tor, "http://rpc.example.org", "p").is_err(), "plain http would be read at the exit");
    assert!(HttpAgent::through(&Network::Direct, &format!("http://{ONION}")).is_err());
    assert!(NearPool::through(&Network::Direct, &format!("https://{ONION}"), "p").is_err());
    assert!(NearPool::through(&Network::Direct, "http://rpc.example.org", "p").is_err());
    assert!(NearPool::through(&Network::Direct, "http://127.0.0.1:3030", "p").is_ok());
}
