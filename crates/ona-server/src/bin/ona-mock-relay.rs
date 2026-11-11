//! A relay with a fake chain and a fake model, on localhost only, for front-end development.
//!
//! `ona-mock-relay [port]`. Routes: `POST /exchange`, `POST /chat`, and `POST /dev/credit`, which
//! hands out a free credit with its owner key, so that the front end can sign the exchange of its
//! own blinded points (`exchange_sig`). That route exists only in this binary.

use std::net::TcpListener;
use std::time::{Duration, Instant};

use ona_server::http::serve_connection;
use ona_server::mock::{MockChain, MockModel};
use ona_server::{system_time_ns, Config, MemoryStore, Relay};
use ona_token::{claim_digest_until, keygen, sign_blinded, sign_digest, token_dst, PendingToken};
use rand::rngs::OsRng;
use serde_json::{json, Value};

const MINT: &str = "mock-mint.test";
const RELAY: &str = "mock-relay.test";
const FLUSH_EVERY: Duration = Duration::from_secs(1);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn new_credit(sk: &ona_token::SecretKey, dst: &[u8]) -> Result<Value, String> {
    let pending = PendingToken::new(&mut OsRng, 0, dst).map_err(|e| e.to_string())?;
    let sig = sign_blinded(sk, &pending.blinded).map_err(|e| e.to_string())?;
    let (token, owner) = pending.finish(&sig, &sk.public_key()).map_err(|e| e.to_string())?;
    // Valid for a day, inside the 7 days the contract accepts.
    let expires_at = system_time_ns().saturating_add(24 * 3_600_000_000_000);
    let digest = claim_digest_until(MINT, RELAY, &token.nullifier(), expires_at);
    Ok(json!({
        "token": hex(&token.to_bytes()),
        "owner_sig": hex(&sign_digest(&owner, &digest)),
        "expires_at": expires_at.to_string(),
        "owner_key": hex(&owner.to_bytes()),
        "mode": "mock",
    }))
}

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(8787);
    let credit_key = keygen(&mut OsRng);
    let dst = token_dst("mock", MINT).expect("the constant names are short");
    let config = Config {
        mint: MINT.into(),
        relay: RELAY.into(),
        mint_dst: dst.clone(),
        credit_key: credit_key.public_key(),
        tokens_per_credit: 8,
        max_tokens_per_request: 4096,
        max_prompt_bytes: 16 * 1024,
    };
    let mut relay = Relay::new(MemoryStore::default(), MockChain::default(), MockModel, config, keygen(&mut OsRng));

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("cannot listen on port {port}: {e}");
            std::process::exit(1);
        }
    };
    println!("MOCK relay on http://127.0.0.1:{port} (fake chain, fake model)");
    println!("request key: {}", hex(&relay.request_public_key()));
    println!("request dst: {}", String::from_utf8_lossy(relay.request_dst()));

    let mut last_flush = Instant::now();
    for stream in listener.incoming().flatten() {
        serve_connection(stream, &mut |path: &str, body: &str| {
            if path == "/dev/credit" {
                return match new_credit(&credit_key, &dst) {
                    Ok(credit) => (200, credit),
                    Err(e) => (503, json!({"error": e, "mode": "mock"})),
                };
            }
            relay.handle(path, body)
        });
        if last_flush.elapsed() >= FLUSH_EVERY {
            if let Err(e) = relay.flush() {
                eprintln!("flush failed: {e}");
            }
            last_flush = Instant::now();
        }
    }
}
