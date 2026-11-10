//! The relay. `ona-relay init-key <file>` creates its request-signing key.
//! `ona-relay run` serves on localhost only, configured by the variables in `docs/INSTALL.md`.
//! The accepting thread only hands connections to a bounded pool. Chain and model calls run in the
//! pool or on the batch thread, without holding the relay state.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ona_near::{load_account_key, Client};
use ona_server::gateway::{GatewayPolicy, NearAiBackend};
use ona_server::http::{Handler, Limits, Pool, Request};
use ona_server::mock::MockModel;
use ona_server::near::NearRelayChain;
use ona_server::{keyfile, Config, FileStore, Relay};
use ona_token::token_dst;
use serde_json::{json, Value};

const NEAR_AI: &str = "https://cloud-api.near.ai";
const ACCEPT_RETRY: Duration = Duration::from_millis(50);
const WORKERS: usize = 8;
const BACKLOG: usize = 32;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn env_number<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| format!("{name} is not a number")),
        Err(_) => Ok(default),
    }
}

fn init_key(path: &Path) -> Result<(), String> {
    let key = keyfile::create(path)?;
    println!("request key: {}", hex(&key.public_key()));
    Ok(())
}

fn run() -> Result<(), String> {
    let rpc = env("ONA_RPC_URL")?;
    let mint = env("ONA_MINT")?;
    let network = env("ONA_NETWORK")?;
    let account = env("ONA_RELAY_ACCOUNT")?;
    let account_key =
        load_account_key(&PathBuf::from(env("ONA_RELAY_ACCOUNT_KEY_FILE")?)).map_err(|e| e.to_string())?;
    let request_key = keyfile::load(&PathBuf::from(env("ONA_RELAY_REQUEST_KEY_FILE")?))?;
    let store = FileStore::open(&PathBuf::from(env("ONA_RELAY_STORE_FILE")?))?;
    let models = env("ONA_MODELS")?.split(',').map(|m| m.trim().to_string()).collect();
    let api_key = env("NEAR_AI_CLOUD_API_KEY")?;
    let port: u16 = env_number("ONA_RELAY_PORT", 8787)?;
    let flush_every = Duration::from_secs(env_number("ONA_FLUSH_SECS", 60)?);

    let new_chain = {
        let (rpc, account, mint, account_key) = (rpc.clone(), account.clone(), mint.clone(), account_key.clone());
        move || NearRelayChain::new(Client::new(&rpc, account_key.clone()), account.clone(), mint.clone())
    };
    let chain = new_chain();
    let config = Config {
        mint_dst: token_dst(&network, &mint).map_err(|e| e.to_string())?,
        credit_key: chain.credit_key()?,
        mint,
        relay: account,
        tokens_per_credit: env_number("ONA_TOKENS_PER_CREDIT", 100)?,
        max_tokens_per_request: env_number("ONA_MAX_TOKENS", 512)?,
    };
    let mut relay = Relay::new(store, chain, MockModel, config, request_key);
    let settled = relay.recover()?;
    let request_key_hex = hex(&relay.request_public_key());
    let relay = Arc::new(Mutex::new(relay));

    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("cannot listen: {e}"))?;
    println!("relay on 127.0.0.1:{port}, {settled} exchanges settled after restart");
    println!("request key: {request_key_hex}");

    let flusher = Arc::clone(&relay);
    let mut flush_chain = new_chain();
    std::thread::spawn(move || loop {
        std::thread::sleep(flush_every);
        match Relay::flush_shared(&flusher, &mut flush_chain) {
            Ok(0) => {}
            Ok(n) => println!("{n} credits claimed"),
            Err(e) => eprintln!("flush failed: {e}"),
        }
    });

    let policy = GatewayPolicy::new(models);
    let backend = NearAiBackend::new(NEAR_AI, api_key);
    let handler: Arc<Handler> = Arc::new(move |request: &Request| {
        if request.target == "/exchange" && request.method == "POST" {
            let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
                return (400, json!({"error": "body is not valid JSON"}).to_string().into_bytes());
            };
            let (status, value) = Relay::exchange_shared(&relay, &mut new_chain(), &body);
            return (status, value.to_string().into_bytes());
        }
        if request.target.starts_with("/v1/") {
            return Relay::gateway_shared(&relay, &mut backend.clone(), &policy, request);
        }
        (404, json!({"error": "not found"}).to_string().into_bytes())
    });
    let pool = Pool::new(WORKERS, BACKLOG, Limits::default(), handler);

    loop {
        match listener.accept() {
            Ok((stream, _)) => pool.dispatch(stream),
            Err(e) => {
                eprintln!("accept failed: {e}");
                std::thread::sleep(ACCEPT_RETRY);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init-key", path] => init_key(Path::new(path)),
        ["run"] => run(),
        _ => Err("usage: ona-relay init-key <file> | ona-relay run".to_string()),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
