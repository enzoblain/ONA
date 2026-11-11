//! The relay. `ona-relay init-key <key-file> <store-file>` creates its request-signing key and the
//! store bound to it. `ona-relay run` serves on localhost only, configured by the variables in
//! `docs/INSTALL.md`, and refuses to start without that store.
//! The accepting thread only hands connections to a bounded pool. Chain and model calls run in the
//! pool or on the batch thread, without holding the relay state.

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ona_near::{check_chain_id, check_network, load_account_key, Client};
use ona_server::crossrpc::{check_rpc_pair, CrossRpc, HttpRpc, Rpc};
use ona_server::gateway::{GatewayPolicy, NearAiBackend};
use ona_server::http::{Handler, Limits, Pool, Request};
use ona_server::near::NearRelayChain;
use ona_server::{keyfile, store_binding, Config, FileStore, NoModel, Relay, SharedRelay};
use ona_token::token_dst;
use serde_json::{json, Value};

const NEAR_AI: &str = "https://cloud-api.near.ai";
const ACCEPT_RETRY: Duration = Duration::from_millis(50);
const RPC_TIMEOUT: Duration = Duration::from_secs(60);
/// Workers mostly wait on NEAR AI or the RPC, so there are many of them.
const WORKERS: usize = 32;
const BACKLOG: usize = 256;

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

/// A model list with no empty name: an empty `ONA_MODELS` would otherwise allow the model "".
fn parse_models(text: &str) -> Result<BTreeSet<String>, String> {
    let models: BTreeSet<String> = text.split(',').map(|m| m.trim().to_string()).collect();
    if models.iter().any(String::is_empty) {
        return Err("ONA_MODELS holds an empty model name".into());
    }
    Ok(models)
}

/// Creates the key, then its store. If the store cannot be made, the key file is removed again, so a
/// failed run leaves nothing that would block the next one.
fn init_key(key_path: &Path, store_path: &Path) -> Result<(), String> {
    if store_path.exists() {
        return Err("the store file already exists: a new key needs a new store".into());
    }
    let key = keyfile::create(key_path)?;
    if let Err(e) = FileStore::create(store_path, &store_binding(&key.public_key())) {
        let _ = std::fs::remove_file(key_path);
        return Err(e);
    }
    println!("request key: {}", hex(&key.public_key()));
    Ok(())
}

/// Both endpoints must report the expected chain, so neither can serve another network.
fn check_chain(client: &Client, second: &HttpRpc, expected: &str) -> Result<(), String> {
    check_network(client, expected).map_err(|e| e.to_string())?;
    let status = second.post("status", json!([]))?;
    check_chain_id(expected, status["chain_id"].as_str().unwrap_or_default()).map_err(|e| e.to_string())
}

/// Chains for the request threads, built once and reused, so that each exchange does not build a new
/// client and copy the account key.
struct ChainPool {
    idle: Mutex<Vec<NearRelayChain>>,
    build: Box<dyn Fn() -> Result<NearRelayChain, String> + Send + Sync>,
}

impl ChainPool {
    fn take(&self) -> Result<NearRelayChain, String> {
        let reused = self.idle.lock().ok().and_then(|mut idle| idle.pop());
        reused.map_or_else(|| (self.build)(), Ok)
    }

    fn give_back(&self, chain: NearRelayChain) {
        if let Ok(mut idle) = self.idle.lock() {
            idle.push(chain);
        }
    }
}

fn run() -> Result<(), String> {
    let rpc = env("ONA_RPC_URL")?;
    let rpc_2 = env("ONA_RPC_URL_2")?;
    check_rpc_pair(&rpc, &rpc_2)?;
    let mint = env("ONA_MINT")?;
    let network = env("ONA_NETWORK")?;
    let chain_id = std::env::var("ONA_CHAIN_ID").unwrap_or_else(|_| network.clone());
    let account = env("ONA_RELAY_ACCOUNT")?;
    let account_key =
        load_account_key(&PathBuf::from(env("ONA_RELAY_ACCOUNT_KEY_FILE")?)).map_err(|e| e.to_string())?;
    let request_key = keyfile::load(&PathBuf::from(env("ONA_RELAY_REQUEST_KEY_FILE")?))?;
    let store = FileStore::open(
        &PathBuf::from(env("ONA_RELAY_STORE_FILE")?),
        &store_binding(&request_key.public_key()),
    )?;
    let models = parse_models(&env("ONA_MODELS")?)?;
    let api_key = env("NEAR_AI_CLOUD_API_KEY")?;
    // Read once, then out of the environment, which child processes and crash reports can see.
    std::env::remove_var("NEAR_AI_CLOUD_API_KEY");
    let port: u16 = env_number("ONA_RELAY_PORT", 8787)?;
    let flush_every = Duration::from_secs(env_number("ONA_FLUSH_SECS", 60)?);

    check_chain(
        &Client::connect(&rpc, account_key.clone()).map_err(|e| e.to_string())?,
        &HttpRpc::new(&rpc_2, RPC_TIMEOUT)?,
        &chain_id,
    )?;
    let new_chain = {
        let (rpc, rpc_2, account, mint) = (rpc.clone(), rpc_2.clone(), account.clone(), mint.clone());
        move || -> Result<NearRelayChain, String> {
            let reads = CrossRpc::new(HttpRpc::new(&rpc, RPC_TIMEOUT)?, HttpRpc::new(&rpc_2, RPC_TIMEOUT)?);
            let client = Client::connect(&rpc, account_key.clone()).map_err(|e| e.to_string())?;
            Ok(NearRelayChain::new(client, reads, account.clone(), mint.clone()))
        }
    };
    let chain = new_chain()?;
    let max_tokens_per_request = env_number("ONA_MAX_TOKENS", 512)?;
    let config = Config {
        mint_dst: token_dst(&network, &mint).map_err(|e| e.to_string())?,
        credit_key: chain.credit_key()?,
        mint,
        relay: account,
        tokens_per_credit: env_number("ONA_TOKENS_PER_CREDIT", 100)?,
        max_tokens_per_request,
        max_prompt_bytes: env_number("ONA_MAX_PROMPT_BYTES", 4096)?,
    };
    let mut relay = Relay::new(store, chain, NoModel, config, request_key);
    let settled = relay.recover()?;
    let request_key_hex = hex(&relay.request_public_key());
    let relay = Arc::new(SharedRelay::new(relay));

    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("cannot listen: {e}"))?;
    println!("relay on 127.0.0.1:{port}, {settled} exchanges settled after restart");
    println!("request key: {request_key_hex}");

    let pool = Arc::new(ChainPool { idle: Mutex::new(Vec::new()), build: Box::new(new_chain) });
    let flusher = Arc::clone(&relay);
    let mut flush_chain = pool.take()?;
    std::thread::spawn(move || loop {
        std::thread::sleep(flush_every);
        match flusher.flush(&mut flush_chain) {
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
            let mut chain = match pool.take() {
                Ok(chain) => chain,
                Err(_) => return (503, json!({"error": "chain unavailable"}).to_string().into_bytes()),
            };
            let (status, value) = relay.exchange(&mut chain, &body);
            pool.give_back(chain);
            return (status, value.to_string().into_bytes());
        }
        if request.target.starts_with("/v1/") {
            return relay.gateway(&mut backend.clone(), &policy, request);
        }
        (404, json!({"error": "not found"}).to_string().into_bytes())
    });
    let workers = Pool::new(WORKERS, BACKLOG, Limits::default(), handler);

    loop {
        match listener.accept() {
            Ok((stream, _)) => workers.dispatch(stream),
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
        ["init-key", key, store] => init_key(Path::new(key), Path::new(store)),
        ["run"] => run(),
        _ => Err("usage: ona-relay init-key <key-file> <store-file> | ona-relay run".to_string()),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_model_name_is_refused() {
        assert!(parse_models("").is_err());
        assert!(parse_models("a/1,,b/2").is_err());
        assert!(parse_models(" , ").is_err());
        assert_eq!(parse_models("a/1, b/2").unwrap().len(), 2);
    }
}
