//! `ona-agent init-keys <key-file> <cash-tiers> [<tiers of vault 0> ...]` creates the blind-signing keys and prints
//! their public halves (base64, compressed, the `pk_g2` the contract takes).
//! `ona-agent init-store <key-file> <store-file> <pool-account>` creates the store bound to those keys.
//! `ona-agent run` serves on `127.0.0.1` only and runs the planner, configured by the variables in `docs/INSTALL.md`.

#![forbid(unsafe_code)]

use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_agent::api::{self, Limits};
use ona_agent::chain::NearPoolChain;
use ona_agent::keys::AgentKeys;
use ona_agent::planner::Params;
use ona_agent::service::{Agent, QueueParams};
use ona_agent::store::FileStore;
use ona_agent::store_binding;
use ona_near::{check_chain_id, check_network, load_account_key, Client};
use ona_server::crossrpc::{check_rpc_pair, CrossRpc, HttpRpc, Rpc};
use ona_server::http::{Handler, Pool, Request};
use serde_json::json;

const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const WORKERS: usize = 8;
const BACKLOG: usize = 64;
const SECOND_NS: u64 = 1_000_000_000;

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn env_number<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| format!("{name} is not a number")),
        Err(_) => Ok(default),
    }
}

fn init_keys(path: &Path, cash: &str, vaults: &[String]) -> Result<(), String> {
    let cash: usize = cash.parse().map_err(|_| "the number of cash tiers must be a number")?;
    let vaults: Vec<usize> =
        vaults.iter().map(|v| v.parse().map_err(|_| "each vault's number of tiers must be a number".to_string())).collect::<Result<_, _>>()?;
    let keys = AgentKeys::generate(cash, &vaults)?;
    keys.save(path)?;
    for (t, pk) in keys.cash_public().iter().enumerate() {
        println!("cash tier {t}: {}", B64.encode(pk));
    }
    for v in 0..keys.vaults.len() {
        for (t, pk) in keys.vault_public(v).unwrap_or_default().iter().enumerate() {
            println!("vault {v} tier {t}: {}", B64.encode(pk));
        }
    }
    Ok(())
}

/// Copies a key file to a new one with one more vault: the same cash and vault keys, plus new keys for the added vault
/// (for a vault the guardian adds later). The old file is left as it is; the new one is never written over an existing
/// file. A store is tied to its keys, so the agent then needs a new store (`init-store`) for the new file.
fn add_vault_keys(from: &Path, to: &Path, tiers: &str) -> Result<(), String> {
    let tiers: usize = tiers.parse().map_err(|_| "the number of tiers must be a number")?;
    let mut keys = AgentKeys::load(from)?;
    let mut layout: Vec<usize> = keys.vaults.iter().map(Vec::len).collect();
    layout.push(tiers);
    let added = AgentKeys::generate(keys.cash.len(), &layout)?.vaults.pop().ok_or("no vault generated")?;
    keys.vaults.push(added);
    keys.save(to)?;
    let v = keys.vaults.len() - 1;
    for (t, pk) in keys.vault_public(v).unwrap_or_default().iter().enumerate() {
        println!("vault {v} tier {t}: {}", B64.encode(pk));
    }
    Ok(())
}

fn init_store(keys: &Path, store: &Path, pool: &str) -> Result<(), String> {
    let keys = AgentKeys::load(keys)?;
    FileStore::create(store, &store_binding(&keys, pool)).map(|_| ())
}

fn params() -> Result<Params, String> {
    let d = Params::default();
    let p = Params {
        reserve_percent: env_number("ONA_AGENT_RESERVE_PERCENT", d.reserve_percent)?,
        settlement_period_ns: env_number("ONA_AGENT_SETTLEMENT_SECS", d.settlement_period_ns / SECOND_NS)?.saturating_mul(SECOND_NS),
        min_active: env_number("ONA_AGENT_MIN_ACTIVE", d.min_active)?,
        steady_period_ns: env_number("ONA_AGENT_STEADY_SECS", 0u64)?.saturating_mul(SECOND_NS),
        steady_amount: env_number("ONA_AGENT_STEADY_YOCTO", d.steady_amount)?,
        unbond_wait_ns: env_number("ONA_AGENT_UNBOND_WAIT_SECS", d.unbond_wait_ns / SECOND_NS)?.saturating_mul(SECOND_NS),
        sync_every_ns: d.sync_every_ns,
        min_move: env_number("ONA_AGENT_MIN_MOVE_YOCTO", d.min_move)?,
    };
    // ONA_AGENT_RESERVE_PERCENT at most 100, ONA_AGENT_STEADY_SECS a multiple of 259200.
    p.check()?;
    Ok(p)
}

fn queue() -> Result<QueueParams, String> {
    let d = QueueParams::default();
    let q = QueueParams {
        window_ns: env_number("ONA_AGENT_WINDOW_SECS", d.window_ns / SECOND_NS)?.saturating_mul(SECOND_NS),
        min_batch: env_number("ONA_AGENT_MIN_BATCH", d.min_batch)?,
        min_delay_ns: env_number("ONA_AGENT_MIN_DELAY_SECS", d.min_delay_ns / SECOND_NS)?.saturating_mul(SECOND_NS),
        jitter_ns: env_number("ONA_AGENT_JITTER_SECS", d.jitter_ns / SECOND_NS)?.saturating_mul(SECOND_NS),
        retention_ns: env_number("ONA_AGENT_RETENTION_SECS", d.retention_ns / SECOND_NS)?.saturating_mul(SECOND_NS),
        issues_per_hour: env_number("ONA_AGENT_ISSUES_PER_HOUR", d.issues_per_hour)?,
    };
    if q.window_ns == 0 || q.min_batch == 0 {
        return Err("ONA_AGENT_WINDOW_SECS and ONA_AGENT_MIN_BATCH must be above 0".into());
    }
    Ok(q)
}

fn run() -> Result<(), String> {
    let rpc = env("ONA_RPC_URL")?;
    let rpc_2 = env("ONA_RPC_URL_2")?;
    check_rpc_pair(&rpc, &rpc_2)?;
    let chain_id = env("ONA_CHAIN_ID")?;
    let pool = env("ONA_POOL")?;
    let account = env("ONA_AGENT_ACCOUNT")?;
    let account_key = load_account_key(Path::new(&env("ONA_AGENT_ACCOUNT_KEY_FILE")?)).map_err(|e| e.to_string())?;
    let keys = AgentKeys::load(Path::new(&env("ONA_AGENT_KEYS_FILE")?))?;
    let store = FileStore::open(Path::new(&env("ONA_AGENT_STORE_FILE")?), &store_binding(&keys, &pool))?;
    let port: u16 = env_number("ONA_AGENT_PORT", 8788)?;
    let tick = Duration::from_secs(env_number("ONA_AGENT_TICK_SECS", 60)?);
    let per_minute: u32 = env_number("ONA_AGENT_PER_MINUTE", api::DEFAULT_PER_MINUTE)?;
    let params = params()?;

    let reads = CrossRpc::new(HttpRpc::new(&rpc, RPC_TIMEOUT)?, HttpRpc::new(&rpc_2, RPC_TIMEOUT)?);
    let client = Client::connect(&rpc, account_key).map_err(|e| e.to_string())?;
    check_network(&client, &chain_id).map_err(|e| e.to_string())?;
    let status = reads.second.post("status", json!([]))?;
    check_chain_id(&chain_id, status["chain_id"].as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
    let chain = NearPoolChain::new(client, reads, account.clone(), pool.clone());
    let agent = Arc::new(Mutex::new(Agent::start(chain, store, keys, &pool, &account, params, queue()?)?));

    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("cannot listen: {e}"))?;
    println!("pool agent on 127.0.0.1:{port}");

    let worker = Arc::clone(&agent);
    std::thread::spawn(move || loop {
        std::thread::sleep(tick);
        let Ok(mut agent) = worker.lock() else {
            eprintln!("agent state is unusable after a panic: restart the agent");
            return;
        };
        match agent.tick() {
            Ok(log) => log.iter().for_each(|line| println!("{line}")),
            Err(e) => eprintln!("tick failed: {e}"),
        }
    });

    let limits = Arc::new(Limits::new(per_minute));
    let handler: Arc<Handler> = Arc::new(move |request: &Request| {
        let (status, value) = api::handle(&agent, &limits, &request.method, &request.target, &request.body);
        (status, value.to_string().into_bytes())
    });
    let pool_threads = Pool::new(WORKERS, BACKLOG, ona_server::http::Limits::default(), handler);
    loop {
        match listener.accept() {
            Ok((stream, _)) => pool_threads.dispatch(stream),
            Err(e) => {
                eprintln!("accept failed: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init-keys", path, cash, ..] => init_keys(Path::new(path), cash, &args[3..]),
        ["add-vault-keys", from, to, tiers] => add_vault_keys(Path::new(from), Path::new(to), tiers),
        ["init-store", keys, store, pool] => init_store(Path::new(keys), Path::new(store), pool),
        ["run"] => run(),
        _ => Err("usage: ona-agent init-keys <key-file> <cash-tiers> [<vault tiers>...] | add-vault-keys <key-file> <new-key-file> <tiers> | init-store <key-file> <store-file> <pool> | run".into()),
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
    fn a_vault_is_added_with_the_same_older_keys() {
        let dir = std::env::temp_dir().join(format!("ona-agent-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (old, new) = (dir.join("old.bin"), dir.join("new.bin"));
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::remove_file(&new);
        AgentKeys::generate(2, &[2]).unwrap().save(&old).unwrap();
        add_vault_keys(&old, &new, "4").unwrap();
        let (a, b) = (AgentKeys::load(&old).unwrap(), AgentKeys::load(&new).unwrap());
        assert_eq!(a.cash_public(), b.cash_public(), "the cash keys are kept");
        assert_eq!(a.vault_public(0), b.vault_public(0), "vault 0's keys are kept");
        assert_eq!(b.vault_public(1).unwrap().len(), 4, "the added vault has its tiers");
        assert!(add_vault_keys(&old, &new, "4").is_err(), "never written over an existing file");
        assert!(add_vault_keys(&old, &dir.join("x.bin"), "0").is_err(), "a vault needs at least one tier");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
