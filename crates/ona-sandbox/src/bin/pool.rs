//! Runs `ona-pool` and its agent on a local `near-sandbox` node, with real transactions:
//!
//! 1. deploys the test build of `ona-pool` (feature `short-admin-delay`, created with an admin delay of two minutes
//!    instead of 7 days) with the plan `ona-deploy pool` uses, and `ona-test-staking`, a test stand-in for a staking
//!    pool (the standard staking pool is not available offline), then lists it as vault 0;
//! 2. runs the agent of `ona-agent` in this process (its `Agent`, its HTTP API and the relay's HTTP front, as
//!    `ona-agent run` does) against the node, reading the node twice as its two endpoints, which `ona-agent run`
//!    refuses; the program ticks it instead of a timer, and moves the node's clock forward (`sandbox_fast_forward`);
//! 3. drives the user's side through `ona-core`'s pool commands and `HttpAgent`: deposit, cash issue, entry, placement
//!    by the planner, synchronisation, leave to cash (which waits for the planner to unstake and withdraw), payment to
//!    the depositing account; then the fallback with the agent stopped: escape exits of cash notes, with and without a
//!    listed request, and of a share note after anyone brought the vault's funds back;
//! 4. prints the gas burnt by every transaction, the agent's included, as a table for SPEC.
//!
//! It stops at the first step that fails, says which, and prints what was verified before.
//!
//! `NEAR_SANDBOX_BIN_PATH` must name a `near-sandbox` binary: without it the library would download one and run it
//! without checking a checksum, which this program refuses. Build the contracts first (`verify.sh`).
#![forbid(unsafe_code)]

#[path = "../node.rs"]
mod node;

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use ona_agent::api::{self, Limits};
use ona_agent::chain::{call_args, Call, CallError, CashInfo, ConfigInfo, HolderInfo, NearPoolChain, PoolChain, VaultInfo};
use ona_agent::keys::AgentKeys;
use ona_agent::nep413;
use ona_agent::planner::Params;
use ona_agent::service::{Agent, QueueParams};
use ona_agent::store::MemoryStore;
use ona_core::pool::{NearPool, PoolClient};
use ona_core::pool_agent::HttpAgent;
use ona_near::{Action, Client, Outcome};
use ona_server::crossrpc::{CrossRpc, HttpRpc};
use ona_token::Token;
use ona_wallet::{NoteStatus, PoolNote, Wallet};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1000;
const SECOND_NS: u64 = 1_000_000_000;
const MINUTE_NS: u64 = 60 * SECOND_NS;
const HOUR_NS: u64 = 60 * MINUTE_NS;
#[cfg(test)]
const DAY_NS: u64 = 24 * HOUR_NS;
/// Admin delay the pool is created with: a new vault takes entries only after it. Two minutes, which only the pool's
/// test build (`short-admin-delay`) accepts; the normal build refuses less than 7 days.
const ADMIN_DELAY_SECS: u64 = 120;
const ADMIN_DELAY_NS: u64 = ADMIN_DELAY_SECS * SECOND_NS;
/// The escape opens after the agent has been silent this long.
const ESCAPE_DELAY_SECS: u64 = 7_200;
/// How long the client's owner signatures stay valid in this run, shorter than the escape delay so that a note whose
/// signature was never used is held again by the time the escape opens (the client's default is 24 hours).
const SIGNATURE_LIFE_NS: u64 = HOUR_NS;
/// How long the test staking pool keeps unstaked funds locked.
const LOCK_SECS: u64 = 120;
/// Price of one share in an empty vault, as in the contract.
const INITIAL_PRICE: u128 = 1_000_000_000_000_000_000;
/// Kept by the contract from each exit.
const EXIT_STORAGE_FEE: u128 = 2 * MILLI;
const CASH_VALUES: [u128; 3] = [100 * MILLI, NEAR, 10 * NEAR];
const VAULT_SHARES: [u128; 2] = [100_000, 1_000_000];
const DEPOSIT: u128 = 12 * NEAR;
const REWARD: u128 = NEAR / 2;
/// Attached to an exit request for its storage, the rest given back when it leaves the list.
const REQUEST_FEE: u128 = 10 * MILLI;
const USER_TGAS: u64 = 300;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Blocks of the first fast-forward, which measures how much block time one block adds.
const PROBE_BLOCKS: u64 = 1_000;
/// Most blocks one fast-forward asks for; a longer wait takes several. A node answered HTTP 500 to 200,000 at once.
const MAX_FAST_FORWARD: u64 = 50_000;
const MAX_FAST_FORWARDS: usize = 32;
const NETWORK: &str = "sandbox";
/// The pool's test build, which `verify.sh` writes next to the normal one.
const POOL_WASM: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/wasm32-unknown-unknown/contract/ona_pool_short_admin_delay.wasm");
const STAKING_WASM: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/wasm32-unknown-unknown/contract/ona_test_staking.wasm");

type Gas = Arc<Mutex<Vec<(String, f64)>>>;

/// Called once a transaction the agent prepared was sent, with the contract method and the transaction hash.
type Recorder = Box<dyn FnMut(&str, &[u8; 32]) + Send>;

/// The agent's chain, unchanged, with every transaction it sends handed to `on_sent` (to read its gas).
struct Measured<C> {
    inner: C,
    prepared: Option<(&'static str, [u8; 32])>,
    on_sent: Recorder,
}

impl<C: PoolChain> PoolChain for Measured<C> {
    fn begin(&mut self) -> Result<u64, String> {
        self.inner.begin()
    }
    fn config(&mut self) -> Result<ConfigInfo, String> {
        self.inner.config()
    }
    fn cash(&mut self) -> Result<CashInfo, String> {
        self.inner.cash()
    }
    fn vault(&mut self, id: u32) -> Result<VaultInfo, String> {
        self.inner.vault(id)
    }
    fn holder(&mut self, account: &str) -> Result<HolderInfo, String> {
        self.inner.holder(account)
    }
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.inner.is_spent(nf)
    }
    fn full_access_key(&mut self, account: &str, pk: &[u8; 32]) -> Result<bool, String> {
        self.inner.full_access_key(account, pk)
    }
    fn prepare(&mut self, call: &Call) -> Result<[u8; 32], CallError> {
        let hash = self.inner.prepare(call)?;
        self.prepared = Some((call_args(call).0, hash));
        Ok(hash)
    }
    fn send_prepared(&mut self) -> Result<(), CallError> {
        let result = self.inner.send_prepared();
        if let Some((method, hash)) = self.prepared.take() {
            // A transaction the node refused before inclusion burnt nothing.
            if !matches!(result, Err(CallError::Refused(_))) {
                (self.on_sent)(method, &hash);
            }
        }
        result
    }
    fn tx_outcome(&mut self, hash: &[u8; 32]) -> Result<Option<bool>, String> {
        self.inner.tx_outcome(hash)
    }
}

type SharedAgent = Arc<Mutex<Agent<Measured<NearPoolChain>, MemoryStore>>>;

/// What was verified, the step running, and the gas of every transaction.
#[derive(Default)]
struct Report {
    step: String,
    verified: Vec<String>,
    gas: Gas,
}

impl Report {
    fn step(&mut self, name: &str) {
        println!("\n== {name}");
        self.step = name.to_string();
    }

    fn ok(&mut self, what: impl Into<String>) {
        let what = what.into();
        println!("  ok: {what}");
        self.verified.push(what);
    }

    fn check(&mut self, holds: bool, what: &str, detail: impl std::fmt::Display) -> Result<()> {
        if !holds {
            bail!("{what}: {detail}");
        }
        self.ok(what);
        Ok(())
    }

    fn record(&self, label: &str, o: &Outcome) -> Result<()> {
        if let Some(f) = &o.failure {
            bail!("{label} failed: {f}");
        }
        if !o.failed_receipts.is_empty() {
            println!("  note: {label} has {} failed receipt(s), first {}", o.failed_receipts.len(), o.failed_receipts[0]);
        }
        self.gas.lock().map_err(|_| anyhow!("gas table unusable"))?.push((label.to_string(), o.tgas));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn call(&self, chain: &Client, label: &str, signer: &str, contract: &str, method: &str, args: Value, deposit: u128) -> Result<Outcome> {
        let o = chain.call_with_gas(signer, contract, method, args, USER_TGAS, deposit).with_context(|| format!("{label}: not sent"))?;
        self.record(label, &o)?;
        Ok(o)
    }
}

/// One line per operation: calls, and the Tgas burnt (a range when the calls differ), in first-seen order.
fn gas_table(rows: &[(String, f64)]) -> Vec<String> {
    let mut order: Vec<&str> = Vec::new();
    let mut seen: BTreeMap<&str, (usize, f64, f64)> = BTreeMap::new();
    for (label, tgas) in rows {
        let entry = seen.entry(label.as_str()).or_insert_with(|| {
            order.push(label.as_str());
            (0, f64::MAX, 0.0)
        });
        entry.0 += 1;
        entry.1 = entry.1.min(*tgas);
        entry.2 = entry.2.max(*tgas);
    }
    let mut out = vec!["| Operation | Calls | Tgas |".to_string(), "|---|---|---|".to_string()];
    for label in order {
        let (n, low, high) = seen[label];
        let tgas = if high - low < 0.05 { format!("{low:.1}") } else { format!("{low:.1} to {high:.1}") };
        out.push(format!("| {label} | {n} | {tgas} |"));
    }
    out
}

/// Blocks to fast-forward for `remaining_ns` of block time: a probe while the time one block adds is unknown, then
/// enough at the measured rate, plus 5 % and 10 blocks.
fn blocks_for(remaining_ns: u64, ns_per_block: Option<f64>) -> u64 {
    match ns_per_block {
        Some(rate) if rate > 0.0 => ((remaining_ns as f64 / rate * 1.05) as u64).saturating_add(10).clamp(1, MAX_FAST_FORWARD),
        _ => PROBE_BLOCKS,
    }
}

fn system_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// yoctoNEAR as NEAR with six decimals, for the log.
fn near(yocto: u128) -> String {
    format!("{}.{:06}", yocto / NEAR, yocto % NEAR / (NEAR / 1_000_000))
}

fn u128_of(v: &Value, key: &str) -> Result<u128> {
    v[key].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("no {key} in {v}"))
}

/// The node's block time, and the clock offset the wallet uses so its deadlines follow it.
struct Time<'a> {
    sandbox: &'a near_sandbox::Sandbox,
    chain: &'a Client,
    ns_per_block: Option<f64>,
    offset: Arc<AtomicU64>,
}

impl Time<'_> {
    fn now(&self) -> Result<u64> {
        self.chain.final_timestamp()
    }

    /// The wallet signs deadlines from its clock and the contract checks them against block time, which runs ahead
    /// of this machine's after a fast-forward.
    fn follow(&self) -> Result<()> {
        self.offset.store(self.now()?.saturating_sub(system_ns()), Ordering::SeqCst);
        Ok(())
    }

    fn final_after(&self, before: u64) -> Result<u64> {
        for _ in 0..60 {
            let t = self.now()?;
            if t > before {
                return Ok(t);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        bail!("the final block time did not move after a fast-forward: this node may not advance block time with it")
    }

    async fn advance(&mut self, ns: u64) -> Result<()> {
        let target = self.now()?.saturating_add(ns);
        for _ in 0..MAX_FAST_FORWARDS {
            let before = self.now()?;
            if before >= target {
                return self.follow();
            }
            let blocks = blocks_for(target - before, self.ns_per_block);
            self.sandbox.fast_forward(blocks).await.map_err(|e| anyhow!("fast-forward of {blocks} blocks: {e:?}"))?;
            let after = self.final_after(before)?;
            self.ns_per_block = Some((after - before) as f64 / blocks as f64);
        }
        bail!("the block time did not reach its target after {MAX_FAST_FORWARDS} fast-forwards")
    }
}

fn tick(agent: &SharedAgent) -> Result<()> {
    let log = agent.lock().map_err(|_| anyhow!("agent state unusable"))?.tick().map_err(|e| anyhow!("agent tick failed: {e}"))?;
    for line in log {
        println!("    agent: {line}");
    }
    Ok(())
}

/// Ticks the agent, then moves the node's clock by `step_ns`, until `done`.
async fn drive(what: &str, agent: &SharedAgent, time: &mut Time<'_>, step_ns: u64, rounds: usize, mut done: impl FnMut() -> Result<bool>) -> Result<()> {
    for _ in 0..rounds {
        tick(agent)?;
        if done()? {
            return Ok(());
        }
        time.advance(step_ns).await?;
    }
    bail!("{what}: not done after {rounds} agent ticks")
}

fn run(client: &mut PoolClient, cmd: &str, request: Value) -> Result<Value> {
    client.run(cmd, &request).map_err(|e| anyhow!("{cmd} {request}: {e}"))
}

/// Nothing left spending or waiting for a signature in the wallet.
fn recovered(client: &mut PoolClient) -> Result<bool> {
    let r = run(client, "pool_recover", json!({}))?;
    println!("    recover: {r}");
    Ok(r["still_spending"] == json!(0) && r["awaiting_signature"] == json!(0))
}

/// Prepares and executes an operation the agent queues: the client hears "outcome unknown", and `pool_recover`
/// collects the result once the agent has sent it.
fn submit(client: &mut PoolClient, op: Value) -> Result<()> {
    let p = run(client, "pool_prepare", op)?;
    println!("  prepared: {}", p["summary"]);
    match client.run("pool_execute", &json!({"prepared_id": p["prepared_id"]})) {
        Ok(v) if v["complete"] == json!(true) => Ok(()),
        Ok(v) => bail!("pool_execute: {v}"),
        Err(e) if e.contains("outcome unknown") => {
            println!("  queued by the agent: {e}");
            Ok(())
        }
        Err(e) => bail!("pool_execute: {e}"),
    }
}

fn note_value(portfolio: &Value, vault: u64, tier: u64) -> Option<u128> {
    let v = portfolio["vaults"].as_array()?.iter().find(|v| v["vault"] == json!(vault))?;
    let t = v["tiers"].as_array()?.iter().find(|t| t["tier"] == json!(tier))?;
    t["note_value"].as_str()?.parse().ok()
}

fn held(client: &PoolClient, vault: Option<u32>, tier: u8) -> Vec<PoolNote> {
    client.wallet().notes().into_iter().filter(|n| n.vault == vault && n.token.denom_id == tier && n.status == NoteStatus::Held).collect()
}

fn note_json(t: &Token) -> Value {
    json!({"tier": t.denom_id, "pk": B64.encode(t.pk), "nonce": B64.encode(t.nonce), "sig": B64.encode(t.sig)})
}

/// Serves the agent's API on a free local port, as `ona-agent run`, until `stop` is set.
fn serve(agent: SharedAgent, stop: Arc<AtomicBool>) -> Result<String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let url = format!("http://{}", listener.local_addr()?);
    listener.set_nonblocking(true)?;
    let limits = Arc::new(Limits::new(api::DEFAULT_PER_MINUTE));
    let handler: Arc<ona_server::http::Handler> = Arc::new(move |r: &ona_server::http::Request| {
        let (status, value) = api::handle(&agent, &limits, &r.method, &r.target, &r.body);
        (status, value.to_string().into_bytes())
    });
    let pool = ona_server::http::Pool::new(4, 16, ona_server::http::Limits::default(), handler);
    std::thread::spawn(move || {
        // Dropping the listener when stopped: later connections are refused, as with an agent that is down.
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if stream.set_nonblocking(false).is_ok() {
                        pool.dispatch(stream);
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    });
    Ok(url)
}

#[tokio::main]
async fn main() {
    let mut report = Report::default();
    let result = run_all(&mut report).await;
    println!("\nverified ({}):", report.verified.len());
    for line in &report.verified {
        println!("  - {line}");
    }
    let rows = report.gas.lock().map(|g| g.clone()).unwrap_or_default();
    println!("\ngas burnt per transaction, receipts included (for SPEC):");
    for line in gas_table(&rows) {
        println!("{line}");
    }
    if let Err(e) = result {
        eprintln!("\nSTOPPED at step \"{}\": {e:#}", report.step);
        std::process::exit(1);
    }
    println!("\nevery step passed");
}

async fn run_all(report: &mut Report) -> Result<()> {
    report.step("start the local node");
    node::sandbox_binary(std::env::var_os("NEAR_SANDBOX_BIN_PATH"))?;
    let pool_code = std::fs::read(POOL_WASM).context("build the contracts first (verify.sh)")?;
    let staking_code = std::fs::read(STAKING_WASM).context("build the contracts first (verify.sh)")?;
    let config = near_sandbox::SandboxConfig {
        additional_config: Some(json!({"telemetry": {"endpoints": []}})),
        ..Default::default()
    };
    let sandbox = near_sandbox::Sandbox::start_sandbox_with_config(config).await.map_err(|e| anyhow!("{e:?}"))?;
    let rpc = sandbox.rpc_addr.trim_end_matches('/').to_string();
    let genesis = near_sandbox::GenesisAccount::default();
    let root = genesis.account_id.to_string();
    let seed = node::key_seed(&genesis.private_key.to_string())?;
    let key = || SigningKey::from_bytes(&seed);
    let chain = Client::new(&rpc, key());
    let sub = |name: &str| format!("{name}.{root}");
    let (guardian, agent_account, alice, bob, staking, pool) =
        (sub("guardian"), sub("agent"), sub("alice"), sub("bob"), sub("staking"), sub("pool"));
    for name in [&guardian, &agent_account, &alice, &bob] {
        let o = chain.send(&root, name, vec![Action::Create, Action::Transfer(500 * NEAR), Action::AddFullKey(chain.public_key())])?;
        if let Some(f) = o.failure {
            bail!("create {name}: {f}");
        }
    }
    let offset = Arc::new(AtomicU64::new(0));
    let mut time = Time { sandbox: &sandbox, chain: &chain, ns_per_block: None, offset: offset.clone() };
    time.follow()?;
    report.ok(format!("local node at {rpc}, accounts created under {root}"));

    report.step("deploy the test staking pool and ona-pool");
    let o = chain.send(&root, &staking, ona_deploy::deploy_actions(5 * NEAR, staking_code.clone(), &json!({"lock_secs": LOCK_SECS})))?;
    report.record("deploy + new (ona-test-staking)", &o)?;
    let keys = AgentKeys::generate(CASH_VALUES.len(), &[VAULT_SHARES.len()]).map_err(|e| anyhow!(e))?;
    let cash = ona_deploy::PoolCash {
        tiers: CASH_VALUES.iter().copied().zip(keys.cash_public()).collect(),
        hourly_cap: 100 * NEAR,
        max_rate_bps: None,
        min_live_notes: 1,
    };
    let args = ona_deploy::pool_init_args(&guardian, &agent_account, NETWORK, Some(ESCAPE_DELAY_SECS), Some(ADMIN_DELAY_SECS), &cash)?;
    let o = chain.send(&root, &pool, ona_deploy::deploy_actions(20 * NEAR, pool_code.clone(), &args))?;
    report.record("deploy + new (ona-pool, 3 cash tiers)", &o)?;
    println!("  ona-pool wasm: {} bytes", pool_code.len());
    let account = chain.account(&pool)?.ok_or_else(|| anyhow!("the pool account does not exist"))?;
    ona_deploy::check_deployed_code(&account, &pool_code)?;
    report.ok("the pool account runs the contract sent");
    let keys_on_pool = chain.query(json!({"request_type": "view_access_key_list", "finality": "final", "account_id": pool}))?;
    let count = keys_on_pool["keys"].as_array().map_or(usize::MAX, Vec::len);
    report.check(count == 0, "the pool account has no access key", format!("{count} keys"))?;

    report.step("list the test staking pool as vault 0");
    let vault_pk = keys.vault_public(0).ok_or_else(|| anyhow!("no keys for vault 0"))?;
    let tiers: Vec<Value> =
        VAULT_SHARES.iter().zip(&vault_pk).map(|(s, k)| json!({"shares": s.to_string(), "pk_g2": B64.encode(k)})).collect();
    let args = json!({
        "kind": "staking", "target": staking, "code_hash": B64.encode(ona_deploy::code_hash(&staking_code)), "tiers": tiers,
        "max_assets": (1000 * NEAR).to_string(), "hourly_cap": (100 * NEAR).to_string(),
    });
    let o = report.call(&chain, "add_vault", &guardian, &pool, "add_vault", args, 0)?;
    report.check(o.value == json!(0), "add_vault returned vault 0", &o.value)?;
    let config = chain.view_final(&pool, "get_config", json!({}))?;
    let pending = config["admin_pending_until"].as_u64().unwrap_or(0);
    report.check(pending > time.now()?, "the new vault waits for the admin delay", &config)?;

    report.step("start the agent against the node");
    let gas = report.gas.clone();
    let reader = Client::new(&rpc, key());
    let sender = agent_account.clone();
    let on_sent: Recorder = Box::new(move |method: &str, hash: &[u8; 32]| match reader.tx_status(hash, &sender) {
        Ok(Some(o)) => {
            let label = if o.failure.is_some() { format!("agent `{method}` (failed)") } else { format!("agent `{method}`") };
            if let Ok(mut rows) = gas.lock() {
                rows.push((label, o.tgas));
            }
        }
        Ok(None) => println!("    gas of agent `{method}` unknown: its outcome is not final yet"),
        Err(e) => println!("    gas of agent `{method}` unknown: {e}"),
    });
    // One local node read twice: both endpoints agree trivially. `ona-agent run` refuses the same endpoint twice.
    let reads = CrossRpc::new(HttpRpc::new(&rpc, READ_TIMEOUT).map_err(|e| anyhow!(e))?, HttpRpc::new(&rpc, READ_TIMEOUT).map_err(|e| anyhow!(e))?);
    let near_chain = NearPoolChain::new(Client::new(&rpc, key()), reads, agent_account.clone(), pool.clone());
    let measured = Measured { inner: near_chain, prepared: None, on_sent };
    let params = Params {
        reserve_percent: 0,
        settlement_period_ns: 0,
        min_active: 0,
        steady_period_ns: 0,
        steady_amount: 0,
        // A margin over the test pool's lock: the agent counts from the block it read before sending its unstake.
        unbond_wait_ns: (LOCK_SECS + 60) * SECOND_NS,
        min_move: MILLI,
        ..Params::default()
    };
    let queue = QueueParams { window_ns: 4 * SECOND_NS, min_batch: 1, min_delay_ns: 0, jitter_ns: 0, ..QueueParams::default() };
    let agent: SharedAgent = Arc::new(Mutex::new(
        Agent::start(measured, MemoryStore::default(), keys, &pool, &agent_account, params, queue).map_err(|e| anyhow!("agent start: {e}"))?,
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let url = serve(agent.clone(), stop.clone())?;
    report.ok(format!("agent started at {url}: its keys match the contract; it reads the one node as both endpoints"));

    report.step("wait out the admin delay");
    time.advance(ADMIN_DELAY_NS + 10 * MINUTE_NS).await?;
    println!("  block time per fast-forwarded block: {:.0} ns", time.ns_per_block.unwrap_or(0.0));
    let config = chain.view_final(&pool, "get_config", json!({}))?;
    report.check(config["admin_pending_until"].as_u64().unwrap_or(u64::MAX) <= time.now()?, "the admin delay is over", &config)?;
    // A sync of the empty vault by the agent counts as its activity: the kind of call its planner makes, even with no
    // funds placed, once half the escape delay passed without activity. With a two-minute admin delay the escape did
    // not open meanwhile, so the check is that the contract recorded the call.
    report.check(config["escape_open"] == json!(false), "the escape is closed before the agent's first call", &config)?;
    let before = config["last_agent_call"].as_u64().ok_or_else(|| anyhow!("get_config has no last_agent_call: {config}"))?;
    agent.lock().map_err(|_| anyhow!("agent state unusable"))?.chain.run(&Call::Sync(0)).map_err(|e| anyhow!("sync: {}", e.message()))?;
    let config = chain.view_final(&pool, "get_config", json!({}))?;
    let after = config["last_agent_call"].as_u64().unwrap_or(0);
    report.check(after > before && config["escape_open"] == json!(false), "a sync by the agent counts as its activity", &config)?;

    report.step("deposit from the depositor's own account, then the cash issue");
    let wallet_path = std::env::temp_dir().join(format!("ona-sandbox-pool-wallet-{}", std::process::id()));
    let _ = std::fs::remove_file(&wallet_path);
    let mut wallet_key = [0u8; 32];
    OsRng.fill_bytes(&mut wallet_key);
    let wallet = Wallet::open(&wallet_path, &wallet_key).map_err(|e| anyhow!("wallet: {e}"))?;
    let clock_offset = offset.clone();
    let mut client = PoolClient::new(wallet, Box::new(NearPool::new(&rpc, &pool)), Box::new(HttpAgent::to_url(&url)), &pool)
        .with_second_chain(Box::new(NearPool::new(&rpc, &pool)))
        .with_clock(Box::new(move || system_ns().saturating_add(clock_offset.load(Ordering::SeqCst))))
        .with_recommended(vec![DEPOSIT])
        .with_signature_life(SIGNATURE_LIFE_NS);
    let result = walk(report, &mut client, &chain, &agent, &mut time, &stop, &key(), &Accounts { alice, bob, staking, pool }).await;
    drop(client);
    let _ = std::fs::remove_file(&wallet_path);
    let mut seal = wallet_path.into_os_string();
    seal.push(".seal");
    let _ = std::fs::remove_file(seal);
    result
}

struct Accounts {
    alice: String,
    bob: String,
    staking: String,
    pool: String,
}

#[allow(clippy::too_many_arguments)]
async fn walk(
    report: &mut Report,
    client: &mut PoolClient,
    chain: &Client,
    agent: &SharedAgent,
    time: &mut Time<'_>,
    stop: &AtomicBool,
    depositor_key: &SigningKey,
    a: &Accounts,
) -> Result<()> {
    let (alice, bob, staking, pool) = (a.alice.as_str(), a.bob.as_str(), a.staking.as_str(), a.pool.as_str());
    let solvent = |report: &mut Report, after: &str| -> Result<()> {
        let s = chain.view_final(pool, "reserve_status", json!({}))?;
        report.check(s["solvent"] == json!(true), &format!("the pool is solvent after {after}"), &s)
    };
    let vault = || chain.view_final(pool, "get_vault", json!({"vault_id": 0}));
    let staked = |method: &str| -> Result<u128> {
        let v = chain.view_final(staking, method, json!({"account_id": pool}))?;
        v.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("{method}: {v}"))
    };

    let p = run(client, "pool_prepare", json!({"op": "deposit", "account": alice, "amount": DEPOSIT.to_string()}))?;
    println!("  prepared: {}", p["summary"]);
    let attached: u128 = p["summary"]["wallet_call"]["attached"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("no wallet call"))?;
    report.call(chain, "deposit", alice, pool, "deposit", json!({}), attached)?;
    let first = run(client, "pool_execute", json!({"prepared_id": p["prepared_id"]}))?;
    let m = &first["sign_message"];
    let nonce: [u8; 32] = m["nonce"]
        .as_str()
        .and_then(|n| B64.decode(n).ok())
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| anyhow!("no nonce to sign: {first}"))?;
    let text = m["message"].as_str().ok_or_else(|| anyhow!("no message to sign: {first}"))?;
    let recipient = m["recipient"].as_str().ok_or_else(|| anyhow!("no recipient: {first}"))?;
    // Signed as the depositor's wallet would, with the NEP-413 layout of `ona-agent` itself: this run does not check
    // that layout against a real wallet.
    let hash = nep413::payload_hash(text, &nonce, recipient);
    let signature = json!({
        "public_key": nep413::write_public_key(&depositor_key.verifying_key().to_bytes()),
        "signature": B64.encode(depositor_key.sign(&hash).to_bytes()),
    });
    match client.run("pool_execute", &json!({"prepared_id": p["prepared_id"], "depositor_signature": signature})) {
        Ok(v) if v["complete"] == json!(true) => println!("  issued at once: {v}"),
        Ok(v) => bail!("pool_execute: {v}"),
        Err(e) if e.contains("outcome unknown") => drive("cash issue", agent, time, 5 * SECOND_NS, 20, || recovered(client)).await?,
        Err(e) => bail!("pool_execute: {e}"),
    }
    let portfolio = run(client, "pool_portfolio", json!({}))?;
    report.check(portfolio["cash"]["value"] == json!(DEPOSIT.to_string()), "the wallet holds 12 NEAR of cash notes", &portfolio)?;
    let holder = chain.view_final(pool, "get_holder", json!({"account": alice}))?;
    report.check(u128_of(&holder, "issued")? == DEPOSIT, "the contract issued exactly that much cash to the depositor", &holder)?;
    solvent(report, "the cash issue")?;

    report.step("enter vault 0 with a 10 NEAR cash note");
    submit(client, json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}))?;
    drive("entry", agent, time, 20 * SECOND_NS, 30, || recovered(client)).await?;
    let v = vault()?;
    report.check(u128_of(&v, "total_shares")? == 9_900_000, "the entry created 9.9 NEAR of shares", &v)?;
    let portfolio = run(client, "pool_portfolio", json!({}))?;
    report.check(note_value(&portfolio, 0, 1) == Some(NEAR), "the wallet holds the share notes", &portfolio)?;
    solvent(report, "the entry")?;

    report.step("the planner places the vault's funds");
    drive("placement", agent, time, 20 * SECOND_NS, 20, || {
        let v = vault()?;
        Ok(u128_of(&v, "placed")? > 0 && v["busy"] == json!(false))
    })
    .await?;
    let v = vault()?;
    let placed = u128_of(&v, "placed")?;
    report.check(staked("get_account_staked_balance")? == placed, "the staking pool holds what the vault placed", &v)?;
    println!("  placed {} NEAR", near(placed));
    solvent(report, "the placement")?;

    report.step("a reward, then the planner's sync raises the share price");
    report.call(chain, "add_reward (test staking pool only)", bob, staking, "add_reward", json!({"account_id": pool}), REWARD)?;
    drive("sync", agent, time, 10 * MINUTE_NS, 12, || Ok(u128_of(&vault()?, "share_price")? > INITIAL_PRICE)).await?;
    let price = u128_of(&vault()?, "share_price")?;
    report.ok(format!("the share price rose to {} NEAR per million shares", near(price.saturating_mul(1_000_000))));

    report.step("leave: one share note back to cash");
    let portfolio = run(client, "pool_portfolio", json!({}))?;
    let value = note_value(&portfolio, 0, 1).ok_or_else(|| anyhow!("no share note of tier 1: {portfolio}"))?;
    submit(client, json!({"op": "exit", "from": 0, "amount": value.to_string()}))?;
    drive("leave", agent, time, 20 * SECOND_NS, 60, || recovered(client)).await?;
    let v = vault()?;
    report.check(v["tiers"][1]["paid"] == json!(1), "the contract spent the share note", &v)?;
    let rows = report.gas.lock().map(|g| g.clone()).unwrap_or_default();
    let has = |m: &str| rows.iter().any(|(label, _)| label == &format!("agent `{m}`"));
    report.check(has("unstake") && has("withdraw"), "the leave waited for the planner to unstake and withdraw", "no unstake or withdraw")?;
    solvent(report, "the leave")?;

    report.step("pay 1 NEAR of cash to the depositing account");
    let before = chain.balance(alice)?.unwrap_or(0);
    submit(client, json!({"op": "exit_cash", "to": alice, "amount": NEAR.to_string()}))?;
    drive("payment", agent, time, 5 * SECOND_NS, 30, || recovered(client)).await?;
    let got = chain.balance(alice)?.unwrap_or(0).saturating_sub(before);
    report.check(got == NEAR - EXIT_STORAGE_FEE, "the depositor received 1 NEAR less the exit fee", format!("received {got}"))?;
    solvent(report, "the payment")?;

    report.step("fallback: the agent stops");
    stop.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(300));
    let p = run(client, "pool_prepare", json!({"op": "exit_cash", "to": alice, "amount": NEAR.to_string()}))?;
    let e = client.run("pool_execute", &json!({"prepared_id": p["prepared_id"]})).err().unwrap_or_default();
    report.check(e.contains("outcome unknown"), "with the agent unreachable the client keeps the note spending", &e)?;
    let r = run(client, "pool_recover", json!({}))?;
    report.check(r["spent"] == json!(0) && r["still_spending"] == json!(1), "pool_recover finds the note unspent on chain", &r)?;
    time.advance(ESCAPE_DELAY_SECS * SECOND_NS + 30 * MINUTE_NS).await?;
    let config = chain.view_final(pool, "get_config", json!({}))?;
    report.check(config["escape_open"] == json!(true), "after the escape delay of silence the escape is open", &config)?;
    let r = run(client, "pool_recover", json!({}))?;
    report.check(r["held_again"] == json!(1), "once its signature expired, pool_recover holds the note again", &r)?;

    report.step("fallback: cash notes leave by the escape");
    let notes = held(client, None, 1);
    let first = notes.first().ok_or_else(|| anyhow!("no held 1 NEAR cash note left"))?;
    let expires_at = time.now()?.saturating_add(HOUR_NS);
    let exit_args = |n: &PoolNote| {
        let digest = ona_wallet::pool::cash_exit_digest(pool, &n.nf, alice, expires_at);
        json!({
            "vault_id": null, "note": note_json(&n.token), "owner_sig": B64.encode(n.owner.sign(&digest).to_bytes()),
            "to": alice, "min_amount": "0", "expires_at": expires_at,
        })
    };
    let before = chain.balance(alice)?.unwrap_or(0);
    report.call(chain, "escape_exit (cash note, by anyone)", bob, pool, "escape_exit", exit_args(first), 0)?;
    let got = chain.balance(alice)?.unwrap_or(0).saturating_sub(before);
    report.check(got == NEAR - EXIT_STORAGE_FEE, "anyone paid a cash note to the depositor without the agent", format!("received {got}"))?;
    match notes.get(1) {
        Some(second) => {
            report.call(chain, "request_exit (cash note)", alice, pool, "request_exit", exit_args(second), REQUEST_FEE)?;
            report.call(chain, "escape_exit (listed cash note)", bob, pool, "escape_exit", exit_args(second), 0)?;
            let c = chain.view_final(pool, "get_cash", json!({}))?;
            let spent = chain.view_final(pool, "is_spent", json!({"nf": B64.encode(second.nf)}))?;
            report.check(c["requests"] == json!(0) && spent == json!(true), "a listed cash note was paid and left the list", &c)?;
        }
        None => println!("  skipped: no second held cash note for a listed exit"),
    }
    solvent(report, "the cash escape")?;

    report.step("fallback: anyone brings the vault's funds back, then a share note leaves");
    report.call(chain, "unstake (amount fixed by the contract, by anyone)", bob, pool, "unstake", json!({"vault_id": 0}), 0)?;
    let (staked_now, unstaked_now) = (staked("get_account_staked_balance")?, staked("get_account_unstaked_balance")?);
    report.check(staked_now == 0 && unstaked_now > 0, "the forced unstake asked for everything staked", format!("staked {staked_now}, unstaked {unstaked_now}"))?;
    time.advance((LOCK_SECS + 60) * SECOND_NS).await?;
    report.call(chain, "withdraw (amount fixed by the contract, by anyone)", bob, pool, "withdraw", json!({"vault_id": 0}), 0)?;
    let v = vault()?;
    report.check(
        staked("get_account_unstaked_balance")? == 0 && u128_of(&v, "liquid")? > 0,
        "the forced withdraw brought the unstaked funds back",
        &v,
    )?;
    report.call(chain, "sync (by anyone, reading over an hour old)", bob, pool, "sync", json!({"vault_id": 0}), 0)?;
    let price = u128_of(&vault()?, "share_price")?;
    let note = held(client, Some(0), 1).into_iter().next().ok_or_else(|| anyhow!("no held share note of tier 1"))?;
    let expires_at = time.now()?.saturating_add(HOUR_NS);
    let digest = ona_wallet::pool::share_exit_digest(pool, 0, &note.nf, alice, 0, expires_at);
    let args = json!({
        "vault_id": 0, "note": note_json(&note.token), "owner_sig": B64.encode(note.owner.sign(&digest).to_bytes()),
        "to": alice, "min_amount": "0", "expires_at": expires_at,
    });
    let before = chain.balance(alice)?.unwrap_or(0);
    report.call(chain, "escape_exit (share note, by anyone)", bob, pool, "escape_exit", args, 0)?;
    let got = chain.balance(alice)?.unwrap_or(0).saturating_sub(before);
    let expected = VAULT_SHARES[1] * price - EXIT_STORAGE_FEE;
    report.check(got == expected, "anyone paid a share note to the depositor without the agent", format!("received {got}, expected {expected}"))?;
    solvent(report, "the share note's escape")?;
    println!("\nfinal reserve: {}", chain.view_final(pool, "reserve_status", json!({}))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        send: Option<CallError>,
    }

    impl PoolChain for Fake {
        fn begin(&mut self) -> Result<u64, String> {
            Ok(0)
        }
        fn config(&mut self) -> Result<ConfigInfo, String> {
            Err("not used".into())
        }
        fn cash(&mut self) -> Result<CashInfo, String> {
            Err("not used".into())
        }
        fn vault(&mut self, _: u32) -> Result<VaultInfo, String> {
            Err("not used".into())
        }
        fn holder(&mut self, _: &str) -> Result<HolderInfo, String> {
            Err("not used".into())
        }
        fn is_spent(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Err("not used".into())
        }
        fn full_access_key(&mut self, _: &str, _: &[u8; 32]) -> Result<bool, String> {
            Err("not used".into())
        }
        fn prepare(&mut self, _: &Call) -> Result<[u8; 32], CallError> {
            Ok([7; 32])
        }
        fn send_prepared(&mut self) -> Result<(), CallError> {
            self.send.clone().map_or(Ok(()), Err)
        }
    }

    type Seen = Arc<Mutex<Vec<(String, [u8; 32])>>>;

    fn measured(send: Option<CallError>) -> (Measured<Fake>, Seen) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let on_sent: Recorder = Box::new(move |m: &str, h: &[u8; 32]| sink.lock().unwrap().push((m.to_string(), *h)));
        (Measured { inner: Fake { send }, prepared: None, on_sent }, seen)
    }

    // Every transaction the agent sends is handed over with its method, through `run` as well; one the node refused
    // before inclusion burnt nothing and is not.
    #[test]
    fn each_sent_transaction_of_the_agent_is_measured_once() {
        let (mut chain, seen) = measured(None);
        chain.run(&Call::Sync(0)).unwrap();
        chain.run(&Call::Place(0, 5)).unwrap();
        let _ = chain.send_prepared();
        assert_eq!(*seen.lock().unwrap(), vec![("sync".to_string(), [7; 32]), ("place".to_string(), [7; 32])]);

        let (mut chain, seen) = measured(Some(CallError::Unknown("lost".into())));
        assert!(chain.run(&Call::Sync(0)).is_err());
        assert_eq!(seen.lock().unwrap().len(), 1, "an unknown outcome may have burnt gas");
        let (mut chain, seen) = measured(Some(CallError::Refused("no".into())));
        assert!(chain.run(&Call::Sync(0)).is_err());
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn the_gas_table_groups_each_operation_in_order() {
        let rows = vec![("b".to_string(), 2.0), ("a".to_string(), 1.0), ("b".to_string(), 4.04)];
        assert_eq!(gas_table(&rows)[2..], ["| b | 2 | 2.0 to 4.0 |".to_string(), "| a | 1 | 1.0 |".to_string()]);
        assert_eq!(gas_table(&[]).len(), 2);
    }

    #[test]
    fn fast_forwards_probe_then_follow_the_measured_rate() {
        assert_eq!(blocks_for(DAY_NS, None), PROBE_BLOCKS);
        assert_eq!(blocks_for(100 * SECOND_NS, Some(SECOND_NS as f64)), 115);
        assert_eq!(blocks_for(u64::MAX, Some(1.0)), MAX_FAST_FORWARD);
        assert_eq!(blocks_for(1, Some(SECOND_NS as f64)), 10);
        assert_eq!(blocks_for(DAY_NS, Some(0.0)), PROBE_BLOCKS, "a node whose time did not move is probed again");
    }

    #[test]
    fn amounts_print_in_near() {
        assert_eq!(near(NEAR + 5 * MILLI), "1.005000");
        assert_eq!(near(0), "0.000000");
    }
}
