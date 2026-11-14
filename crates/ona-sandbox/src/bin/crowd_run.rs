//! Plays a small crowd of real users on a deployed pool (testnet), so that a demo user's notes are not alone in their
//! tiers. **Not run live yet** (written 14/11/2026).
//!
//! Each crowd user is an implicit NEAR account (its id is the hex of a fresh ed25519 public key), created by a transfer
//! from one funder account. At its scheduled time each user goes through the same client code as the desktop app
//! (`ona-core`'s `PoolClient` and `HttpAgent`), as `ona-sandbox-pool` does on a local node:
//!
//! 1. the funder sends it its amount, the deposit's storage margin, a gas reserve and its account's storage reserve;
//! 2. `pool_prepare` deposit, then the `deposit` transaction signed with the user's own key;
//! 3. `pool_execute`: the client makes the cash notes (saved in the user's wallet before anything leaves) and the text
//!    to sign; the user's key signs it (NEP-413, with `ona-agent`'s own layout); `pool_execute` again: the agent issues
//!    the cash and blind-signs the notes;
//! 4. `pool_prepare` enter into the user's vault with all its cash, `pool_execute`, then `pool_recover` until the share
//!    notes are signed.
//!
//! Everything the run will send is computed and printed before the first transaction, and the run is refused above
//! `ONA_CROWD_MAX_SPEND_NEAR`. Mainnet is refused by its names, and by the chain id the RPC nodes report before
//! anything is sent. Keys go to new files only their owner can read, in a new folder outside the repository, and are
//! never printed. A user that fails does not stop the others; a summary follows, then the notes in circulation per
//! tier of each vault used, read from the contract.
//!
//! **Every crowd account is funded by the same account**, so anyone can list them on chain and set them apart from
//! real users. This makes the tiers fuller, not the crowd independent.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use ona_agent::nep413;
use ona_core::pool::{NearPool, PoolClient, DEPOSIT_MARGIN, NOTE_STORAGE_FEE};
use ona_core::pool_agent::HttpAgent;
use ona_core::tor::Network;
use ona_near::{check_account_id, check_network, Action, Client};
use ona_wallet::Wallet;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde_json::{json, Value};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1000;
/// The cash notes of the testnet pool (0.1 and 0.5 NEAR); checked against the contract before a real run.
const CASH_NOTES: [u128; 2] = [100 * MILLI, 500 * MILLI];
const DEFAULT_USERS: usize = 8;
const DEFAULT_VAULTS: [u32; 1] = [1];
const DEFAULT_AMOUNTS: [u128; 3] = [100 * MILLI, 500 * MILLI, 600 * MILLI];
const DEFAULT_MIN_GAP_SECS: u64 = 60;
const DEFAULT_MAX_GAP_SECS: u64 = 600;
const DEFAULT_WAIT_MINS: u64 = 40;
const DEFAULT_MAX_SPEND: &str = "6";
const DEFAULT_CHAIN_ID: &str = "testnet";
const DEFAULT_AGENT_URL: &str = "http://127.0.0.1:8788";
const HOUR_SECS: u64 = 3600;
/// Most NEAR planned into one vault in any 60 minutes. The contract's `hourly_cap` (2 NEAR on the testnet vaults) limits
/// the agent's placements and the leaves of each calendar hour, not entries; planning under it lets the agent place
/// everything the crowd brings within the hour.
const PLAN_PER_VAULT_HOUR: u128 = 1800 * MILLI;
/// Kept for the gas of the user's one transaction (the deposit, 2.4 Tgas measured on a local node, sent with 30 Tgas
/// prepaid). A reserve, not a measure of testnet's gas price.
const GAS_RESERVE: u128 = 50 * MILLI;
/// The new implicit account must hold the storage of its own record and access key.
const ACCOUNT_STORAGE_RESERVE: u128 = 10 * MILLI;
/// Counted for the gas of each transfer the funder sends.
const FUNDER_GAS_PER_TRANSFER: u128 = MILLI;
const DEPOSIT_TGAS: u64 = 30;
const POLL: Duration = Duration::from_secs(5);
const ISSUE_ATTEMPTS: usize = 3;
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

// ---- the plan (no network) ----

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    users: usize,
    vaults: Vec<u32>,
    amounts: Vec<u128>,
    min_gap_secs: u64,
    max_gap_secs: u64,
    wait_mins: u64,
    out: Option<PathBuf>,
    dry_run: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            users: DEFAULT_USERS,
            vaults: DEFAULT_VAULTS.to_vec(),
            amounts: DEFAULT_AMOUNTS.to_vec(),
            min_gap_secs: DEFAULT_MIN_GAP_SECS,
            max_gap_secs: DEFAULT_MAX_GAP_SECS,
            wait_mins: DEFAULT_WAIT_MINS,
            out: None,
            dry_run: false,
        }
    }
}

const USAGE: &str = "usage: ona-crowd-run [--dry-run] [--out <new folder outside the repo>] [--users N] \
[--vaults 1[,0...]] [--amounts 0.1,0.5,0.6] [--min-gap-secs S] [--max-gap-secs S] [--wait-mins M]";

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options> {
    let mut o = Options::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| anyhow!("{arg} needs a value\n{USAGE}"));
        match arg.as_str() {
            "--dry-run" => o.dry_run = true,
            "--out" => o.out = Some(PathBuf::from(value()?)),
            "--users" => o.users = value()?.parse().context("--users")?,
            "--vaults" => o.vaults = value()?.split(',').map(|v| v.trim().parse().context("--vaults")).collect::<Result<_>>()?,
            "--amounts" => o.amounts = value()?.split(',').map(parse_near).collect::<Result<_>>()?,
            "--min-gap-secs" => o.min_gap_secs = value()?.parse().context("--min-gap-secs")?,
            "--max-gap-secs" => o.max_gap_secs = value()?.parse().context("--max-gap-secs")?,
            "--wait-mins" => o.wait_mins = value()?.parse().context("--wait-mins")?,
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }
    if o.users == 0 || o.users > 64 {
        bail!("--users must be between 1 and 64");
    }
    if o.vaults.is_empty() || o.amounts.is_empty() {
        bail!("--vaults and --amounts need at least one value");
    }
    if o.min_gap_secs > o.max_gap_secs {
        bail!("--min-gap-secs is above --max-gap-secs");
    }
    if o.wait_mins == 0 {
        bail!("--wait-mins must be above 0");
    }
    for a in &o.amounts {
        cash_notes(*a, &CASH_NOTES).ok_or_else(|| anyhow!("{} NEAR is not a sum of cash notes of 0.1 and 0.5 NEAR", near(*a)))?;
        if *a > PLAN_PER_VAULT_HOUR {
            bail!("{} NEAR is above the {} NEAR planned per vault and per hour", near(*a), near(PLAN_PER_VAULT_HOUR));
        }
    }
    if !o.dry_run && o.out.is_none() {
        bail!("a real run needs --out <new folder outside the repository>\n{USAGE}");
    }
    Ok(o)
}

/// NEAR written in decimal (`"0.5"`, `"6"`) as yoctoNEAR.
fn parse_near(text: &str) -> Result<u128> {
    let text = text.trim();
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || (text.contains('.') && !digits(frac)) || frac.len() > 24 {
        bail!("not an amount of NEAR: {text:?}");
    }
    let frac_yocto: u128 = if frac.is_empty() { 0 } else { format!("{frac:0<24}").parse()? };
    whole.parse::<u128>()?.checked_mul(NEAR).and_then(|w| w.checked_add(frac_yocto)).ok_or_else(|| anyhow!("amount too large: {text}"))
}

/// yoctoNEAR as NEAR with three decimals.
fn near(yocto: u128) -> String {
    format!("{}.{:03}", yocto / NEAR, yocto % NEAR / MILLI)
}

/// The cash notes an amount becomes, largest first (as the client splits a deposit), or `None` if it is not an exact sum.
fn cash_notes(amount: u128, notes: &[u128]) -> Option<Vec<u128>> {
    let mut sorted = notes.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let (mut left, mut out) = (amount, Vec::new());
    for n in sorted.into_iter().filter(|n| *n > 0) {
        while left >= n {
            left -= n;
            out.push(n);
        }
    }
    (amount > 0 && left == 0).then_some(out)
}

/// The earliest time at or after `at` (seconds) when `amount` fits under `cap` together with the `history` of the same
/// vault (time, amount) that falls in the 60 minutes up to that time.
fn cap_wait(history: &[(u64, u128)], at: u64, amount: u128, cap: u128) -> Result<u64> {
    if amount > cap {
        bail!("{} NEAR alone is above the hourly plan of {} NEAR", near(amount), near(cap));
    }
    let fits = |t: u64| {
        let used: u128 = history.iter().filter(|(h, _)| *h <= t && h + HOUR_SECS > t).map(|(_, a)| a).sum();
        used + amount <= cap
    };
    let mut candidates: Vec<u64> = std::iter::once(at).chain(history.iter().map(|(h, _)| h + HOUR_SECS)).filter(|t| *t >= at).collect();
    candidates.sort_unstable();
    candidates.into_iter().find(|t| fits(*t)).ok_or_else(|| anyhow!("no time fits the hourly plan"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedUser {
    /// Seconds after the start.
    at: u64,
    vault: u32,
    amount: u128,
}

/// Each user draws an amount and a vault, and starts a random gap after the previous one, later when its vault's
/// hourly plan is full.
fn make_plan(o: &Options, rng: &mut impl Rng) -> Result<Vec<PlannedUser>> {
    let mut history: BTreeMap<u32, Vec<(u64, u128)>> = BTreeMap::new();
    let mut plan = Vec::new();
    let mut t = 0u64;
    for i in 0..o.users {
        if i > 0 {
            t = t.saturating_add(rng.gen_range(o.min_gap_secs..=o.max_gap_secs));
        }
        let vault = o.vaults[rng.gen_range(0..o.vaults.len())];
        let amount = o.amounts[rng.gen_range(0..o.amounts.len())];
        let h = history.entry(vault).or_default();
        t = cap_wait(h, t, amount, PLAN_PER_VAULT_HOUR)?;
        h.push((t, amount));
        plan.push(PlannedUser { at: t, vault, amount });
    }
    Ok(plan)
}

/// What the funder sends one user: its amount, the deposit's storage margin, a gas reserve and its account's storage.
fn funding(amount: u128) -> u128 {
    amount + DEPOSIT_MARGIN + GAS_RESERVE + ACCOUNT_STORAGE_RESERVE
}

/// Everything the funder account will spend: every user's funding and the gas of each transfer.
fn total_spend(plan: &[PlannedUser]) -> u128 {
    plan.iter().map(|u| funding(u.amount) + FUNDER_GAS_PER_TRANSFER).sum()
}

fn check_spend(total: u128, cap: u128) -> Result<()> {
    if total > cap {
        bail!("the run would spend {} NEAR, above ONA_CROWD_MAX_SPEND_NEAR ({} NEAR): nothing sent", near(total), near(cap));
    }
    Ok(())
}

/// Testnet or a local node only: refuses mainnet in the chain id, an RPC address and the account names (a `.near`
/// account is a mainnet name; on testnet a named account must end with `.testnet`).
fn check_target(chain_id: &str, rpc_urls: &[&str], accounts: &[&str]) -> Result<()> {
    for url in rpc_urls {
        ona_deploy::check_names(chain_id, chain_id, url)?;
    }
    for a in accounts {
        check_account_id(a)?;
        if a.ends_with(".near") || *a == "near" || a.contains("mainnet") {
            bail!("{a} is a mainnet account");
        }
        if chain_id == "testnet" && !is_implicit(a) && !a.ends_with(".testnet") {
            bail!("on testnet the account {a} must end with .testnet");
        }
    }
    Ok(())
}

fn is_implicit(account: &str) -> bool {
    account.len() == 64 && account.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The implicit account of a key: the hex of its public key.
fn implicit_account(key: &SigningKey) -> String {
    key.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// The `ed25519:<base58 of seed and public key>` text NEAR tools read.
fn account_key_text(key: &SigningKey) -> String {
    let mut bytes = key.to_bytes().to_vec();
    bytes.extend_from_slice(&key.verifying_key().to_bytes());
    format!("ed25519:{}", bs58::encode(bytes).into_string())
}

/// Whether `path` (made absolute) is inside `root`. A folder that does not exist yet is judged by its parent.
fn inside(path: &Path, root: &Path) -> Result<bool> {
    let root = root.canonicalize().context("cannot read the repository folder")?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = parent.canonicalize().with_context(|| format!("the folder {} does not exist", parent.display()))?;
    Ok(parent.join(path.file_name().unwrap_or_default()).starts_with(&root))
}

/// A new file only its owner can read; an existing file is never replaced.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut f = options.open(path).with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn print_plan(plan: &[PlannedUser]) {
    println!("plan ({} users, at most {} NEAR per vault in any 60 minutes):", plan.len(), near(PLAN_PER_VAULT_HOUR));
    println!("  user  start      vault  amount (NEAR)  cash notes        funding (NEAR)");
    for (i, u) in plan.iter().enumerate() {
        let notes: Vec<String> = cash_notes(u.amount, &CASH_NOTES).unwrap_or_default().iter().map(|n| near(*n)).collect();
        println!(
            "  {:>4}  +{:>3}m{:02}s   {:>5}  {:>13}  {:<16}  {:>14}",
            i + 1,
            u.at / 60,
            u.at % 60,
            u.vault,
            near(u.amount),
            notes.join("+"),
            near(funding(u.amount))
        );
    }
    let mut per_vault: BTreeMap<u32, u128> = BTreeMap::new();
    for u in plan {
        *per_vault.entry(u.vault).or_default() += u.amount;
    }
    for (v, a) in per_vault {
        println!("  vault {v}: {} NEAR in total", near(a));
    }
    if let Some(last) = plan.last() {
        println!("  last user starts {} min after the first", last.at / 60);
    }
    println!(
        "  per user: amount + {} storage margin (deposit) + {} gas reserve + {} account storage; about {} NEAR stays in each account",
        near(DEPOSIT_MARGIN),
        near(GAS_RESERVE),
        near(ACCOUNT_STORAGE_RESERVE),
        near(GAS_RESERVE + ACCOUNT_STORAGE_RESERVE)
    );
}

// ---- the real run ----

struct Settings {
    chain_id: String,
    rpc: String,
    rpc2: Option<String>,
    pool: String,
    agent_url: String,
    funder: String,
    funder_key_file: PathBuf,
}

fn env_opt(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(v) if v.trim().is_empty() => Ok(None),
        Ok(v) => Ok(Some(v.trim().to_string())),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => bail!("{name} is not valid text"),
    }
}

fn env_req(name: &str) -> Result<String> {
    env_opt(name)?.ok_or_else(|| anyhow!("{name} is not set (docs/INSTALL.md, \"Run a crowd on testnet\")"))
}

impl Settings {
    fn from_env() -> Result<Self> {
        Ok(Self {
            chain_id: env_opt("ONA_CHAIN_ID")?.unwrap_or_else(|| DEFAULT_CHAIN_ID.into()),
            rpc: env_req("ONA_RPC_URL")?,
            rpc2: env_opt("ONA_RPC_URL_2")?,
            pool: env_req("ONA_POOL")?,
            agent_url: env_opt("ONA_POOL_AGENT_URL")?.unwrap_or_else(|| DEFAULT_AGENT_URL.into()),
            funder: env_req("ONA_CROWD_FUNDER_ACCOUNT")?,
            funder_key_file: PathBuf::from(env_req("ONA_CROWD_FUNDER_KEY_FILE")?),
        })
    }

    fn check(&self) -> Result<()> {
        let mut urls = vec![self.rpc.as_str()];
        urls.extend(self.rpc2.as_deref());
        check_target(&self.chain_id, &urls, &[&self.pool, &self.funder])?;
        ona_near::check_rpc_url(&self.agent_url).context("ONA_POOL_AGENT_URL")?;
        Ok(())
    }
}

fn u128_of(v: &Value, key: &str) -> Result<u128> {
    v[key].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("no {key} in {v}"))
}

fn hash_text(o: &ona_near::Outcome) -> String {
    o.tx_hash.map(|h| bs58::encode(h).into_string()).unwrap_or_else(|| "?".into())
}

/// The vault's price rounded up, as the client computes it for an entry.
fn price_up(v: &Value) -> Result<u128> {
    let total = u128_of(v, "total_shares")?;
    let assets = (u128_of(v, "liquid")? + u128_of(v, "placed")?).saturating_sub(u128_of(v, "fee_owed")?).saturating_sub(u128_of(v, "orphan")?);
    match total {
        0 => u128_of(v, "share_price"),
        _ => Ok(assets.div_ceil(total)),
    }
}

/// Value of the share notes a cash note becomes in tiers of `shares` at `unit` yoctoNEAR per share (largest first, as
/// the client splits it), and what is left in the cash.
fn fit(cash_note: u128, shares: &[u128], unit: u128) -> (u128, u128) {
    let budget = cash_note.saturating_sub(NOTE_STORAGE_FEE);
    let mut sorted = shares.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let mut left = budget;
    for s in sorted {
        let each = s.saturating_mul(unit);
        if each > 0 {
            left %= each;
        }
    }
    (budget - left, left)
}

/// Before anything is sent: the cash notes are the pool's, each planned vault is open, every cash note planned for it
/// becomes share notes there, and the vault's cap leaves room for the plan.
fn check_pool(chain: &Client, pool: &str, plan: &[PlannedUser]) -> Result<()> {
    let cash = chain.view_final(pool, "get_cash", json!({}))?;
    let values: Vec<u128> = cash["tiers"].as_array().ok_or_else(|| anyhow!("get_cash without tiers"))?.iter().map(|t| u128_of(t, "value")).collect::<Result<_>>()?;
    for n in CASH_NOTES {
        if !values.contains(&n) {
            bail!("the pool has no cash note of {} NEAR (its notes: {:?})", near(n), values.iter().map(|v| near(*v)).collect::<Vec<_>>());
        }
    }
    let mut per_vault: BTreeMap<u32, u128> = BTreeMap::new();
    for u in plan {
        *per_vault.entry(u.vault).or_default() += u.amount;
    }
    for (id, planned) in per_vault {
        let v = chain.view_final(pool, "get_vault", json!({"vault_id": id})).with_context(|| format!("vault {id}"))?;
        if v["frozen"] != json!(false) {
            bail!("vault {id} is frozen");
        }
        let shares: Vec<u128> = v["tiers"].as_array().ok_or_else(|| anyhow!("vault {id} without tiers"))?.iter().map(|t| u128_of(t, "shares")).collect::<Result<_>>()?;
        let unit = price_up(&v)?;
        let mut used: Vec<u128> = plan.iter().filter(|u| u.vault == id).flat_map(|u| cash_notes(u.amount, &CASH_NOTES).unwrap_or_default()).collect();
        used.sort_unstable();
        used.dedup();
        for n in used {
            let (value, left) = fit(n, &shares, unit);
            if value == 0 {
                bail!("a cash note of {} NEAR becomes no share note in vault {id}: choose another vault", near(n));
            }
            println!("  vault {id}: a {} NEAR cash note becomes {} NEAR of shares, {} NEAR left in the cash (estimate at the current price)", near(n), near(value), near(left));
        }
        let room = u128_of(&v, "max_assets")?.saturating_sub(u128_of(&v, "liquid")? + u128_of(&v, "placed")?);
        if planned > room {
            bail!("vault {id} has room for {} NEAR under its cap, the plan brings {} NEAR", near(room), near(planned));
        }
    }
    Ok(())
}

/// Notes in circulation (issued minus paid) per tier, from a `get_cash` or `get_vault` view.
fn live_per_tier(view: &Value, size_key: &str) -> Vec<(String, u64)> {
    view["tiers"]
        .as_array()
        .map(|tiers| {
            tiers
                .iter()
                .map(|t| {
                    let live = t["issued"].as_u64().unwrap_or(0).saturating_sub(t["paid"].as_u64().unwrap_or(0));
                    (t[size_key].as_str().unwrap_or("?").to_string(), live)
                })
                .collect()
        })
        .unwrap_or_default()
}

struct User {
    index: usize,
    key: SigningKey,
    account: String,
    wallet: PathBuf,
    wallet_key: [u8; 32],
    plan: PlannedUser,
}

impl User {
    fn log(&self, what: impl std::fmt::Display) {
        println!("[user {:02} {}..] {what}", self.index, &self.account[..8]);
    }
}

#[derive(Debug, PartialEq)]
enum Status {
    Done,
    Failed(String),
}

fn run_cmd(client: &mut PoolClient, cmd: &str, request: Value) -> Result<Value> {
    client.run(cmd, &request).map_err(|e| anyhow!("{cmd}: {e}"))
}

/// `pool_recover` until nothing is spending or waiting for a signature, or `timeout`.
fn wait_recovered(user: &User, client: &mut PoolClient, what: &str, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        let r = run_cmd(client, "pool_recover", json!({}))?;
        if r["still_spending"] == json!(0) && r["awaiting_signature"] == json!(0) {
            return Ok(());
        }
        if let Some(e) = r["agent_error"].as_str() {
            user.log(format!("  agent: {e}"));
        }
        if start.elapsed() > timeout {
            bail!("{what}: not finished after {} min ({r}); the wallet keeps it, run pool_recover later", timeout.as_secs() / 60);
        }
        std::thread::sleep(POLL);
    }
}

/// The deposit and the cash issue. The deposit is sent once; a refused issue is asked again with a new preparation
/// (nothing more is sent on chain).
fn deposit_and_issue(user: &User, client: &mut PoolClient, chain: &Client, pool: &str, wait: Duration) -> Result<()> {
    let amount = user.plan.amount.to_string();
    let p = run_cmd(client, "pool_prepare", json!({"op": "deposit", "account": user.account, "amount": amount}))?;
    let attached: u128 = p["summary"]["wallet_call"]["attached"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("no wallet call in {p}"))?;
    let o = chain.call_with_gas(&user.account, pool, "deposit", json!({}), DEPOSIT_TGAS, attached).context("deposit not sent")?;
    o.require_all_receipts_ok().with_context(|| format!("deposit {}", hash_text(&o)))?;
    user.log(format!("deposit of {} NEAR (attached {}): tx {}", near(user.plan.amount), near(attached), hash_text(&o)));

    let mut prepared = p;
    for attempt in 1..=ISSUE_ATTEMPTS {
        let id = prepared["prepared_id"].clone();
        let first = run_cmd(client, "pool_execute", json!({"prepared_id": id}))?;
        let m = &first["sign_message"];
        let nonce: [u8; 32] = m["nonce"].as_str().and_then(|n| B64.decode(n).ok()).and_then(|n| n.try_into().ok()).ok_or_else(|| anyhow!("no nonce to sign: {first}"))?;
        let text = m["message"].as_str().ok_or_else(|| anyhow!("no message to sign: {first}"))?;
        let recipient = m["recipient"].as_str().ok_or_else(|| anyhow!("no recipient: {first}"))?;
        let hash = nep413::payload_hash(text, &nonce, recipient);
        let signature = json!({
            "public_key": nep413::write_public_key(&user.key.verifying_key().to_bytes()),
            "signature": B64.encode(user.key.sign(&hash).to_bytes()),
        });
        user.log("cash notes made by the client, issue message signed with the account key (NEP-413)");
        match client.run("pool_execute", &json!({"prepared_id": id, "depositor_signature": signature})) {
            Ok(v) if v["complete"] == json!(true) => {
                user.log(format!("cash issued and signed by the agent: {}", v["steps"]));
                return Ok(());
            }
            Ok(v) => bail!("cash issue: {v}"),
            Err(e) if e.contains("outcome unknown") => {
                user.log(format!("cash issue queued by the agent: {e}"));
                return wait_recovered(user, client, "cash issue", wait);
            }
            Err(e) if attempt < ISSUE_ATTEMPTS => {
                user.log(format!("cash issue refused ({e}); asking again in 15 s"));
                std::thread::sleep(Duration::from_secs(15));
                prepared = run_cmd(client, "pool_prepare", json!({"op": "deposit", "account": user.account, "amount": amount}))?;
            }
            Err(e) => bail!("cash issue: {e}"),
        }
    }
    bail!("cash issue: no attempt left")
}

fn enter(user: &User, client: &mut PoolClient, wait: Duration) -> Result<()> {
    let p = run_cmd(client, "pool_prepare", json!({"op": "enter", "vault": user.plan.vault, "amount": user.plan.amount.to_string()}))?;
    user.log(format!(
        "entry into vault {}: shares worth {} NEAR, {} NEAR left in the cash",
        user.plan.vault,
        near(u128_of(&p["summary"], "shares_value").unwrap_or(0)),
        near(u128_of(&p["summary"], "left_in_cash").unwrap_or(0))
    ));
    match client.run("pool_execute", &json!({"prepared_id": p["prepared_id"]})) {
        Ok(v) if v["complete"] == json!(true) => user.log(format!("entered at once: {}", v["steps"])),
        Ok(v) => bail!("entry: {v}"),
        Err(e) if e.contains("outcome unknown") => {
            user.log(format!("entry queued by the agent: {e}"));
            wait_recovered(user, client, "entry", wait)?;
        }
        Err(e) => bail!("entry: {e}"),
    }
    let portfolio = run_cmd(client, "pool_portfolio", json!({}))?;
    let vault = portfolio["vaults"].as_array().and_then(|vs| vs.iter().find(|v| v["vault"] == json!(user.plan.vault)).cloned());
    match vault {
        Some(v) if u128_of(&v, "value").unwrap_or(0) > 0 => {
            user.log(format!("share notes signed: {} NEAR in vault {}, tiers {}", near(u128_of(&v, "value")?), user.plan.vault, v["tiers"]));
            Ok(())
        }
        _ => bail!("no share note in vault {} after the entry: {portfolio}", user.plan.vault),
    }
}

fn open_client(user: &User, s: &Settings) -> Result<PoolClient> {
    let wallet = Wallet::open(&user.wallet, &user.wallet_key).map_err(|e| anyhow!("wallet: {e}"))?;
    let direct = Network::Direct;
    let first = NearPool::through(&direct, &s.rpc, &s.pool).map_err(|e| anyhow!("ONA_RPC_URL: {e}"))?;
    let agent = HttpAgent::through(&direct, &s.agent_url).map_err(|e| anyhow!("ONA_POOL_AGENT_URL: {e}"))?;
    let mut client = PoolClient::new(wallet, Box::new(first), Box::new(agent), &s.pool).with_recommended(DEFAULT_AMOUNTS.to_vec());
    if let Some(url) = &s.rpc2 {
        client = client.with_second_chain(Box::new(NearPool::through(&direct, url, &s.pool).map_err(|e| anyhow!("ONA_RPC_URL_2: {e}"))?));
    }
    Ok(client)
}

fn run_user(user: &User, s: &Settings, funder: &Client, wait: Duration) -> Result<()> {
    let amount = funding(user.plan.amount);
    let o = funder.send(&s.funder, &user.account, vec![Action::Transfer(amount)]).context("funding transfer not sent")?;
    o.require_all_receipts_ok().with_context(|| format!("funding transfer {}", hash_text(&o)))?;
    user.log(format!("funded with {} NEAR: tx {}", near(amount), hash_text(&o)));
    let chain = Client::connect(&s.rpc, user.key.clone())?;
    let mut client = open_client(user, s)?;
    deposit_and_issue(user, &mut client, &chain, &s.pool, wait)?;
    enter(user, &mut client, wait)
}

fn real_run(o: &Options, plan: &[PlannedUser], total: u128) -> Result<()> {
    let s = Settings::from_env()?;
    s.check()?;
    let out = o.out.clone().ok_or_else(|| anyhow!("--out is needed"))?;
    if inside(&out, Path::new(REPO_ROOT))? {
        bail!("choose an output folder outside the repository: the keys must not end up in it");
    }
    let funder_key = ona_near::load_account_key(&s.funder_key_file).context("ONA_CROWD_FUNDER_KEY_FILE")?;
    let funder = Client::connect(&s.rpc, funder_key)?;
    let reported = check_network(&funder, &s.chain_id)?;
    if let Some(url) = &s.rpc2 {
        check_network(&Client::connect(url, SigningKey::generate(&mut OsRng))?, &s.chain_id).context("ONA_RPC_URL_2")?;
    }
    println!("RPC nodes report chain {reported}");
    let balance = funder.balance(&s.funder)?.ok_or_else(|| anyhow!("the funder account {} does not exist", s.funder))?;
    if balance < total {
        bail!("the funder holds {} NEAR, the run needs {} NEAR", near(balance), near(total));
    }
    check_pool(&funder, &s.pool, plan)?;

    // Keys first, before anything is sent: a crash later loses no account.
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(&out).with_context(|| format!("{} must be a new folder", out.display()))?;
    let wallets = out.join("wallets");
    builder.create(&wallets)?;
    let mut users = Vec::new();
    let mut records = Vec::new();
    for (i, p) in plan.iter().enumerate() {
        let key = SigningKey::generate(&mut OsRng);
        let mut wallet_key = [0u8; 32];
        OsRng.fill_bytes(&mut wallet_key);
        let account = implicit_account(&key);
        let wallet = wallets.join(format!("user-{:02}", i + 1));
        let key_file = wallets.join(format!("user-{:02}.key", i + 1));
        let hex: String = wallet_key.iter().map(|b| format!("{b:02x}")).collect();
        write_private(&key_file, hex.as_bytes())?;
        records.push(json!({
            "user": i + 1, "account": account, "account_key": account_key_text(&key),
            "wallet_file": wallet, "wallet_key_file": key_file, "vault": p.vault, "amount": p.amount.to_string(),
        }));
        users.push(User { index: i + 1, key, account, wallet, wallet_key, plan: p.clone() });
    }
    write_private(&out.join("keys.json"), serde_json::to_string_pretty(&records)?.as_bytes())?;
    println!("keys written to {} (readable by you only, never printed)", out.join("keys.json").display());

    let start = Instant::now();
    let wait = Duration::from_secs(o.wait_mins * 60);
    let mut entered: BTreeMap<u32, Vec<(u64, u128)>> = BTreeMap::new();
    let mut results = Vec::new();
    for user in &users {
        // The plan's time, later if earlier users ran late and the vault's hour is full.
        let now = start.elapsed().as_secs();
        let at = cap_wait(entered.get(&user.plan.vault).map_or(&[][..], Vec::as_slice), now.max(user.plan.at), user.plan.amount, PLAN_PER_VAULT_HOUR)?;
        if at > now {
            user.log(format!("waiting {} s for its turn", at - now));
            std::thread::sleep(Duration::from_secs(at - now));
        }
        user.log(format!("starts: {} NEAR into vault {}, account {}", near(user.plan.amount), user.plan.vault, user.account));
        let status = match run_user(user, &s, &funder, wait) {
            Ok(()) => Status::Done,
            Err(e) => {
                user.log(format!("FAILED: {e:#}"));
                Status::Failed(format!("{e:#}"))
            }
        };
        // Counted whether it finished or not: a queued entry may still go through.
        entered.entry(user.plan.vault).or_default().push((start.elapsed().as_secs(), user.plan.amount));
        results.push(status);
    }

    println!("\nsummary:");
    let done = results.iter().filter(|r| **r == Status::Done).count();
    for (user, r) in users.iter().zip(&results) {
        match r {
            Status::Done => println!("  user {:02} {}  {} NEAR -> vault {}: done", user.index, user.account, near(user.plan.amount), user.plan.vault),
            Status::Failed(e) => println!("  user {:02} {}  {} NEAR -> vault {}: FAILED: {e}", user.index, user.account, near(user.plan.amount), user.plan.vault),
        }
    }
    println!("  {done} of {} users went through", users.len());

    println!("\nnotes in circulation, read from the contract (what a user's note of the same tier hides among):");
    match funder.view_final(&s.pool, "get_cash", json!({})) {
        Ok(c) => println!("  cash: {}", live_per_tier(&c, "value").iter().map(|(v, n)| format!("{} NEAR: {n}", v.parse().map(near).unwrap_or_else(|_| v.clone()))).collect::<Vec<_>>().join(", ")),
        Err(e) => println!("  cash: unreadable: {e}"),
    }
    let vaults: std::collections::BTreeSet<u32> = plan.iter().map(|u| u.vault).collect();
    for id in vaults {
        match funder.view_final(&s.pool, "get_vault", json!({"vault_id": id})) {
            Ok(v) => println!("  vault {id}: {}", live_per_tier(&v, "shares").iter().map(|(s, n)| format!("{s} shares: {n}")).collect::<Vec<_>>().join(", ")),
            Err(e) => println!("  vault {id}: unreadable: {e}"),
        }
    }
    if done < users.len() {
        bail!("{} users did not go through (see above); their wallets and keys are kept in {}", users.len() - done, out.display());
    }
    Ok(())
}

fn main() {
    if let Err(e) = main_inner() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn main_inner() -> Result<()> {
    let o = parse_args(std::env::args().skip(1))?;
    let cap = parse_near(&env_opt("ONA_CROWD_MAX_SPEND_NEAR")?.unwrap_or_else(|| DEFAULT_MAX_SPEND.into())).context("ONA_CROWD_MAX_SPEND_NEAR")?;
    let plan = make_plan(&o, &mut OsRng)?;
    print_plan(&plan);
    let total = total_spend(&plan);
    println!("total the funder will spend: {} NEAR (cap {} NEAR, ONA_CROWD_MAX_SPEND_NEAR)", near(total), near(cap));
    check_spend(total, cap)?;
    if o.dry_run {
        // Names only, no network: whatever is set is checked.
        let chain_id = env_opt("ONA_CHAIN_ID")?.unwrap_or_else(|| DEFAULT_CHAIN_ID.into());
        let urls: Vec<String> = ["ONA_RPC_URL", "ONA_RPC_URL_2"].iter().filter_map(|n| env_opt(n).transpose()).collect::<Result<_>>()?;
        let accounts: Vec<String> = ["ONA_POOL", "ONA_CROWD_FUNDER_ACCOUNT"].iter().filter_map(|n| env_opt(n).transpose()).collect::<Result<_>>()?;
        check_target(&chain_id, &urls.iter().map(String::as_str).collect::<Vec<_>>(), &accounts.iter().map(String::as_str).collect::<Vec<_>>())?;
        println!("dry run: nothing sent, no file written");
        return Ok(());
    }
    real_run(&o, &plan, total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn amounts_parse_in_near() {
        assert_eq!(parse_near("0.1").unwrap(), 100 * MILLI);
        assert_eq!(parse_near("6").unwrap(), 6 * NEAR);
        assert_eq!(parse_near("1.25").unwrap(), 1250 * MILLI);
        for bad in ["", ".5", "1.", "-1", "1e3", "0.1.2", "abc"] {
            assert!(parse_near(bad).is_err(), "{bad}");
        }
        assert_eq!(near(600 * MILLI), "0.600");
    }

    #[test]
    fn amounts_are_whole_cash_notes() {
        assert_eq!(cash_notes(600 * MILLI, &CASH_NOTES), Some(vec![500 * MILLI, 100 * MILLI]));
        assert_eq!(cash_notes(NEAR, &CASH_NOTES), Some(vec![500 * MILLI, 500 * MILLI]));
        assert_eq!(cash_notes(150 * MILLI, &CASH_NOTES), None);
        assert_eq!(cash_notes(0, &CASH_NOTES), None);
        assert!(parse_args(args(&["--dry-run", "--amounts", "0.15"])).is_err());
        assert!(parse_args(args(&["--dry-run", "--amounts", "2"])).is_err(), "above the hourly plan of one vault");
        assert!(parse_args(args(&["--users", "3"])).is_err(), "a real run needs --out");
        let o = parse_args(args(&["--dry-run", "--users", "3", "--vaults", "0,1", "--amounts", "0.5,1"])).unwrap();
        assert_eq!((o.users, o.vaults, o.amounts), (3, vec![0, 1], vec![500 * MILLI, NEAR]));
        let d = parse_args(args(&["--dry-run"])).unwrap();
        assert_eq!((d.users, d.vaults), (8, vec![1]));
    }

    #[test]
    fn the_hourly_plan_waits_for_room() {
        let cap = PLAN_PER_VAULT_HOUR;
        assert_eq!(cap_wait(&[], 10, NEAR, cap).unwrap(), 10);
        let h = [(0, NEAR), (100, 600 * MILLI)];
        assert_eq!(cap_wait(&h, 200, 100 * MILLI, cap).unwrap(), 200, "1.7 NEAR fits under 1.8");
        assert_eq!(cap_wait(&h, 200, 500 * MILLI, cap).unwrap(), HOUR_SECS, "waits until the first entry is an hour old");
        assert_eq!(cap_wait(&h, 200, 1800 * MILLI, cap).unwrap(), HOUR_SECS + 100);
        assert!(cap_wait(&[], 0, 2 * NEAR, cap).is_err());
    }

    #[test]
    fn plans_keep_every_vault_under_the_hourly_plan() {
        let o = Options { users: 40, vaults: vec![0, 1], amounts: vec![500 * MILLI, 600 * MILLI], min_gap_secs: 0, max_gap_secs: 30, ..Options::default() };
        for seed in 0..20 {
            let plan = make_plan(&o, &mut StdRng::seed_from_u64(seed)).unwrap();
            assert_eq!(plan.len(), 40);
            assert!(plan.windows(2).all(|w| w[0].at <= w[1].at), "users start in order");
            for u in &plan {
                assert!(o.vaults.contains(&u.vault) && o.amounts.contains(&u.amount));
                for v in &o.vaults {
                    let used: u128 = plan.iter().filter(|p| p.vault == *v && p.at <= u.at && p.at + HOUR_SECS > u.at).map(|p| p.amount).sum();
                    assert!(used <= PLAN_PER_VAULT_HOUR, "seed {seed}: {used} in the hour up to {}", u.at);
                }
            }
        }
        let gaps = Options { users: 5, min_gap_secs: 60, max_gap_secs: 60, amounts: vec![100 * MILLI], ..Options::default() };
        let plan = make_plan(&gaps, &mut StdRng::seed_from_u64(1)).unwrap();
        assert_eq!(plan.iter().map(|u| u.at).collect::<Vec<_>>(), vec![0, 60, 120, 180, 240]);
        assert!(plan.iter().all(|u| u.vault == 1));
    }

    #[test]
    fn the_spend_is_counted_before_anything_is_sent() {
        let plan = vec![PlannedUser { at: 0, vault: 1, amount: 100 * MILLI }, PlannedUser { at: 60, vault: 1, amount: 600 * MILLI }];
        // 0.1 + 0.6 + 2 x (0.01 margin + 0.05 gas + 0.01 storage + 0.001 transfer)
        assert_eq!(total_spend(&plan), 700 * MILLI + 2 * 71 * MILLI);
        assert_eq!(funding(500 * MILLI), 570 * MILLI);
        assert!(check_spend(total_spend(&plan), 6 * NEAR).is_ok());
        assert!(check_spend(total_spend(&plan), 800 * MILLI).is_err());
        // The default plan never exceeds the default cap: 8 users of at most 0.6 NEAR.
        let worst = vec![PlannedUser { at: 0, vault: 1, amount: 600 * MILLI }; DEFAULT_USERS];
        assert!(check_spend(total_spend(&worst), parse_near(DEFAULT_MAX_SPEND).unwrap()).is_ok());
        let over = vec![PlannedUser { at: 0, vault: 1, amount: 600 * MILLI }; 10];
        assert!(check_spend(total_spend(&over), parse_near(DEFAULT_MAX_SPEND).unwrap()).is_err());
    }

    #[test]
    fn mainnet_is_refused() {
        let rpc = "https://test.rpc.fastnear.com";
        assert!(check_target("testnet", &[rpc], &["pool.example.testnet", "funder.testnet"]).is_ok());
        assert!(check_target("mainnet", &[rpc], &["pool.example.testnet"]).is_err());
        assert!(check_target("testnet", &["https://rpc.mainnet.near.org"], &["pool.example.testnet"]).is_err());
        assert!(check_target("testnet", &[rpc], &["pool.example.near"]).is_err());
        assert!(check_target("testnet", &[rpc], &["pool.example"]).is_err(), "a named account must end with .testnet");
        assert!(check_target("testnet", &["http://rpc.example.com"], &[]).is_err(), "plain http only to this machine");
        let key = SigningKey::from_bytes(&[7; 32]);
        assert!(check_target("testnet", &[rpc], &[&implicit_account(&key)]).is_ok(), "an implicit account passes");
    }

    #[test]
    fn implicit_accounts_and_keys_use_near_formats() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let account = implicit_account(&key);
        assert!(is_implicit(&account));
        assert!(check_account_id(&account).is_ok());
        let parsed = ona_near::parse_account_key(&account_key_text(&key)).unwrap();
        assert_eq!(parsed.to_bytes(), key.to_bytes());
    }

    #[test]
    fn entries_fit_the_vault_tiers() {
        let price = 1_000_000_000_000_000_000; // 1e-6 NEAR per share
        let vault1 = [498_000, 98_000, 10_000, 1_000];
        assert_eq!(fit(100 * MILLI, &vault1, price), (98 * MILLI, 0));
        assert_eq!(fit(500 * MILLI, &vault1, price), (498 * MILLI, 0));
        let vault0 = [100_000, 500_000];
        assert_eq!(fit(100 * MILLI, &vault0, price), (0, 98 * MILLI), "a 0.1 NEAR note becomes nothing in vault 0");
        assert_eq!(fit(500 * MILLI, &vault0, price), (400 * MILLI, 98 * MILLI));
    }

    #[test]
    fn circulation_is_issued_minus_paid() {
        let v = json!({"tiers": [{"shares": "498000", "issued": 5, "paid": 2}, {"shares": "98000", "issued": 1, "paid": 0}]});
        assert_eq!(live_per_tier(&v, "shares"), vec![("498000".to_string(), 3), ("98000".to_string(), 1)]);
    }

    #[test]
    fn the_output_folder_must_be_outside_the_repository() {
        let root = Path::new(REPO_ROOT);
        assert!(inside(&root.join("crowd-out"), root).unwrap());
        assert!(inside(&root.join("crates"), root).unwrap());
        assert!(!inside(&std::env::temp_dir().join("ona-crowd-out-test"), root).unwrap());
    }

    #[test]
    fn private_files_are_new_and_owner_only() {
        let dir = std::env::temp_dir().join(format!("ona-crowd-run-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("k");
        let _ = std::fs::remove_file(&f);
        write_private(&f, b"x").unwrap();
        assert!(write_private(&f, b"y").is_err(), "never replaced");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
