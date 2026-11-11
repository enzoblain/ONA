//! The user's side of `ona-pool`: deposit, enter a vault, switch vaults, exit to cash, pay cash out, the portfolio and
//! recovery after an interruption.
//!
//! Each operation has two steps. `pool_prepare` computes what will be done (operation, vault, amount, notes, fees)
//! from the contract's public figures and returns it with a `prepared_id`: the app shows it and the user confirms
//! on the computer. `pool_execute` takes that id, once, within `PREPARATION_LIFE_NS`: it is bound to the network, the
//! contract, the operation, the vault, the amount and a random nonce. The notes a preparation picks are reserved
//! until it is used or expires. Nothing is confirmed on the phone.
//!
//! Notes live in the encrypted wallet with their status. Each note has a fresh owner key. Every owner signature
//! follows the formats of SPEC (`ona-pool`), built by `ona_wallet::pool`. Calls only the agent may make
//! (`issue_cash`, `enter`, `leave`, `pay_exit`) go through `PoolAgent`; the transport to the real agent is not
//! built yet, so `NoAgent` refuses them. Reading the portfolio reads the configuration, the cash and every vault,
//! whoever runs it, and sends nothing to the relay.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use ona_token::{g2_from_raw, PendingToken, Token, G1_LEN, G2_LEN, G2_RAW_LEN};
use ona_wallet::{pool, NoteStatus, PoolNote, Wallet};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// Share price of a vault with no share, as in the contract.
const INITIAL_PRICE: u128 = 1_000_000_000_000_000_000;
/// Kept by the contract from the note an entry or a leave spends, and from each exit.
pub const NOTE_STORAGE_FEE: u128 = 2_000_000_000_000_000_000_000;
pub const EXIT_STORAGE_FEE: u128 = 2_000_000_000_000_000_000_000;
/// The contract's smallest deposit.
pub const MIN_DEPOSIT: u128 = NEAR / 10;
/// Most notes one entry or leave can create, as in the contract.
pub const MAX_OUTPUTS: u64 = 64;
/// Added to a deposit so the storage of the depositor's record never eats into the cash it buys. An estimate:
/// the contract measures the real storage and keeps the rest refundable.
pub const DEPOSIT_MARGIN: u128 = 10_000_000_000_000_000_000_000;
/// How long the owner's signatures of an execution stay valid: long enough for the agent to batch them.
pub const SIGNATURE_LIFE_NS: u64 = 24 * 3_600_000_000_000;
/// How long a preparation can be executed, and keeps its notes reserved.
pub const PREPARATION_LIFE_NS: u64 = 5 * 60_000_000_000;
/// Deposit amounts the app recommends unless configured otherwise, in NEAR: common amounts hide better.
pub const DEFAULT_RECOMMENDED_NEAR: [u128; 3] = [100, 500, 2_000];

/// The commands this module answers.
pub const COMMANDS: [&str; 4] = ["pool_portfolio", "pool_prepare", "pool_execute", "pool_recover"];

/// Read-only access to the pool contract.
pub trait PoolChain {
    fn view(&self, method: &str, args: Value) -> Result<Value, String>;

    /// Labels every reply, so figures from a fake chain cannot pass for real ones.
    fn mode(&self) -> &'static str;
}

/// The pool read through a NEAR RPC endpoint, on final blocks.
pub struct NearPool {
    client: ona_near::Client,
    pool: String,
}

impl NearPool {
    pub fn new(rpc_url: &str, pool: &str) -> Self {
        // Views sign nothing; the client only needs a key to exist.
        Self { client: ona_near::Client::new(rpc_url, SigningKey::generate(&mut OsRng)), pool: pool.into() }
    }
}

impl PoolChain for NearPool {
    fn view(&self, method: &str, args: Value) -> Result<Value, String> {
        self.client.view_final(&self.pool, method, args).map_err(|e| e.to_string())
    }

    fn mode(&self) -> &'static str {
        crate::remote::REAL_MODE
    }
}

/// A note as the contract takes it, with the owner's signature and its deadline.
#[derive(Clone, Debug)]
pub struct SignedNote {
    pub tier: u8,
    pub pk: [u8; 32],
    pub nonce: [u8; 32],
    pub sig: [u8; G1_LEN],
    pub owner_sig: [u8; 64],
    pub expires_at: u64,
}

impl SignedNote {
    /// The contract's arguments for this note, its owner signature and deadline (for the agent transport).
    pub fn contract_args(&self) -> Value {
        json!({
            "note": {"tier": self.tier, "pk": b64(&self.pk), "nonce": b64(&self.nonce), "sig": b64(&self.sig)},
            "owner_sig": b64(&self.owner_sig),
            "expires_at": self.expires_at,
        })
    }
}

/// Why an agent call gave no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentError {
    /// Certainly not done: nothing was sent, or the chain refused it. The note is held again.
    Refused(String),
    /// Maybe done: sent, no answer. The note stays spending until `pool_recover` finds out.
    Unknown(String),
}

impl AgentError {
    fn message(&self) -> String {
        match self {
            Self::Refused(m) => m.clone(),
            Self::Unknown(m) => format!("outcome unknown, run pool_recover later: {m}"),
        }
    }
}

/// The calls only the agent may make, and the blind signatures it returns, one per blinded point in order.
/// `issue_cash` must be authenticated by the depositor on the agent's side (not built): the agent issues cash
/// only to the account that deposited, and the contract refuses more than its deposits.
pub trait PoolAgent {
    fn issue_cash(&mut self, account: &str, tier: u8, blinded: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError>;
    fn enter(
        &mut self,
        vault: u32,
        note: &SignedNote,
        outputs: &[(u8, u64)],
        blinded: &[[u8; G1_LEN]],
    ) -> Result<Vec<[u8; G1_LEN]>, AgentError>;
    fn leave(
        &mut self,
        vault: u32,
        note: &SignedNote,
        outputs: &[(u8, u64)],
        blinded: &[[u8; G1_LEN]],
    ) -> Result<Vec<[u8; G1_LEN]>, AgentError>;
    fn pay_exit(&mut self, note: &SignedNote, to: &str) -> Result<(), AgentError>;
    /// The blind signatures the agent made for these points, if any, in order: used to recover notes whose
    /// answer was lost.
    fn signatures(&mut self, blinded: &[[u8; G1_LEN]]) -> Result<Vec<Option<[u8; G1_LEN]>>, AgentError>;
}

/// No transport to the agent exists yet: every agent call is refused before anything is sent.
pub struct NoAgent;

const NO_AGENT: &str = "no connection to the pool agent yet";

impl PoolAgent for NoAgent {
    fn issue_cash(&mut self, _: &str, _: u8, _: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        Err(AgentError::Refused(NO_AGENT.into()))
    }
    fn enter(&mut self, _: u32, _: &SignedNote, _: &[(u8, u64)], _: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        Err(AgentError::Refused(NO_AGENT.into()))
    }
    fn leave(&mut self, _: u32, _: &SignedNote, _: &[(u8, u64)], _: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        Err(AgentError::Refused(NO_AGENT.into()))
    }
    fn pay_exit(&mut self, _: &SignedNote, _: &str) -> Result<(), AgentError> {
        Err(AgentError::Refused(NO_AGENT.into()))
    }
    fn signatures(&mut self, _: &[[u8; G1_LEN]]) -> Result<Vec<Option<[u8; G1_LEN]>>, AgentError> {
        Err(AgentError::Refused(NO_AGENT.into()))
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn u128_field(v: &Value, key: &str) -> Result<u128, String> {
    v[key].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| format!("pool view without {key}"))
}

fn tier_key(v: &Value) -> Result<[u8; G2_LEN], String> {
    use base64::Engine;
    let raw = v["pk_raw"]
        .as_str()
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        .ok_or("pool view without pk_raw")?;
    let raw: [u8; G2_RAW_LEN] = raw.try_into().map_err(|_| "tier key of the wrong length".to_string())?;
    g2_from_raw(&raw).map_err(|e| format!("bad tier key: {e}"))
}

fn overflow() -> String {
    "a value read from the pool is too large".into()
}

/// A tier as read from the contract: shares per note (vaults) or value per note (cash), and its key.
struct Tier {
    size: u128,
    pk: [u8; G2_LEN],
}

struct VaultInfo {
    tiers: Vec<Tier>,
    /// Rounded down: what a share is worth when it leaves.
    price: u128,
    /// Rounded up: what a share costs when it enters.
    price_up: u128,
    frozen: bool,
}

struct State {
    network: String,
    cash: Vec<Tier>,
    vaults: Vec<VaultInfo>,
}

impl State {
    fn vault(&self, id: u32) -> Result<&VaultInfo, String> {
        self.vaults.get(id as usize).ok_or_else(|| format!("no vault {id}"))
    }

    fn note_value(&self, n: &PoolNote) -> Result<u128, String> {
        let tier = usize::from(n.token.denom_id);
        match n.vault {
            None => self.cash.get(tier).map(|t| t.size).ok_or_else(|| "unknown cash tier".into()),
            Some(v) => {
                let vi = self.vault(v)?;
                let t = vi.tiers.get(tier).ok_or("unknown tier")?;
                t.size.checked_mul(vi.price).ok_or_else(overflow)
            }
        }
    }
}

/// The price a share costs when it enters, computed from the published figures as the contract does: what the
/// vault holds, less its fee and what no share owns (`orphan`), over its shares, rounded up.
fn read_vault(v: &Value) -> Result<VaultInfo, String> {
    let mut tiers = Vec::new();
    for t in v["tiers"].as_array().ok_or("pool view without tiers")? {
        tiers.push(Tier { size: u128_field(t, "shares")?, pk: tier_key(t)? });
    }
    let total = u128_field(v, "total_shares")?;
    let assets = u128_field(v, "liquid")?
        .checked_add(u128_field(v, "placed")?)
        .ok_or_else(overflow)?
        .saturating_sub(u128_field(v, "fee_owed")?)
        .saturating_sub(u128_field(v, "orphan")?);
    let price_up = if total == 0 { INITIAL_PRICE } else { assets / total + u128::from(assets % total != 0) };
    Ok(VaultInfo { tiers, price: u128_field(v, "share_price")?, price_up, frozen: v["frozen"].as_bool().unwrap_or(true) })
}

/// Splits `budget` into notes of `tiers` (sizes times `unit`), largest first, as `(tier, count)` in tier order.
/// Returns what is left, always less than the smallest note.
fn split(budget: u128, tiers: &[Tier], unit: u128) -> Result<(Vec<(u8, u64)>, u128), String> {
    let mut order: Vec<usize> = (0..tiers.len()).collect();
    order.sort_by(|a, b| tiers[*b].size.cmp(&tiers[*a].size));
    let mut left = budget;
    let mut counts = vec![0u64; tiers.len()];
    for t in order {
        let each = tiers[t].size.checked_mul(unit).ok_or_else(overflow)?;
        if each == 0 {
            continue;
        }
        counts[t] = u64::try_from(left / each).map_err(|_| "too many notes")?;
        left %= each;
    }
    let outputs: Vec<(u8, u64)> = counts.iter().enumerate().filter(|(_, c)| **c > 0).map(|(t, c)| (t as u8, *c)).collect();
    if outputs.is_empty() {
        return Err("worth less than the smallest note it could become".into());
    }
    if outputs.iter().map(|(_, c)| c).sum::<u64>() > MAX_OUTPUTS {
        return Err(format!("would become more than {MAX_OUTPUTS} notes: use fewer at once"));
    }
    Ok((outputs, left))
}

/// Picks notes worth exactly `amount`, largest first; `"all"` takes them all.
fn select(available: Vec<(PoolNote, u128)>, amount: &str) -> Result<Vec<(PoolNote, u128)>, String> {
    if available.is_empty() {
        return Err("no held notes for this".into());
    }
    if amount == "all" {
        return Ok(available);
    }
    let target: u128 = amount.parse().map_err(|_| "amount must be yoctoNEAR digits or \"all\"".to_string())?;
    let mut notes = available;
    notes.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
    let mut left = target;
    let mut chosen = Vec::new();
    for (n, v) in notes {
        if v > 0 && v <= left {
            left -= v;
            chosen.push((n, v));
        }
    }
    if left != 0 || target == 0 {
        return Err("the amount is not a sum of whole notes: build it from the note values of the portfolio".into());
    }
    Ok(chosen)
}

/// One step of an execution, planned at `pool_prepare`.
#[derive(Clone, Debug)]
enum Step {
    /// After the user's own deposit: cash notes of these tiers for this account.
    Issue { account: String, outputs: Vec<(u8, u64)> },
    /// A held cash note into share notes of `vault`.
    Enter { nf: [u8; 32], vault: u32, outputs: Vec<(u8, u64)> },
    /// A held share note into cash notes; with `then_enter`, each new cash note then enters that vault as planned.
    Leave { nf: [u8; 32], vault: u32, outputs: Vec<(u8, u64)>, then_enter: Option<(u32, Vec<Vec<(u8, u64)>>)> },
    /// A held cash note paid to `to`.
    Pay { nf: [u8; 32], to: String },
}

struct Prepared {
    op: String,
    vault: Option<u32>,
    amount: String,
    nonce: [u8; 32],
    steps: Vec<Step>,
    created_at: u64,
    reserved: Vec<[u8; 32]>,
}

pub struct PoolClient {
    wallet: Wallet,
    chain: Box<dyn PoolChain>,
    agent: Box<dyn PoolAgent>,
    contract: String,
    clock: Box<dyn Fn() -> u64>,
    recommended: Vec<u128>,
    prepared: BTreeMap<String, Prepared>,
}

/// Reads a 32-byte key written as 64 hex characters, in a file only its owner can read.
pub fn load_wallet_key(path: &Path) -> Result<[u8; 32], String> {
    let meta = fs::metadata(path).map_err(|_| "cannot read the wallet key file".to_string())?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err("wallet key file is accessible to other users".into());
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let text = text.trim();
    let bytes: Option<Vec<u8>> = (text.len() == 64 && text.is_ascii())
        .then(|| (0..64).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect())
        .flatten();
    bytes.and_then(|b| b.try_into().ok()).ok_or_else(|| "wallet key must be 64 hex characters".to_string())
}

/// Reads a comma-separated list of whole NEAR amounts.
pub fn parse_recommended(text: &str) -> Result<Vec<u128>, String> {
    text.split(',')
        .map(|s| {
            s.trim()
                .parse::<u128>()
                .ok()
                .and_then(|n| n.checked_mul(NEAR))
                .filter(|v| *v >= MIN_DEPOSIT)
                .ok_or_else(|| format!("not a whole amount of NEAR: {s}"))
        })
        .collect()
}

fn system_clock() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

impl PoolClient {
    pub fn new(wallet: Wallet, chain: Box<dyn PoolChain>, agent: Box<dyn PoolAgent>, contract: &str) -> Self {
        Self {
            wallet,
            chain,
            agent,
            contract: contract.into(),
            clock: Box::new(system_clock),
            recommended: DEFAULT_RECOMMENDED_NEAR.iter().map(|n| n * NEAR).collect(),
            prepared: BTreeMap::new(),
        }
    }

    /// Replaces the clock (nanoseconds since 1970), for tests.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64>) -> Self {
        self.clock = clock;
        self
    }

    /// Replaces the recommended deposit amounts (yoctoNEAR).
    pub fn with_recommended(mut self, amounts: Vec<u128>) -> Self {
        self.recommended = amounts;
        self
    }

    /// `None` when `ONA_WALLET_FILE` is not set. Otherwise `ONA_WALLET_KEY_FILE`, `ONA_POOL` and `ONA_RPC_URL` are
    /// needed, and `ONA_POOL_RECOMMENDED_NEAR` may list the recommended deposits. The agent is `NoAgent`: no
    /// transport to it exists yet.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(file) = std::env::var("ONA_WALLET_FILE") else {
            return Ok(None);
        };
        let need = |k: &str| std::env::var(k).map_err(|_| format!("{k} is not set"));
        let key = load_wallet_key(Path::new(&need("ONA_WALLET_KEY_FILE")?))?;
        let pool = need("ONA_POOL")?;
        let rpc = need("ONA_RPC_URL")?;
        ona_near::check_rpc_url(&rpc).map_err(|e| format!("ONA_RPC_URL: {e}"))?;
        let recommended = match std::env::var("ONA_POOL_RECOMMENDED_NEAR") {
            Ok(text) => Some(parse_recommended(&text).map_err(|e| format!("ONA_POOL_RECOMMENDED_NEAR: {e}"))?),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("ONA_POOL_RECOMMENDED_NEAR is not valid text".into()),
        };
        let wallet = Wallet::open(Path::new(&file), &key)?;
        let client = Self::new(wallet, Box::new(NearPool::new(&rpc, &pool)), Box::new(NoAgent), &pool);
        Ok(Some(match recommended {
            Some(r) => client.with_recommended(r),
            None => client,
        }))
    }

    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The configuration, the cash and every vault: the same reads whoever runs them.
    fn state(&self) -> Result<State, String> {
        let config = self.chain.view("get_config", json!({}))?;
        let network = config["network"].as_str().ok_or("pool config without network")?.to_string();
        let count = config["vault_count"].as_u64().ok_or("pool config without vault_count")?;
        let cash_view = self.chain.view("get_cash", json!({}))?;
        let mut cash = Vec::new();
        for t in cash_view["tiers"].as_array().ok_or("cash view without tiers")? {
            cash.push(Tier { size: u128_field(t, "value")?, pk: tier_key(t)? });
        }
        let vaults = (0..count)
            .map(|id| self.chain.view("get_vault", json!({"vault_id": id})).and_then(|v| read_vault(&v)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(State { network, cash, vaults })
    }

    /// Drops preparations older than `PREPARATION_LIFE_NS`, freeing their notes.
    fn expire(&mut self) {
        let now = self.now();
        self.prepared.retain(|_, p| now < p.created_at.saturating_add(PREPARATION_LIFE_NS));
    }

    /// Held notes of `vault` (cash when `None`) not reserved by a live preparation, with their value.
    fn available(&self, state: &State, vault: Option<u32>) -> Result<Vec<(PoolNote, u128)>, String> {
        let reserved: BTreeSet<[u8; 32]> = self.prepared.values().flat_map(|p| p.reserved.iter().copied()).collect();
        self.wallet
            .notes()
            .into_iter()
            .filter(|n| n.vault == vault && n.status == NoteStatus::Held && !reserved.contains(&n.nf))
            .map(|n| state.note_value(&n).map(|v| (n, v)))
            .collect()
    }

    pub fn run(&mut self, cmd: &str, request: &Value) -> Result<Value, String> {
        self.expire();
        let mut reply = match cmd {
            "pool_portfolio" => self.portfolio(),
            "pool_prepare" => self.prepare(request),
            "pool_execute" => self.execute(request),
            "pool_recover" => self.recover(),
            other => Err(format!("unknown command {other}")),
        }?;
        reply["mode"] = json!(self.chain.mode());
        Ok(reply)
    }

    fn portfolio(&self) -> Result<Value, String> {
        let state = self.state()?;
        let notes = self.wallet.notes();
        let pending = self.wallet.notes_pending()?;
        let group = |vault: Option<u32>, tiers: &[Tier], unit: u128| -> Result<(Vec<Value>, u128, u128, usize), String> {
            let mine: Vec<&PoolNote> = notes.iter().filter(|n| n.vault == vault).collect();
            let mut out = Vec::new();
            let (mut value, mut moving) = (0u128, 0u128);
            for (t, tier) in tiers.iter().enumerate() {
                let each = tier.size.checked_mul(unit).ok_or_else(overflow)?;
                let count = |s: NoteStatus| mine.iter().filter(|n| n.status == s && usize::from(n.token.denom_id) == t).count();
                let (held, spending) = (count(NoteStatus::Held), count(NoteStatus::Spending));
                value = each.checked_mul(held as u128).and_then(|v| v.checked_add(value)).ok_or_else(overflow)?;
                moving = each.checked_mul(spending as u128).and_then(|v| v.checked_add(moving)).ok_or_else(overflow)?;
                if held + spending > 0 {
                    out.push(json!({"tier": t, "note_value": each.to_string(), "held": held, "spending": spending}));
                }
            }
            let waiting = pending.iter().filter(|(v, _)| *v == vault).count();
            Ok((out, value, moving, waiting))
        };
        let (cash_tiers, cash_value, cash_moving, cash_waiting) = group(None, &state.cash, 1)?;
        let mut total = cash_value;
        let mut vaults = Vec::new();
        for (id, v) in state.vaults.iter().enumerate() {
            let (tiers, value, moving, waiting) = group(Some(id as u32), &v.tiers, v.price)?;
            if tiers.is_empty() && waiting == 0 {
                continue;
            }
            total = total.checked_add(value).ok_or_else(overflow)?;
            vaults.push(json!({
                "vault": id, "share_price": v.price.to_string(), "frozen": v.frozen, "tiers": tiers,
                "value": value.to_string(), "spending_value": moving.to_string(), "awaiting_signature": waiting,
            }));
        }
        Ok(json!({
            "cash": {"tiers": cash_tiers, "value": cash_value.to_string(), "spending_value": cash_moving.to_string(),
                     "awaiting_signature": cash_waiting},
            "vaults": vaults,
            "vault_count": state.vaults.len(),
            "total": total.to_string(),
        }))
    }

    fn prepare(&mut self, request: &Value) -> Result<Value, String> {
        let state = self.state()?;
        let op = request["op"].as_str().ok_or("missing field op")?.to_string();
        let amount = request["amount"].as_str().ok_or("missing field amount")?.to_string();
        let vault_arg = |key: &str| -> Result<u32, String> {
            let id = request[key].as_u64().ok_or_else(|| format!("missing field {key}"))?;
            let id = u32::try_from(id).map_err(|_| format!("no vault {id}"))?;
            state.vault(id)?;
            Ok(id)
        };
        let account = |key: &str| -> Result<String, String> {
            let a = request[key].as_str().ok_or_else(|| format!("missing field {key}"))?;
            ona_near::check_account_id(a).map_err(|e| format!("{key}: {e}"))?;
            Ok(a.to_string())
        };
        let mut summary = json!({"op": op, "amount": amount});
        let mut reserved = Vec::new();
        let (vault, steps) = match op.as_str() {
            "deposit" => {
                let account = account("account")?;
                let total: u128 = amount.parse().map_err(|_| "amount must be yoctoNEAR digits".to_string())?;
                if total < MIN_DEPOSIT {
                    return Err("below the contract's smallest deposit (0.1 NEAR)".into());
                }
                let (outputs, rest) = split(total, &state.cash, 1)?;
                if rest != 0 {
                    return Err("the amount is not a sum of cash notes".into());
                }
                let attach = total.checked_add(DEPOSIT_MARGIN).ok_or_else(overflow)?;
                summary["account"] = json!(account);
                summary["cash_notes"] = notes_json(&outputs, &state.cash)?;
                summary["recommended"] = json!(self.recommended.iter().map(|a| a.to_string()).collect::<Vec<_>>());
                if !self.recommended.contains(&total) {
                    summary["warning"] = json!(
                        "this amount is not one of the recommended amounts: an unusual deposit is easier to link to its exit"
                    );
                }
                summary["wallet_call"] = json!({
                    "receiver": self.contract, "method": "deposit", "args": {}, "attached": attach.to_string(),
                });
                summary["fees"] = json!({"storage_margin": DEPOSIT_MARGIN.to_string(), "refundable": "unused margin"});
                (None, vec![Step::Issue { account, outputs }])
            }
            "enter" => {
                let id = vault_arg("vault")?;
                let v = state.vault(id)?;
                if v.frozen {
                    return Err("this vault is frozen".into());
                }
                let chosen = select(self.available(&state, None)?, &amount)?;
                let mut steps = Vec::new();
                let (mut cost, mut rest) = (0u128, 0u128);
                for (n, value) in &chosen {
                    let budget = value.checked_sub(NOTE_STORAGE_FEE).ok_or("a cash note is worth less than its fee")?;
                    let (outputs, left) = split(budget, &v.tiers, v.price_up)?;
                    cost += budget - left;
                    rest += left;
                    reserved.push(n.nf);
                    steps.push(Step::Enter { nf: n.nf, vault: id, outputs });
                }
                summary["vault"] = json!(id);
                summary["shares_value"] = json!(cost.to_string());
                summary["left_in_cash"] = json!(rest.to_string());
                summary["fees"] = json!({"storage": (NOTE_STORAGE_FEE * chosen.len() as u128).to_string()});
                (Some(id), steps)
            }
            "exit" | "switch" => {
                let from = vault_arg("from")?;
                let a = state.vault(from)?;
                let chosen = select(self.available(&state, Some(from))?, &amount)?;
                let to_vault = if op == "switch" { Some(vault_arg("to")?) } else { None };
                if to_vault == Some(from) {
                    return Err("choose another vault".into());
                }
                let mut steps = Vec::new();
                let (mut fees, mut cash_out, mut rest, mut new_shares) = (0u128, 0u128, 0u128, 0u128);
                for (n, value) in &chosen {
                    let budget = value.checked_sub(NOTE_STORAGE_FEE).ok_or("a share note is worth less than its fee")?;
                    let (outputs, left) = split(budget, &state.cash, 1)?;
                    fees += NOTE_STORAGE_FEE;
                    rest += left;
                    cash_out += budget - left;
                    let mut then_enter = None;
                    if let Some(to) = to_vault {
                        let b = state.vault(to)?;
                        if b.frozen {
                            return Err("the destination vault is frozen".into());
                        }
                        let mut plans = Vec::new();
                        for (tier, count) in &outputs {
                            for _ in 0..*count {
                                let cash = state.cash[usize::from(*tier)].size;
                                let budget = cash.checked_sub(NOTE_STORAGE_FEE).ok_or("a cash note is worth less than its fee")?;
                                let (shares, left) = split(budget, &b.tiers, b.price_up)?;
                                fees += NOTE_STORAGE_FEE;
                                rest += left;
                                new_shares += budget - left;
                                plans.push(shares);
                            }
                        }
                        then_enter = Some((to, plans));
                    }
                    reserved.push(n.nf);
                    steps.push(Step::Leave { nf: n.nf, vault: from, outputs, then_enter });
                }
                summary["from"] = json!(from);
                summary["share_price"] = json!(a.price.to_string());
                summary["left_in_cash"] = json!(rest.to_string());
                summary["fees"] = json!({"storage": fees.to_string()});
                match to_vault {
                    Some(to) => {
                        summary["to"] = json!(to);
                        summary["new_shares_value"] = json!(new_shares.to_string());
                    }
                    None => summary["cash_value"] = json!(cash_out.to_string()),
                }
                (Some(from), steps)
            }
            "exit_cash" => {
                let to = account("to")?;
                let chosen = select(self.available(&state, None)?, &amount)?;
                let mut received = 0u128;
                let mut paid = 0u128;
                for (_, value) in &chosen {
                    paid = paid.checked_add(*value).ok_or_else(overflow)?;
                    received = value.checked_sub(EXIT_STORAGE_FEE).and_then(|v| v.checked_add(received)).ok_or("a cash note is worth less than its fee")?;
                }
                // The account's own limit, read from the contract (the account is named by the payment anyway).
                let holder = self.chain.view("get_holder", json!({"account": to}))?;
                let limit = u128_field(&holder, "exit_limit")?;
                if paid > limit {
                    return Err(format!("over this account's exit limit ({limit} yoctoNEAR)"));
                }
                summary["to"] = json!(to);
                summary["received"] = json!(received.to_string());
                summary["exit_limit"] = json!(limit.to_string());
                summary["fees"] = json!({"storage": (EXIT_STORAGE_FEE * chosen.len() as u128).to_string()});
                reserved = chosen.iter().map(|(n, _)| n.nf).collect();
                (None, chosen.iter().map(|(n, _)| Step::Pay { nf: n.nf, to: to.clone() }).collect())
            }
            other => return Err(format!("unknown operation {other}")),
        };
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let id = prepared_id(&state.network, &self.contract, &op, vault, &amount, &nonce);
        let created_at = self.now();
        summary["network"] = json!(state.network);
        summary["contract"] = json!(self.contract);
        summary["expires_at"] = json!(created_at.saturating_add(PREPARATION_LIFE_NS));
        self.prepared.insert(id.clone(), Prepared { op, vault, amount, nonce, steps, created_at, reserved });
        Ok(json!({"prepared_id": id, "summary": summary}))
    }

    fn execute(&mut self, request: &Value) -> Result<Value, String> {
        let id = request["prepared_id"].as_str().ok_or("missing field prepared_id")?;
        let prepared = self.prepared.remove(id).ok_or("unknown, expired or already used prepared_id")?;
        let state = self.state()?;
        let expected = prepared_id(&state.network, &self.contract, &prepared.op, prepared.vault, &prepared.amount, &prepared.nonce);
        if expected != id {
            return Err("this preparation belongs to another network or contract".into());
        }
        let mut done = Vec::new();
        let result = self.run_steps(&state, &prepared.steps, &mut done);
        match result {
            Ok(()) => Ok(json!({"executed": prepared.op, "complete": true, "steps": done})),
            Err(e) if done.is_empty() => Err(e),
            // Part of it ran: say what, with the error.
            Err(e) => Ok(json!({"executed": prepared.op, "complete": false, "error": e, "steps": done})),
        }
    }

    fn run_steps(&mut self, state: &State, steps: &[Step], done: &mut Vec<Value>) -> Result<(), String> {
        for step in steps {
            match step {
                Step::Issue { account, outputs } => {
                    for (tier, count) in outputs {
                        let notes = self.issue(state, account, *tier, *count)?;
                        done.push(json!({"issued_cash": notes}));
                    }
                }
                Step::Enter { nf, vault, outputs } => {
                    self.enter(state, nf, *vault, outputs)?;
                    done.push(json!({"entered": vault}));
                }
                Step::Leave { nf, vault, outputs, then_enter } => {
                    let cash = self.leave(state, nf, *vault, outputs)?;
                    done.push(json!({"left": vault, "cash_notes": cash.len()}));
                    if let Some((to, plans)) = then_enter {
                        for (note, plan) in cash.iter().zip(plans) {
                            self.enter(state, note, *to, plan)?;
                            done.push(json!({"entered": to}));
                        }
                    }
                }
                Step::Pay { nf, to } => {
                    self.pay(nf, to)?;
                    done.push(json!({"paid": 1, "to": to}));
                }
            }
        }
        Ok(())
    }

    /// After an interruption: each spending note is checked on chain; a spent one is marked spent, an unspent one
    /// whose signature has expired is held again (the operation can no longer happen), others wait. Then the agent
    /// is asked for the blind signatures of every note still waiting for one (a lost answer, a deposit whose cash
    /// was never finished).
    fn recover(&mut self) -> Result<Value, String> {
        let state = self.state()?;
        let now = self.now();
        let (mut spent, mut held, mut waiting) = (0, 0, 0);
        for n in self.wallet.notes().into_iter().filter(|n| n.status == NoteStatus::Spending) {
            let is_spent = self.chain.view("is_spent", json!({"nf": b64(&n.nf)}))?.as_bool().ok_or("is_spent did not answer a boolean")?;
            if is_spent {
                self.wallet.set_note_status(&n.nf, NoteStatus::Spent)?;
                spent += 1;
            } else if self.wallet.spending_until(&n.nf).is_some_and(|until| now > until) {
                self.wallet.set_note_status(&n.nf, NoteStatus::Held)?;
                held += 1;
            } else {
                waiting += 1;
            }
        }
        let pending = self.wallet.notes_pending()?;
        let mut recovered = 0;
        if !pending.is_empty() {
            let blinded: Vec<[u8; G1_LEN]> = pending.iter().map(|(_, p)| p.blinded).collect();
            let sigs = self.agent.signatures(&blinded).map_err(|e| e.message())?;
            if sigs.len() != blinded.len() {
                return Err("the agent returned a wrong number of signatures".into());
            }
            for ((vault, p), sig) in pending.iter().zip(sigs) {
                if let Some(sig) = sig {
                    let pk = match vault {
                        None => &state.cash.get(usize::from(p.denom_id)).ok_or("unknown cash tier")?.pk,
                        Some(v) => &state.vault(*v)?.tiers.get(usize::from(p.denom_id)).ok_or("unknown tier")?.pk,
                    };
                    self.wallet.finish_note(*vault, &p.blinded, &sig, pk)?;
                    recovered += 1;
                }
            }
        }
        let still = self.wallet.notes_pending()?.len();
        Ok(json!({
            "spent": spent, "held_again": held, "still_spending": waiting,
            "signatures_recovered": recovered, "awaiting_signature": still,
        }))
    }

    /// New notes of `vault` (cash when `None`), saved before their blinded points leave.
    fn new_notes(&mut self, state: &State, vault: Option<u32>, outputs: &[(u8, u64)]) -> Result<Vec<[u8; G1_LEN]>, String> {
        let dst = match vault {
            None => pool::cash_dst(&state.network, &self.contract),
            Some(v) => pool::note_dst(&state.network, &self.contract, v),
        };
        let mut blinded = Vec::new();
        for (tier, count) in outputs {
            for _ in 0..*count {
                let note = PendingToken::new(&mut OsRng, *tier, dst.as_bytes()).map_err(|e| e.to_string())?;
                self.wallet.save_note_pending(vault, &note)?;
                blinded.push(note.blinded);
            }
        }
        Ok(blinded)
    }

    /// Keeps the notes the agent signed, each checked under its tier's key read from the contract.
    fn finish(&mut self, state: &State, vault: Option<u32>, blinded: &[[u8; G1_LEN]], sigs: &[[u8; G1_LEN]]) -> Result<Vec<[u8; 32]>, String> {
        if sigs.len() != blinded.len() {
            return Err("the agent returned a wrong number of signatures".into());
        }
        let pending = self.wallet.notes_pending()?;
        let mut nfs = Vec::new();
        for (b, s) in blinded.iter().zip(sigs) {
            let tier = pending.iter().find(|(v, p)| *v == vault && &p.blinded == b).map(|(_, p)| p.denom_id).ok_or("lost a pending note")?;
            let pk = match vault {
                None => &state.cash.get(usize::from(tier)).ok_or("unknown cash tier")?.pk,
                Some(v) => &state.vault(v)?.tiers.get(usize::from(tier)).ok_or("unknown tier")?.pk,
            };
            nfs.push(self.wallet.finish_note(vault, b, s, pk)?.nf);
        }
        Ok(nfs)
    }

    fn issue(&mut self, state: &State, account: &str, tier: u8, count: u64) -> Result<usize, String> {
        let blinded = self.new_notes(state, None, &[(tier, count)])?;
        let sigs = self.agent.issue_cash(account, tier, &blinded).map_err(|e| e.message())?;
        Ok(self.finish(state, None, &blinded, &sigs)?.len())
    }

    fn note(&self, nf: &[u8; 32]) -> Result<PoolNote, String> {
        self.wallet.notes().into_iter().find(|n| &n.nf == nf && n.status == NoteStatus::Held).ok_or_else(|| "a planned note is no longer held".into())
    }

    /// Runs one agent call that spends `n`: the note is marked spending (with its signature's deadline) before the
    /// signature leaves; spent on success; held again only when the call was certainly refused. When the outcome
    /// is unknown the note stays spending, and its new notes stay waiting for their signatures.
    fn spend<T>(
        &mut self,
        n: &PoolNote,
        digest: impl Fn(u64) -> [u8; 32],
        call: impl FnOnce(&mut Self, &SignedNote) -> Result<T, AgentError>,
    ) -> Result<T, String> {
        let expires_at = self.now().saturating_add(SIGNATURE_LIFE_NS);
        let owner_sig = n.owner.sign(&digest(expires_at)).to_bytes();
        let note = signed_note(&n.token, owner_sig, expires_at);
        self.wallet.set_note_spending(&n.nf, expires_at)?;
        match call(self, &note) {
            Ok(v) => {
                self.wallet.set_note_status(&n.nf, NoteStatus::Spent)?;
                Ok(v)
            }
            Err(AgentError::Refused(e)) => {
                self.wallet.set_note_status(&n.nf, NoteStatus::Held)?;
                Err(e)
            }
            Err(e) => Err(e.message()),
        }
    }

    fn enter(&mut self, state: &State, nf: &[u8; 32], vault: u32, outputs: &[(u8, u64)]) -> Result<(), String> {
        let n = self.note(nf)?;
        let blinded = self.new_notes(state, Some(vault), outputs)?;
        let contract = self.contract.clone();
        let sigs = self.spend(
            &n,
            |exp| pool::enter_digest(&contract, &n.nf, vault, outputs, exp),
            |me, note| me.agent.enter(vault, note, outputs, &blinded),
        )?;
        self.finish(state, Some(vault), &blinded, &sigs)?;
        Ok(())
    }

    fn leave(&mut self, state: &State, nf: &[u8; 32], vault: u32, outputs: &[(u8, u64)]) -> Result<Vec<[u8; 32]>, String> {
        let n = self.note(nf)?;
        let blinded = self.new_notes(state, None, outputs)?;
        let contract = self.contract.clone();
        let sigs = self.spend(
            &n,
            |exp| pool::leave_digest(&contract, vault, &n.nf, outputs, exp),
            |me, note| me.agent.leave(vault, note, outputs, &blinded),
        )?;
        self.finish(state, None, &blinded, &sigs)
    }

    fn pay(&mut self, nf: &[u8; 32], to: &str) -> Result<(), String> {
        let n = self.note(nf)?;
        let contract = self.contract.clone();
        self.spend(&n, |exp| pool::cash_exit_digest(&contract, &n.nf, to, exp), |me, note| me.agent.pay_exit(note, to))
    }
}

fn signed_note(token: &Token, owner_sig: [u8; 64], expires_at: u64) -> SignedNote {
    SignedNote { tier: token.denom_id, pk: token.pk, nonce: token.nonce, sig: token.sig, owner_sig, expires_at }
}

fn notes_json(outputs: &[(u8, u64)], tiers: &[Tier]) -> Result<Value, String> {
    let list = outputs
        .iter()
        .map(|(t, c)| {
            let tier = tiers.get(usize::from(*t)).ok_or("unknown tier")?;
            Ok(json!({"tier": t, "count": c, "note_value": tier.size.to_string()}))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!(list))
}

/// `hex(SHA-256("ONA-POOL-PREPARE-V1" || 0 || network || 0 || contract || 0 || op || 0 || vault (u32 LE, u32::MAX for none) || amount || 0 || nonce))`.
fn prepared_id(network: &str, contract: &str, op: &str, vault: Option<u32>, amount: &str, nonce: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    for part in [b"ONA-POOL-PREPARE-V1".as_slice(), network.as_bytes(), contract.as_bytes(), op.as_bytes()] {
        h.update(part);
        h.update([0u8]);
    }
    h.update(vault.unwrap_or(u32::MAX).to_le_bytes());
    h.update(amount.as_bytes());
    h.update([0u8]);
    h.update(nonce);
    hex(&h.finalize())
}
