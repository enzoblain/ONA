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
//! (`issue_cash`, `enter`, `leave`, `pay_exit`) go through `PoolAgent`: `pool_agent::HttpAgent` when
//! `ONA_POOL_AGENT_URL` is set, otherwise `NoAgent`, which refuses them. Reading the portfolio reads the
//! configuration, the cash and every vault, whoever runs it, and sends nothing to the relay. With `ONA_TOR_SOCKS` set,
//! every RPC read and every agent call goes through Tor, each request on its own circuit (`tor::Network`).
//!
//! A deposit's `pool_execute` runs twice: the first call makes the cash notes and returns `sign_message`, the text the
//! user's own NEAR wallet signs (NEP-413 `signMessage`); the second call carries that signature
//! (`depositor_signature`), and the agent issues the cash only for it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use ona_token::{g2_from_raw, PendingToken, Token, G1_LEN, G2_LEN, G2_RAW_LEN};
use ona_wallet::{pool, NoteStatus, PoolNote, Wallet};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::tor::Network;

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
/// Allowance for this computer's clock running ahead of the chain's: a spending note is held again only this long
/// after its signature's deadline. A design margin.
pub const CLOCK_MARGIN_NS: u64 = 10 * 60_000_000_000;
/// How long a preparation can be executed, and keeps its notes reserved.
pub const PREPARATION_LIFE_NS: u64 = 5 * 60_000_000_000;
/// Deposit amounts the app recommends unless configured otherwise, in NEAR: common amounts hide better.
pub const DEFAULT_RECOMMENDED_NEAR: [u128; 3] = [100, 500, 2_000];

/// How long the owner's signature of an exit request stays valid: the contract accepts at most 30 days from filing;
/// a day less leaves room for this computer's clock and the time the wallet takes to send it.
pub const REQUEST_LIFE_NS: u64 = 29 * 24 * 3_600_000_000_000;
/// Attached to `request_exit`: the contract's 336 bytes of a request (its estimate) at 10^19 yoctoNEAR per byte, the
/// NEAR storage price as documented (not verified here). Given back when the request leaves the list, less 80 bytes.
pub const REQUEST_FEE: u128 = 336 * 10_000_000_000_000_000_000;

/// The commands this module answers. `pool_request_exit` and `pool_escape_exit` are `pool_prepare` with that `op`.
pub const COMMANDS: [&str; 8] = [
    "pool_portfolio", "pool_prepare", "pool_execute", "pool_recover", "pool_request_exit", "pool_escape_exit", "pool_privacy",
    "pool_info",
];

/// Read-only access to the pool contract.
pub trait PoolChain {
    fn view(&self, method: &str, args: Value) -> Result<Value, String>;

    /// Labels every reply, so figures from a fake chain cannot pass for real ones.
    fn mode(&self) -> &'static str;

    /// The final block (`height` = `None`) or the block at `height`, as `(height, hash)`. Needed only when a
    /// second endpoint is set.
    fn block(&self, _height: Option<u64>) -> Result<(u64, String), String> {
        Err("this endpoint cannot read blocks".into())
    }

    /// A view at the block with this hash. Needed only when a second endpoint is set.
    fn view_at(&self, _block_hash: &str, _method: &str, _args: Value) -> Result<Value, String> {
        Err("this endpoint cannot read at a given block".into())
    }
}

/// Most blocks the two endpoints' final blocks may be apart, as in `ona-server`'s cross-checked reads.
pub const MAX_HEIGHT_GAP: u64 = 20;

/// The pool read through a NEAR RPC endpoint, on final blocks. Each read makes its own client: through Tor, its own
/// circuit, so the endpoint cannot tie the reads of one recovery or of two operations to one circuit.
pub struct NearPool {
    url: String,
    pool: String,
    network: Network,
}

impl NearPool {
    /// Directly to `rpc_url`, unchecked (a local test node over plain http included).
    pub fn new(rpc_url: &str, pool: &str) -> Self {
        Self { url: rpc_url.into(), pool: pool.into(), network: Network::Direct }
    }

    /// `rpc_url` reached through `network`, checked for it: through Tor `https` to a host name or `http` to an onion
    /// service; directly `https`, or `http` to this machine, never an onion address.
    pub fn through(network: &Network, rpc_url: &str, pool: &str) -> Result<Self, String> {
        network.check(rpc_url)?;
        if !network.is_tor() {
            ona_near::check_rpc_url(rpc_url).map_err(|e| e.to_string())?;
        }
        Ok(Self { url: rpc_url.into(), pool: pool.into(), network: network.clone() })
    }

    /// Views sign nothing; the client only needs a key to exist.
    fn client(&self) -> Result<ona_near::Client, String> {
        let key = SigningKey::generate(&mut OsRng);
        match &self.network {
            Network::Direct => Ok(ona_near::Client::new(&self.url, key)),
            Network::Tor(proxy) => crate::tor::near_client(&self.url, key, proxy),
        }
    }

    /// Runs a read, again on a new client (through Tor, a new circuit) when it failed in transport: a Tor exit that
    /// refuses the endpoint ("general SOCKS server failure") or drops the connection. Reads change nothing, so trying
    /// again is safe. An answer from the endpoint (an error it returned) is not retried.
    fn read<T>(&self, mut f: impl FnMut(ona_near::Client) -> Result<T, String>) -> Result<T, String> {
        let mut last = String::new();
        for _ in 0..READ_ATTEMPTS {
            match f(self.client()?) {
                Ok(v) => return Ok(v),
                Err(e) if is_transport_error(&e) => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }
}

/// Reads of the pool tried at most this many times, each on its own circuit through Tor.
const READ_ATTEMPTS: usize = 4;

/// A failure to reach the endpoint at all (SOCKS, connection, timeout), as opposed to an answer from it.
fn is_transport_error(e: &str) -> bool {
    let e = e.to_lowercase();
    ["socks", "io:", "connection", "timed out", "timeout", "reset", "broken pipe", "eof"].iter().any(|k| e.contains(k))
}

impl PoolChain for NearPool {
    fn view(&self, method: &str, args: Value) -> Result<Value, String> {
        self.read(|c| c.view_final(&self.pool, method, args.clone()).map_err(|e| e.to_string()))
    }

    fn mode(&self) -> &'static str {
        crate::remote::REAL_MODE
    }

    fn block(&self, height: Option<u64>) -> Result<(u64, String), String> {
        let params = match height {
            None => json!({"finality": "final"}),
            Some(h) => json!({"block_id": h}),
        };
        let block = self.read(|c| c.post("block", params.clone()).map_err(|e| e.to_string()))?;
        let header = &block["header"];
        let height = header["height"].as_u64().ok_or("unexpected block reply")?;
        let hash = header["hash"].as_str().filter(|h| !h.is_empty()).ok_or("unexpected block reply")?;
        Ok((height, hash.to_string()))
    }

    fn view_at(&self, block_hash: &str, method: &str, args: Value) -> Result<Value, String> {
        let params = json!({
            "request_type": "call_function", "block_id": block_hash, "account_id": self.pool,
            "method_name": method, "args_base64": b64(args.to_string().as_bytes()),
        });
        let result = self.read(|c| c.post("query", params.clone()).map_err(|e| e.to_string()))?;
        if result["block_hash"].as_str() != Some(block_hash) {
            return Err(format!("RPC answered {method} for another block"));
        }
        let bytes: Vec<u8> = result["result"]
            .as_array()
            .ok_or_else(|| format!("view {method} failed"))?
            .iter()
            .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
            .collect::<Option<_>>()
            .ok_or_else(|| format!("view {method} returned bytes out of range"))?;
        serde_json::from_slice(&bytes).map_err(|_| format!("view {method} did not return JSON"))
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

/// The depositor's wallet signature over `issue_message`, in the NEP-413 form: its key (a full-access key of the
/// account), the signature and the nonce the wallet signed with. The recipient is the pool contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositorProof {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
    pub nonce: [u8; 32],
}

impl DepositorProof {
    pub fn public_key_text(&self) -> String {
        format!("ed25519:{}", bs58_encode(&self.public_key))
    }

    /// `{"public_key": "ed25519:<base58>", "signature": <base64>}`, with the nonce the wallet was given.
    fn parse(v: &Value, nonce: [u8; 32]) -> Result<Self, String> {
        use base64::Engine;
        let bad = || "depositor_signature needs public_key (ed25519:…) and signature (base64)".to_string();
        let key = v["public_key"].as_str().and_then(|k| k.strip_prefix("ed25519:")).ok_or_else(bad)?;
        let public_key = bs58_decode(key).and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
        let signature = v["signature"]
            .as_str()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(bad)?;
        Ok(Self { public_key, signature, nonce })
    }
}

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn bs58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = u32::from(b);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    std::iter::repeat_n(b'1', zeros).chain(digits.iter().rev().map(|d| BASE58[usize::from(*d)])).map(char::from).collect()
}

fn bs58_decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in text.bytes() {
        let mut carry = u32::try_from(BASE58.iter().position(|x| *x == c)?).ok()?;
        for b in bytes.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = text.bytes().take_while(|c| *c == b'1').count();
    Some(std::iter::repeat_n(0u8, zeros).chain(bytes.into_iter().rev()).collect())
}

/// The exact text the depositor's wallet signs (NEP-413, recipient: the pool) to have these cash notes issued:
/// the pool, the account, and `hex(SHA-256((tier || blinded point)*))` over the notes in order. The agent builds the
/// same text from the request (`ona-agent` `nep413::issue_message`).
pub fn issue_message(pool: &str, account: &str, notes: &[(u8, [u8; G1_LEN])]) -> String {
    let mut h = Sha256::new();
    for (tier, blinded) in notes {
        h.update([*tier]);
        h.update(blinded);
    }
    format!("ONA pool cash issue v1\npool: {pool}\naccount: {account}\nnotes: {}", hex(&h.finalize()))
}

/// The calls only the agent may make, and the blind signatures it returns, one per blinded point in order.
/// `issue_cash` carries the depositor's wallet signature: the agent issues cash only to the account that signed,
/// and the contract refuses more than its deposits.
pub trait PoolAgent {
    fn issue_cash(&mut self, account: &str, notes: &[(u8, [u8; G1_LEN])], proof: &DepositorProof) -> Result<Vec<[u8; G1_LEN]>, AgentError>;
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
    /// False when no agent exists at all, so nothing was ever sent to one.
    fn connected(&self) -> bool {
        true
    }
}

/// No transport to the agent exists yet: every agent call is refused before anything is sent.
pub struct NoAgent;

const NO_AGENT: &str = "no connection to the pool agent yet";

impl PoolAgent for NoAgent {
    fn issue_cash(&mut self, _: &str, _: &[(u8, [u8; G1_LEN])], _: &DepositorProof) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
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
    fn connected(&self) -> bool {
        false
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

/// `*total += value`, refusing an overflow.
fn plus(total: &mut u128, value: u128) -> Result<(), String> {
    *total = total.checked_add(value).ok_or_else(overflow)?;
    Ok(())
}

/// `fee * count`, refusing an overflow.
fn times(fee: u128, count: usize) -> Result<u128, String> {
    fee.checked_mul(count as u128).ok_or_else(overflow)
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
    /// A held note (cash, or share of `vault`) the user's own wallet asks to exit to `to`, with `request_exit` or,
    /// once the contract has opened it, `escape_exit`: signed here, sent by the wallet.
    Exit { nf: [u8; 32], vault: Option<u32>, to: String, min_amount: u128, escape: bool },
}

struct Prepared {
    op: String,
    vault: Option<u32>,
    amount: String,
    nonce: [u8; 32],
    steps: Vec<Step>,
    created_at: u64,
    reserved: Vec<[u8; 32]>,
    /// A deposit's cash notes, made by its first `pool_execute`, and the nonce its wallet signature uses.
    issue: Option<(Vec<(u8, [u8; G1_LEN])>, [u8; 32])>,
}

pub struct PoolClient {
    wallet: Wallet,
    chain: Box<dyn PoolChain>,
    /// A second RPC endpoint, run by another operator, that `pool_recover` must agree with.
    second: Option<Box<dyn PoolChain>>,
    agent: Box<dyn PoolAgent>,
    contract: String,
    clock: Box<dyn Fn() -> u64>,
    recommended: Vec<u128>,
    prepared: BTreeMap<String, Prepared>,
    /// How long an owner signature stays valid, `SIGNATURE_LIFE_NS` unless a test shortens it.
    signature_life_ns: u64,
}

/// Reads a 32-byte key written as 64 hex characters, in a file only its owner can read.
pub fn load_wallet_key(path: &Path) -> Result<[u8; 32], String> {
    let meta = fs::metadata(path).map_err(|_| "cannot read the wallet key file".to_string())?;
    if crate::private_fs::open_to_others(&meta) {
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
            second: None,
            agent,
            contract: contract.into(),
            clock: Box::new(system_clock),
            recommended: DEFAULT_RECOMMENDED_NEAR.iter().map(|n| n * NEAR).collect(),
            prepared: BTreeMap::new(),
            signature_life_ns: SIGNATURE_LIFE_NS,
        }
    }

    /// Replaces how long an owner signature stays valid (nanoseconds), for tests that move a node's clock: a note
    /// whose signature was never used is held again only once it expired. Between 15 minutes and `SIGNATURE_LIFE_NS`:
    /// the agent drops a queued operation whose signature expires within 10 minutes.
    pub fn with_signature_life(mut self, ns: u64) -> Self {
        self.signature_life_ns = ns.clamp(15 * 60_000_000_000, SIGNATURE_LIFE_NS);
        self
    }

    /// Replaces the clock (nanoseconds since 1970), for tests.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64>) -> Self {
        self.clock = clock;
        self
    }

    /// Adds a second RPC endpoint that `pool_recover`'s chain reads must agree with.
    pub fn with_second_chain(mut self, chain: Box<dyn PoolChain>) -> Self {
        self.second = Some(chain);
        self
    }

    /// Replaces the recommended deposit amounts (yoctoNEAR).
    pub fn with_recommended(mut self, amounts: Vec<u128>) -> Self {
        self.recommended = amounts;
        self
    }

    /// `None` when `ONA_WALLET_FILE` is not set. Otherwise `ONA_WALLET_KEY_FILE`, `ONA_POOL` and `ONA_RPC_URL` are
    /// needed, and `ONA_POOL_RECOMMENDED_NEAR` may list the recommended deposits. The agent is reached at
    /// `ONA_POOL_AGENT_URL` when it is set; otherwise it is `NoAgent`, which refuses every agent call. Every RPC node and
    /// the agent are reached through `network` (`tor::Network::from_env`), their addresses checked for it. A variable
    /// that is not valid text is an error.
    pub fn from_env(network: &Network) -> Result<Option<Self>, String> {
        Self::from_lookup(
            |name| match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(_) => Err(format!("{name} is not valid text")),
            },
            network,
        )
    }

    /// Like `from_env`, with the settings read by name from `get` (the desktop apps read them from a file).
    pub fn from_lookup(get: impl Fn(&str) -> Result<Option<String>, String>, network: &Network) -> Result<Option<Self>, String> {
        let Some(file) = get("ONA_WALLET_FILE")? else {
            return Ok(None);
        };
        let need = |k: &str| get(k)?.ok_or_else(|| format!("{k} is not set"));
        let key = load_wallet_key(Path::new(&need("ONA_WALLET_KEY_FILE")?))?;
        let pool = need("ONA_POOL")?;
        let rpc = need("ONA_RPC_URL")?;
        let first = NearPool::through(network, &rpc, &pool).map_err(|e| format!("ONA_RPC_URL: {e}"))?;
        let recommended = match get("ONA_POOL_RECOMMENDED_NEAR")? {
            Some(text) => Some(parse_recommended(&text).map_err(|e| format!("ONA_POOL_RECOMMENDED_NEAR: {e}"))?),
            None => None,
        };
        let second = match get("ONA_RPC_URL_2")? {
            Some(url) => Some(NearPool::through(network, &url, &pool).map_err(|e| format!("ONA_RPC_URL_2: {e}"))?),
            None => None,
        };
        // Directly, the agent's address follows the RPC rule: https, or plain http to this machine only. Through Tor,
        // https to a host name or http to an onion service.
        let agent: Box<dyn PoolAgent> = match get("ONA_POOL_AGENT_URL")? {
            Some(url) => {
                if !network.is_tor() {
                    ona_near::check_rpc_url(&url).map_err(|e| format!("ONA_POOL_AGENT_URL: {e}"))?;
                }
                Box::new(crate::pool_agent::HttpAgent::through(network, &url).map_err(|e| format!("ONA_POOL_AGENT_URL: {e}"))?)
            }
            None => Box::new(NoAgent),
        };
        let wallet = Wallet::open(Path::new(&file), &key)?;
        let mut client = Self::new(wallet, Box::new(first), agent, &pool);
        if let Some(second) = second {
            client = client.with_second_chain(Box::new(second));
        }
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

    /// Drops preparations older than `PREPARATION_LIFE_NS`, freeing their notes. A deposit abandoned between its two calls
    /// also forgets the cash notes its first call made: no signature was asked for them.
    fn expire(&mut self) {
        let now = self.now();
        let (live, gone): (BTreeMap<_, _>, BTreeMap<_, _>) =
            std::mem::take(&mut self.prepared).into_iter().partition(|(_, p)| now < p.created_at.saturating_add(PREPARATION_LIFE_NS));
        self.prepared = live;
        for (_, p) in gone {
            if let Some((notes, _)) = p.issue {
                let blinded: Vec<[u8; G1_LEN]> = notes.iter().map(|n| n.1).collect();
                if let Err(e) = self.drop_pending(None, &blinded) {
                    eprintln!("cannot forget the notes of an abandoned deposit: {e}");
                }
            }
        }
    }

    /// Held notes of `vault` (cash when `None`) not reserved by a live preparation, with their value. A note ever named
    /// in an exit request is left out: the contract lets it leave only by an exit.
    fn available(&self, state: &State, vault: Option<u32>) -> Result<Vec<(PoolNote, u128)>, String> {
        self.candidates(state, vault, |me, n| n.status == NoteStatus::Held && me.wallet.requested(&n.nf).is_none())
    }

    /// The notes an exit request or an escape can take: held notes (a request whose signature expired can be filed
    /// again) and, for the escape, notes whose request is still live, which the contract pays first.
    fn exit_candidates(&self, state: &State, vault: Option<u32>, escape: bool) -> Result<Vec<(PoolNote, u128)>, String> {
        let now = self.now();
        self.candidates(state, vault, |me, n| {
            n.status == NoteStatus::Held || (escape && n.status == NoteStatus::Spending && me.live_request(&n.nf, now).is_some())
        })
    }

    fn candidates(&self, state: &State, vault: Option<u32>, keep: impl Fn(&Self, &PoolNote) -> bool) -> Result<Vec<(PoolNote, u128)>, String> {
        let reserved: BTreeSet<[u8; 32]> = self.prepared.values().flat_map(|p| p.reserved.iter().copied()).collect();
        self.wallet
            .notes()
            .into_iter()
            .filter(|n| n.vault == vault && !reserved.contains(&n.nf) && keep(self, n))
            .map(|n| state.note_value(&n).map(|v| (n, v)))
            .collect()
    }

    /// The account a note's request pays, while its signature is valid.
    fn live_request(&self, nf: &[u8; 32], now: u64) -> Option<String> {
        self.wallet.requested(nf).filter(|(_, until)| now <= *until).map(|(to, _)| to)
    }

    pub fn run(&mut self, cmd: &str, request: &Value) -> Result<Value, String> {
        self.expire();
        let mut reply = match cmd {
            "pool_portfolio" => self.portfolio(),
            "pool_prepare" => self.prepare(request),
            "pool_request_exit" | "pool_escape_exit" => {
                let mut request = request.clone();
                request["op"] = json!(if cmd == "pool_request_exit" { "request_exit" } else { "escape_exit" });
                self.prepare(&request)
            }
            "pool_execute" => self.execute(request),
            "pool_recover" => self.recover(),
            "pool_privacy" => self.privacy(request),
            "pool_info" => self.info(),
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

    /// What the pool offers, from the contract's public views and this client's settings, nothing about this wallet's
    /// notes: the network, the contract, the cash tiers and their hourly cap, each vault's kind (`adapter`) and the
    /// account it places into (`target`), its share price, note values, cap and state, the notes in circulation per
    /// tier, the smallest deposit and the recommended deposits. A field the contract does not publish is `null`.
    fn info(&self) -> Result<Value, String> {
        let state = self.state()?;
        let text = |v: &Value, key: &str| v[key].as_str().map(String::from);
        let live = |t: &Value| -> Option<u64> { Some(t["issued"].as_u64()?.saturating_sub(t["paid"].as_u64()?)) };
        let cash_view = self.chain.view("get_cash", json!({}))?;
        let cash_tiers: Vec<Value> = cash_view["tiers"]
            .as_array()
            .ok_or("cash view without tiers")?
            .iter()
            .enumerate()
            .map(|(t, view)| {
                let value = state.cash.get(t).map(|tier| tier.size.to_string());
                json!({"tier": t, "note_value": value, "live": live(view)})
            })
            .collect();
        let mut vaults = Vec::new();
        for (id, v) in state.vaults.iter().enumerate() {
            let view = self.chain.view("get_vault", json!({"vault_id": id}))?;
            let views = view["tiers"].as_array().cloned().unwrap_or_default();
            let mut tiers = Vec::new();
            for (t, tier) in v.tiers.iter().enumerate() {
                let value = tier.size.checked_mul(v.price).ok_or_else(overflow)?;
                tiers.push(json!({"tier": t, "note_shares": tier.size.to_string(), "note_value": value.to_string(),
                                  "live": views.get(t).and_then(live)}));
            }
            vaults.push(json!({
                "vault": id, "adapter": text(&view, "adapter"), "target": text(&view, "target"),
                "share_price": v.price.to_string(), "frozen": v.frozen, "hourly_cap": text(&view, "hourly_cap"),
                "tiers": tiers,
            }));
        }
        Ok(json!({
            "network": state.network,
            "contract": self.contract,
            "cash": {"tiers": cash_tiers, "hourly_cap": text(&cash_view, "hourly_cap")},
            "vaults": vaults,
            "min_deposit": MIN_DEPOSIT.to_string(),
            "recommended": self.recommended.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        }))
    }

    /// The privacy figures of the side panel (docs/desktop/privacy.md), from the contract's public counts only.
    ///
    /// The measure: a note hides among the notes **still in circulation** of the same value at the same place (the cash,
    /// or one vault): `issued - paid` of its tier, as `get_cash` and `get_vault` publish them. An observer of the chain
    /// cannot tell it from the others of that set. The wallet's figure is its smallest set, its weakest note. For each
    /// open vault, `if_entered` gives the smallest set the notes of an entry would join (the held cash, or `amount`),
    /// and `gain` the difference from the cash notes spent: the "+ X" next to a recommendation.
    ///
    /// These are upper bounds: an observer who also uses deposit and exit times, amounts and batches can rule some
    /// notes out (`ona-crowd` measures that on simulated crowds). Without ONA, a deposit straight into staking is tied
    /// to its account: a set of one, `without_ona`.
    fn privacy(&self, request: &Value) -> Result<Value, String> {
        let state = self.state()?;
        let live_counts = |view: &Value| -> Result<Vec<u64>, String> {
            view["tiers"]
                .as_array()
                .ok_or("pool view without tiers")?
                .iter()
                .map(|t| {
                    let issued = t["issued"].as_u64().ok_or("pool view without issued")?;
                    let paid = t["paid"].as_u64().ok_or("pool view without paid")?;
                    Ok(issued.saturating_sub(paid))
                })
                .collect()
        };
        let cash_live = live_counts(&self.chain.view("get_cash", json!({}))?)?;
        let vault_live = (0..state.vaults.len())
            .map(|id| self.chain.view("get_vault", json!({"vault_id": id})).and_then(|v| live_counts(&v)))
            .collect::<Result<Vec<_>, _>>()?;
        let live = |vault: Option<u32>, tier: u8| -> u64 {
            let counts = match vault {
                None => Some(&cash_live),
                Some(v) => vault_live.get(v as usize),
            };
            counts.and_then(|c| c.get(usize::from(tier))).copied().unwrap_or(0)
        };

        let held: Vec<PoolNote> = self.wallet.notes().into_iter().filter(|n| n.status == NoteStatus::Held).collect();
        let notes: Vec<Value> = held
            .iter()
            .map(|n| json!({"vault": n.vault, "tier": n.token.denom_id, "set": live(n.vault, n.token.denom_id)}))
            .collect();
        let smallest = |sets: &mut dyn Iterator<Item = u64>| sets.min();
        let wallet_min = smallest(&mut held.iter().map(|n| live(n.vault, n.token.denom_id)));
        let cash_held: Vec<&PoolNote> = held.iter().filter(|n| n.vault.is_none()).collect();
        let cash_min = smallest(&mut cash_held.iter().map(|n| live(None, n.token.denom_id)));

        // What an entry would join: the held cash by default, or `amount` (yoctoNEAR).
        let amount = match request["amount"].as_str() {
            Some(a) => a.parse::<u128>().map_err(|_| "amount must be yoctoNEAR digits".to_string())?,
            None => {
                let mut total = 0u128;
                for n in &cash_held {
                    let tier = state.cash.get(usize::from(n.token.denom_id)).ok_or("a cash note of an unknown tier")?;
                    plus(&mut total, tier.size)?;
                }
                total
            }
        };
        let mut vaults = Vec::new();
        for (id, v) in state.vaults.iter().enumerate() {
            let id = id as u32;
            let tiers: Vec<Value> = (0..v.tiers.len())
                .map(|t| json!({"tier": t, "note_shares": v.tiers[t].size.to_string(), "live": live(Some(id), t as u8)}))
                .collect();
            let mut entry = json!({"vault": id, "frozen": v.frozen, "tiers": tiers});
            if !v.frozen && amount > 0 {
                let (outputs, _) = split(amount, &v.tiers, v.price_up)?;
                // A new note joins its tier's set: the set it hides in counts it too.
                let after = outputs.iter().map(|(t, _)| live(Some(id), *t).saturating_add(1)).min();
                entry["if_entered"] = json!(after);
                if let (Some(after), Some(before)) = (after, cash_min) {
                    entry["gain"] = json!(after as i128 - before as i128);
                }
            }
            vaults.push(entry);
        }
        Ok(json!({
            "measure": "notes in circulation of the same value at the same place (upper bound)",
            "wallet": {"smallest_set": wallet_min, "notes": notes},
            "cash": {"smallest_set": cash_min,
                     "tiers": cash_live.iter().enumerate().map(|(t, n)| json!({"tier": t, "live": n})).collect::<Vec<_>>()},
            "vaults": vaults,
            "amount": amount.to_string(),
            "without_ona": 1,
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
                    plus(&mut cost, budget - left)?;
                    plus(&mut rest, left)?;
                    reserved.push(n.nf);
                    steps.push(Step::Enter { nf: n.nf, vault: id, outputs });
                }
                summary["vault"] = json!(id);
                summary["shares_value"] = json!(cost.to_string());
                summary["left_in_cash"] = json!(rest.to_string());
                summary["fees"] = json!({"storage": times(NOTE_STORAGE_FEE, chosen.len())?.to_string()});
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
                    plus(&mut fees, NOTE_STORAGE_FEE)?;
                    plus(&mut rest, left)?;
                    plus(&mut cash_out, budget - left)?;
                    let mut then_enter = None;
                    if let Some(to) = to_vault {
                        let b = state.vault(to)?;
                        if b.frozen {
                            return Err("the destination vault is frozen".into());
                        }
                        let mut plans = Vec::new();
                        for (tier, count) in &outputs {
                            for _ in 0..*count {
                                let cash = state.cash.get(usize::from(*tier)).ok_or("unknown cash tier")?.size;
                                let budget = cash.checked_sub(NOTE_STORAGE_FEE).ok_or("a cash note is worth less than its fee")?;
                                let (shares, left) = split(budget, &b.tiers, b.price_up)?;
                                plus(&mut fees, NOTE_STORAGE_FEE)?;
                                plus(&mut rest, left)?;
                                plus(&mut new_shares, budget - left)?;
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
                summary["fees"] = json!({"storage": times(EXIT_STORAGE_FEE, chosen.len())?.to_string()});
                reserved = chosen.iter().map(|(n, _)| n.nf).collect();
                (None, chosen.iter().map(|(n, _)| Step::Pay { nf: n.nf, to: to.clone() }).collect())
            }
            "request_exit" | "escape_exit" => {
                let escape = op == "escape_exit";
                let to = account("to")?;
                let vault = if request.get("from").is_some_and(|v| !v.is_null()) { Some(vault_arg("from")?) } else { None };
                let min_amount: u128 = match request.get("min_amount").and_then(Value::as_str) {
                    Some(m) => m.parse().map_err(|_| "min_amount must be yoctoNEAR digits".to_string())?,
                    None => 0,
                };
                if vault.is_none() && min_amount != 0 {
                    return Err("min_amount applies to share notes only: a cash note is worth its value".into());
                }
                if escape {
                    let open = match vault {
                        Some(id) => self.chain.view("get_vault", json!({"vault_id": id}))?["open"].as_bool(),
                        None => self.chain.view("get_cash", json!({}))?["open"].as_bool(),
                    };
                    if open != Some(true) {
                        return Err("the escape is not open for these notes: file an exit request first (pool_request_exit)".into());
                    }
                }
                let chosen = select(self.exit_candidates(&state, vault, escape)?, &amount)?;
                let now = self.now();
                if let Some(other) = chosen.iter().filter_map(|(n, _)| self.live_request(&n.nf, now)).find(|r| *r != to) {
                    return Err(format!("a chosen note's request pays {other}: the escape pays the same account"));
                }
                let (mut paid, mut received) = (0u128, 0u128);
                for (_, value) in &chosen {
                    let payout = value.checked_sub(EXIT_STORAGE_FEE).ok_or("a note is worth less than its exit fee")?;
                    if payout < min_amount {
                        return Err("a note would pay less than min_amount at the current price".into());
                    }
                    plus(&mut paid, *value)?;
                    plus(&mut received, payout)?;
                }
                let holder = self.chain.view("get_holder", json!({"account": to}))?;
                let limit = u128_field(&holder, "exit_limit")?;
                if paid > limit {
                    return Err(format!("over this account's exit limit ({limit} yoctoNEAR)"));
                }
                summary["to"] = json!(to);
                summary["received"] = json!(received.to_string());
                summary["exit_limit"] = json!(limit.to_string());
                let mut fees = json!({"storage": times(EXIT_STORAGE_FEE, chosen.len())?.to_string()});
                if !escape {
                    fees["request_deposit"] = json!(times(REQUEST_FEE, chosen.len())?.to_string());
                    fees["request_deposit_back"] = json!("when the request leaves the list, less 80 bytes per note");
                }
                summary["fees"] = fees;
                let mut warnings = vec!["the account named here is shown with the exit".to_string()];
                if let Some(id) = vault {
                    summary["from"] = json!(id);
                    summary["min_amount"] = json!(min_amount.to_string());
                    warnings.push("a share note's exit shows its vault".into());
                }
                if escape {
                    warnings.push("while the agent is active, only notes with a listed exit request leave by the escape".into());
                } else {
                    warnings.push("a note named in a request can afterwards only leave by an exit".into());
                }
                summary["warnings"] = json!(warnings);
                reserved = chosen.iter().map(|(n, _)| n.nf).collect();
                let steps = chosen.iter().map(|(n, _)| Step::Exit { nf: n.nf, vault, to: to.clone(), min_amount, escape }).collect();
                (vault, steps)
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
        self.prepared.insert(id.clone(), Prepared { op, vault, amount, nonce, steps, created_at, reserved, issue: None });
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
        if let Some(Step::Issue { account, outputs }) = prepared.steps.first().cloned() {
            return self.execute_deposit(&state, id, prepared, &account, &outputs, request);
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

    /// First call: makes the cash notes (saved before anything leaves) and returns the text the depositor's wallet must
    /// sign; the preparation stays usable until it expires. Second call, with `depositor_signature`: the agent issues
    /// the cash for that signature.
    fn execute_deposit(
        &mut self,
        state: &State,
        id: &str,
        mut prepared: Prepared,
        account: &str,
        outputs: &[(u8, u64)],
        request: &Value,
    ) -> Result<Value, String> {
        use base64::Engine;
        let Some((notes, nonce)) = prepared.issue.clone() else {
            let mut notes = Vec::new();
            for (tier, count) in outputs {
                for b in self.new_notes(state, None, &[(*tier, *count)])? {
                    notes.push((*tier, b));
                }
            }
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            let message = issue_message(&self.contract, account, &notes);
            prepared.issue = Some((notes, nonce));
            self.prepared.insert(id.to_string(), prepared);
            return Ok(json!({
                "executed": "deposit", "complete": false,
                "sign_message": {
                    "message": message, "recipient": self.contract,
                    "nonce": base64::engine::general_purpose::STANDARD.encode(nonce),
                },
                "next": "sign sign_message with the depositing account's wallet (NEP-413), then call pool_execute again with depositor_signature",
            }));
        };
        let Some(signature) = request.get("depositor_signature") else {
            self.prepared.insert(id.to_string(), prepared);
            return Err("missing field depositor_signature: sign sign_message with the depositing account's wallet first".into());
        };
        let proof = DepositorProof::parse(signature, nonce)?;
        let blinded: Vec<[u8; G1_LEN]> = notes.iter().map(|n| n.1).collect();
        let sigs = match self.agent.issue_cash(account, &notes, &proof) {
            Ok(sigs) => sigs,
            Err(AgentError::Refused(e)) => {
                // Some tiers may have been issued before the refusal: keep what the agent signed, forget the rest.
                // Without its answer nothing is forgotten: `pool_recover` asks again later.
                let signed = match self.agent.signatures(&blinded) {
                    Ok(signed) if signed.len() == blinded.len() => signed,
                    // No agent at all: nothing was sent, nothing can have been signed.
                    _ if !self.agent.connected() => vec![None; blinded.len()],
                    Ok(_) => return Err(format!("{e} (the agent's list of signatures has the wrong length: run pool_recover later)")),
                    Err(asked) => return Err(format!("{e} (cannot ask the agent which notes it signed: {}; run pool_recover later)", asked.message())),
                };
                let mut kept = 0;
                for (b, s) in blinded.iter().zip(signed.iter()) {
                    match s {
                        Some(sig) => kept += self.finish(state, None, &[*b], &[*sig])?.len(),
                        None => self.drop_pending(None, &[*b])?,
                    }
                }
                return Err(if kept == 0 { e } else { format!("{e} ({kept} cash notes were issued before the refusal and are kept)") });
            }
            Err(e) => return Err(e.message()),
        };
        let issued = self.finish(state, None, &blinded, &sigs)?.len();
        Ok(json!({"executed": "deposit", "complete": true, "steps": [{"issued_cash": issued}]}))
    }

    fn run_steps(&mut self, state: &State, steps: &[Step], done: &mut Vec<Value>) -> Result<(), String> {
        for step in steps {
            match step {
                // Handled by `execute_deposit`.
                Step::Issue { .. } => return Err("a deposit runs through execute_deposit".into()),
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
                Step::Exit { nf, vault, to, min_amount, escape } => {
                    let call = self.exit_call(nf, *vault, to, *min_amount, *escape)?;
                    done.push(json!({"wallet_call": call}));
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
        let spending: Vec<PoolNote> = self.wallet.notes().into_iter().filter(|n| n.status == NoteStatus::Spending).collect();
        let block = if spending.is_empty() { None } else { self.agreed_block()? };
        for n in spending {
            if self.is_spent(&n.nf, block.as_deref())? {
                self.wallet.set_note_status(&n.nf, NoteStatus::Spent)?;
                spent += 1;
            } else if self.wallet.spending_until(&n.nf).is_some_and(|until| now > until.saturating_add(CLOCK_MARGIN_NS)) {
                self.wallet.set_note_status(&n.nf, NoteStatus::Held)?;
                held += 1;
            } else {
                waiting += 1;
            }
        }
        let pending = self.wallet.notes_pending()?;
        let mut recovered = 0;
        let mut agent_error = None;
        if !pending.is_empty() {
            let blinded: Vec<[u8; G1_LEN]> = pending.iter().map(|(_, p)| p.blinded).collect();
            match self.agent.signatures(&blinded) {
                // Without the agent, what the chain told is still reported, with what waits.
                Err(e) => agent_error = Some(e.message()),
                Ok(sigs) if sigs.len() != blinded.len() => agent_error = Some("the agent returned a wrong number of signatures".into()),
                Ok(sigs) => {
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
            }
        }
        let still: Vec<Value> = self
            .wallet
            .notes_pending()?
            .iter()
            .map(|(vault, p)| json!({"vault": vault, "tier": p.denom_id}))
            .collect();
        let mut reply = json!({
            "spent": spent, "held_again": held, "still_spending": waiting,
            "signatures_recovered": recovered, "awaiting_signature": still.len(), "waiting": still,
        });
        if let Some(e) = agent_error {
            reply["agent_error"] = json!(e);
        }
        Ok(reply)
    }

    /// Whether the contract has spent this nullifier, read from both RPC endpoints when a second one is set:
    /// a single endpoint could hide a spend or invent one.
    fn is_spent(&self, nf: &[u8; 32], block: Option<&str>) -> Result<bool, String> {
        let args = json!({"nf": b64(nf)});
        let read = |chain: &dyn PoolChain| -> Result<bool, String> {
            let answer = match block {
                Some(hash) => chain.view_at(hash, "is_spent", args.clone())?,
                None => chain.view("is_spent", args.clone())?,
            };
            answer.as_bool().ok_or_else(|| "is_spent did not answer a boolean".into())
        };
        let first = read(self.chain.as_ref())?;
        if let Some(second) = &self.second {
            if read(second.as_ref())? != first {
                return Err("the two RPC endpoints disagree on a note: try again later".into());
            }
        }
        Ok(first)
    }

    /// With a second endpoint: the lower of the two final blocks, checked by height on the other endpoint (same
    /// hash), the two final heights at most `MAX_HEIGHT_GAP` apart. Every read of one recovery is made there.
    fn agreed_block(&self) -> Result<Option<String>, String> {
        let Some(second) = &self.second else {
            return Ok(None);
        };
        let a = self.chain.block(None)?;
        let b = second.block(None)?;
        let gap = a.0.abs_diff(b.0);
        if gap > MAX_HEIGHT_GAP {
            return Err(format!("the two RPC endpoints are {gap} blocks apart, more than {MAX_HEIGHT_GAP}"));
        }
        let (low, seen) = if a.0 <= b.0 { (a.clone(), second.block(Some(a.0))?) } else { (b.clone(), self.chain.block(Some(b.0))?) };
        if seen != low {
            return Err("the two RPC endpoints disagree on a final block".into());
        }
        Ok(Some(low.1))
    }

    /// Forgets the new notes of an operation certainly refused: no signature can come for them.
    fn drop_pending(&mut self, vault: Option<u32>, blinded: &[[u8; G1_LEN]]) -> Result<(), String> {
        for b in blinded {
            self.wallet.drop_note_pending(vault, b)?;
        }
        Ok(())
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
        new: Option<(Option<u32>, &[[u8; G1_LEN]])>,
    ) -> Result<T, String> {
        let expires_at = self.now().saturating_add(self.signature_life_ns);
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
                if let Some((vault, blinded)) = new {
                    self.drop_pending(vault, blinded)?;
                }
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
            Some((Some(vault), &blinded)),
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
            Some((None, &blinded)),
        )?;
        self.finish(state, None, &blinded, &sigs)
    }

    fn pay(&mut self, nf: &[u8; 32], to: &str) -> Result<(), String> {
        let n = self.note(nf)?;
        let contract = self.contract.clone();
        self.spend(&n, |exp| pool::cash_exit_digest(&contract, &n.nf, to, exp), |me, note| me.agent.pay_exit(note, to), None)
    }
}

impl PoolClient {
    /// Signs one note's exit as the contract checks it (CASH-EXIT-V1 for a cash note, EXIT-V2 for a share note) and
    /// marks the note spending until the signature's deadline, before the call leaves. The call is for the user's own
    /// wallet to send; `pool_recover` then finds the note spent once paid, or holds it again after the deadline.
    fn exit_call(&mut self, nf: &[u8; 32], vault: Option<u32>, to: &str, min_amount: u128, escape: bool) -> Result<Value, String> {
        let now = self.now();
        // A note whose request is live is already spending, until that request's deadline: the escape leaves it so.
        let requested = escape && self.live_request(nf, now).is_some();
        let n = if requested {
            self.wallet.notes().into_iter().find(|n| &n.nf == nf && n.status == NoteStatus::Spending).ok_or("a planned note is no longer spending")?
        } else {
            self.note(nf)?
        };
        let expires_at = now.saturating_add(if escape { self.signature_life_ns } else { REQUEST_LIFE_NS });
        let digest = match vault {
            None => pool::cash_exit_digest(&self.contract, &n.nf, to, expires_at),
            Some(v) => pool::share_exit_digest(&self.contract, v, &n.nf, to, min_amount, expires_at),
        };
        let note = signed_note(&n.token, n.owner.sign(&digest).to_bytes(), expires_at);
        let mut args = note.contract_args();
        args["vault_id"] = json!(vault);
        args["to"] = json!(to);
        args["min_amount"] = json!(min_amount.to_string());
        if !requested {
            self.wallet.set_note_spending(&n.nf, expires_at)?;
        }
        if !escape {
            self.wallet.set_note_requested(&n.nf, to, expires_at)?;
        }
        Ok(json!({
            "receiver": self.contract,
            "method": if escape { "escape_exit" } else { "request_exit" },
            "args": args,
            "attached": if escape { "0".to_string() } else { REQUEST_FEE.to_string() },
        }))
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

#[cfg(test)]
mod read_tests {
    use super::*;

    #[test]
    fn only_failures_to_reach_the_endpoint_are_tried_again() {
        // Seen through Tor on 14/11/2026.
        assert!(is_transport_error("RPC request failed: io: general SOCKS server failure"));
        assert!(is_transport_error("RPC request failed: Connection reset by peer"));
        assert!(is_transport_error("timed out reading response"));
        assert!(!is_transport_error("RPC request failed: http status: 429"), "an answer from the endpoint");
        assert!(!is_transport_error("view get_vault failed: no such vault"));
    }
}
