//! `ona-server`: the relay. It exchanges an on-chain credit for anonymous request tokens, and
//! passes encrypted model calls against those tokens (`gateway`). `Relay::chat` serves a local fake
//! model for tests and the mock relay: its replies are labelled `mode: mock`.
//!
//! The relay is not trusted with content. An honest relay forwards only ciphertext, but it sits
//! between the client and the model, and encryption version 2 lets it replace the client key: see
//! `gateway`. Version 3 is meant to prevent that.
//!
//! Not done yet: fixed-size batches padded with the relay's own tokens, Tor, and the enclave.

pub mod crossrpc;
pub mod gateway;
pub mod http;
pub mod keyfile;
pub mod mock;
pub mod near;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use ona_token::{
    claim_digest_until, g1_to_raw, hash_to_g1, sign_blinded, verify, verify_digest, verify_token, SecretKey,
    Token, G1_LEN, G2_LEN,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const MODE: &str = "mock";
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
/// The contract refuses more than 28 claims per call (`ona-mint` `MAX_CLAIM`).
pub const MAX_BATCH: usize = 28;
const HOUR_NS: u64 = 3_600_000_000_000;
/// Longest validity the contract accepts for a claim signature (`ona-mint` `MAX_SIGNATURE_VALIDITY_NS`).
pub const MAX_CLAIM_VALIDITY_NS: u64 = 7 * 24 * HOUR_NS;
/// A claim signature must stay valid at least this long when the exchange is accepted, so that a batch
/// can carry it to the chain.
pub const MIN_CLAIM_VALIDITY_NS: u64 = HOUR_NS / 2;
/// A pending claim this close to its expiry is not sent any more: it could not land in time.
pub const CLAIM_LANDING_MARGIN_NS: u64 = 5 * 60 * 1_000_000_000;

/// Time on this machine, in nanoseconds. The contract checks expiry against block time, so the margins
/// above absorb a clock a few minutes off.
pub fn system_time_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;
const REQUEST_TOKEN_LEN: usize = 32 + G1_LEN;
/// The journal is rewritten once this many lines are obsolete, and at least as many as are live.
const COMPACT_MIN_DEAD_LINES: usize = 64;
/// First line of every store file.
const STORE_FORMAT: &str = "ona-relay-store-v1";

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Lowercase hexadecimal only, so that one value has one spelling.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// What the credit's owner signs, besides the claim, to fix the blinded points of an exchange:
/// someone who sees the request cannot swap in their own points and take the request tokens.
pub fn exchange_digest(mint: &str, relay: &str, nf: &[u8; 32], blinded: &[[u8; G1_LEN]]) -> [u8; 32] {
    let mut points = Sha256::new();
    for point in blinded {
        points.update(point);
    }
    let mut h = Sha256::new();
    h.update(b"ONA-EXCHANGE-V1");
    h.update(Sha256::digest(mint.as_bytes()));
    h.update(Sha256::digest(relay.as_bytes()));
    h.update(nf);
    h.update(points.finalize());
    h.finalize().into()
}

/// Ties a store file to one request key: a store made for another key, or none at all, is refused.
pub fn store_binding(request_pk: &[u8]) -> String {
    to_hex(&Sha256::digest(request_pk))
}

pub fn request_dst(relay: &str) -> Vec<u8> {
    format!("ONA-RELAY-V1:{relay}:BLS12381G1_XMD:SHA-256_SSWU_RO_").into_bytes()
}

/// Where a credit stands. Written durably before each step that cannot be undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeState {
    Pending { blinded_hash: String, token: String, owner_sig: String, expires_at: u64, blinded: Vec<String> },
    /// Sent to the chain. After a crash, only the chain can say what happened.
    Submitted { blinded_hash: String, token: String, owner_sig: String, expires_at: u64, blinded: Vec<String> },
    Done { blinded_hash: String, signatures: Vec<String> },
    Refused,
    /// The claim signature expired, by the chain's own clock, before the claim was seen on chain. The
    /// points are kept: if a claim sent earlier lands after all, a new request for the credit finds it
    /// claimed by this relay and gets these signatures. Otherwise the owner may exchange it again.
    Expired { blinded_hash: String, blinded: Vec<String> },
}

pub trait Store {
    fn get(&self, nf: &str) -> Option<ExchangeState>;
    fn put(&mut self, nf: &str, state: ExchangeState) -> Result<(), String>;
    fn unfinished(&self) -> Vec<(String, ExchangeState)>;
    /// Records a request token. Returns false if it was already used.
    fn use_request_token(&mut self, x: &str) -> Result<bool, String>;
    fn is_request_token_used(&self, x: &str) -> bool;
    /// Makes a used token usable again, for a call that certainly was not billed.
    fn release_request_token(&mut self, x: &str) -> Result<(), String>;
}

#[derive(Default)]
pub struct MemoryStore {
    exchanges: BTreeMap<String, ExchangeState>,
    used: BTreeSet<String>,
}

impl Store for MemoryStore {
    fn get(&self, nf: &str) -> Option<ExchangeState> {
        self.exchanges.get(nf).cloned()
    }
    fn put(&mut self, nf: &str, state: ExchangeState) -> Result<(), String> {
        self.exchanges.insert(nf.to_string(), state);
        Ok(())
    }
    fn unfinished(&self) -> Vec<(String, ExchangeState)> {
        self.exchanges
            .iter()
            .filter(|(_, s)| matches!(s, ExchangeState::Pending { .. } | ExchangeState::Submitted { .. }))
            .map(|(k, s)| (k.clone(), s.clone()))
            .collect()
    }
    fn use_request_token(&mut self, x: &str) -> Result<bool, String> {
        Ok(self.used.insert(x.to_string()))
    }
    fn is_request_token_used(&self, x: &str) -> bool {
        self.used.contains(x)
    }
    fn release_request_token(&mut self, x: &str) -> Result<(), String> {
        self.used.remove(x);
        Ok(())
    }
}

fn state_to_json(state: &ExchangeState) -> Value {
    match state {
        ExchangeState::Pending { blinded_hash, token, owner_sig, expires_at, blinded } => {
            json!({"s":"pending","h":blinded_hash,"t":token,"o":owner_sig,"e":expires_at.to_string(),"b":blinded})
        }
        ExchangeState::Submitted { blinded_hash, token, owner_sig, expires_at, blinded } => {
            json!({"s":"submitted","h":blinded_hash,"t":token,"o":owner_sig,"e":expires_at.to_string(),"b":blinded})
        }
        ExchangeState::Done { blinded_hash, signatures } => {
            json!({"s":"done","h":blinded_hash,"g":signatures})
        }
        ExchangeState::Refused => json!({"s":"refused"}),
        ExchangeState::Expired { blinded_hash, blinded } => json!({"s":"expired","h":blinded_hash,"b":blinded}),
    }
}

fn state_from_json(v: &Value) -> Option<ExchangeState> {
    let text = |k: &str| v[k].as_str().map(String::from);
    let number = |k: &str| v[k].as_str().and_then(|n| n.parse::<u64>().ok());
    let list = |k: &str| -> Option<Vec<String>> {
        v[k].as_array()?.iter().map(|x| x.as_str().map(String::from)).collect()
    };
    match v["s"].as_str()? {
        "pending" => Some(ExchangeState::Pending {
            blinded_hash: text("h")?,
            token: text("t")?,
            owner_sig: text("o")?,
            expires_at: number("e")?,
            blinded: list("b")?,
        }),
        "submitted" => Some(ExchangeState::Submitted {
            blinded_hash: text("h")?,
            token: text("t")?,
            owner_sig: text("o")?,
            expires_at: number("e")?,
            blinded: list("b")?,
        }),
        "done" => Some(ExchangeState::Done { blinded_hash: text("h")?, signatures: list("g")? }),
        "refused" => Some(ExchangeState::Refused),
        "expired" => Some(ExchangeState::Expired { blinded_hash: text("h")?, blinded: list("b")? }),
        _ => None,
    }
}

fn exchange_line(nf: &str, state: &ExchangeState) -> Value {
    json!({"nf": nf, "state": state_to_json(state)})
}

fn push_line(out: &mut Vec<u8>, line: &Value) {
    out.extend_from_slice(line.to_string().as_bytes());
    out.push(b'\n');
}

/// Makes a file creation or a rename durable.
#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Append-only log, synced to disk on every write. The latest line for a key wins.
///
/// Its first line names the request key it belongs to. A store is created once, with its key
/// (`ona-relay init-key`), and only opened afterwards: a missing or replaced file would make every
/// used request token valid again, so the relay refuses to start rather than begin a new one. One
/// process at a time holds it, through an exclusive lock on `<file>.lock`.
pub struct FileStore {
    file: File,
    path: PathBuf,
    binding: String,
    memory: MemoryStore,
    dead_lines: usize,
    /// Set after a failed write: what is on disk is unknown, so nothing more may be appended.
    failed: bool,
    /// Held for the life of the store. Dropping it releases the lock.
    _lock: File,
    lock_path: PathBuf,
    /// The lock file's identity. If the file is deleted or replaced, another process could take a new
    /// lock on the same store, so every write first checks that it is still the one held here.
    lock_id: (u64, u64),
}

fn file_id(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

fn header_line(binding: &str) -> Value {
    json!({"store": STORE_FORMAT, "binding": binding})
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

impl FileStore {
    /// Creates a new, empty store readable by its owner only. Never overwrites one.
    pub fn create(path: &Path, binding: &str) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot create store file: {e}"))?;
        let mut bytes = Vec::new();
        push_line(&mut bytes, &header_line(binding));
        file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|e| e.to_string())?;
        sync_parent(path).map_err(|e| e.to_string())?;
        drop(file);
        Self::open(path, binding)
    }

    /// Opens an existing store made for `binding`. Only a last line without its newline can come from
    /// a crash during a write, and such a write was never acknowledged, so it is cut off. Any other
    /// damage is an error.
    pub fn open(path: &Path, binding: &str) -> Result<Self, String> {
        let lock_path = with_suffix(path, ".lock");
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| format!("cannot open store lock: {e}"))?;
        lock.try_lock().map_err(|_| "store is in use by another relay process".to_string())?;
        let lock_id = file_id(&lock.metadata().map_err(|e| e.to_string())?);
        let meta = fs::metadata(path).map_err(|e| format!("cannot open store file, create it with init-key: {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("store file is accessible to other users".into());
        }
        let _ = fs::remove_file(Self::compact_path(path));

        let mut memory = MemoryStore::default();
        let mut lines = 0;
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let mut records = bytes[..complete].split_inclusive(|b| *b == b'\n');
        let header: Option<Value> = records.next().and_then(|line| serde_json::from_slice(line).ok());
        if header.as_ref() != Some(&header_line(binding)) {
            return Err("store file belongs to another request key, or has no header".into());
        }
        for line in records {
            let v: Value = serde_json::from_slice(line).map_err(|_| "corrupt store line".to_string())?;
            if let Some(x) = v["x"].as_str() {
                if v["r"] == json!(true) {
                    memory.used.remove(x);
                } else {
                    memory.used.insert(x.to_string());
                }
            } else {
                let nf = v["nf"].as_str().ok_or("corrupt store line")?;
                let state = state_from_json(&v["state"]).ok_or("corrupt store line")?;
                memory.exchanges.insert(nf.to_string(), state);
            }
            lines += 1;
        }
        if complete < bytes.len() {
            let file = OpenOptions::new().write(true).open(path).map_err(|e| e.to_string())?;
            file.set_len(complete as u64).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
        }
        let file = OpenOptions::new().append(true).open(path).map_err(|e| e.to_string())?;
        let live = memory.exchanges.len() + memory.used.len();
        Ok(Self {
            file,
            path: path.to_path_buf(),
            binding: binding.to_string(),
            memory,
            dead_lines: lines - live.min(lines),
            failed: false,
            _lock: lock,
            lock_path,
            lock_id,
        })
    }

    /// Stops the store for good if its lock file is no longer the one this process holds.
    fn check_lock(&mut self) -> Result<(), String> {
        let current = fs::metadata(&self.lock_path).map(|m| file_id(&m)).ok();
        if current != Some(self.lock_id) {
            self.failed = true;
            return Err("store lock file was removed or replaced: restart the relay".into());
        }
        Ok(())
    }

    fn compact_path(path: &Path) -> PathBuf {
        with_suffix(path, ".compact")
    }

    fn write_line(&mut self, line: &Value) -> Result<(), String> {
        if self.failed {
            return Err("store stopped after a write error: restart the relay".into());
        }
        self.check_lock()?;
        let mut bytes = Vec::new();
        push_line(&mut bytes, line);
        let result = self.file.write_all(&bytes).and_then(|()| self.file.sync_all());
        result.map_err(|e| {
            self.failed = true;
            e.to_string()
        })
    }

    /// Rewrites the log with one line per credit and per used token. Lines of finished exchanges
    /// that held a credit and an owner signature are gone. The switch is an atomic rename, so a
    /// crash leaves either the old log or the new one, and every used token is in both.
    pub fn compact(&mut self) -> Result<(), String> {
        if self.failed {
            return Err("store stopped after a write error: restart the relay".into());
        }
        self.check_lock()?;
        let mut bytes = Vec::new();
        push_line(&mut bytes, &header_line(&self.binding));
        for (nf, state) in &self.memory.exchanges {
            push_line(&mut bytes, &exchange_line(nf, state));
        }
        for x in &self.memory.used {
            push_line(&mut bytes, &json!({"x": x}));
        }
        let target = Self::compact_path(&self.path);
        let _ = fs::remove_file(&target);
        let mut file =
            OpenOptions::new().create_new(true).append(true).mode(0o600).open(&target).map_err(|e| e.to_string())?;
        let written = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&target, &self.path));
        if let Err(e) = written {
            let _ = fs::remove_file(&target);
            return Err(e.to_string());
        }
        self.file = file;
        self.dead_lines = 0;
        sync_parent(&self.path).map_err(|e| {
            self.failed = true;
            e.to_string()
        })
    }

    fn compaction_is_due(&self) -> bool {
        let live = self.memory.exchanges.len() + self.memory.used.len();
        self.dead_lines >= COMPACT_MIN_DEAD_LINES.max(live)
    }
}

impl Store for FileStore {
    fn get(&self, nf: &str) -> Option<ExchangeState> {
        self.memory.get(nf)
    }
    fn put(&mut self, nf: &str, state: ExchangeState) -> Result<(), String> {
        self.write_line(&exchange_line(nf, &state))?;
        if self.memory.exchanges.contains_key(nf) {
            self.dead_lines += 1;
        }
        let finished = matches!(state, ExchangeState::Done { .. } | ExchangeState::Refused);
        self.memory.put(nf, state)?;
        if finished && self.compaction_is_due() {
            // The new state is already durable, so a failed compaction loses nothing.
            if let Err(e) = self.compact() {
                eprintln!("store compaction failed: {e}");
            }
        }
        Ok(())
    }
    fn unfinished(&self) -> Vec<(String, ExchangeState)> {
        self.memory.unfinished()
    }
    fn use_request_token(&mut self, x: &str) -> Result<bool, String> {
        if self.memory.used.contains(x) {
            return Ok(false);
        }
        self.write_line(&json!({"x": x}))?;
        self.memory.use_request_token(x)
    }
    fn is_request_token_used(&self, x: &str) -> bool {
        self.memory.is_request_token_used(x)
    }
    fn release_request_token(&mut self, x: &str) -> Result<(), String> {
        if !self.memory.used.contains(x) {
            return Ok(());
        }
        self.write_line(&json!({"x": x, "r": true}))?;
        self.dead_lines += 2;
        self.memory.release_request_token(x)
    }
}

pub struct Claim {
    pub token: Token,
    pub owner_sig: [u8; 64],
    /// Nanoseconds; signed by the owner with the claim (`claim_digest_until`).
    pub expires_at: u64,
}

pub trait Chain {
    /// Must read a final block.
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String>;
    /// Sends `relay_claim` and waits for finality. One result per item.
    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String>;
    /// Whether this relay's own claim of the nullifier reached the chain, for crash recovery.
    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String>;
    /// Time of a final block, in nanoseconds: the clock the contract judges claim expiries by. A sent
    /// claim is given up only once this time has passed its expiry. The default, 0, never gives one up.
    fn final_timestamp(&mut self) -> Result<u64, String> {
        Ok(0)
    }
}

pub struct ModelReply {
    pub text: String,
    pub tokens_used: u32,
}

pub trait Upstream {
    fn complete(&mut self, prompt: &str, max_tokens: u32) -> Result<ModelReply, String>;
}

/// For the real relay, which reaches the model only through `gateway`: `Relay::chat` always fails.
pub struct NoModel;

impl Upstream for NoModel {
    fn complete(&mut self, _prompt: &str, _max_tokens: u32) -> Result<ModelReply, String> {
        Err("this relay has no direct model route".into())
    }
}

pub struct Config {
    pub mint: String,
    pub relay: String,
    pub mint_dst: Vec<u8>,
    pub credit_key: [u8; G2_LEN],
    /// Request tokens given for one credit.
    pub tokens_per_credit: usize,
    /// Most model tokens a single request may consume.
    pub max_tokens_per_request: u32,
    /// Most bytes of text in a chat message, before encryption.
    pub max_prompt_bytes: usize,
}

/// Every check that needs only the configuration and public keys: credits, owner signatures,
/// blinded points, request tokens and the chat policy. It is cheap to clone, so threads run these
/// checks without holding the relay's lock.
#[derive(Clone)]
pub struct Verifier {
    config: Arc<Config>,
    request_pk: [u8; G2_LEN],
    dst: Arc<[u8]>,
    clock: Clock,
}

pub struct Relay<S, C, U> {
    pub store: S,
    pub chain: C,
    pub upstream: U,
    verifier: Verifier,
    request_key: SecretKey,
    free_routes: gateway::FreeRoutes,
}

/// A relay used by several threads. Its verifier lives outside the lock.
pub struct SharedRelay<S, C, U> {
    verifier: Verifier,
    state: Mutex<Relay<S, C, U>>,
}

/// A panic while the relay was locked leaves its state unknown, so every later request is refused
/// until a restart.
fn lock<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.lock() {
        Ok(guard) => Some(guard),
        Err(_) => {
            eprintln!("relay state is unusable after a panic: answering 503 until the relay is restarted");
            None
        }
    }
}

pub type Response = (u16, Value);

/// An exchange request whose credit and owner signature have been verified.
struct CheckedExchange {
    token: Token,
    owner_sig: [u8; 64],
    expires_at: u64,
    /// The credit's earlier claim was given up: whether it landed after all must be read from the chain.
    after_expiry: bool,
    blinded: Vec<String>,
    blinded_hash: String,
    nf: [u8; 32],
    key: String,
}

/// A record that was sent, or is about to be sent, to the chain.
struct ClaimPart {
    nf: String,
    raw: [u8; 32],
    blinded_hash: String,
    expires_at: u64,
    blinded: Vec<String>,
}

struct ClaimBatch {
    claims: Vec<Claim>,
    parts: Vec<ClaimPart>,
}

/// What a final block says about one credit.
enum FinalView {
    ClaimedByRelay,
    SpentElsewhere,
    Open,
}

/// What an exchange request learns from the chain: a new credit needs only `is_spent`, a credit whose
/// earlier claim was given up needs the full final view.
fn exchange_view<C: Chain>(chain: &mut C, checked: &CheckedExchange) -> Result<FinalView, String> {
    if checked.after_expiry {
        read_final(chain, &checked.nf)
    } else if chain.is_spent(&checked.nf)? {
        Ok(FinalView::SpentElsewhere)
    } else {
        Ok(FinalView::Open)
    }
}

/// Reads a sent claim's fate, and whether it can be given up. The chain's time is read before the
/// view: if that time is past the expiry and the view still shows the credit open, no later block can
/// accept the claim. The machine's clock only decides whether the chain's time is worth asking for.
fn read_part<C: Chain>(chain: &mut C, part: &ClaimPart, local_now: u64) -> Result<(FinalView, bool), String> {
    let chain_time = if local_now >= part.expires_at { Some(chain.final_timestamp()?) } else { None };
    let view = read_final(chain, &part.raw)?;
    let expired = matches!(view, FinalView::Open) && chain_time.is_some_and(|t| t > part.expires_at);
    Ok((view, expired))
}

/// `is_spent` comes first. The two reads may be made at two blocks, and a nullifier, once spent, stays
/// spent with the same owner flag: so a claim landing between the reads gives `Open` (read again
/// later), never "spent by someone else" for a credit this relay collected.
fn read_final<C: Chain>(chain: &mut C, raw: &[u8; 32]) -> Result<FinalView, String> {
    if !chain.is_spent(raw)? {
        Ok(FinalView::Open)
    } else if chain.claimed_by_relay(raw)? {
        Ok(FinalView::ClaimedByRelay)
    } else {
        Ok(FinalView::SpentElsewhere)
    }
}

fn error(status: u16, message: &str) -> Response {
    (status, json!({"error": message}))
}

fn hash_blinded(blinded: &[String]) -> String {
    let mut h = Sha256::new();
    for b in blinded {
        h.update(b.as_bytes());
        h.update([0]);
    }
    to_hex(&h.finalize())
}

impl Verifier {
    /// The credit and its owner signature come first: no other work happens for a request that
    /// cannot prove it holds a credit.
    fn check_exchange(&self, body: &Value) -> Result<CheckedExchange, Response> {
        let bad = || error(400, "malformed exchange request");
        let token_bytes = body["token"].as_str().and_then(from_hex).ok_or_else(bad)?;
        let token = Token::from_bytes(&token_bytes).map_err(|_| bad())?;
        let signature = |field: &str| -> Result<[u8; 64], Response> {
            body[field].as_str().and_then(from_hex).and_then(|v| v.try_into().ok()).ok_or_else(bad)
        };
        let owner_sig = signature("owner_sig")?;
        let exchange_sig = signature("exchange_sig")?;
        let expires_at: u64 = body["expires_at"].as_str().and_then(|e| e.parse().ok()).ok_or_else(bad)?;
        if token.denom_id != 0 {
            return Err(error(400, "only the lowest tier buys request tokens"));
        }
        if !verify_token(&self.config.credit_key, &token, &self.config.mint_dst) {
            return Err(error(400, "invalid token"));
        }
        let nf = token.nullifier();
        let digest = claim_digest_until(&self.config.mint, &self.config.relay, &nf, expires_at);
        if !verify_digest(&token.pk, &digest, &owner_sig) {
            return Err(error(400, "invalid owner signature"));
        }

        let points = body["blinded"].as_array().ok_or_else(bad)?;
        if points.len() != self.config.tokens_per_credit {
            return Err(error(400, "wrong number of blinded points"));
        }
        let blinded: Vec<String> =
            points.iter().map(|b| b.as_str().map(String::from)).collect::<Option<_>>().ok_or_else(bad)?;
        let raw: Vec<[u8; G1_LEN]> = blinded
            .iter()
            .map(|b| from_hex(b).and_then(|bytes| bytes.try_into().ok()))
            .collect::<Option<_>>()
            .ok_or_else(bad)?;
        let exchange = exchange_digest(&self.config.mint, &self.config.relay, &nf, &raw);
        if !verify_digest(&token.pk, &exchange, &exchange_sig) {
            return Err(error(400, "invalid exchange signature"));
        }
        for point in &raw {
            // Refused now: otherwise the credit would be claimed and then fail at signing time.
            g1_to_raw(point).map_err(|_| error(400, "invalid blinded point"))?;
        }
        let blinded_hash = hash_blinded(&blinded);
        Ok(CheckedExchange { token, owner_sig, expires_at, after_expiry: false, blinded, blinded_hash, key: to_hex(&nf), nf })
    }

    /// Returns the token's identifier. Whether it was already used is for the store to say.
    fn verify_request_token(&self, encoded: &str) -> Result<String, Response> {
        let bytes = from_hex(encoded).filter(|b| b.len() == REQUEST_TOKEN_LEN).ok_or_else(|| error(400, "malformed request token"))?;
        let (x, sig) = bytes.split_at(32);
        let sig: [u8; G1_LEN] = sig.try_into().map_err(|_| error(400, "malformed request token"))?;
        if !verify(&self.request_pk, x, &self.dst, &sig) {
            return Err(error(401, "invalid request token"));
        }
        Ok(to_hex(x))
    }
}

impl<S: Store, C: Chain, U: Upstream> Relay<S, C, U> {
    pub fn new(store: S, chain: C, upstream: U, config: Config, request_key: SecretKey) -> Self {
        let verifier = Verifier {
            request_pk: request_key.public_key(),
            dst: request_dst(&config.relay).into(),
            config: Arc::new(config),
            clock: Arc::new(system_time_ns),
        };
        Self { store, chain, upstream, verifier, request_key, free_routes: Default::default() }
    }

    /// Replaces the clock used for claim expiries, for tests. Call it before `SharedRelay::new`.
    pub fn set_clock(&mut self, clock: Clock) {
        self.verifier.clock = clock;
    }

    fn now(&self) -> u64 {
        (self.verifier.clock)()
    }

    pub fn request_public_key(&self) -> [u8; G2_LEN] {
        self.verifier.request_pk
    }

    pub fn request_dst(&self) -> &[u8] {
        &self.verifier.dst
    }

    fn exchange_begin(&self, body: &Value) -> Result<CheckedExchange, Response> {
        self.exchange_lookup(self.verifier.check_exchange(body)?)
    }

    /// A given-up claim was not seen on chain, so a new exchange for the credit is accepted; the chain
    /// is read to learn whether an earlier claim landed after all.
    fn recorded(&self, key: &str) -> Option<ExchangeState> {
        self.store.get(key).filter(|state| !matches!(state, ExchangeState::Expired { .. }))
    }

    /// A new record needs a claim signature the contract will still accept when the batch lands.
    fn check_new_expiry(&self, expires_at: u64) -> Result<(), Response> {
        let now = self.now();
        if expires_at < now.saturating_add(MIN_CLAIM_VALIDITY_NS) {
            return Err(error(400, "claim signature expires too soon: sign with a later expires_at"));
        }
        if expires_at > now.saturating_add(MAX_CLAIM_VALIDITY_NS) {
            return Err(error(400, "claim signature expires too late: the contract accepts at most 7 days"));
        }
        Ok(())
    }

    /// Runs before the chain read, so a request that cannot be recorded costs no read.
    /// A request for a credit whose claim was given up is always let through to the chain read: the
    /// claim may have landed after all, and then the signatures are owed whatever the new expiry says.
    fn exchange_lookup(&self, mut checked: CheckedExchange) -> Result<CheckedExchange, Response> {
        match self.store.get(&checked.key) {
            Some(ExchangeState::Expired { .. }) => {
                checked.after_expiry = true;
                Ok(checked)
            }
            Some(existing) => Err(Self::exchange_reply(&existing, &checked.blinded_hash)),
            None => self.check_new_expiry(checked.expires_at).map(|()| checked),
        }
    }

    /// The store is read again: another request for this credit may have landed meanwhile.
    fn exchange_end(&mut self, checked: CheckedExchange, view: Result<FinalView, String>) -> Response {
        let CheckedExchange { token, owner_sig, expires_at, blinded, blinded_hash, key, .. } = checked;
        let given_up = self.store.get(&key);
        if let Some(existing) = self.recorded(&key) {
            return Self::exchange_reply(&existing, &blinded_hash);
        }
        match view {
            Ok(FinalView::Open) => {}
            Ok(FinalView::ClaimedByRelay) => {
                // An earlier claim landed after it was given up: the relay was paid, so it signs the
                // points that claim was for.
                let Some(ExchangeState::Expired { blinded_hash: claimed_hash, blinded: claimed }) = given_up else {
                    return error(503, "chain unavailable");
                };
                if self.finish(&key, claimed_hash, &claimed, true).is_err() {
                    return error(503, "storage unavailable");
                }
                return match self.store.get(&key) {
                    Some(done) => Self::exchange_reply(&done, &blinded_hash),
                    None => error(503, "storage unavailable"),
                };
            }
            Ok(FinalView::SpentElsewhere) => {
                // Remembered, so that replaying a spent credit costs no further chain read. Each entry
                // stands for a credit someone paid for, so this cannot grow for free.
                if self.store.put(&key, ExchangeState::Refused).is_err() {
                    return error(503, "storage unavailable");
                }
                return error(409, "credit already spent");
            }
            Err(_) => return error(503, "chain unavailable"),
        }
        // Checked only for a new record: a client collecting a finished exchange may hold an expired
        // signature by then.
        if let Err(response) = self.check_new_expiry(expires_at) {
            return match given_up {
                Some(expired @ ExchangeState::Expired { .. }) => Self::exchange_reply(&expired, &blinded_hash),
                _ => response,
            };
        }
        let state = ExchangeState::Pending {
            blinded_hash: blinded_hash.clone(),
            token: to_hex(&token.to_bytes()),
            owner_sig: to_hex(&owner_sig),
            expires_at,
            blinded,
        };
        if self.store.put(&key, state.clone()).is_err() {
            return error(503, "storage unavailable");
        }
        Self::exchange_reply(&state, &blinded_hash)
    }

    fn exchange_reply(state: &ExchangeState, blinded_hash: &str) -> Response {
        match state {
            ExchangeState::Pending { blinded_hash: h, .. } | ExchangeState::Submitted { blinded_hash: h, .. } => {
                if h == blinded_hash {
                    (202, json!({"state": "pending"}))
                } else {
                    error(409, "credit already used with other blinded points")
                }
            }
            ExchangeState::Done { blinded_hash: h, signatures } => {
                if h == blinded_hash {
                    (200, json!({"state": "done", "signatures": signatures}))
                } else {
                    error(409, "credit already used with other blinded points")
                }
            }
            ExchangeState::Refused => error(409, "credit refused"),
            ExchangeState::Expired { .. } => {
                error(410, "claim expired before it reached the chain: send the exchange again with a later expires_at and the same blinded points")
            }
        }
    }

    /// Accepts a credit for the next batch. Nothing is signed until the chain has confirmed the
    /// claim. The same request can be repeated safely to collect the result.
    pub fn exchange(&mut self, body: &Value) -> Response {
        let checked = match self.exchange_begin(body) {
            Ok(checked) => checked,
            Err(response) => return response,
        };
        let view = exchange_view(&mut self.chain, &checked);
        self.exchange_end(checked, view)
    }

    fn sign_all(&self, blinded: &[String]) -> Result<Vec<String>, String> {
        blinded
            .iter()
            .map(|b| {
                let bytes = from_hex(b).ok_or("stored point is not hex")?;
                let point: [u8; G1_LEN] = bytes.try_into().map_err(|_| "stored point length")?;
                sign_blinded(&self.request_key, &point).map(|s| to_hex(&s)).map_err(|e| e.to_string())
            })
            .collect()
    }

    fn finish(&mut self, nf: &str, blinded_hash: String, blinded: &[String], accepted: bool) -> Result<(), String> {
        let state = if accepted {
            ExchangeState::Done { blinded_hash, signatures: self.sign_all(blinded)? }
        } else {
            ExchangeState::Refused
        };
        self.store.put(nf, state)
    }

    /// Records left in `Submitted`, whose fate only the chain knows.
    fn submitted(&self) -> Result<Vec<ClaimPart>, String> {
        let mut parts = Vec::new();
        for (nf, state) in self.store.unfinished() {
            if let ExchangeState::Submitted { blinded_hash, expires_at, blinded, .. } = state {
                let raw: [u8; 32] =
                    from_hex(&nf).and_then(|v| v.try_into().ok()).ok_or("stored nullifier is not valid")?;
                parts.push(ClaimPart { nf, raw, blinded_hash, expires_at, blinded });
            }
        }
        Ok(parts)
    }

    /// Applies what a final block says. Returns whether the credit is settled and accepted;
    /// `None` when it is still open: the transaction never landed, or the hourly limit refused it
    /// without spending it, so `flush` sends it again. An open claim is given up only when `expired`,
    /// that is when the chain's own time has passed its expiry (`read_part`).
    fn apply_final(&mut self, part: ClaimPart, view: FinalView, expired: bool) -> Result<Option<bool>, String> {
        let accepted = match view {
            FinalView::ClaimedByRelay => true,
            FinalView::SpentElsewhere => false,
            FinalView::Open if expired => {
                self.store.put(&part.nf, ExchangeState::Expired { blinded_hash: part.blinded_hash, blinded: part.blinded })?;
                return Ok(Some(false));
            }
            FinalView::Open => return Ok(None),
        };
        self.finish(&part.nf, part.blinded_hash, &part.blinded, accepted)?;
        Ok(Some(accepted))
    }

    /// Settles records left in `Submitted` by a crash. The chain decides, never the local state.
    pub fn recover(&mut self) -> Result<usize, String> {
        let mut settled = 0;
        for part in self.submitted()? {
            let now = self.now();
            let (view, expired) = read_part(&mut self.chain, &part, now)?;
            settled += usize::from(self.apply_final(part, view, expired)?.is_some());
        }
        Ok(settled)
    }

    /// Sends one batch of credits to the chain. Signs only those the chain accepted.
    pub fn flush(&mut self) -> Result<usize, String> {
        // A claim that landed but whose reply was lost would come back `false` if sent again,
        // and the user would lose a credit the relay really collected.
        self.recover()?;
        let Some(batch) = self.prepare_batch()? else {
            return Ok(0);
        };
        let results = self.chain.relay_claim(&batch.claims)?;
        let mut accepted = 0;
        for part in Self::settle_claims(batch.parts, results)? {
            let now = self.now();
            let (view, expired) = read_part(&mut self.chain, &part, now)?;
            accepted += usize::from(self.apply_final(part, view, expired)? == Some(true));
        }
        Ok(accepted)
    }

    /// Picks the next batch and records each credit as sent before anything leaves the relay. A
    /// pending claim too close to its expiry to land is given up instead of sent.
    fn prepare_batch(&mut self) -> Result<Option<ClaimBatch>, String> {
        let now = self.now();
        let mut batch = Vec::new();
        for (nf, state) in self.store.unfinished() {
            if batch.len() == MAX_BATCH {
                break;
            }
            // Never sent, so nothing can land later: the machine's clock is enough here.
            if let ExchangeState::Pending { expires_at, blinded_hash, blinded, .. } = &state {
                if now.saturating_add(CLAIM_LANDING_MARGIN_NS) >= *expires_at {
                    let given_up = ExchangeState::Expired { blinded_hash: blinded_hash.clone(), blinded: blinded.clone() };
                    self.store.put(&nf, given_up)?;
                    continue;
                }
            }
            batch.push((nf, state));
        }
        if batch.is_empty() {
            return Ok(None);
        }
        let mut claims = Vec::with_capacity(batch.len());
        let mut parts = Vec::with_capacity(batch.len());
        for (nf, state) in batch {
            let (ExchangeState::Pending { blinded_hash, token, owner_sig, expires_at, blinded }
            | ExchangeState::Submitted { blinded_hash, token, owner_sig, expires_at, blinded }) = state
            else {
                continue;
            };
            let token_bytes = from_hex(&token).ok_or("stored token is not hex")?;
            let parsed = Token::from_bytes(&token_bytes).map_err(|e| e.to_string())?;
            let sig: [u8; 64] = from_hex(&owner_sig)
                .and_then(|v| v.try_into().ok())
                .ok_or("stored signature is not valid")?;
            self.store.put(
                &nf,
                ExchangeState::Submitted {
                    blinded_hash: blinded_hash.clone(),
                    token,
                    owner_sig,
                    expires_at,
                    blinded: blinded.clone(),
                },
            )?;
            let raw = parsed.nullifier();
            claims.push(Claim { token: parsed, owner_sig: sig, expires_at });
            parts.push(ClaimPart { nf, raw, blinded_hash, expires_at, blinded });
        }
        Ok(Some(ClaimBatch { claims, parts }))
    }

    /// The claim results decide nothing by themselves. A `true` comes from a single RPC endpoint, which
    /// could lie, and a `false` may mean spent by someone else, already claimed by this relay, or
    /// stopped by the hourly limit. Every part is returned, so the caller signs only what a final
    /// block, read through both endpoints, shows as claimed by this relay.
    fn settle_claims(parts: Vec<ClaimPart>, results: Vec<bool>) -> Result<Vec<ClaimPart>, String> {
        if results.len() != parts.len() {
            return Err("chain returned the wrong number of results".into());
        }
        Ok(parts)
    }

    /// Written before the model call, so a crash cannot make a token reusable.
    fn spend_request_token(&mut self, id: &str) -> Result<(), Response> {
        match self.store.use_request_token(id) {
            Ok(true) => Ok(()),
            Ok(false) => Err(error(409, "request token already used")),
            Err(_) => Err(error(503, "storage unavailable")),
        }
    }

    fn check_request_token(&mut self, encoded: &str) -> Result<String, Response> {
        let id = self.verifier.verify_request_token(encoded)?;
        self.spend_request_token(&id)?;
        Ok(id)
    }

    /// Serves one model call. The token is spent even if the model fails: the budget is checked
    /// on what the model actually consumed, and a reply over budget is withheld.
    pub fn chat(&mut self, body: &Value) -> Response {
        let Some(token) = body["token"].as_str() else {
            return error(400, "missing request token");
        };
        let Some(prompt) = body["prompt"].as_str() else {
            return error(400, "missing prompt");
        };
        if prompt.len() > MAX_PROMPT_BYTES {
            return error(413, "prompt too long");
        }
        if let Err(response) = self.check_request_token(token) {
            return response;
        }
        let max = self.verifier.config.max_tokens_per_request;
        match self.upstream.complete(prompt, max) {
            Ok(reply) if reply.tokens_used > max => error(402, "reply withheld: over the request budget"),
            Ok(reply) => (200, json!({"reply": reply.text, "tokens_used": reply.tokens_used, "mode": MODE})),
            Err(_) => error(502, "model unavailable"),
        }
    }

    pub fn handle(&mut self, path: &str, body: &str) -> Response {
        let Ok(value) = serde_json::from_str::<Value>(body) else {
            return error(400, "body is not valid JSON");
        };
        match path {
            "/exchange" => self.exchange(&value),
            "/chat" => self.chat(&value),
            _ => error(404, "not found"),
        }
    }
}

impl<S: Store, C: Chain, U: Upstream> SharedRelay<S, C, U> {
    pub fn new(relay: Relay<S, C, U>) -> Self {
        Self { verifier: relay.verifier.clone(), state: Mutex::new(relay) }
    }

    /// The relay itself, for single-threaded work such as startup or tests.
    pub fn state(&self) -> &Mutex<Relay<S, C, U>> {
        &self.state
    }

    /// As `Relay::exchange`. The credit is checked before the lock is taken, and the relay is not
    /// locked during the chain read.
    pub fn exchange<V: Chain>(&self, chain: &mut V, body: &Value) -> Response {
        let unavailable = || error(503, "relay unavailable");
        let checked = match self.verifier.check_exchange(body) {
            Ok(checked) => checked,
            Err(response) => return response,
        };
        let started = match lock(&self.state) {
            Some(guard) => guard.exchange_lookup(checked),
            None => return unavailable(),
        };
        let checked = match started {
            Ok(checked) => checked,
            Err(response) => return response,
        };
        let view = exchange_view(chain, &checked);
        match lock(&self.state) {
            Some(mut guard) => guard.exchange_end(checked, view),
            None => unavailable(),
        }
    }

    /// As `Relay::flush`, for a dedicated thread: the relay is locked only between chain calls.
    pub fn flush<V: Chain>(&self, chain: &mut V) -> Result<usize, String> {
        let lock = || lock(&self.state).ok_or_else(|| "relay state is unusable after a panic: restart the relay".to_string());
        let now = || (self.verifier.clock)();
        let open = lock()?.submitted()?;
        for part in open {
            let (view, expired) = read_part(chain, &part, now())?;
            lock()?.apply_final(part, view, expired)?;
        }
        let Some(batch) = lock()?.prepare_batch()? else {
            return Ok(0);
        };
        let results = chain.relay_claim(&batch.claims)?;
        let mut accepted = 0;
        for part in Relay::<S, C, U>::settle_claims(batch.parts, results)? {
            let (view, expired) = read_part(chain, &part, now())?;
            accepted += usize::from(lock()?.apply_final(part, view, expired)? == Some(true));
        }
        Ok(accepted)
    }

    /// As `Relay::gateway`. The request is checked before the lock is taken, and the relay is not
    /// locked while the service is called.
    pub fn gateway<B: gateway::Backend>(
        &self,
        backend: &mut B,
        policy: &gateway::GatewayPolicy,
        request: &http::Request,
    ) -> (u16, Vec<u8>) {
        let unavailable = || (503, json!({"error": "relay unavailable"}).to_string().into_bytes());
        let checked = match self.verifier.check_call(policy, request) {
            Ok(checked) => checked,
            Err(response) => return response,
        };
        let admitted = match lock(&self.state) {
            Some(mut guard) => guard.admit(policy, checked),
            None => return unavailable(),
        };
        let forward = match admitted {
            Ok(forward) => forward,
            Err(response) => return response,
        };
        let outcome = backend.forward(&request.method, &request.target, forward.headers(), &request.body);
        match lock(&self.state) {
            Some(mut guard) => guard.gateway_end(forward, outcome),
            None => unavailable(),
        }
    }
}

pub fn request_message_point(x: &[u8; 32], dst: &[u8]) -> [u8; G1_LEN] {
    hash_to_g1(x, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_write_stops_the_store() {
        let path = std::env::temp_dir().join(format!("ona-store-{}-failed.log", std::process::id()));
        let _ = fs::remove_file(&path);
        let mut store = FileStore::create(&path, "k").unwrap();
        assert!(store.use_request_token("aa").unwrap());

        // A handle opened for reading makes the next write fail.
        store.file = File::open(&path).unwrap();
        assert!(store.use_request_token("bb").is_err());

        // Even with a working file again, nothing more may be appended.
        store.file = OpenOptions::new().append(true).open(&path).unwrap();
        assert!(store.use_request_token("cc").is_err());
        assert!(store.put("nf", ExchangeState::Refused).is_err());
        assert!(store.compact().is_err());
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2, "the header and one token");

        drop(store);
        let mut reopened = FileStore::open(&path, "k").unwrap();
        assert!(!reopened.use_request_token("aa").unwrap());
        assert!(reopened.use_request_token("bb").unwrap(), "the failed write was never recorded");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn hex_has_one_spelling() {
        assert_eq!(from_hex("0aff"), Some(vec![0x0a, 0xff]));
        for bad in ["0AFF", "+a", "0x", "a", "zz", "é0"] {
            assert_eq!(from_hex(bad), None, "{bad}");
        }
    }
}
