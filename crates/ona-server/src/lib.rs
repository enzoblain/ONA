//! `ona-server`: the relay. It exchanges an on-chain credit for anonymous request tokens, and
//! serves model calls against those tokens. The model and the chain are behind traits and are
//! faked in this version: every model reply is labelled `mode: mock`.
//!
//! The relay is not trusted with content. An honest relay forwards only ciphertext, but it sits
//! between the client and the model, and encryption version 2 lets it replace the client key: see
//! `gateway`.
//!
//! Not done yet: fixed-size batches padded with the relay's own tokens, the real RPC client, Tor,
//! and the enclave.

pub mod gateway;
pub mod http;
pub mod keyfile;
pub mod mock;
pub mod near;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ona_token::{
    claim_digest, g1_to_raw, hash_to_g1, sign_blinded, verify, verify_digest, verify_token, SecretKey,
    Token, G1_LEN, G2_LEN,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const MODE: &str = "mock";
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
pub const MAX_BATCH: usize = 32;
const REQUEST_TOKEN_LEN: usize = 32 + G1_LEN;
/// The journal is rewritten once this many lines are obsolete, and at least as many as are live.
const COMPACT_MIN_DEAD_LINES: usize = 64;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn request_dst(relay: &str) -> Vec<u8> {
    format!("ONA-RELAY-V1:{relay}:BLS12381G1_XMD:SHA-256_SSWU_RO_").into_bytes()
}

/// Where a credit stands. Written durably before each step that cannot be undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeState {
    Pending { blinded_hash: String, token: String, owner_sig: String, blinded: Vec<String> },
    /// Sent to the chain. After a crash, only the chain can say what happened.
    Submitted { blinded_hash: String, token: String, owner_sig: String, blinded: Vec<String> },
    Done { blinded_hash: String, signatures: Vec<String> },
    Refused,
}

pub trait Store {
    fn get(&self, nf: &str) -> Option<ExchangeState>;
    fn put(&mut self, nf: &str, state: ExchangeState) -> Result<(), String>;
    fn unfinished(&self) -> Vec<(String, ExchangeState)>;
    /// Records a request token. Returns false if it was already used.
    fn use_request_token(&mut self, x: &str) -> Result<bool, String>;
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
    fn release_request_token(&mut self, x: &str) -> Result<(), String> {
        self.used.remove(x);
        Ok(())
    }
}

fn state_to_json(state: &ExchangeState) -> Value {
    match state {
        ExchangeState::Pending { blinded_hash, token, owner_sig, blinded } => {
            json!({"s":"pending","h":blinded_hash,"t":token,"o":owner_sig,"b":blinded})
        }
        ExchangeState::Submitted { blinded_hash, token, owner_sig, blinded } => {
            json!({"s":"submitted","h":blinded_hash,"t":token,"o":owner_sig,"b":blinded})
        }
        ExchangeState::Done { blinded_hash, signatures } => {
            json!({"s":"done","h":blinded_hash,"g":signatures})
        }
        ExchangeState::Refused => json!({"s":"refused"}),
    }
}

fn state_from_json(v: &Value) -> Option<ExchangeState> {
    let text = |k: &str| v[k].as_str().map(String::from);
    let list = |k: &str| -> Option<Vec<String>> {
        v[k].as_array()?.iter().map(|x| x.as_str().map(String::from)).collect()
    };
    match v["s"].as_str()? {
        "pending" => Some(ExchangeState::Pending { blinded_hash: text("h")?, token: text("t")?, owner_sig: text("o")?, blinded: list("b")? }),
        "submitted" => Some(ExchangeState::Submitted { blinded_hash: text("h")?, token: text("t")?, owner_sig: text("o")?, blinded: list("b")? }),
        "done" => Some(ExchangeState::Done { blinded_hash: text("h")?, signatures: list("g")? }),
        "refused" => Some(ExchangeState::Refused),
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
pub struct FileStore {
    file: File,
    path: PathBuf,
    memory: MemoryStore,
    dead_lines: usize,
    /// Set after a failed write: what is on disk is unknown, so nothing more may be appended.
    failed: bool,
}

impl FileStore {
    /// Only a last line without its newline can come from a crash during a write, and such a write
    /// was never acknowledged, so it is cut off. Any other damage is an error.
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut memory = MemoryStore::default();
        let mut lines = 0;
        let compact_file = Self::compact_path(path);
        let _ = fs::remove_file(&compact_file);
        let created = !path.exists();
        if !created {
            let bytes = fs::read(path).map_err(|e| e.to_string())?;
            let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            for line in bytes[..complete].split_inclusive(|b| *b == b'\n') {
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
        }
        let file = OpenOptions::new().create(true).append(true).open(path).map_err(|e| e.to_string())?;
        if created {
            file.sync_all().map_err(|e| e.to_string())?;
            sync_parent(path).map_err(|e| e.to_string())?;
        }
        let live = memory.exchanges.len() + memory.used.len();
        Ok(Self { file, path: path.to_path_buf(), memory, dead_lines: lines - live.min(lines), failed: false })
    }

    fn compact_path(path: &Path) -> PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(".compact");
        PathBuf::from(name)
    }

    fn write_line(&mut self, line: &Value) -> Result<(), String> {
        if self.failed {
            return Err("store stopped after a write error: restart the relay".into());
        }
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
        let mut bytes = Vec::new();
        for (nf, state) in &self.memory.exchanges {
            push_line(&mut bytes, &exchange_line(nf, state));
        }
        for x in &self.memory.used {
            push_line(&mut bytes, &json!({"x": x}));
        }
        let target = Self::compact_path(&self.path);
        let _ = fs::remove_file(&target);
        let mut file = OpenOptions::new().create_new(true).append(true).open(&target).map_err(|e| e.to_string())?;
        let written = fs::metadata(&self.path)
            .and_then(|meta| file.set_permissions(meta.permissions()))
            .and_then(|()| file.write_all(&bytes))
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
}

pub trait Chain {
    /// Must read a final block.
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String>;
    /// Sends `relay_claim` and waits for finality. One result per item.
    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String>;
    /// Whether this relay's own claim of the nullifier reached the chain, for crash recovery.
    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String>;
}

pub struct ModelReply {
    pub text: String,
    pub tokens_used: u32,
}

pub trait Upstream {
    fn complete(&mut self, prompt: &str, max_tokens: u32) -> Result<ModelReply, String>;
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
}

pub struct Relay<S, C, U> {
    pub store: S,
    pub chain: C,
    pub upstream: U,
    config: Config,
    request_key: SecretKey,
    request_pk: [u8; G2_LEN],
    dst: Vec<u8>,
    free_routes: gateway::MinuteWindow,
}

pub type Response = (u16, Value);

/// An exchange request whose credit and owner signature have been verified.
struct CheckedExchange {
    token: Token,
    owner_sig: [u8; 64],
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

fn read_final<C: Chain>(chain: &mut C, raw: &[u8; 32]) -> Result<FinalView, String> {
    if chain.claimed_by_relay(raw)? {
        Ok(FinalView::ClaimedByRelay)
    } else if chain.is_spent(raw)? {
        Ok(FinalView::SpentElsewhere)
    } else {
        Ok(FinalView::Open)
    }
}

fn error(status: u16, message: &str) -> Response {
    (status, json!({"error": message, "mode": MODE}))
}

fn hash_blinded(blinded: &[String]) -> String {
    let mut h = Sha256::new();
    for b in blinded {
        h.update(b.as_bytes());
        h.update([0]);
    }
    to_hex(&h.finalize())
}

impl<S: Store, C: Chain, U: Upstream> Relay<S, C, U> {
    pub fn new(store: S, chain: C, upstream: U, config: Config, request_key: SecretKey) -> Self {
        let request_pk = request_key.public_key();
        let dst = request_dst(&config.relay);
        Self { store, chain, upstream, config, request_key, request_pk, dst, free_routes: Default::default() }
    }

    pub fn request_public_key(&self) -> [u8; G2_LEN] {
        self.request_pk
    }

    pub fn request_dst(&self) -> &[u8] {
        &self.dst
    }

    /// The credit and its owner signature come first: no other work happens for a request that
    /// cannot prove it holds a credit.
    fn check_exchange(&self, body: &Value) -> Result<CheckedExchange, Response> {
        let bad = || error(400, "malformed exchange request");
        let token_bytes = body["token"].as_str().and_then(from_hex).ok_or_else(bad)?;
        let token = Token::from_bytes(&token_bytes).map_err(|_| bad())?;
        let owner_sig: [u8; 64] = body["owner_sig"]
            .as_str()
            .and_then(from_hex)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(bad)?;
        if token.denom_id != 0 {
            return Err(error(400, "only the lowest tier buys request tokens"));
        }
        if !verify_token(&self.config.credit_key, &token, &self.config.mint_dst) {
            return Err(error(400, "invalid token"));
        }
        let nf = token.nullifier();
        let digest = claim_digest(&self.config.mint, &self.config.relay, &nf);
        if !verify_digest(&token.pk, &digest, &owner_sig) {
            return Err(error(400, "invalid owner signature"));
        }

        let points = body["blinded"].as_array().ok_or_else(bad)?;
        if points.len() != self.config.tokens_per_credit {
            return Err(error(400, "wrong number of blinded points"));
        }
        let blinded: Vec<String> =
            points.iter().map(|b| b.as_str().map(String::from)).collect::<Option<_>>().ok_or_else(bad)?;
        for b in &blinded {
            let bytes = from_hex(b).ok_or_else(bad)?;
            let point: [u8; G1_LEN] = bytes.try_into().map_err(|_| bad())?;
            // Refused now: otherwise the credit would be claimed and then fail at signing time.
            g1_to_raw(&point).map_err(|_| error(400, "invalid blinded point"))?;
        }
        let blinded_hash = hash_blinded(&blinded);
        Ok(CheckedExchange { token, owner_sig, blinded, blinded_hash, key: to_hex(&nf), nf })
    }

    fn exchange_begin(&self, body: &Value) -> Result<CheckedExchange, Response> {
        let checked = self.check_exchange(body)?;
        match self.store.get(&checked.key) {
            Some(existing) => Err(Self::exchange_reply(&existing, &checked.blinded_hash)),
            None => Ok(checked),
        }
    }

    /// The store is read again: another request for this credit may have landed meanwhile.
    fn exchange_end(&mut self, checked: CheckedExchange, spent: Result<bool, String>) -> Response {
        let CheckedExchange { token, owner_sig, blinded, blinded_hash, key, .. } = checked;
        if let Some(existing) = self.store.get(&key) {
            return Self::exchange_reply(&existing, &blinded_hash);
        }
        match spent {
            Ok(false) => {}
            Ok(true) => return error(409, "credit already spent"),
            Err(_) => return error(503, "chain unavailable"),
        }
        let state = ExchangeState::Pending {
            blinded_hash: blinded_hash.clone(),
            token: to_hex(&token.to_bytes()),
            owner_sig: to_hex(&owner_sig),
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
                    (202, json!({"state": "pending", "mode": MODE}))
                } else {
                    error(409, "credit already used with other blinded points")
                }
            }
            ExchangeState::Done { blinded_hash: h, signatures } => {
                if h == blinded_hash {
                    (200, json!({"state": "done", "signatures": signatures, "mode": MODE}))
                } else {
                    error(409, "credit already used with other blinded points")
                }
            }
            ExchangeState::Refused => error(409, "credit refused"),
        }
    }

    /// Accepts a credit for the next batch. Nothing is signed until the chain has confirmed the
    /// claim. The same request can be repeated safely to collect the result.
    pub fn exchange(&mut self, body: &Value) -> Response {
        let checked = match self.exchange_begin(body) {
            Ok(checked) => checked,
            Err(response) => return response,
        };
        let spent = self.chain.is_spent(&checked.nf);
        self.exchange_end(checked, spent)
    }

    /// As `exchange`, for several threads: the relay is not locked during the chain read.
    pub fn exchange_shared<V: Chain>(relay: &Mutex<Self>, chain: &mut V, body: &Value) -> Response {
        let unavailable = || error(503, "relay unavailable");
        let started = match relay.lock() {
            Ok(guard) => guard.exchange_begin(body),
            Err(_) => return unavailable(),
        };
        let checked = match started {
            Ok(checked) => checked,
            Err(response) => return response,
        };
        let spent = chain.is_spent(&checked.nf);
        match relay.lock() {
            Ok(mut guard) => guard.exchange_end(checked, spent),
            Err(_) => unavailable(),
        }
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
            if let ExchangeState::Submitted { blinded_hash, blinded, .. } = state {
                let raw: [u8; 32] =
                    from_hex(&nf).and_then(|v| v.try_into().ok()).ok_or("stored nullifier is not valid")?;
                parts.push(ClaimPart { nf, raw, blinded_hash, blinded });
            }
        }
        Ok(parts)
    }

    /// Applies what a final block says. Returns whether the credit is settled and accepted;
    /// `None` when it is still open: the transaction never landed, or the hourly limit refused it
    /// without spending it, so `flush` sends it again.
    fn apply_final(&mut self, part: ClaimPart, view: FinalView) -> Result<Option<bool>, String> {
        let accepted = match view {
            FinalView::ClaimedByRelay => true,
            FinalView::SpentElsewhere => false,
            FinalView::Open => return Ok(None),
        };
        self.finish(&part.nf, part.blinded_hash, &part.blinded, accepted)?;
        Ok(Some(accepted))
    }

    /// Settles records left in `Submitted` by a crash. The chain decides, never the local state.
    pub fn recover(&mut self) -> Result<usize, String> {
        let mut settled = 0;
        for part in self.submitted()? {
            let view = read_final(&mut self.chain, &part.raw)?;
            settled += usize::from(self.apply_final(part, view)?.is_some());
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
        let (mut accepted, refused) = self.settle_claims(batch.parts, results)?;
        for part in refused {
            let view = read_final(&mut self.chain, &part.raw)?;
            accepted += usize::from(self.apply_final(part, view)? == Some(true));
        }
        Ok(accepted)
    }

    /// As `flush`, for a dedicated thread: the relay is locked only between chain calls.
    pub fn flush_shared<V: Chain>(relay: &Mutex<Self>, chain: &mut V) -> Result<usize, String> {
        let lock = || relay.lock().map_err(|_| "relay state is unavailable".to_string());
        let open = lock()?.submitted()?;
        for part in open {
            let view = read_final(chain, &part.raw)?;
            lock()?.apply_final(part, view)?;
        }
        let Some(batch) = lock()?.prepare_batch()? else {
            return Ok(0);
        };
        let results = chain.relay_claim(&batch.claims)?;
        let (mut accepted, refused) = lock()?.settle_claims(batch.parts, results)?;
        for part in refused {
            let view = read_final(chain, &part.raw)?;
            accepted += usize::from(lock()?.apply_final(part, view)? == Some(true));
        }
        Ok(accepted)
    }

    /// Picks the next batch and records each credit as sent before anything leaves the relay.
    fn prepare_batch(&mut self) -> Result<Option<ClaimBatch>, String> {
        let batch: Vec<(String, ExchangeState)> = self.store.unfinished().into_iter().take(MAX_BATCH).collect();
        if batch.is_empty() {
            return Ok(None);
        }
        let mut claims = Vec::with_capacity(batch.len());
        let mut parts = Vec::with_capacity(batch.len());
        for (nf, state) in batch {
            let (ExchangeState::Pending { blinded_hash, token, owner_sig, blinded }
            | ExchangeState::Submitted { blinded_hash, token, owner_sig, blinded }) = state
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
                    blinded: blinded.clone(),
                },
            )?;
            let raw = parsed.nullifier();
            claims.push(Claim { token: parsed, owner_sig: sig });
            parts.push(ClaimPart { nf, raw, blinded_hash, blinded });
        }
        Ok(Some(ClaimBatch { claims, parts }))
    }

    /// Signs the claims the chain accepted. A `false` proves nothing by itself: the credit may have
    /// been spent by someone else, already claimed by this relay, or stopped by the hourly limit.
    /// Those are returned so that the caller can read a final block.
    fn settle_claims(&mut self, parts: Vec<ClaimPart>, results: Vec<bool>) -> Result<(usize, Vec<ClaimPart>), String> {
        if results.len() != parts.len() {
            return Err("chain returned the wrong number of results".into());
        }
        let mut accepted = 0;
        let mut refused = Vec::new();
        for (part, ok) in parts.into_iter().zip(results) {
            if ok {
                self.finish(&part.nf, part.blinded_hash, &part.blinded, true)?;
                accepted += 1;
            } else {
                refused.push(part);
            }
        }
        Ok((accepted, refused))
    }

    fn check_request_token(&mut self, encoded: &str) -> Result<String, Response> {
        let bytes = from_hex(encoded).filter(|b| b.len() == REQUEST_TOKEN_LEN).ok_or_else(|| error(400, "malformed request token"))?;
        let (x, sig) = bytes.split_at(32);
        let sig: [u8; G1_LEN] = sig.try_into().map_err(|_| error(400, "malformed request token"))?;
        if !verify(&self.request_pk, x, &self.dst, &sig) {
            return Err(error(401, "invalid request token"));
        }
        let id = to_hex(x);
        // Written before the model call, so a crash cannot make a token reusable.
        match self.store.use_request_token(&id) {
            Ok(true) => Ok(id),
            Ok(false) => Err(error(409, "request token already used")),
            Err(_) => Err(error(503, "storage unavailable")),
        }
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
        let max = self.config.max_tokens_per_request;
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
        let mut store = FileStore::open(&path).unwrap();
        assert!(store.use_request_token("aa").unwrap());

        // A handle opened for reading makes the next write fail.
        store.file = File::open(&path).unwrap();
        assert!(store.use_request_token("bb").is_err());

        // Even with a working file again, nothing more may be appended.
        store.file = OpenOptions::new().append(true).open(&path).unwrap();
        assert!(store.use_request_token("cc").is_err());
        assert!(store.put("nf", ExchangeState::Refused).is_err());
        assert!(store.compact().is_err());
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);

        drop(store);
        let mut reopened = FileStore::open(&path).unwrap();
        assert!(!reopened.use_request_token("aa").unwrap());
        assert!(reopened.use_request_token("bb").unwrap(), "the failed write was never recorded");
        fs::remove_file(&path).unwrap();
    }
}
