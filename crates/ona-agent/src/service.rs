//! The agent's handling of requests: check, record, queue, send in batches, confirm on chain, blind-sign.
//!
//! Rules every request follows:
//! - **Checked off chain first**, before any RPC read or gas: the note's signature under its tier key (the agent holds
//!   the keys), its owner's signature for exactly this operation, the outputs, the blinded points, and the deadline
//!   by this machine's clock. Then, at a pinned final block: the deadline again and that the note is not spent. A cash
//!   issue needs the depositor's wallet signature (`nep413`) by a full-access key of the account.
//! - **One owner signature, one set of points.** The first request carrying a note's owner signature fixes its blinded
//!   points: a later request with the same signature and other points is refused for good, even after the first was
//!   refused. A refused transaction is public (note, owner signature, outputs, deadline), so without this anyone
//!   could replay it with their own points and take the new notes. The owner can still sign again, with another
//!   deadline.
//! - **Recorded before anything else**, and answered from the record when repeated: a done request returns the same
//!   signatures; a queued or sent one answers "pending".
//! - **Queued, then sent in batches** (`QueueParams`): an entry, a leave or a cash exit waits at least `min_delay_ns`
//!   plus a random part of `jitter_ns` after it arrives, and goes out only in a processing window, with at least
//!   `min_batch` other requests of the same window class that can go now (funds, price and escape checked before
//!   counting), in random order. Entries and leaves share windows; cash exits use the other windows, so a payment never
//!   leaves in the same window as a leave. A leave or a payment waits while the liquid funds (less what listed exit
//!   requests may claim) or the hourly cap would not cover it, since a refused call is public and names the vault. A
//!   request whose owner's deadline passes while it waits is refused, and its note freed. Nothing is queued while the
//!   escape is open on the cash or the vault it spends from.
//! - **Signed only for the agent's own work**: a note request is signed only when one of its own transactions
//!   succeeded as both read endpoints report it; a queued request whose note was spent another way (`escape_exit`, a
//!   listed request) is refused. A cash issue is signed once a cross-checked read shows the account's issued cash grew.
//!   Never on the word of the endpoint that sent the transaction.
//! - **Note operations may be resent** while their outcome is unknown (the contract spends a note once), only in a
//!   window of their kind and once per window. A cash issue is never resent: one whose outcome stays unknown blocks
//!   further issues for that account until the account's issued cash shows it, both read endpoints report it failed,
//!   or `TX_EXPIRY_NS` has passed.
//! - **Kept only as long as needed**: finished records keep no account, vault or deadline; they and the signatures are
//!   deleted `retention_ns` after they finished; a note's binding to its points goes once its deadline has passed.

use std::collections::{BTreeMap, HashMap};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_token::{g1_to_raw, sign_blinded, verify_token, Token, G1_LEN, G2_LEN};
use ona_wallet::pool as digests;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::chain::{Call, CallError, Note, PoolChain, VaultInfo};
use crate::keys::AgentKeys;
use crate::nep413;
use crate::planner::{self, Action, Memory, Params};
use crate::store::Store;

/// Most notes one entry or leave creates, as the contract.
pub const MAX_OUTPUTS: u64 = 64;
/// A share price is used only if read within the hour (`ona-pool` `SYNC_FRESH_NS`); a vault is synced first when its
/// reading is older than this.
pub const SYNC_BEFORE_USE_NS: u64 = 50 * 60_000_000_000;
/// After this, a cash issue whose outcome stayed unknown is taken as never landed. A NEAR transaction stops being
/// valid about a day after the block it names (not verified); this keeps a margin.
pub const TX_EXPIRY_NS: u64 = 2 * 24 * 3_600_000_000_000;
/// A queued request is not sent this close to its owner's deadline: it could land too late.
pub const SEND_MARGIN_NS: u64 = 10 * 60_000_000_000;
/// This machine's clock may be this far from the chain's when the deadline is checked off chain.
pub const CLOCK_MARGIN_NS: u64 = 5 * 60_000_000_000;
const HOUR_NS: u64 = 3_600_000_000_000;

/// When queued requests leave, and how long the agent keeps what it no longer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueParams {
    /// Length of a processing window. Windows alternate: entries and leaves, then cash exits.
    pub window_ns: u64,
    /// Requests of a window's class needed before any of them is sent.
    pub min_batch: usize,
    /// Least time between a request's arrival and its sending.
    pub min_delay_ns: u64,
    /// Added to `min_delay_ns`, drawn at random for each request between 0 and this.
    pub jitter_ns: u64,
    /// Finished records and signatures are deleted this long after they finished.
    pub retention_ns: u64,
    /// Cash issues one account may ask for per hour.
    pub issues_per_hour: u32,
}

/// The owner's signature lasts 24 hours (`ona-core` `SIGNATURE_LIFE_NS`): a request can wait for a batch.
impl Default for QueueParams {
    fn default() -> Self {
        Self {
            window_ns: 15 * 60_000_000_000,
            min_batch: 5,
            min_delay_ns: 10 * 60_000_000_000,
            jitter_ns: 50 * 60_000_000_000,
            retention_ns: 7 * 24 * HOUR_NS,
            issues_per_hour: 6,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
    pub nonce: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct IssueRequest {
    pub account: String,
    pub notes: Vec<(u8, [u8; G1_LEN])>,
    pub proof: Proof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Enter,
    Leave,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Enter => "enter",
            Kind::Leave => "leave",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NoteRequest {
    pub kind: Kind,
    pub vault: u32,
    pub note: Note,
    pub owner_sig: [u8; 64],
    pub outputs: Vec<(u8, u64)>,
    pub blinded: Vec<[u8; G1_LEN]>,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct PayRequest {
    pub note: Note,
    pub owner_sig: [u8; 64],
    pub to: String,
    pub expires_at: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Reply {
    /// Blind signatures, one per blinded point in order.
    Signed(Vec<[u8; G1_LEN]>),
    Paid,
    /// Queued, sent or waiting for confirmation: ask again later.
    Pending(String),
    /// Certainly not done, with an HTTP status.
    Refused(u16, String),
}

/// Never prints signatures, so logs hold none.
impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reply::Signed(sigs) => write!(f, "Signed({} signatures)", sigs.len()),
            Reply::Paid => write!(f, "Paid"),
            Reply::Pending(why) => write!(f, "Pending({why})"),
            Reply::Refused(status, why) => write!(f, "Refused({status}, {why})"),
        }
    }
}

fn refused(status: u16, message: impl Into<String>) -> Reply {
    Reply::Refused(status, message.into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    (0..64).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect::<Option<Vec<u8>>>()?.try_into().ok()
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn decode_points(values: &Value) -> Option<Vec<[u8; G1_LEN]>> {
    values.as_array()?.iter().map(|v| v.as_str().and_then(|s| B64.decode(s).ok()).and_then(|b| b.try_into().ok())).collect()
}

fn valid_points(points: &[[u8; G1_LEN]]) -> bool {
    !points.is_empty() && points.iter().all(|p| g1_to_raw(p).is_ok())
}

fn points_hash(points: &[[u8; G1_LEN]]) -> String {
    let mut h = Sha256::new();
    for p in points {
        h.update(p);
    }
    hex(&h.finalize())
}

/// The most a vault's listed exit requests can claim from its liquid funds (`ona-pool` `reserved`): the contract
/// publishes how many there are, not their value, so each counts as one of the vault's largest notes.
fn listed_bound(info: &VaultInfo) -> u128 {
    let largest = info.tiers.iter().map(|t| t.0).max().unwrap_or(0).saturating_mul(info.share_price);
    largest.saturating_mul(u128::from(info.requests))
}

/// `ona-pool` `use_window`: in an hour with nothing out yet any single amount passes; otherwise the total stays under
/// the cap.
fn window_ok(used: u128, cap: u128, amount: u128) -> bool {
    used == 0 || used.saturating_add(amount) <= cap
}

fn system_time_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

pub type Clock = Box<dyn Fn() -> u64 + Send>;

pub struct Agent<C, S> {
    pub chain: C,
    pub store: S,
    keys: AgentKeys,
    pool: String,
    network: String,
    params: Params,
    queue: QueueParams,
    clock: Clock,
    /// Cash issues per account in the current hour, in memory.
    issues: HashMap<String, (u64, u32)>,
}

impl<C: PoolChain, S: Store> Agent<C, S> {
    /// Refuses to start if the keys held here are not the ones the contract verifies against, or if this account is
    /// not the contract's agent.
    pub fn start(mut chain: C, store: S, keys: AgentKeys, pool: &str, account: &str, params: Params, queue: QueueParams) -> Result<Self, String> {
        chain.begin()?;
        let config = chain.config()?;
        if config.agent != account {
            return Err(format!("the pool's agent is {}, not {account}", config.agent));
        }
        let cash = chain.cash()?;
        if cash.tiers.iter().map(|t| t.1).collect::<Vec<_>>() != keys.cash_public() {
            return Err("the cash keys do not match the contract".into());
        }
        for id in 0..config.vault_count {
            let vault = chain.vault(id)?;
            let expected = keys.vault_public(id as usize).ok_or_else(|| format!("no keys for vault {id}"))?;
            if vault.tiers.iter().map(|t| t.1).collect::<Vec<_>>() != expected {
                return Err(format!("the keys of vault {id} do not match the contract"));
            }
        }
        Ok(Self {
            chain,
            store,
            keys,
            pool: pool.into(),
            network: config.network,
            params,
            queue,
            clock: Box::new(system_time_ns),
            issues: HashMap::new(),
        })
    }

    /// This machine's clock, for the off-chain checks; replaced in tests.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    fn put(&mut self, key: &str, value: Value) -> Result<(), Reply> {
        self.store.put(key, value).map_err(|e| refused(503, format!("storage unavailable: {e}")))
    }

    fn chain_err(e: String) -> Reply {
        Reply::Pending(format!("chain unavailable: {e}"))
    }

    fn sign(&self, keys: &[ona_token::SecretKey], tiers: &[u8], blinded: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, String> {
        tiers
            .iter()
            .zip(blinded)
            .map(|(tier, b)| {
                let key = keys.get(usize::from(*tier)).ok_or("unknown tier")?;
                sign_blinded(key, b).map_err(|e| e.to_string())
            })
            .collect()
    }

    /// Keeps every signature by its blinded point, for `signatures`, until the retention ends.
    fn remember(&mut self, blinded: &[[u8; G1_LEN]], sigs: &[[u8; G1_LEN]], now: u64) -> Result<(), Reply> {
        for (b, s) in blinded.iter().zip(sigs) {
            self.put(&format!("b:{}", hex(b)), json!({"sig": b64(s), "at": now}))?;
        }
        Ok(())
    }

    fn signed_reply(record: &Value) -> Option<Reply> {
        match record["s"].as_str()? {
            "done" => Some(match decode_points(&record["sigs"]) {
                Some(sigs) if !sigs.is_empty() => Reply::Signed(sigs),
                _ => Reply::Paid,
            }),
            "refused" => Some(refused(409, record["why"].as_str().unwrap_or("refused").to_string())),
            _ => None,
        }
    }

    // ---- cash issue ----

    pub fn issue(&mut self, request: &IssueRequest) -> Reply {
        if ona_near::check_account_id(&request.account).is_err() {
            return refused(400, "not a NEAR account");
        }
        let points: Vec<[u8; G1_LEN]> = request.notes.iter().map(|(_, b)| *b).collect();
        let cash_tiers = self.keys.cash.len();
        if !valid_points(&points) || request.notes.iter().any(|(t, _)| usize::from(*t) >= cash_tiers) {
            return refused(400, "invalid blinded points or unknown cash tier");
        }
        let mut groups: BTreeMap<u8, Vec<[u8; G1_LEN]>> = BTreeMap::new();
        for (tier, b) in &request.notes {
            groups.entry(*tier).or_default().push(*b);
        }
        if groups.values().any(|g| g.len() as u64 > MAX_OUTPUTS) {
            return refused(400, "at most 64 notes per tier");
        }
        let id = {
            let mut h = Sha256::new();
            h.update(request.account.as_bytes());
            h.update([0]);
            for (tier, b) in &request.notes {
                h.update([*tier]);
                h.update(b);
            }
            format!("i:{}", hex(&h.finalize()))
        };
        if let Some(reply) = self.store.get(&id).as_ref().and_then(Self::signed_reply) {
            return reply;
        }
        // The proof first: nothing is read or recorded for a request the depositor did not sign.
        let message = nep413::issue_message(&self.pool, &request.account, &request.notes);
        let hash = nep413::payload_hash(&message, &request.proof.nonce, &self.pool);
        if !nep413::verify(&request.proof.public_key, &hash, &request.proof.signature) {
            return refused(401, "the depositor's signature does not match this request");
        }
        if self.store.get(&id).is_none() {
            let local = (self.clock)();
            let hour = local / HOUR_NS;
            let entry = self.issues.entry(request.account.clone()).or_insert((hour, 0));
            if entry.0 != hour {
                *entry = (hour, 0);
            }
            if entry.1 >= self.queue.issues_per_hour {
                return refused(429, "too many cash issues for this account this hour");
            }
            entry.1 += 1;
        }
        if let Err(e) = self.chain.begin() {
            return Self::chain_err(e);
        }
        // Checked when the issue opens. A replay of an open issue is not checked again: the account may have removed
        // the key since, and the client would forget notes the agent can still sign.
        if self.store.get(&id).is_none() {
            match self.chain.full_access_key(&request.account, &request.proof.public_key) {
                Ok(true) => {}
                Ok(false) => return refused(401, "the signing key is not a full-access key of this account"),
                Err(e) => return Self::chain_err(e),
            }
        }
        let lock_key = format!("a:{}", request.account);
        match self.store.get(&lock_key).and_then(|v| v.as_str().map(String::from)) {
            // A lock left by a crash after its issue closed holds nothing.
            Some(other) if other != id && self.store.get(&other).is_some_and(|r| r["s"] == "open") => {
                return refused(409, "an earlier cash issue of this account is not settled yet")
            }
            _ => {}
        }
        if self.store.get(&id).is_none() {
            let cash = match self.chain.cash() {
                Ok(cash) => cash,
                Err(e) => return Self::chain_err(e),
            };
            let mut total = 0u128;
            for (t, g) in &groups {
                let value = cash.tiers.get(usize::from(*t)).and_then(|tier| tier.0.checked_mul(g.len() as u128));
                match value.and_then(|v| total.checked_add(v)) {
                    Some(sum) => total = sum,
                    None => return refused(400, "amount too large"),
                }
            }
            match self.chain.holder(&request.account) {
                Ok(h) if h.refundable >= total => {}
                Ok(_) => return refused(409, "more than this account's deposits not turned into cash"),
                Err(e) => return Self::chain_err(e),
            }
            let steps: Vec<Value> = groups.iter().map(|(t, g)| json!({"tier": t, "count": g.len(), "s": "new"})).collect();
            let notes: Vec<Value> = request.notes.iter().map(|(t, b)| json!({"tier": t, "b": b64(b)})).collect();
            let record = json!({"s": "open", "account": request.account, "notes": notes, "steps": steps});
            // The record first: `tick` restores a missing account lock from an open record.
            if let Err(r) = self.put(&id, record).and_then(|()| self.put(&lock_key, json!(id))) {
                return r;
            }
        }
        self.advance_issue(&id)
    }

    fn issue_notes(record: &Value) -> Vec<(u8, [u8; G1_LEN])> {
        record["notes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|n| {
                        let b: [u8; G1_LEN] = n["b"].as_str().and_then(|s| B64.decode(s).ok())?.try_into().ok()?;
                        Some((u8::try_from(n["tier"].as_u64()?).ok()?, b))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Runs or confirms each tier of a recorded issue in turn; signs when every tier is confirmed.
    fn advance_issue(&mut self, id: &str) -> Reply {
        let Some(mut record) = self.store.get(id) else {
            return refused(404, "unknown request");
        };
        if let Some(reply) = Self::signed_reply(&record) {
            return reply;
        }
        let account = record["account"].as_str().unwrap_or_default().to_string();
        let now = match self.chain.begin() {
            Ok(now) => now,
            Err(e) => return Self::chain_err(e),
        };
        let cash = match self.chain.cash() {
            Ok(cash) => cash,
            Err(e) => return Self::chain_err(e),
        };
        let steps = record["steps"].as_array().cloned().unwrap_or_default();
        for (i, step) in steps.iter().enumerate() {
            let tier = step["tier"].as_u64().and_then(|t| u8::try_from(t).ok()).unwrap_or(u8::MAX);
            let count = step["count"].as_u64().unwrap_or(0);
            let Some(value) = cash.tiers.get(usize::from(tier)).and_then(|t| t.0.checked_mul(u128::from(count))) else {
                return refused(409, "unknown cash tier");
            };
            let issued_now = match self.chain.holder(&account) {
                Ok(h) => h.issued,
                Err(e) => return Self::chain_err(e),
            };
            match step["s"].as_str() {
                Some("done") => continue,
                Some("sent") => {
                    let before: u128 = step["issued_before"].as_str().and_then(|s| s.parse().ok()).unwrap_or(u128::MAX);
                    if issued_now >= before.saturating_add(value) {
                        record["steps"][i]["s"] = json!("done");
                        if let Err(r) = self.put(id, record.clone()) {
                            return r;
                        }
                        continue;
                    }
                    // Both read endpoints reporting a final failure stop the wait; nothing here starts a signature.
                    if let Some(hash) = step["tx"].as_str().and_then(unhex32) {
                        if let Ok(Some(false)) = self.chain.tx_outcome(&hash) {
                            record["steps"][i]["s"] = json!("new");
                            return self.close_refused(id, &mut record, &account, "the cash issue failed on chain", now);
                        }
                    }
                    let sent_at = step["sent_at"].as_u64().unwrap_or(0);
                    if now > sent_at.saturating_add(TX_EXPIRY_NS) {
                        return self.close_refused(id, &mut record, &account, "the cash issue never landed", now);
                    }
                    return Reply::Pending("cash issue sent, waiting for the chain".into());
                }
                _ => {}
            }
            // Signed first: its hash is recorded with the step before the transaction leaves, so a crash in between
            // still lets the agent find it.
            let hash = match self.chain.prepare(&Call::IssueCash { account: account.clone(), tier, count }) {
                Ok(hash) => hash,
                Err(e) => return Reply::Pending(format!("cannot sign the cash issue yet: {}", e.message())),
            };
            record["steps"][i]["s"] = json!("sent");
            record["steps"][i]["issued_before"] = json!(issued_now.to_string());
            record["steps"][i]["sent_at"] = json!(now);
            record["steps"][i]["tx"] = json!(hex(&hash));
            if let Err(r) = self.put(id, record.clone()) {
                return r;
            }
            match self.chain.send_prepared() {
                // Confirmed below, by a cross-checked read, before anything is signed.
                Ok(()) => {
                    if let Err(e) = self.chain.begin() {
                        return Self::chain_err(e);
                    }
                    match self.chain.holder(&account) {
                        Ok(h) if h.issued >= issued_now.saturating_add(value) => {
                            record["steps"][i]["s"] = json!("done");
                            if let Err(r) = self.put(id, record.clone()) {
                                return r;
                            }
                        }
                        Ok(_) => return Reply::Pending("cash issue sent, not seen on chain yet".into()),
                        Err(e) => return Self::chain_err(e),
                    }
                }
                Err(CallError::Refused(e)) => {
                    record["steps"][i]["s"] = json!("new");
                    return self.close_refused(id, &mut record, &account, &format!("refused by the chain: {e}"), now);
                }
                // One node's "failed" is confirmed by both read endpoints (above, on the next pass) before the issue
                // is closed: until then it waits as an unknown outcome.
                Err(CallError::Failed(e) | CallError::Unknown(e)) => {
                    return Reply::Pending(format!("outcome not confirmed: {e}"));
                }
            }
        }
        let notes = Self::issue_notes(&record);
        let tiers: Vec<u8> = notes.iter().map(|n| n.0).collect();
        let blinded: Vec<[u8; G1_LEN]> = notes.iter().map(|n| n.1).collect();
        let sigs = match self.sign(&self.keys.cash, &tiers, &blinded) {
            Ok(sigs) => sigs,
            Err(e) => return refused(500, e),
        };
        // The finished record keeps no account.
        let done = json!({"s": "done", "sigs": sigs.iter().map(|s| b64(s)).collect::<Vec<_>>(), "at": now});
        if let Err(r) = self.remember(&blinded, &sigs, now).and_then(|()| self.put(id, done)).and_then(|()| self.put(&format!("a:{account}"), Value::Null)) {
            return r;
        }
        Reply::Signed(sigs)
    }

    /// Closes an issue that cannot complete. Tiers already issued keep their signatures, available through
    /// `signatures`.
    fn close_refused(&mut self, id: &str, record: &mut Value, account: &str, why: &str, now: u64) -> Reply {
        let done_tiers: Vec<u8> = record["steps"]
            .as_array()
            .map(|s| s.iter().filter(|s| s["s"] == "done").filter_map(|s| s["tier"].as_u64()).filter_map(|t| u8::try_from(t).ok()).collect())
            .unwrap_or_default();
        let notes: Vec<(u8, [u8; G1_LEN])> = Self::issue_notes(record).into_iter().filter(|(t, _)| done_tiers.contains(t)).collect();
        let tiers: Vec<u8> = notes.iter().map(|n| n.0).collect();
        let blinded: Vec<[u8; G1_LEN]> = notes.iter().map(|n| n.1).collect();
        if let Ok(sigs) = self.sign(&self.keys.cash, &tiers, &blinded) {
            if let Err(r) = self.remember(&blinded, &sigs, now) {
                return r;
            }
        }
        let closed = json!({"s": "refused", "why": why, "at": now});
        if let Err(r) = self.put(id, closed).and_then(|()| self.put(&format!("a:{account}"), Value::Null)) {
            return r;
        }
        refused(409, why)
    }

    // ---- notes: enter, leave, pay ----

    /// Checks a note under its tier key and its owner's signature on `digest`, off chain.
    fn check_note(note: &Note, key: &[u8; G2_LEN], dst: &str, owner_sig: &[u8; 64], digest: &[u8; 32]) -> Result<(), Reply> {
        let token = Token { denom_id: note.tier, pk: note.pk, nonce: note.nonce, sig: note.sig };
        if !verify_token(key, &token, dst.as_bytes()) {
            return Err(refused(400, "invalid note"));
        }
        if !nep413::verify(&note.pk, digest, owner_sig) {
            return Err(refused(400, "bad owner signature"));
        }
        Ok(())
    }

    fn local_deadline_ok(&self, expires_at: u64) -> Result<(), Reply> {
        if (self.clock)() > expires_at.saturating_add(CLOCK_MARGIN_NS) {
            return Err(refused(400, "the owner's signature has expired"));
        }
        Ok(())
    }

    pub fn note_request(&mut self, request: &NoteRequest) -> Reply {
        let total: u64 = request.outputs.iter().map(|(_, c)| *c).fold(0, u64::saturating_add);
        if request.outputs.is_empty() || total == 0 || total > MAX_OUTPUTS || total as usize != request.blinded.len() {
            return refused(400, "outputs and blinded points do not match, or more than 64 notes");
        }
        if !valid_points(&request.blinded) {
            return refused(400, "invalid blinded point");
        }
        if let Err(r) = self.local_deadline_ok(request.expires_at) {
            return r;
        }
        // Keys held here: no RPC read before the note and its owner's signature check.
        let Some(vault_keys) = self.keys.vault_public(request.vault as usize) else {
            return refused(400, "no such vault");
        };
        let cash_keys = self.keys.cash_public();
        let (note_key, note_dst, out_tiers, nf) = match request.kind {
            Kind::Enter => (
                cash_keys.get(usize::from(request.note.tier)).copied(),
                digests::cash_dst(&self.network, &self.pool),
                vault_keys.len(),
                digests::cash_nullifier(request.note.tier, &request.note.pk, &request.note.nonce),
            ),
            Kind::Leave => (
                vault_keys.get(usize::from(request.note.tier)).copied(),
                digests::note_dst(&self.network, &self.pool, request.vault),
                cash_keys.len(),
                digests::note_nullifier(request.vault, request.note.tier, &request.note.pk, &request.note.nonce),
            ),
        };
        let Some(note_key) = note_key else {
            return refused(400, "unknown tier");
        };
        if request.outputs.iter().any(|(t, _)| usize::from(*t) >= out_tiers) {
            return refused(400, "unknown output tier");
        }
        let digest = match request.kind {
            Kind::Enter => digests::enter_digest(&self.pool, &nf, request.vault, &request.outputs, request.expires_at),
            Kind::Leave => digests::leave_digest(&self.pool, request.vault, &nf, &request.outputs, request.expires_at),
        };
        if let Err(r) = Self::check_note(&request.note, &note_key, &note_dst, &request.owner_sig, &digest) {
            return r;
        }
        let payload = json!({
            "kind": request.kind.name(), "vault": request.vault, "note": request.note.to_json(),
            "owner_sig": b64(&request.owner_sig), "expires_at": request.expires_at,
            "outputs": request.outputs.iter().map(|(t, c)| json!([t, c])).collect::<Vec<_>>(),
            "blinded": request.blinded.iter().map(|b| b64(b)).collect::<Vec<_>>(),
        });
        // An entry spends a cash note into a vault, a leave a share note of that vault.
        let cash = request.kind == Kind::Enter;
        self.queue_note(nf, &request.owner_sig, &points_hash(&request.blinded), payload, request.expires_at, (cash, Some(request.vault)))
    }

    pub fn pay(&mut self, request: &PayRequest) -> Reply {
        if ona_near::check_account_id(&request.to).is_err() {
            return refused(400, "not a NEAR account");
        }
        if let Err(r) = self.local_deadline_ok(request.expires_at) {
            return r;
        }
        let Some(key) = self.keys.cash_public().get(usize::from(request.note.tier)).copied() else {
            return refused(400, "unknown tier");
        };
        let nf = digests::cash_nullifier(request.note.tier, &request.note.pk, &request.note.nonce);
        let digest = digests::cash_exit_digest(&self.pool, &nf, &request.to, request.expires_at);
        if let Err(r) = Self::check_note(&request.note, &key, &digests::cash_dst(&self.network, &self.pool), &request.owner_sig, &digest) {
            return r;
        }
        let payload = json!({
            "kind": "pay", "note": request.note.to_json(), "owner_sig": b64(&request.owner_sig),
            "expires_at": request.expires_at, "to": request.to,
        });
        let to_hash = hex(&Sha256::digest(request.to.as_bytes()));
        self.queue_note(nf, &request.owner_sig, &to_hash, payload, request.expires_at, (true, None))
    }

    /// Whether a queued or sent request holds its note.
    fn live(&self, id: &str) -> bool {
        self.store.get(id).is_some_and(|r| matches!(r["s"].as_str(), Some("queued" | "sent")))
    }

    /// Refuses while the escape is open on the cash (when `scope.0`) or on the vault: anyone may then spend the note
    /// with `escape_exit`, and a request waiting in the queue would be overtaken.
    fn escape_closed(&mut self, scope: (bool, Option<u32>)) -> Result<(), Reply> {
        if scope.0 && self.chain.cash().map_err(Self::chain_err)?.open {
            return Err(refused(409, "the cash's escape is open: no request is queued until it closes"));
        }
        if let Some(v) = scope.1 {
            if self.chain.vault(v).map_err(Self::chain_err)?.open {
                return Err(refused(409, "this vault's escape is open: no request is queued until it closes"));
            }
        }
        Ok(())
    }

    /// Records a checked note request and queues it. The record is written first; its note binding and its owner
    /// signature's binding follow, and `tick` restores them if a crash came between.
    fn queue_note(&mut self, nf: [u8; 32], owner_sig: &[u8; 64], bound: &str, payload: Value, expires_at: u64, scope: (bool, Option<u32>)) -> Reply {
        let id = format!("q:{}", hex(&Sha256::digest(payload.to_string().as_bytes())));
        let nf_key = format!("n:{}", hex(&nf));
        let sig_key = format!("o:{}:{}", hex(&nf), hex(&Sha256::digest(owner_sig)));
        if let Some(record) = self.store.get(&id) {
            return Self::signed_reply(&record).unwrap_or_else(|| Reply::Pending("queued, sent with a later batch".into()));
        }
        match self.store.get(&sig_key) {
            Some(v) if v["h"].as_str() != Some(bound) => {
                return refused(409, "this owner signature already went out with other points: sign again with a new deadline")
            }
            _ => {}
        }
        match self.store.get(&nf_key).and_then(|v| v.as_str().map(String::from)) {
            // A binding left by a crash after its request finished holds nothing.
            Some(other) if other != id && self.live(&other) => return refused(409, "this note is already used by another request"),
            _ => {}
        }
        let now = match self.chain.begin() {
            Ok(now) => now,
            Err(e) => return Self::chain_err(e),
        };
        if now > expires_at {
            return refused(400, "the owner's signature has expired");
        }
        match self.chain.is_spent(&nf) {
            Ok(false) => {}
            Ok(true) => return refused(409, "note already spent"),
            Err(e) => return Self::chain_err(e),
        }
        if let Err(r) = self.escape_closed(scope) {
            return r;
        }
        let jitter = if self.queue.jitter_ns == 0 { 0 } else { OsRng.gen_range(0..=self.queue.jitter_ns) };
        let not_before = now.saturating_add(self.queue.min_delay_ns).saturating_add(jitter);
        let record = json!({"s": "queued", "nf": hex(&nf), "sig": sig_key, "bound": bound, "p": payload, "expires_at": expires_at, "not_before": not_before});
        if let Err(r) = self
            .put(&id, record)
            .and_then(|()| self.put(&sig_key, json!({"h": bound, "exp": expires_at})))
            .and_then(|()| self.put(&nf_key, json!(id)))
        {
            return r;
        }
        Reply::Pending("queued, sent with a later batch".into())
    }

    /// The value a queued request will take out: a share note's at the vault's price, or a cash note's.
    fn outflow(&mut self, p: &Value) -> Result<(Option<u32>, u128), String> {
        let tier = usize::from(p["note"]["tier"].as_u64().and_then(|t| u8::try_from(t).ok()).ok_or("corrupt record")?);
        match p["kind"].as_str() {
            Some("leave") => {
                let vault = u32::try_from(p["vault"].as_u64().ok_or("corrupt record")?).map_err(|_| "corrupt record")?;
                let v = self.chain.vault(vault)?;
                let shares = v.tiers.get(tier).ok_or("unknown tier")?.0;
                Ok((Some(vault), shares.checked_mul(v.share_price).ok_or("amount too large")?))
            }
            Some("pay") => Ok((None, self.chain.cash()?.tiers.get(tier).ok_or("unknown tier")?.0)),
            _ => Ok((None, 0)),
        }
    }

    /// What the agent itself has taken out of a vault (`Some`) or the cash (`None`) in this calendar hour: the
    /// contract counts every exit of the hour against one cap.
    fn hour_used(&self, scope: Option<u32>, now: u64) -> u128 {
        let key = scope.map_or("h:cash".to_string(), |v| format!("h:v{v}"));
        match self.store.get(&key) {
            Some(h) if h["hour"].as_u64() == Some(now / HOUR_NS) => h["used"].as_str().and_then(|s| s.parse().ok()).unwrap_or(u128::MAX),
            _ => 0,
        }
    }

    fn add_hour(&mut self, scope: Option<u32>, now: u64, amount: u128) {
        let key = scope.map_or("h:cash".to_string(), |v| format!("h:v{v}"));
        let used = self.hour_used(scope, now).saturating_add(amount);
        let _ = self.store.put(&key, json!({"hour": now / HOUR_NS, "used": used.to_string()}));
    }

    /// Whether the funds a request takes out are there: liquid funds beyond what the vault's listed exit requests may
    /// claim, and room under the hourly cap. A refused call is public and names the vault, so the agent waits instead.
    fn fits(&mut self, scope: Option<u32>, value: u128, now: u64) -> Result<bool, String> {
        let used = self.hour_used(scope, now);
        let (free, cap) = match scope {
            Some(v) => {
                let info = self.chain.vault(v)?;
                (info.liquid.saturating_sub(listed_bound(&info)), info.hourly_cap)
            }
            None => {
                let cash = self.chain.cash()?;
                (cash.liquid, cash.hourly_cap)
            }
        };
        Ok(value <= free && window_ok(used, cap, value))
    }

    /// Moves one queued or sent note request on. A note found spent is signed only if this request's own transaction
    /// is confirmed by both read endpoints; a request still queued whose note is spent (by `escape_exit` or a listed
    /// request) is refused. Past its deadline it is refused and its note freed. Otherwise, when `send_in` names the
    /// current window, it is sent (again) once its funds are there.
    fn advance_note(&mut self, id: &str, now: u64, send_in: Option<u64>) -> Reply {
        let Some(record) = self.store.get(id) else {
            return refused(404, "unknown request");
        };
        if let Some(reply) = Self::signed_reply(&record) {
            return reply;
        }
        let Some(nf) = record["nf"].as_str().and_then(unhex32) else {
            return refused(500, "corrupt record");
        };
        let expires_at = record["expires_at"].as_u64().unwrap_or(0);
        match self.chain.is_spent(&nf) {
            Ok(true) if record["s"] == "queued" => {
                return self.release_note(id, &nf, "the note was spent by another call before this request was sent", now)
            }
            Ok(true) => return self.confirm_sent(id, &record, &nf, expires_at, now),
            Ok(false) => {}
            Err(e) => return Self::chain_err(e),
        }
        if record["s"] == "sent" && self.all_failed(&record) {
            return self.release_note(id, &nf, "its transaction failed on chain", now);
        }
        if now.saturating_add(SEND_MARGIN_NS) > expires_at {
            if now > expires_at || record["s"] == "queued" {
                return self.release_note(id, &nf, "the owner's signature expired before the request could be sent", now);
            }
            return Reply::Pending("sent, waiting for the chain".into());
        }
        let Some(window) = send_in else {
            return Reply::Pending("sent, waiting for the chain or for a window of its kind".into());
        };
        let p = record["p"].clone();
        let (Some(note), Some(owner_sig)) =
            (parse_note(&p["note"]), p["owner_sig"].as_str().and_then(|s| B64.decode(s).ok()).and_then(|b| <[u8; 64]>::try_from(b).ok()))
        else {
            return refused(500, "corrupt record");
        };
        let outputs: Vec<(u8, u64)> = p["outputs"]
            .as_array()
            .map(|a| a.iter().filter_map(|o| Some((u8::try_from(o[0].as_u64()?).ok()?, o[1].as_u64()?))).collect())
            .unwrap_or_default();
        let vault = p["vault"].as_u64().and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
        let kind = p["kind"].as_str().unwrap_or_default().to_string();
        // A refused call is public and names the vault: wait for the funds instead.
        let (scope, value) = match self.outflow(&p) {
            Ok(out) => out,
            Err(e) => return Self::chain_err(e),
        };
        if kind != "enter" {
            match self.fits(scope, value, now) {
                Ok(true) => {}
                Ok(false) => return Reply::Pending("waiting for liquid funds".into()),
                Err(e) => return Self::chain_err(e),
            }
        }
        if kind != "pay" {
            if let Err(r) = self.fresh_price(vault, now) {
                return r;
            }
        }
        let call = match kind.as_str() {
            "enter" => Call::Enter { vault, note, owner_sig, outputs, expires_at },
            "leave" => Call::Leave { vault, note, owner_sig, outputs, expires_at },
            _ => Call::PayExit { note, owner_sig, to: p["to"].as_str().unwrap_or_default().to_string(), expires_at },
        };
        // Signed first, and its hash recorded with the request before it leaves: after a crash in between, the
        // agent still finds its own transaction and can confirm it.
        let hash = match self.chain.prepare(&call) {
            Ok(hash) => hash,
            Err(e) => return Reply::Pending(format!("cannot sign the transaction yet: {}", e.message())),
        };
        let mut sent = record.clone();
        sent["s"] = json!("sent");
        sent["w"] = json!(window);
        let mut txs = sent["txs"].as_array().cloned().unwrap_or_default();
        txs.push(json!(hex(&hash)));
        sent["txs"] = json!(txs);
        if let Err(r) = self.put(id, sent.clone()) {
            return r;
        }
        if kind != "enter" {
            self.add_hour(scope, now, value);
        }
        match self.chain.send_prepared() {
            Ok(()) | Err(CallError::Unknown(_) | CallError::Failed(_)) => {
                // Confirmed by cross-checked reads, never by the sending endpoint's word, whether it says success or
                // failure.
                if let Err(e) = self.chain.begin() {
                    return Self::chain_err(e);
                }
                match self.chain.is_spent(&nf) {
                    Ok(true) => self.confirm_sent(id, &sent, &nf, expires_at, now),
                    Ok(false) if self.all_failed(&sent) => self.release_note(id, &nf, "its transaction failed on chain", now),
                    Ok(false) => Reply::Pending("sent, not seen on chain yet".into()),
                    Err(e) => Self::chain_err(e),
                }
            }
            Err(CallError::Refused(e)) => self.release_note(id, &nf, &format!("not sent: {e}"), now),
        }
    }

    /// Every transaction sent for this request has a final failure on both read endpoints.
    fn all_failed(&mut self, record: &Value) -> bool {
        let txs: Vec<[u8; 32]> = record["txs"].as_array().map(|a| a.iter().filter_map(|h| h.as_str().and_then(unhex32)).collect()).unwrap_or_default();
        !txs.is_empty() && txs.iter().all(|h| matches!(self.chain.tx_outcome(h), Ok(Some(false))))
    }

    /// The note is spent. Signed only if one of this request's own transactions succeeded, as both read endpoints
    /// report; refused once all of them failed, or once the outcome stays unknown `TX_EXPIRY_NS` past the deadline.
    fn confirm_sent(&mut self, id: &str, record: &Value, nf: &[u8; 32], expires_at: u64, now: u64) -> Reply {
        let txs: Vec<[u8; 32]> = record["txs"].as_array().map(|a| a.iter().filter_map(|h| h.as_str().and_then(unhex32)).collect()).unwrap_or_default();
        let mut unknown = txs.is_empty();
        for hash in &txs {
            match self.chain.tx_outcome(hash) {
                Ok(Some(true)) => return self.finish_note(id, record, now),
                Ok(Some(false)) => {}
                _ => unknown = true,
            }
        }
        if unknown && now <= expires_at.saturating_add(TX_EXPIRY_NS) {
            return Reply::Pending("the note is spent: waiting for both endpoints to confirm this request's transaction".into());
        }
        self.release_note(id, nf, "the note was spent, not by this request's transaction", now)
    }

    /// The vault's price must be read within the hour: the agent syncs it first when its reading is old.
    fn fresh_price(&mut self, vault: u32, now: u64) -> Result<(), Reply> {
        let info = self.chain.vault(vault).map_err(Self::chain_err)?;
        if now >= info.synced_at.saturating_add(SYNC_BEFORE_USE_NS) {
            self.chain.run(&Call::Sync(vault)).map_err(|e| Reply::Pending(format!("vault sync first: {}", e.message())))?;
        }
        Ok(())
    }

    fn finish_note(&mut self, id: &str, record: &Value, now: u64) -> Reply {
        let p = &record["p"];
        let kind = p["kind"].as_str().unwrap_or_default();
        let nf_key = format!("n:{}", record["nf"].as_str().unwrap_or_default());
        if kind == "pay" {
            return match self.put(id, json!({"s": "done", "at": now})).and_then(|()| self.put(&nf_key, Value::Null)) {
                Ok(()) => Reply::Paid,
                Err(r) => r,
            };
        }
        let blinded = decode_points(&p["blinded"]).unwrap_or_default();
        let tiers: Vec<u8> = p["outputs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .flat_map(|o| std::iter::repeat_n(o[0].as_u64().and_then(|t| u8::try_from(t).ok()).unwrap_or(u8::MAX), o[1].as_u64().unwrap_or(0) as usize))
                    .collect()
            })
            .unwrap_or_default();
        let vault = p["vault"].as_u64().unwrap_or(0) as usize;
        let keys = if kind == "enter" { self.keys.vaults.get(vault).map(Vec::as_slice).unwrap_or(&[]) } else { &self.keys.cash };
        let sigs = match self.sign(keys, &tiers, &blinded) {
            Ok(sigs) => sigs,
            Err(e) => return refused(500, e),
        };
        // The finished record keeps no vault, note or deadline.
        let done = json!({"s": "done", "sigs": sigs.iter().map(|s| b64(s)).collect::<Vec<_>>(), "at": now});
        if let Err(r) = self.remember(&blinded, &sigs, now).and_then(|()| self.put(id, done)).and_then(|()| self.put(&nf_key, Value::Null)) {
            return r;
        }
        let mut memory = self.memory();
        memory.activity += 1;
        let _ = self.store.put("p:memory", memory.to_json());
        Reply::Signed(sigs)
    }

    /// The note was not spent and never will be by this request: it may serve another one. The binding of its owner
    /// signature to its points stays until that signature's deadline.
    fn release_note(&mut self, id: &str, nf: &[u8; 32], why: &str, now: u64) -> Reply {
        if let Err(r) = self.put(id, json!({"s": "refused", "why": why, "at": now})).and_then(|()| self.put(&format!("n:{}", hex(nf)), Value::Null)) {
            return r;
        }
        refused(409, why)
    }

    /// The signatures already made for these points, in order.
    pub fn signatures(&self, blinded: &[[u8; G1_LEN]]) -> Vec<Option<[u8; G1_LEN]>> {
        blinded
            .iter()
            .map(|b| {
                self.store
                    .get(&format!("b:{}", hex(b)))
                    .and_then(|v| v["sig"].as_str().and_then(|s| B64.decode(s).ok()))
                    .and_then(|b| b.try_into().ok())
            })
            .collect()
    }

    // ---- background work ----

    fn memory(&self) -> Memory {
        self.store.get("p:memory").map(|v| Memory::from_json(&v)).unwrap_or_default()
    }

    /// Restores bindings a crash may have left unwritten after their record, and removes those a crash left behind
    /// after their request finished (a note binding, an account's lock).
    fn repair(&mut self) -> Result<(), String> {
        for (key, v) in self.store.scan("n:") {
            if !v.as_str().is_some_and(|id| self.live(id)) {
                self.store.put(&key, Value::Null)?;
            }
        }
        for (key, v) in self.store.scan("a:") {
            if !v.as_str().is_some_and(|id| self.store.get(id).is_some_and(|r| r["s"] == "open")) {
                self.store.put(&key, Value::Null)?;
            }
        }
        for (id, record) in self.store.scan("q:") {
            if !matches!(record["s"].as_str(), Some("queued" | "sent")) {
                continue;
            }
            if let (Some(sig_key), Some(bound)) = (record["sig"].as_str(), record["bound"].as_str()) {
                if self.store.get(sig_key).is_none() {
                    self.store.put(sig_key, json!({"h": bound, "exp": record["expires_at"]}))?;
                }
            }
            let nf_key = format!("n:{}", record["nf"].as_str().unwrap_or_default());
            if self.store.get(&nf_key).is_none() {
                self.store.put(&nf_key, json!(id))?;
            }
        }
        for (id, record) in self.store.scan("i:") {
            if record["s"] == "open" {
                let lock = format!("a:{}", record["account"].as_str().unwrap_or_default());
                if self.store.get(&lock).is_none() {
                    self.store.put(&lock, json!(id))?;
                }
            }
        }
        Ok(())
    }

    /// Deletes what is no longer needed: finished records and signatures after the retention, owner-signature
    /// bindings after their deadline.
    fn purge(&mut self, now: u64) -> Result<(), String> {
        let old = |v: &Value| v["at"].as_u64().is_some_and(|at| now > at.saturating_add(self.queue.retention_ns));
        let mut gone = Vec::new();
        for prefix in ["q:", "i:"] {
            for (k, v) in self.store.scan(prefix) {
                if matches!(v["s"].as_str(), Some("done" | "refused")) && old(&v) {
                    gone.push(k);
                }
            }
        }
        for (k, v) in self.store.scan("b:") {
            if old(&v) {
                gone.push(k);
            }
        }
        for (k, v) in self.store.scan("o:") {
            if v["exp"].as_u64().is_some_and(|exp| now > exp) {
                gone.push(k);
            }
        }
        if gone.is_empty() {
            return Ok(());
        }
        for k in gone {
            self.store.put(&k, Value::Null)?;
        }
        // What was deleted leaves the file now, not after hundreds of later writes.
        self.store.compact()
    }

    /// The class of a window: entries and leaves in even windows, cash exits in odd ones.
    fn window_class(&self, now: u64) -> (u64, &'static [&'static str]) {
        let window = now / self.queue.window_ns.max(1);
        (window, if window % 2 == 0 { &["enter", "leave"] } else { &["pay"] })
    }

    /// Sends the current window's batch, if at least `min_batch` of its ready requests can go now, in random order.
    fn run_batch(&mut self, now: u64, log: &mut Vec<String>) {
        let (window, class) = self.window_class(now);
        let records = self.store.scan("q:");
        // Requests sent earlier with an unknown outcome are confirmed whatever the window, and sent again only in a
        // window of their kind, once per window.
        for (id, record) in &records {
            if record["s"] == "sent" {
                let kind = record["p"]["kind"].as_str().unwrap_or_default();
                let send_in = (class.contains(&kind) && record["w"].as_u64() != Some(window)).then_some(window);
                log.push(format!("{id}: {:?}", self.advance_note(id, now, send_in)));
            }
        }
        let mut ready = Vec::new();
        for (id, record) in records {
            if record["s"] != "queued" {
                continue;
            }
            let expires_at = record["expires_at"].as_u64().unwrap_or(0);
            if now.saturating_add(SEND_MARGIN_NS) > expires_at {
                log.push(format!("{id}: {:?}", self.advance_note(&id, now, None)));
                continue;
            }
            let kind = record["p"]["kind"].as_str().unwrap_or_default();
            if class.contains(&kind) && record["not_before"].as_u64().is_some_and(|t| now >= t) {
                ready.push(id);
            }
        }
        let k = self.queue.min_batch.max(1);
        if self.memory().last_window == Some(window) || ready.len() < k {
            return;
        }
        // Random order: the order of arrival does not show in the order of sending.
        for i in (1..ready.len()).rev() {
            let j = (OsRng.next_u64() % (i as u64 + 1)) as usize;
            ready.swap(i, j);
        }
        // The batch is counted after the funds and the prices are checked: k requests leave together, or none.
        let sendable = self.sendable(&ready, now);
        if sendable.len() < k {
            log.push(format!("window {window}: {} of {} ready requests can go now, fewer than {k}", sendable.len(), ready.len()));
            return;
        }
        for id in sendable {
            log.push(format!("{id}: {:?}", self.advance_note(&id, now, Some(window))));
        }
        let mut memory = self.memory();
        memory.last_window = Some(window);
        let _ = self.store.put("p:memory", memory.to_json());
    }

    /// The ready requests that can be sent now, in their order: the vault's price fresh (synced first when old), no
    /// escape open on what they spend, and their outflows together within the liquid funds (less what listed exit
    /// requests may claim) and the hourly caps, counting what the agent already took out this hour.
    fn sendable(&mut self, ready: &[String], now: u64) -> Vec<String> {
        let Ok(cash) = self.chain.cash() else {
            return Vec::new();
        };
        let mut cash_left = cash.liquid;
        let mut cash_used = self.hour_used(None, now);
        // Per vault: its figures once fresh, liquid funds left, taken out this hour. `None`: unusable now.
        let mut vaults: HashMap<u32, Option<(VaultInfo, u128, u128)>> = HashMap::new();
        let mut out = Vec::new();
        for id in ready {
            let Some(record) = self.store.get(id) else { continue };
            let p = &record["p"];
            let tier = p["note"]["tier"].as_u64().and_then(|t| usize::try_from(t).ok()).unwrap_or(usize::MAX);
            let kind = p["kind"].as_str().unwrap_or_default();
            if kind == "pay" {
                let Some(value) = cash.tiers.get(tier).map(|t| t.0) else { continue };
                if !cash.open && value <= cash_left && window_ok(cash_used, cash.hourly_cap, value) {
                    cash_left -= value;
                    cash_used = cash_used.saturating_add(value);
                    out.push(id.clone());
                }
                continue;
            }
            let Some(v) = p["vault"].as_u64().and_then(|v| u32::try_from(v).ok()) else { continue };
            if !vaults.contains_key(&v) {
                let state = self.fresh_vault(v, now).map(|info| {
                    let left = info.liquid.saturating_sub(listed_bound(&info));
                    (info, left, self.hour_used(Some(v), now))
                });
                vaults.insert(v, state);
            }
            let Some(Some((info, left, used))) = vaults.get_mut(&v) else { continue };
            if info.open {
                continue;
            }
            if kind == "enter" {
                if !cash.open && !info.frozen {
                    out.push(id.clone());
                }
                continue;
            }
            let Some(value) = info.tiers.get(tier).and_then(|t| t.0.checked_mul(info.share_price)) else { continue };
            if value <= *left && window_ok(*used, info.hourly_cap, value) {
                *left -= value;
                *used = used.saturating_add(value);
                out.push(id.clone());
            }
        }
        out
    }

    /// A vault's figures with a price read within the hour, syncing it first when needed.
    fn fresh_vault(&mut self, v: u32, now: u64) -> Option<VaultInfo> {
        let info = self.chain.vault(v).ok()?;
        if now < info.synced_at.saturating_add(SYNC_BEFORE_USE_NS) {
            return Some(info);
        }
        self.chain.run(&Call::Sync(v)).ok()?;
        self.chain.begin().ok()?;
        self.chain.vault(v).ok().filter(|info| now < info.synced_at.saturating_add(SYNC_BEFORE_USE_NS))
    }

    /// What queued leaves will take out of each vault.
    fn demand(&mut self, vault_count: u32) -> Vec<u128> {
        let mut demand = vec![0u128; vault_count as usize];
        for (_, record) in self.store.scan("q:") {
            if record["s"] == "queued" && record["p"]["kind"] == "leave" {
                if let Ok((Some(v), value)) = self.outflow(&record["p"].clone()) {
                    if let Some(d) = demand.get_mut(v as usize) {
                        *d = d.saturating_add(value);
                    }
                }
            }
        }
        demand
    }

    /// Repairs, settles open issues, sends the window's batch, runs the planner's actions and purges. Returns what it
    /// did, for the log, without any signature.
    pub fn tick(&mut self) -> Result<Vec<String>, String> {
        let mut log = Vec::new();
        self.repair()?;
        for (id, record) in self.store.scan("i:") {
            if record["s"] == "open" {
                log.push(format!("{id}: {:?}", self.advance_issue(&id)));
            }
        }
        let now = self.chain.begin()?;
        self.run_batch(now, &mut log);
        let now = self.chain.begin()?;
        let config = self.chain.config()?;
        let vaults = (0..config.vault_count).map(|id| self.chain.vault(id)).collect::<Result<Vec<_>, _>>()?;
        let demand = self.demand(config.vault_count);
        let mut memory = self.memory();
        let plan = planner::plan(&self.params, now, &config, &vaults, &memory, &demand);
        for action in &plan.actions {
            let result = match *action {
                Action::Sync(v) => self.chain.run(&Call::Sync(v)),
                Action::Place(v, amount) => self.chain.run(&Call::Place(v, amount)),
                Action::Unstake(v, amount) => self.chain.run(&Call::Unstake(v, amount)),
                Action::Withdraw(v, amount) => self.chain.run(&Call::Withdraw(v, amount)),
            };
            if result.is_ok() {
                memory.apply(action, now);
            }
            log.push(format!("{action:?}: {}", result.as_ref().map_or_else(|e| e.message().to_string(), |()| "ok".into())));
        }
        for (v, line) in &plan.steady {
            memory.steady_line(*v, *line);
        }
        if plan.settled {
            memory.settled(now, &self.params);
        }
        self.store.put("p:memory", memory.to_json())?;
        self.purge(now)?;
        Ok(log)
    }
}

pub fn parse_note(v: &Value) -> Option<Note> {
    let bytes = |k: &str| v[k].as_str().and_then(|s| B64.decode(s).ok());
    Some(Note {
        tier: u8::try_from(v["tier"].as_u64()?).ok()?,
        pk: bytes("pk")?.try_into().ok()?,
        nonce: bytes("nonce")?.try_into().ok()?,
        sig: bytes("sig")?.try_into().ok()?,
    })
}
