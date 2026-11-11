//! The pool commands against a fake contract and a fake agent. The fake checks every note under the tier keys and
//! every owner signature against digests written here from SPEC (`ona-pool`), independently of `ona_wallet::pool`.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_core::pool::{
    AgentError, PoolAgent, PoolChain, PoolClient, SignedNote, CLOCK_MARGIN_NS, EXIT_STORAGE_FEE, NOTE_STORAGE_FEE,
    PREPARATION_LIFE_NS, SIGNATURE_LIFE_NS,
};
use ona_core::Core;
use ona_token::{g2_to_raw, keygen, sign_blinded, verify_digest, verify_token, SecretKey, Token, G1_LEN};
use ona_wallet::Wallet;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const NETWORK: &str = "sandbox";
const POOL: &str = "pool.test";
const KEY: [u8; 32] = [5u8; 32];
const CASH: [u128; 3] = [NEAR / 10, NEAR, 10 * NEAR];
/// Share notes of 0.01, 0.1 and 1 NEAR at the initial price.
const SHARES: [u128; 3] = [10_000, 100_000, 1_000_000];
const INITIAL_PRICE: u128 = 1_000_000_000_000_000_000;

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn outs_bytes(list: &[(u8, u64)]) -> Vec<u8> {
    let mut d = (list.len() as u32).to_le_bytes().to_vec();
    for (tier, count) in list {
        d.push(*tier);
        d.extend_from_slice(&count.to_le_bytes());
    }
    d
}

struct VaultState {
    keys: Vec<SecretKey>,
    liquid: u128,
    total_shares: u128,
    /// Owned by no share, as the contract sets aside when a vault empties.
    orphan: u128,
    /// A share price the view reports instead of the real one, to test absurd figures.
    shown_price: Option<u128>,
}

#[derive(Default)]
struct Log {
    views: Vec<String>,
    payments: Vec<(String, u128)>,
}

/// How the next agent call fails, if it does.
#[derive(Clone, Copy, PartialEq)]
enum Fail {
    No,
    /// Refused by the chain: nothing happened.
    Refused,
    /// Done on chain, but the answer is lost on the way back.
    AnswerLost,
}

struct FakePool {
    cash_keys: Vec<SecretKey>,
    vaults: Vec<VaultState>,
    cash_liquid: u128,
    nullifiers: BTreeSet<[u8; 32]>,
    owner_keys: BTreeSet<[u8; 32]>,
    /// Per account: deposited, issued, received.
    holders: BTreeMap<String, (u128, u128, u128)>,
    /// Every blind signature the agent made, by blinded point.
    signed: BTreeMap<[u8; G1_LEN], [u8; G1_LEN]>,
    log: Log,
    fail: Fail,
    /// Fail on the n-th agent call from now (1 = the next one).
    fail_after: u32,
}

type Shared = Rc<RefCell<FakePool>>;

struct Chain(Shared);
struct Agent(Shared, Rc<Cell<u64>>);

fn price(v: &VaultState) -> u128 {
    if v.total_shares == 0 {
        INITIAL_PRICE
    } else {
        (v.liquid - v.orphan) / v.total_shares
    }
}

fn price_up(v: &VaultState) -> u128 {
    if v.total_shares == 0 {
        INITIAL_PRICE
    } else {
        (v.liquid - v.orphan).div_ceil(v.total_shares)
    }
}

fn raw(k: &SecretKey) -> String {
    B64.encode(g2_to_raw(&k.public_key()).unwrap())
}

impl PoolChain for Chain {
    fn view(&self, method: &str, args: Value) -> Result<Value, String> {
        let mut f = self.0.borrow_mut();
        f.log.views.push(format!("{method} {args}"));
        match method {
            "get_config" => Ok(json!({"network": NETWORK, "vault_count": f.vaults.len()})),
            "get_cash" => Ok(json!({"tiers": f.cash_keys.iter().zip(CASH).map(|(k, v)| json!({
                "value": v.to_string(), "pk_raw": raw(k)})).collect::<Vec<_>>(), "liquid": f.cash_liquid.to_string()})),
            "get_vault" => {
                let v = &f.vaults[args["vault_id"].as_u64().unwrap() as usize];
                Ok(json!({
                    "tiers": v.keys.iter().zip(SHARES).map(|(k, s)| json!({"shares": s.to_string(), "pk_raw": raw(k)})).collect::<Vec<_>>(),
                    "liquid": v.liquid.to_string(), "placed": "0", "fee_owed": "0", "orphan": v.orphan.to_string(),
                    "total_shares": v.total_shares.to_string(),
                    "share_price": v.shown_price.unwrap_or_else(|| price(v)).to_string(), "frozen": false,
                }))
            }
            "get_holder" => {
                let (d, _, r) = f.holders.get(args["account"].as_str().unwrap()).copied().unwrap_or_default();
                Ok(json!({"exit_limit": d.saturating_sub(r).to_string()}))
            }
            "is_spent" => {
                let nf: [u8; 32] = B64.decode(args["nf"].as_str().unwrap()).unwrap().try_into().unwrap();
                Ok(json!(f.nullifiers.contains(&nf)))
            }
            _ => Err("not faked".into()),
        }
    }

    fn mode(&self) -> &'static str {
        "mock"
    }
}

fn token(n: &SignedNote) -> Token {
    Token { denom_id: n.tier, pk: n.pk, nonce: n.nonce, sig: n.sig }
}

impl FakePool {
    /// Whether the call is refused before anything happens; arms the lost answer otherwise.
    fn start(&mut self) -> Result<bool, AgentError> {
        if self.fail != Fail::No {
            self.fail_after -= 1;
            if self.fail_after == 0 {
                let fail = std::mem::replace(&mut self.fail, Fail::No);
                if fail == Fail::Refused {
                    return Err(AgentError::Refused("refused by the chain".into()));
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn check(&mut self, note: &SignedNote, vault: Option<u32>, digest: [u8; 32], now: u64) {
        let t = token(note);
        let (nf, dst, pk) = match vault {
            None => (
                sha(&[b"ONA-POOL-CASH-NF-V1", &[t.denom_id], &t.pk, &t.nonce]),
                format!("ONA-POOL-CASH-V1:{NETWORK}:{POOL}:BLS12381G1_XMD:SHA-256_SSWU_RO_"),
                self.cash_keys[usize::from(t.denom_id)].public_key(),
            ),
            Some(v) => (
                sha(&[b"ONA-POOL-NF-V1", &v.to_le_bytes(), &[t.denom_id], &t.pk, &t.nonce]),
                format!("ONA-POOL-V1:{NETWORK}:{POOL}:{v}:BLS12381G1_XMD:SHA-256_SSWU_RO_"),
                self.vaults[v as usize].keys[usize::from(t.denom_id)].public_key(),
            ),
        };
        assert!(verify_token(&pk, &t, dst.as_bytes()), "a valid note");
        assert!(!self.nullifiers.contains(&nf), "never spent twice");
        assert!(!self.owner_keys.contains(&t.pk), "a fresh owner key for every note");
        assert!(note.expires_at > now, "a deadline in the future");
        assert!(verify_digest(&t.pk, &digest, &note.owner_sig), "the owner signed the SPEC digest");
        self.nullifiers.insert(nf);
        self.owner_keys.insert(t.pk);
    }

    fn sign(&mut self, cash: bool, vault: u32, outputs: &[(u8, u64)], blinded: &[[u8; G1_LEN]]) -> Vec<[u8; G1_LEN]> {
        let tiers: Vec<u8> = outputs.iter().flat_map(|(t, c)| std::iter::repeat(*t).take(*c as usize)).collect();
        assert_eq!(tiers.len(), blinded.len(), "one blinded point per new note");
        let sigs: Vec<[u8; G1_LEN]> = tiers
            .iter()
            .zip(blinded)
            .map(|(t, b)| {
                let key = if cash { &self.cash_keys[usize::from(*t)] } else { &self.vaults[vault as usize].keys[usize::from(*t)] };
                sign_blinded(key, b).unwrap()
            })
            .collect();
        for (b, s) in blinded.iter().zip(&sigs) {
            self.signed.insert(*b, *s);
        }
        sigs
    }
}

fn nf_of(n: &SignedNote, vault: Option<u32>) -> [u8; 32] {
    match vault {
        None => sha(&[b"ONA-POOL-CASH-NF-V1", &[n.tier], &n.pk, &n.nonce]),
        Some(v) => sha(&[b"ONA-POOL-NF-V1", &v.to_le_bytes(), &[n.tier], &n.pk, &n.nonce]),
    }
}

fn c() -> [u8; 32] {
    sha(&[POOL.as_bytes()])
}

fn lost<T>(lose: bool, value: T) -> Result<T, AgentError> {
    if lose {
        Err(AgentError::Unknown("no answer from the agent".into()))
    } else {
        Ok(value)
    }
}

impl PoolAgent for Agent {
    fn issue_cash(&mut self, account: &str, tier: u8, blinded: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        let mut f = self.0.borrow_mut();
        let lose = f.start()?;
        let value = CASH[usize::from(tier)] * blinded.len() as u128;
        let (deposited, issued, received) = f.holders.get(account).copied().ok_or(AgentError::Refused("not a depositor".into()))?;
        if deposited - issued < value {
            return Err(AgentError::Refused("more than this account's deposits".into()));
        }
        f.holders.insert(account.into(), (deposited, issued + value, received));
        f.cash_liquid += value;
        let sigs = f.sign(true, 0, &[(tier, blinded.len() as u64)], blinded);
        lost(lose, sigs)
    }

    fn enter(&mut self, vault: u32, note: &SignedNote, outputs: &[(u8, u64)], blinded: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        let now = self.1.get();
        let mut f = self.0.borrow_mut();
        let lose = f.start()?;
        let nf = nf_of(note, None);
        let digest = sha(&[b"ONA-POOL-ENTER-V1", &c(), &nf, &vault.to_le_bytes(), &outs_bytes(outputs), &note.expires_at.to_le_bytes()]);
        let value = CASH[usize::from(note.tier)];
        let shares: u128 = outputs.iter().map(|(t, n)| SHARES[usize::from(*t)] * u128::from(*n)).sum();
        let pu = price_up(&f.vaults[vault as usize]);
        let cost = shares * pu;
        if cost + NOTE_STORAGE_FEE > value {
            return Err(AgentError::Refused("the new notes are worth more than the note".into()));
        }
        // As the contract: what is left must be less than one of the vault's smallest notes.
        if value - NOTE_STORAGE_FEE - cost >= SHARES[0] * pu {
            return Err(AgentError::Refused("too much left over: ask for more notes".into()));
        }
        f.check(note, None, digest, now);
        f.cash_liquid -= cost + NOTE_STORAGE_FEE;
        let v = &mut f.vaults[vault as usize];
        v.liquid += cost;
        v.total_shares += shares;
        let sigs = f.sign(false, vault, outputs, blinded);
        lost(lose, sigs)
    }

    fn leave(&mut self, vault: u32, note: &SignedNote, outputs: &[(u8, u64)], blinded: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        let now = self.1.get();
        let mut f = self.0.borrow_mut();
        let lose = f.start()?;
        let nf = nf_of(note, Some(vault));
        let digest = sha(&[b"ONA-POOL-LEAVE-V1", &c(), &vault.to_le_bytes(), &nf, &outs_bytes(outputs), &note.expires_at.to_le_bytes()]);
        f.check(note, Some(vault), digest, now);
        let shares = SHARES[usize::from(note.tier)];
        let value = shares * price(&f.vaults[vault as usize]);
        let cash: u128 = outputs.iter().map(|(t, n)| CASH[usize::from(*t)] * u128::from(*n)).sum();
        assert!(cash + NOTE_STORAGE_FEE <= value, "the cash notes fit in the share note");
        let v = &mut f.vaults[vault as usize];
        v.liquid -= value;
        v.total_shares -= shares;
        f.cash_liquid += value - NOTE_STORAGE_FEE;
        let sigs = f.sign(true, 0, outputs, blinded);
        lost(lose, sigs)
    }

    fn pay_exit(&mut self, note: &SignedNote, to: &str) -> Result<(), AgentError> {
        let now = self.1.get();
        let mut f = self.0.borrow_mut();
        let lose = f.start()?;
        let nf = nf_of(note, None);
        let digest = sha(&[b"ONA-POOL-CASH-EXIT-V1", &c(), &nf, &sha(&[to.as_bytes()]), &note.expires_at.to_le_bytes()]);
        f.check(note, None, digest, now);
        let value = CASH[usize::from(note.tier)];
        let holder = f.holders.get_mut(to).expect("exits go only to an account that deposited");
        holder.2 += value;
        f.cash_liquid -= value;
        f.log.payments.push((to.into(), value - EXIT_STORAGE_FEE));
        lost(lose, ())
    }

    fn signatures(&mut self, blinded: &[[u8; G1_LEN]]) -> Result<Vec<Option<[u8; G1_LEN]>>, AgentError> {
        let f = self.0.borrow();
        Ok(blinded.iter().map(|b| f.signed.get(b).copied()).collect())
    }
}

struct World {
    core: Core,
    fake: Shared,
    now: Rc<Cell<u64>>,
    path: PathBuf,
}

fn path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ona-pool-cmds-{}-{name}", std::process::id()))
}

fn remove_wallet(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let mut seal = path.clone().into_os_string();
    seal.push(".seal");
    let _ = fs::remove_file(PathBuf::from(seal));
}

impl World {
    fn new(name: &str) -> Self {
        let path = path(name);
        remove_wallet(&path);
        let fake = Rc::new(RefCell::new(FakePool {
            cash_keys: (0..3).map(|_| keygen(&mut OsRng)).collect(),
            vaults: (0..2)
                .map(|_| VaultState {
                    keys: (0..3).map(|_| keygen(&mut OsRng)).collect(),
                    liquid: 0,
                    total_shares: 0,
                    orphan: 0,
                    shown_price: None,
                })
                .collect(),
            cash_liquid: 0,
            nullifiers: BTreeSet::new(),
            owner_keys: BTreeSet::new(),
            holders: BTreeMap::new(),
            signed: BTreeMap::new(),
            log: Log::default(),
            fail: Fail::No,
            fail_after: 0,
        }));
        let mut w = Self { core: Core::new(), fake, now: Rc::new(Cell::new(1_000_000_000_000_000_000)), path };
        w.restart();
        w
    }

    /// A new core on the same wallet file, as after a restart of the app.
    fn restart(&mut self) {
        self.core = Core::new();
        let wallet = Wallet::open(&self.path, &KEY).unwrap();
        let now = self.now.clone();
        let client = PoolClient::new(wallet, Box::new(Chain(self.fake.clone())), Box::new(Agent(self.fake.clone(), self.now.clone())), POOL)
            .with_clock(Box::new(move || now.get()))
            .with_recommended(vec![10 * NEAR, 11 * NEAR]);
        self.core.set_pool(client);
    }

    fn fail_on(&self, call: u32, how: Fail) {
        let mut f = self.fake.borrow_mut();
        f.fail = how;
        f.fail_after = call;
    }

    fn send(&mut self, request: Value) -> Value {
        serde_json::from_str(&self.core.dispatch(&request.to_string())).unwrap()
    }

    fn ok(&mut self, request: Value) -> Value {
        let reply = self.send(request.clone());
        assert_eq!(reply["ok"], true, "{request} -> {reply}");
        reply
    }

    fn error(&mut self, request: Value) -> String {
        let reply = self.send(request);
        assert_eq!(reply["ok"], false, "{reply}");
        reply["error"].as_str().unwrap().to_string()
    }

    /// The user's own wallet sends the deposit the preparation asked for.
    fn user_deposits(&self, account: &str, attached: u128) {
        let mut f = self.fake.borrow_mut();
        f.holders.entry(account.into()).or_insert((0, 0, 0)).0 += attached;
    }

    fn prepare(&mut self, request: Value) -> Value {
        let mut request = request;
        request["cmd"] = json!("pool_prepare");
        let prepared = self.ok(request);
        if prepared["summary"]["op"] == "deposit" {
            let attached: u128 = prepared["summary"]["wallet_call"]["attached"].as_str().unwrap().parse().unwrap();
            let account = prepared["summary"]["account"].as_str().unwrap().to_string();
            self.user_deposits(&account, attached);
        }
        prepared
    }

    /// Prepares, then executes after the user confirmed.
    fn run(&mut self, request: Value) -> Value {
        let prepared = self.prepare(request);
        self.ok(json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}))
    }

    fn portfolio(&mut self) -> Value {
        self.ok(json!({"cmd": "pool_portfolio"}))
    }

    fn cash_value(&mut self) -> String {
        self.portfolio()["cash"]["value"].as_str().unwrap().to_string()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        remove_wallet(&self.path);
    }
}

#[test]
fn a_deposit_is_prepared_for_the_users_wallet_and_becomes_cash_notes() {
    let mut w = World::new("deposit");
    let prepared = w.prepare(json!({"op": "deposit", "account": "alice.test", "amount": (111 * NEAR / 10).to_string()}));
    let s = &prepared["summary"];
    assert_eq!(s["wallet_call"]["receiver"], POOL);
    assert_eq!(s["wallet_call"]["method"], "deposit");
    assert_eq!(s["cash_notes"], json!([
        {"tier": 0, "count": 1, "note_value": CASH[0].to_string()},
        {"tier": 1, "count": 1, "note_value": CASH[1].to_string()},
        {"tier": 2, "count": 1, "note_value": CASH[2].to_string()},
    ]));
    assert_eq!(s["network"], NETWORK);
    assert_eq!(prepared["mode"], "mock", "figures from a fake pool are labelled so");
    w.ok(json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}));
    assert_eq!(w.cash_value(), (111 * NEAR / 10).to_string());
}

#[test]
fn a_deposit_shows_the_recommended_amounts_and_warns_about_others() {
    let mut w = World::new("recommended");
    let p = w.prepare(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    assert_eq!(p["summary"]["recommended"], json!([(10 * NEAR).to_string(), (11 * NEAR).to_string()]));
    assert!(p["summary"].get("warning").is_none(), "a recommended amount needs no warning");
    let p = w.prepare(json!({"op": "deposit", "account": "alice.test", "amount": (12 * NEAR).to_string()}));
    assert!(p["summary"]["warning"].as_str().unwrap().contains("not one of the recommended amounts"));
    let e = w.error(json!({"cmd": "pool_prepare", "op": "deposit", "account": "alice.test", "amount": (NEAR / 20).to_string()}));
    assert!(e.contains("below the contract's smallest deposit"), "{e}");
    assert_eq!(ona_core::pool::parse_recommended("100, 500,2000").unwrap(), vec![100 * NEAR, 500 * NEAR, 2_000 * NEAR]);
    assert!(ona_core::pool::parse_recommended("100,abc").is_err());
}

#[test]
fn a_preparation_is_used_once_expires_and_reserves_its_notes() {
    let mut w = World::new("once");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    let a = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    let e = w.error(json!({"cmd": "pool_prepare", "op": "enter", "vault": 1, "amount": (10 * NEAR).to_string()}));
    assert!(e.contains("no held notes"), "the note is reserved by the first preparation: {e}");
    w.now.set(w.now.get() + PREPARATION_LIFE_NS);
    let e = w.error(json!({"cmd": "pool_execute", "prepared_id": a["prepared_id"]}));
    assert!(e.contains("unknown, expired or already used"), "{e}");
    let b = w.prepare(json!({"op": "enter", "vault": 1, "amount": (10 * NEAR).to_string()}));
    w.ok(json!({"cmd": "pool_execute", "prepared_id": b["prepared_id"]}));
    let e = w.error(json!({"cmd": "pool_execute", "prepared_id": b["prepared_id"]}));
    assert!(e.contains("unknown, expired or already used"), "{e}");
    let e = w.error(json!({"cmd": "pool_execute"}));
    assert!(e.contains("missing field prepared_id"), "{e}");
}

#[test]
fn an_amount_that_is_not_a_sum_of_notes_is_refused() {
    let mut w = World::new("denoms");
    let e = w.error(json!({"cmd": "pool_prepare", "op": "deposit", "account": "a.test", "amount": (NEAR / 5 + 1).to_string()}));
    assert!(e.contains("not a sum of cash notes"), "{e}");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": NEAR.to_string()}));
    let e = w.error(json!({"cmd": "pool_prepare", "op": "exit_cash", "to": "alice.test", "amount": (2 * NEAR).to_string()}));
    assert!(e.contains("not a sum of whole notes"), "{e}");
    let e = w.error(json!({"cmd": "pool_prepare", "op": "enter", "vault": 7, "amount": "all"}));
    assert!(e.contains("no vault 7"), "{e}");
    let e = w.error(json!({"cmd": "pool_prepare", "op": "fly", "amount": "1"}));
    assert!(e.contains("unknown operation"), "{e}");
    let e = w.error(json!({"cmd": "pool_prepare", "op": "exit_cash", "to": "Not An Account!", "amount": "all"}));
    assert!(e.contains("to:"), "the account is checked before anything is signed: {e}");
}

#[test]
fn entering_a_vault_spends_cash_notes_for_share_notes() {
    let mut w = World::new("enter");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    let prepared = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    let s = &prepared["summary"];
    assert_eq!(s["shares_value"], (999 * NEAR / 100).to_string(), "nine notes of each tier at the initial price");
    assert_eq!(s["fees"]["storage"], NOTE_STORAGE_FEE.to_string());
    let left: u128 = s["left_in_cash"].as_str().unwrap().parse().unwrap();
    assert_eq!(left, 10 * NEAR - NOTE_STORAGE_FEE - 999 * NEAR / 100);
    w.ok(json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}));
    let p = w.portfolio();
    assert_eq!(p["cash"]["value"], "0");
    assert_eq!(p["vaults"][0]["value"], (999 * NEAR / 100).to_string());
}

#[test]
fn switching_vaults_moves_shares_through_cash_without_an_exit() {
    let mut w = World::new("switch");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.run(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    let prepared = w.prepare(json!({"op": "switch", "from": 0, "to": 1, "amount": NEAR.to_string()}));
    assert_eq!(prepared["summary"]["new_shares_value"], (81 * NEAR / 100).to_string());
    w.ok(json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}));
    let p = w.portfolio();
    let vault1 = p["vaults"].as_array().unwrap().iter().find(|v| v["vault"] == 1).unwrap().clone();
    assert_eq!(vault1["value"], (81 * NEAR / 100).to_string());
    assert!(w.fake.borrow().log.payments.is_empty(), "no exit was paid");
}

#[test]
fn an_exit_turns_shares_into_cash_and_the_payment_is_a_separate_step() {
    // A payment right after a leave from a vault would point to that vault: the two never run together.
    let mut w = World::new("exit");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.run(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    let prepared = w.prepare(json!({"op": "exit", "from": 0, "amount": NEAR.to_string()}));
    assert_eq!(prepared["summary"]["cash_value"], (9 * CASH[0]).to_string());
    assert!(prepared["summary"].get("to").is_none(), "an exit to cash names no account");
    w.ok(json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}));
    assert!(w.fake.borrow().log.payments.is_empty(), "nothing is paid by the exit itself");
    assert_eq!(w.cash_value(), (9 * CASH[0]).to_string());
    let paid = w.prepare(json!({"op": "exit_cash", "to": "alice.test", "amount": (9 * CASH[0]).to_string()}));
    assert_eq!(paid["summary"]["received"], (9 * (CASH[0] - EXIT_STORAGE_FEE)).to_string());
    w.ok(json!({"cmd": "pool_execute", "prepared_id": paid["prepared_id"]}));
    assert_eq!(w.fake.borrow().log.payments.len(), 9);
}

#[test]
fn a_cash_payment_respects_the_accounts_exit_limit() {
    let mut w = World::new("limit");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (11 * NEAR).to_string()}));
    w.run(json!({"op": "deposit", "account": "bob.test", "amount": (10 * NEAR).to_string()}));
    let e = w.error(json!({"cmd": "pool_prepare", "op": "exit_cash", "to": "carol.test", "amount": NEAR.to_string()}));
    assert!(e.contains("over this account's exit limit"), "{e}");
    w.run(json!({"op": "exit_cash", "to": "alice.test", "amount": NEAR.to_string()}));
    assert_eq!(w.fake.borrow().log.payments, vec![("alice.test".to_string(), NEAR - EXIT_STORAGE_FEE)]);
}

#[test]
fn the_portfolio_reads_every_vault_and_nothing_about_the_notes() {
    let mut w = World::new("reads");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.fake.borrow_mut().log.views.clear();
    w.portfolio();
    let expected = vec![
        "get_config {}".to_string(),
        "get_cash {}".to_string(),
        "get_vault {\"vault_id\":0}".to_string(),
        "get_vault {\"vault_id\":1}".to_string(),
    ];
    assert_eq!(w.fake.borrow().log.views, expected, "the same reads whoever holds what");
}

#[test]
fn a_certain_refusal_holds_the_note_again_and_notes_survive_a_restart() {
    let mut w = World::new("refused");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.fail_on(1, Fail::Refused);
    let prepared = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    let e = w.error(json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}));
    assert!(e.contains("refused by the chain"), "{e}");
    assert_eq!(w.cash_value(), (10 * NEAR).to_string(), "the note is held again");
    w.restart();
    assert_eq!(w.cash_value(), (10 * NEAR).to_string(), "kept across a restart");
    w.run(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    w.restart();
    assert_eq!(w.portfolio()["vaults"][0]["value"], (999 * NEAR / 100).to_string());
}

#[test]
fn an_unknown_outcome_keeps_the_note_spending_until_recovery_finds_it_spent() {
    let mut w = World::new("unknown");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.fail_on(1, Fail::AnswerLost);
    let prepared = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    let e = w.error(json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}));
    assert!(e.contains("outcome unknown"), "{e}");
    let p = w.portfolio();
    assert_eq!(p["cash"]["value"], "0", "nothing is shown as available");
    assert_eq!(p["cash"]["spending_value"], (10 * NEAR).to_string());
    assert_eq!(p["vaults"][0]["awaiting_signature"], 27, "the expected share notes stay recorded");
    w.restart();
    let r = w.ok(json!({"cmd": "pool_recover"}));
    assert_eq!((r["spent"].clone(), r["signatures_recovered"].clone(), r["awaiting_signature"].clone()), (json!(1), json!(27), json!(0)));
    let p = w.portfolio();
    assert_eq!(p["cash"]["spending_value"], "0");
    assert_eq!(p["vaults"][0]["value"], (999 * NEAR / 100).to_string(), "the shares are back in the wallet");
}

#[test]
fn recovery_holds_an_unspent_note_again_only_after_its_signature_expired() {
    let mut w = World::new("expired");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    // An agent that answers "unknown" without acting: the chain never sees the note.
    struct Silent;
    impl PoolAgent for Silent {
        fn issue_cash(&mut self, _: &str, _: u8, _: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
            Err(AgentError::Unknown("timeout".into()))
        }
        fn enter(&mut self, _: u32, _: &SignedNote, _: &[(u8, u64)], _: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
            Err(AgentError::Unknown("timeout".into()))
        }
        fn leave(&mut self, _: u32, _: &SignedNote, _: &[(u8, u64)], _: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
            Err(AgentError::Unknown("timeout".into()))
        }
        fn pay_exit(&mut self, _: &SignedNote, _: &str) -> Result<(), AgentError> {
            Err(AgentError::Unknown("timeout".into()))
        }
        fn signatures(&mut self, b: &[[u8; G1_LEN]]) -> Result<Vec<Option<[u8; G1_LEN]>>, AgentError> {
            Ok(vec![None; b.len()])
        }
    }
    w.core = Core::new();
    let now = w.now.clone();
    let client = PoolClient::new(Wallet::open(&w.path, &KEY).unwrap(), Box::new(Chain(w.fake.clone())), Box::new(Silent), POOL)
        .with_clock(Box::new(move || now.get()));
    w.core.set_pool(client);
    let p = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    w.error(json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    let r = w.ok(json!({"cmd": "pool_recover"}));
    assert_eq!(r["still_spending"], 1, "the agent may still submit it");
    w.now.set(w.now.get() + SIGNATURE_LIFE_NS + 1);
    let r = w.ok(json!({"cmd": "pool_recover"}));
    assert_eq!(r["still_spending"], 1, "just past its deadline, this clock may be ahead of the chain's");
    assert_eq!(r["agent_error"], json!(null), "the agent answered");
    w.now.set(w.now.get() + CLOCK_MARGIN_NS);
    let r = w.ok(json!({"cmd": "pool_recover"}));
    assert_eq!(r["held_again"], 1, "past its deadline and the margin the operation can no longer happen");
    assert_eq!(w.cash_value(), (10 * NEAR).to_string());
}

/// Answers every view like the real chain, except `is_spent`, which it inverts.
struct Lying(Shared);

impl PoolChain for Lying {
    fn view(&self, method: &str, args: Value) -> Result<Value, String> {
        let honest = Chain(self.0.clone()).view(method, args)?;
        Ok(if method == "is_spent" { json!(!honest.as_bool().unwrap()) } else { honest })
    }

    fn mode(&self) -> &'static str {
        "mock"
    }
}

#[test]
fn recovery_refuses_to_decide_when_two_rpc_endpoints_disagree() {
    let mut w = World::new("two-rpc");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.fail_on(1, Fail::AnswerLost);
    let p = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    w.error(json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    w.core = Core::new();
    let now = w.now.clone();
    let client = PoolClient::new(
        Wallet::open(&w.path, &KEY).unwrap(),
        Box::new(Chain(w.fake.clone())),
        Box::new(Agent(w.fake.clone(), w.now.clone())),
        POOL,
    )
    .with_clock(Box::new(move || now.get()))
    .with_second_chain(Box::new(Lying(w.fake.clone())));
    w.core.set_pool(client);
    let e = w.error(json!({"cmd": "pool_recover"}));
    assert!(e.contains("the two RPC endpoints disagree"), "{e}");
    assert_eq!(w.portfolio()["cash"]["spending_value"], (10 * NEAR).to_string(), "nothing decided on one endpoint's word");
}

#[test]
fn recovery_without_the_agent_reports_what_the_chain_says_and_what_waits() {
    let mut w = World::new("recover-noagent");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.fail_on(1, Fail::AnswerLost);
    let p = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    w.error(json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    w.core = Core::new();
    let client = PoolClient::new(Wallet::open(&w.path, &KEY).unwrap(), Box::new(Chain(w.fake.clone())), Box::new(ona_core::pool::NoAgent), POOL);
    w.core.set_pool(client);
    let r = w.ok(json!({"cmd": "pool_recover"}));
    assert_eq!(r["spent"], 1, "the chain's answer is kept");
    assert_eq!(r["awaiting_signature"], 27);
    assert_eq!(r["waiting"][0], json!({"vault": 0, "tier": 0}));
    assert_eq!(r["agent_error"], "no connection to the pool agent yet");
}

#[test]
fn a_certain_refusal_leaves_no_note_waiting_for_a_signature() {
    let mut w = World::new("refused-clean");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.fail_on(1, Fail::Refused);
    let p = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    w.error(json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    let portfolio = w.portfolio();
    assert_eq!(portfolio["vaults"].as_array().unwrap().len(), 0, "the 27 share notes made for the entry are forgotten");
    w.restart();
    assert_eq!(w.portfolio()["vaults"].as_array().unwrap().len(), 0, "also after a restart");
    // A refused deposit leaves no cash note waiting either.
    let p = w.prepare(json!({"op": "deposit", "account": "carol.test", "amount": (10 * NEAR).to_string()}));
    w.fake.borrow_mut().holders.remove("carol.test");
    w.error(json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    assert_eq!(w.portfolio()["cash"]["awaiting_signature"], 0);
}

#[test]
fn an_entry_is_priced_without_what_no_share_owns() {
    let mut w = World::new("orphan");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (20 * NEAR).to_string()}));
    {
        // The vault holds 5 NEAR for 4 million shares, plus 1 NEAR owned by no share: the price is 1.25e18, not 1.5e18.
        let mut f = w.fake.borrow_mut();
        let v = &mut f.vaults[0];
        v.liquid = 6 * NEAR;
        v.orphan = NEAR;
        v.total_shares = 4_000_000;
    }
    let p = w.prepare(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    let shares: u128 = p["summary"]["shares_value"].as_str().unwrap().parse().unwrap();
    let left: u128 = p["summary"]["left_in_cash"].as_str().unwrap().parse().unwrap();
    assert!(left < SHARES[0] * (INITIAL_PRICE / 4 * 5), "at the right price little is left over");
    assert_eq!(shares + left + NOTE_STORAGE_FEE, 10 * NEAR);
    w.ok(json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
}

#[test]
fn an_absurd_figure_from_the_contract_is_an_error_not_a_crash() {
    let mut w = World::new("absurd");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.run(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    w.fake.borrow_mut().vaults[0].shown_price = Some(u128::MAX / 2);
    let e = w.error(json!({"cmd": "pool_prepare", "op": "exit", "from": 0, "amount": "all"}));
    assert!(e.contains("too large"), "{e}");
    let e = w.error(json!({"cmd": "pool_portfolio"}));
    assert!(e.contains("too large"), "{e}");
}

#[test]
fn a_deposit_whose_cash_was_never_finished_is_recovered() {
    let mut w = World::new("deposit-lost");
    w.fail_on(1, Fail::AnswerLost);
    let p = w.prepare(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    let e = w.error(json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    assert!(e.contains("outcome unknown"), "{e}");
    assert_eq!(w.portfolio()["cash"]["awaiting_signature"], 1);
    let r = w.ok(json!({"cmd": "pool_recover"}));
    assert_eq!(r["signatures_recovered"], 1);
    assert_eq!(w.cash_value(), (10 * NEAR).to_string());
}

#[test]
fn a_failure_in_the_middle_of_a_switch_reports_what_was_done() {
    let mut w = World::new("partial");
    w.run(json!({"op": "deposit", "account": "alice.test", "amount": (10 * NEAR).to_string()}));
    w.run(json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    w.fail_on(3, Fail::Refused); // the leave and one entry pass, the second entry is refused
    let p = w.prepare(json!({"op": "switch", "from": 0, "to": 1, "amount": NEAR.to_string()}));
    let r = w.ok(json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    assert_eq!(r["complete"], false);
    assert!(r["error"].as_str().unwrap().contains("refused"), "{r}");
    assert_eq!(r["steps"], json!([{"left": 0, "cash_notes": 9}, {"entered": 1}]));
    assert_eq!(w.cash_value(), (8 * CASH[0]).to_string(), "the cash not yet entered is held");
}

#[test]
fn pool_commands_need_a_wallet() {
    let mut core = Core::new();
    let reply: Value = serde_json::from_str(&core.dispatch(r#"{"cmd":"pool_portfolio"}"#)).unwrap();
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"], "no pool wallet configured");
}

#[test]
fn without_an_agent_nothing_is_spent() {
    let path = path("noagent");
    remove_wallet(&path);
    let w = World::new("noagent-chain");
    let mut core = Core::new();
    let wallet = Wallet::open(&path, &KEY).unwrap();
    core.set_pool(PoolClient::new(wallet, Box::new(Chain(w.fake.clone())), Box::new(ona_core::pool::NoAgent), POOL));
    let send = |core: &mut Core, v: Value| -> Value { serde_json::from_str(&core.dispatch(&v.to_string())).unwrap() };
    let prepared = send(&mut core, json!({"cmd": "pool_prepare", "op": "deposit", "account": "alice.test", "amount": NEAR.to_string()}));
    let reply = send(&mut core, json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}));
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"], "no connection to the pool agent yet");
    let p = send(&mut core, json!({"cmd": "pool_portfolio"}));
    assert_eq!(p["cash"]["awaiting_signature"], 0, "nothing was sent, so nothing is left waiting");
    drop(core);
    remove_wallet(&path);
}

/// Prints each request and reply of a full run; `docs/desktop/pool-commands.md` quotes this output.
#[test]
fn examples_for_the_docs() {
    let mut w = World::new("examples");
    let show = |w: &mut World, request: Value| -> Value {
        let reply = w.ok(request.clone());
        println!("> {request}\n< {reply}\n");
        reply
    };
    let p = show(&mut w, json!({"cmd": "pool_prepare", "op": "deposit", "account": "alice.test", "amount": (11 * NEAR).to_string()}));
    let attached: u128 = p["summary"]["wallet_call"]["attached"].as_str().unwrap().parse().unwrap();
    w.user_deposits("alice.test", attached);
    show(&mut w, json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    let p = show(&mut w, json!({"cmd": "pool_prepare", "op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}));
    show(&mut w, json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    show(&mut w, json!({"cmd": "pool_portfolio"}));
    let p = show(&mut w, json!({"cmd": "pool_prepare", "op": "switch", "from": 0, "to": 1, "amount": NEAR.to_string()}));
    show(&mut w, json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    let p = show(&mut w, json!({"cmd": "pool_prepare", "op": "exit", "from": 0, "amount": NEAR.to_string()}));
    show(&mut w, json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    let p = show(&mut w, json!({"cmd": "pool_prepare", "op": "exit_cash", "to": "alice.test", "amount": (19 * NEAR / 10).to_string()}));
    show(&mut w, json!({"cmd": "pool_execute", "prepared_id": p["prepared_id"]}));
    show(&mut w, json!({"cmd": "pool_recover"}));
}
