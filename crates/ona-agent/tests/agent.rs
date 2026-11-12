//! The agent against a fake `ona-pool` that keeps the contract's money rules (a note spends once, cash issues only
//! within an account's deposits, leaves only from liquid funds), and the client core against the agent over HTTP on
//! this machine. No real chain, no network beyond `127.0.0.1`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ona_agent::api::{self, Limits};
use ona_agent::chain::{Call, CallError, CashInfo, ConfigInfo, HolderInfo, Note, PoolChain, VaultInfo};
use ona_agent::keys::AgentKeys;
use ona_agent::nep413;
use ona_agent::planner::{Action, Params};
use ona_agent::service::{Agent, IssueRequest, Kind, NoteRequest, PayRequest, Proof, QueueParams, Reply};
use ona_agent::store::{FileStore, MemoryStore, Store};
use ona_token::{g2_to_raw, PendingToken, Token, G1_LEN, G2_LEN};
use ona_wallet::pool as digests;
use rand::rngs::OsRng;
use serde_json::{json, Value};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const POOL: &str = "pool.test";
const NETWORK: &str = "sandbox";
const AGENT: &str = "agent.test";
const NOW: u64 = 1_000_000_000_000_000_000;
const HOUR: u64 = 3_600_000_000_000;
const CASH: [u128; 3] = [NEAR / 10, NEAR, 10 * NEAR];
const SHARES: [u128; 3] = [10_000, 100_000, 1_000_000];
const PRICE: u128 = 1_000_000_000_000_000_000;
const FEE: u128 = 2_000_000_000_000_000_000_000;

/// What the next transaction does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    Normal,
    Refuse,
    /// Lands, but the answer is lost.
    LandsUnknown,
    /// Does not land, and the answer is lost.
    LostUnknown,
    /// The sending endpoint says success, nothing happened.
    Lie,
    /// Rejected by the node before it could be included: certainly not done.
    Rejected,
    /// Lands and succeeds, but the sending node reports a failure.
    FalseFailure,
}

type Effect = Box<dyn FnOnce(&mut State) -> Result<(), String> + Send>;

#[derive(Clone, Debug)]
struct FakeVault {
    keys: Vec<[u8; G2_LEN]>,
    liquid: u128,
    placed: u128,
    total_shares: u128,
    synced_at: u64,
    open: bool,
    requests: u32,
}

struct State {
    now: u64,
    cash_keys: Vec<[u8; G2_LEN]>,
    cash_liquid: u128,
    vaults: Vec<FakeVault>,
    /// account -> (deposited, issued, received)
    holders: BTreeMap<String, (u128, u128, u128)>,
    full_keys: BTreeMap<String, BTreeSet<[u8; 32]>>,
    spent: BTreeSet<[u8; 32]>,
    next: Next,
    calls: Vec<String>,
    /// Final outcome of each transaction both read endpoints know, by hash.
    outcomes: BTreeMap<[u8; 32], bool>,
    tx_count: u64,
    /// Signed and not sent yet: name, effect, hash.
    prepared: Option<(String, Effect, [u8; 32])>,
    /// The agent crashes right after the next transaction leaves.
    crash_after_send: bool,
    /// The second read endpoint does not know any transaction.
    second_unsure: bool,
    cash_open: bool,
    /// The contract's record of the agent's last sync, placement or paid exit.
    last_agent_call: u64,
    escape_delay: u64,
    /// The staking pool refuses the next `withdraw`; the contract's callback catches it.
    withdraw_fails: bool,
    /// Rewards a sync finds on the staking pool and adds to the vault's placed funds.
    sync_reward: u128,
    /// Times at which `enter`, `leave` and `pay_exit` reached the chain.
    sent_at: Vec<(String, u64)>,
}

type Shared = Arc<Mutex<State>>;

fn world(keys: &AgentKeys) -> Shared {
    Arc::new(Mutex::new(State {
        now: NOW,
        cash_keys: keys.cash_public(),
        cash_liquid: 0,
        vaults: (0..keys.vaults.len())
            .map(|v| FakeVault { keys: keys.vault_public(v).unwrap(), liquid: 0, placed: 0, total_shares: 0, synced_at: NOW, open: false, requests: 0 })
            .collect(),
        holders: BTreeMap::new(),
        full_keys: BTreeMap::new(),
        spent: BTreeSet::new(),
        next: Next::Normal,
        calls: vec![],
        outcomes: BTreeMap::new(),
        tx_count: 0,
        prepared: None,
        crash_after_send: false,
        second_unsure: false,
        cash_open: false,
        last_agent_call: NOW,
        escape_delay: 7 * 24 * HOUR,
        withdraw_fails: false,
        sync_reward: 0,
        sent_at: vec![],
    }))
}

fn escape_open(s: &State) -> bool {
    s.now >= s.last_agent_call + s.escape_delay
}

fn price(v: &FakeVault) -> u128 {
    if v.total_shares == 0 {
        PRICE
    } else {
        (v.liquid + v.placed) / v.total_shares
    }
}

/// The agent's view of the fake pool.
#[derive(Clone)]
struct FakeChain(Shared);

impl FakeChain {
    fn effect(call: &Call) -> (&'static str, Effect) {
        match call.clone() {
            Call::IssueCash { account, tier, count } => ("issue_cash", Box::new(move |s: &mut State| {
                let value = CASH[usize::from(tier)] * u128::from(count);
                let h = s.holders.get_mut(&account).ok_or("not a depositor")?;
                if h.0 - h.1 < value {
                    return Err("more than this account's deposits".into());
                }
                h.1 += value;
                s.cash_liquid += value;
                Ok(())
            })),
            Call::Enter { vault, note, outputs, .. } => {
                let nf = digests::cash_nullifier(note.tier, &note.pk, &note.nonce);
                ("enter", Box::new(move |s: &mut State| {
                    spend(s, nf)?;
                    let shares: u128 = outputs.iter().map(|(t, c)| SHARES[usize::from(*t)] * u128::from(*c)).sum();
                    let v = &mut s.vaults[vault as usize];
                    let cost = shares * price(v);
                    v.liquid += cost;
                    v.total_shares += shares;
                    s.cash_liquid -= cost.min(CASH[usize::from(note.tier)]);
                    Ok(())
                }))
            }
            Call::Leave { vault, note, .. } => {
                let nf = digests::note_nullifier(vault, note.tier, &note.pk, &note.nonce);
                ("leave", Box::new(move |s: &mut State| {
                    let v = &mut s.vaults[vault as usize];
                    let value = SHARES[usize::from(note.tier)] * price(v);
                    if value > v.liquid {
                        return Err("not enough liquid funds in this vault".into());
                    }
                    spend(s, nf)?;
                    let v = &mut s.vaults[vault as usize];
                    v.liquid -= value;
                    v.total_shares -= SHARES[usize::from(note.tier)];
                    s.cash_liquid += value - FEE;
                    Ok(())
                }))
            }
            Call::PayExit { note, to, .. } => {
                let nf = digests::cash_nullifier(note.tier, &note.pk, &note.nonce);
                ("pay_exit", Box::new(move |s: &mut State| {
                    spend(s, nf)?;
                    s.last_agent_call = s.now;
                    let h = s.holders.get_mut(&to).ok_or("exits go only to an account that deposited")?;
                    h.2 += CASH[usize::from(note.tier)];
                    s.cash_liquid -= CASH[usize::from(note.tier)];
                    Ok(())
                }))
            }
            Call::Place(vault, amount) => ("place", Box::new(move |s: &mut State| {
                let v = &mut s.vaults[vault as usize];
                v.liquid -= amount;
                v.placed += amount;
                s.last_agent_call = s.now;
                Ok(())
            })),
            Call::Sync(vault) => ("sync", Box::new(move |s: &mut State| {
                let now = s.now;
                let reward = s.sync_reward;
                let v = &mut s.vaults[vault as usize];
                v.synced_at = now;
                v.placed += reward;
                s.last_agent_call = now;
                Ok(())
            })),
            Call::Unstake(..) => ("unstake", Box::new(|_: &mut State| Ok(()))),
            Call::Withdraw(vault, amount) => ("withdraw", Box::new(move |s: &mut State| {
                if !std::mem::take(&mut s.withdraw_fails) {
                    let v = &mut s.vaults[vault as usize];
                    v.placed -= amount;
                    v.liquid += amount;
                }
                Ok(())
            })),
        }
    }
}

fn spend(s: &mut State, nf: [u8; 32]) -> Result<(), String> {
    if !s.spent.insert(nf) {
        return Err("note already spent".into());
    }
    Ok(())
}

impl PoolChain for FakeChain {
    fn begin(&mut self) -> Result<u64, String> {
        Ok(self.0.lock().unwrap().now)
    }
    fn config(&mut self) -> Result<ConfigInfo, String> {
        let s = self.0.lock().unwrap();
        Ok(ConfigInfo {
            agent: AGENT.into(),
            network: NETWORK.into(),
            vault_count: s.vaults.len() as u32,
            escape_open: escape_open(&s),
            last_agent_call: s.last_agent_call,
            admin_pending_until: 0,
            escape_delay_ns: s.escape_delay,
        })
    }
    fn cash(&mut self) -> Result<CashInfo, String> {
        let s = self.0.lock().unwrap();
        Ok(CashInfo {
            tiers: CASH.iter().copied().zip(s.cash_keys.iter().copied()).collect(),
            liquid: s.cash_liquid,
            outstanding: 0,
            hourly_cap: 1_000 * NEAR,
            requests: 0,
            open: s.cash_open || escape_open(&s),
        })
    }
    fn vault(&mut self, id: u32) -> Result<VaultInfo, String> {
        let s = self.0.lock().unwrap();
        let v = s.vaults.get(id as usize).ok_or("no vault")?;
        Ok(VaultInfo {
            tiers: SHARES.iter().copied().zip(v.keys.iter().copied()).collect(),
            liquid: v.liquid,
            placed: v.placed,
            withdrawing: 0,
            total_shares: v.total_shares,
            share_price: price(v),
            synced_at: v.synced_at,
            max_assets: u128::MAX,
            hourly_cap: 1_000 * NEAR,
            frozen: false,
            busy: false,
            requests: v.requests,
            open: v.open || escape_open(&s),
            staking: true,
        })
    }
    fn holder(&mut self, account: &str) -> Result<HolderInfo, String> {
        let s = self.0.lock().unwrap();
        let (d, i, _) = s.holders.get(account).copied().unwrap_or_default();
        Ok(HolderInfo { issued: i, refundable: d - i })
    }
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        Ok(self.0.lock().unwrap().spent.contains(nf))
    }
    fn full_access_key(&mut self, account: &str, pk: &[u8; 32]) -> Result<bool, String> {
        Ok(self.0.lock().unwrap().full_keys.get(account).is_some_and(|k| k.contains(pk)))
    }
    fn prepare(&mut self, call: &Call) -> Result<[u8; 32], CallError> {
        let (name, effect) = Self::effect(call);
        let mut s = self.0.lock().unwrap();
        s.tx_count += 1;
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&s.tx_count.to_le_bytes());
        s.prepared = Some((name.to_string(), effect, hash));
        Ok(hash)
    }
    /// Applies the prepared transaction according to the injected outcome.
    fn send_prepared(&mut self) -> Result<(), CallError> {
        let (reply, crash) = {
            let mut s = self.0.lock().unwrap();
            let (name, effect, hash) = s.prepared.take().ok_or_else(|| CallError::Refused("nothing prepared".into()))?;
            s.calls.push(name.clone());
            if matches!(name.as_str(), "enter" | "leave" | "pay_exit") {
                let now = s.now;
                s.sent_at.push((name, now));
            }
            let next = std::mem::replace(&mut s.next, Next::Normal);
            let landed = match next {
                Next::Refuse => Some(Err("refused".to_string())),
                Next::Rejected | Next::Lie | Next::LostUnknown => None,
                Next::Normal | Next::LandsUnknown | Next::FalseFailure => Some(effect(&mut s)),
            };
            if let Some(result) = &landed {
                s.outcomes.insert(hash, result.is_ok());
            }
            let reply = match (next, landed) {
                (Next::Rejected, _) => Err(CallError::Refused("rejected by the node".into())),
                (Next::Lie, _) => Ok(()),
                (Next::LostUnknown, _) => Err(CallError::Unknown("timeout".into())),
                (_, Some(Err(e))) => Err(CallError::Failed(e)),
                (Next::LandsUnknown, _) => Err(CallError::Unknown("timeout".into())),
                (Next::FalseFailure, _) => Err(CallError::Failed("the sending node says it failed".into())),
                _ => Ok(()),
            };
            (reply, std::mem::take(&mut s.crash_after_send))
        };
        // Outside the lock, so the shared state survives the crash.
        if crash {
            panic!("the agent stops right after sending");
        }
        reply
    }
    fn tx_outcome(&mut self, hash: &[u8; 32]) -> Result<Option<bool>, String> {
        let s = self.0.lock().unwrap();
        Ok(if s.second_unsure { None } else { s.outcomes.get(hash).copied() })
    }
}

/// The client core's view of the same fake pool, in the contract's JSON.
struct ClientView(Shared);

impl ona_core::pool::PoolChain for ClientView {
    fn view(&self, method: &str, args: Value) -> Result<Value, String> {
        let s = self.0.lock().unwrap();
        let raw = |k: &[u8; G2_LEN]| B64.encode(g2_to_raw(k).unwrap());
        Ok(match method {
            "get_config" => json!({"network": NETWORK, "vault_count": s.vaults.len()}),
            "get_cash" => json!({"tiers": CASH.iter().zip(&s.cash_keys).map(|(v, k)| json!({"value": v.to_string(), "pk_raw": raw(k)})).collect::<Vec<_>>()}),
            "get_vault" => {
                let v = &s.vaults[args["vault_id"].as_u64().unwrap() as usize];
                json!({
                    "tiers": SHARES.iter().zip(&v.keys).map(|(n, k)| json!({"shares": n.to_string(), "pk_raw": raw(k)})).collect::<Vec<_>>(),
                    "total_shares": v.total_shares.to_string(), "liquid": v.liquid.to_string(), "placed": v.placed.to_string(),
                    "fee_owed": "0", "orphan": "0", "share_price": price(v).to_string(), "frozen": false,
                })
            }
            "is_spent" => {
                let nf: [u8; 32] = B64.decode(args["nf"].as_str().unwrap()).unwrap().try_into().unwrap();
                json!(s.spent.contains(&nf))
            }
            "get_holder" => {
                let (d, _, r) = s.holders.get(args["account"].as_str().unwrap()).copied().unwrap_or_default();
                json!({"exit_limit": (d - r).to_string()})
            }
            other => return Err(format!("unknown view {other}")),
        })
    }
    fn mode(&self) -> &'static str {
        "mock"
    }
}

/// Batches of one, no delay, one-hour windows: each test moves the chain's time to the window it needs.
fn quick() -> QueueParams {
    QueueParams { window_ns: HOUR, min_batch: 1, min_delay_ns: 0, jitter_ns: 0, ..QueueParams::default() }
}

fn agent_with(keys: AgentKeys, shared: &Shared, params: Params, queue: QueueParams) -> Agent<FakeChain, MemoryStore> {
    Agent::start(FakeChain(shared.clone()), MemoryStore::default(), keys, POOL, AGENT, params, queue)
        .unwrap()
        .with_clock(Box::new(|| NOW))
}

fn agent_on(keys: AgentKeys, shared: &Shared) -> Agent<FakeChain, MemoryStore> {
    agent_with(keys, shared, Params::default(), quick())
}

/// Moves the chain's time to the start of the next window of a class (entries and leaves, or cash exits), with
/// one-hour windows, and returns it.
fn next_window(shared: &Shared, pays: bool) -> u64 {
    let mut s = shared.lock().unwrap();
    let mut w = s.now / HOUR + 1;
    if (w % 2 == 1) != pays {
        w += 1;
    }
    s.now = w * HOUR;
    for v in s.vaults.iter_mut() {
        v.synced_at = w * HOUR;
    }
    s.now
}

fn run_window<S: Store>(agent: &mut Agent<FakeChain, S>, shared: &Shared, pays: bool) -> Vec<String> {
    next_window(shared, pays);
    agent.tick().unwrap()
}

fn keys() -> AgentKeys {
    AgentKeys::generate(3, &[3, 2]).unwrap()
}

/// A depositor with a full-access key, who deposited `amount`.
fn depositor(shared: &Shared, account: &str, amount: u128) -> SigningKey {
    let key = SigningKey::generate(&mut OsRng);
    let mut s = shared.lock().unwrap();
    s.full_keys.entry(account.into()).or_default().insert(key.verifying_key().to_bytes());
    s.holders.entry(account.into()).or_default().0 += amount;
    key
}

fn cash_pending(tier: u8) -> PendingToken {
    PendingToken::new(&mut OsRng, tier, digests::cash_dst(NETWORK, POOL).as_bytes()).unwrap()
}

fn proof(key: &SigningKey, account: &str, notes: &[(u8, [u8; G1_LEN])]) -> Proof {
    let nonce = [5u8; 32];
    let hash = nep413::payload_hash(&nep413::issue_message(POOL, account, notes), &nonce, POOL);
    Proof { public_key: key.verifying_key().to_bytes(), signature: key.sign(&hash).to_bytes(), nonce }
}

/// Cash notes of `tier` issued by the agent, finished as a wallet would.
fn issue_notes(agent: &mut Agent<FakeChain, impl Store>, key: &SigningKey, account: &str, tier: u8, count: usize) -> Vec<(Token, SigningKey)> {
    let pending: Vec<PendingToken> = (0..count).map(|_| cash_pending(tier)).collect();
    let notes: Vec<(u8, [u8; G1_LEN])> = pending.iter().map(|p| (tier, p.blinded)).collect();
    let reply = agent.issue(&IssueRequest { account: account.into(), notes: notes.clone(), proof: proof(key, account, &notes) });
    let Reply::Signed(sigs) = reply else { panic!("{reply:?}") };
    let pk = agent.chain.cash().unwrap().tiers[usize::from(tier)].1;
    pending.into_iter().zip(sigs).map(|(p, s)| p.finish(&s, &pk).unwrap()).collect()
}

fn note_of(t: &Token) -> Note {
    Note { tier: t.denom_id, pk: t.pk, nonce: t.nonce, sig: t.sig }
}

fn enter_request(token: &Token, owner: &SigningKey, vault: u32, outputs: Vec<(u8, u64)>) -> (NoteRequest, Vec<PendingToken>) {
    enter_request_until(token, owner, vault, outputs, NOW + 24 * HOUR)
}

fn enter_request_until(token: &Token, owner: &SigningKey, vault: u32, outputs: Vec<(u8, u64)>, expires_at: u64) -> (NoteRequest, Vec<PendingToken>) {
    let nf = digests::cash_nullifier(token.denom_id, &token.pk, &token.nonce);
    let digest = digests::enter_digest(POOL, &nf, vault, &outputs, expires_at);
    let dst = digests::note_dst(NETWORK, POOL, vault);
    let pending: Vec<PendingToken> = outputs
        .iter()
        .flat_map(|(t, c)| (0..*c).map(|_| PendingToken::new(&mut OsRng, *t, dst.as_bytes()).unwrap()).collect::<Vec<_>>())
        .collect();
    let request = NoteRequest {
        kind: Kind::Enter,
        vault,
        note: note_of(token),
        owner_sig: owner.sign(&digest).to_bytes(),
        outputs,
        blinded: pending.iter().map(|p| p.blinded).collect(),
        expires_at,
    };
    (request, pending)
}

#[test]
fn cash_is_issued_only_for_the_depositors_wallet_signature() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let notes: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded)];

    let mallory = SigningKey::generate(&mut OsRng);
    let forged = agent.issue(&IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: proof(&mallory, "alice.test", &notes) });
    assert!(matches!(forged, Reply::Refused(401, _)), "a key that is not alice's: {forged:?}");

    let stolen = proof(&alice, "alice.test", &notes);
    let other_points = vec![(1, cash_pending(1).blinded)];
    let swapped = agent.issue(&IssueRequest { account: "alice.test".into(), notes: other_points, proof: stolen.clone() });
    assert!(matches!(swapped, Reply::Refused(401, _)), "alice's signature serves only her points: {swapped:?}");
    assert!(shared.lock().unwrap().calls.is_empty(), "nothing reached the chain");

    let reply = agent.issue(&IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: stolen.clone() });
    let Reply::Signed(sigs) = reply else { panic!("{reply:?}") };
    assert_eq!(sigs.len(), 1);
    let again = agent.issue(&IssueRequest { account: "alice.test".into(), notes, proof: stolen });
    assert_eq!(again, Reply::Signed(sigs), "a replay gets the same signatures");
    assert_eq!(shared.lock().unwrap().calls, vec!["issue_cash"], "and is not paid twice");
}

#[test]
fn no_cash_beyond_the_deposit_and_none_on_a_lying_endpoint() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", NEAR);
    let notes: Vec<(u8, [u8; G1_LEN])> = vec![(2, cash_pending(2).blinded)];
    let reply = agent.issue(&IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: proof(&alice, "alice.test", &notes) });
    assert!(matches!(reply, Reply::Refused(409, _)), "10 NEAR of cash for a 1 NEAR deposit: {reply:?}");

    let small: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded)];
    shared.lock().unwrap().next = Next::Lie;
    let reply = agent.issue(&IssueRequest { account: "alice.test".into(), notes: small.clone(), proof: proof(&alice, "alice.test", &small) });
    assert!(matches!(reply, Reply::Pending(_)), "the sending endpoint said yes, the chain shows nothing: {reply:?}");
    assert_eq!(agent.signatures(&[small[0].1]), vec![None], "nothing signed");
}

fn temp(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ona-agent-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn an_issue_whose_outcome_is_unknown_is_signed_after_a_restart_once_the_chain_shows_it() {
    let (key_path, store_path) = (temp("keys"), temp("store"));
    let k = keys();
    k.save(&key_path).unwrap();
    let shared = world(&k);
    let binding = ona_agent::store_binding(&k, POOL);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let notes: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded), (0, cash_pending(0).blinded)];
    let request = IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: proof(&alice, "alice.test", &notes) };
    {
        let store = FileStore::create(&store_path, &binding).unwrap();
        let mut agent = Agent::start(FakeChain(shared.clone()), store, k, POOL, AGENT, Params::default(), quick()).unwrap();
        shared.lock().unwrap().next = Next::LandsUnknown;
        assert!(matches!(agent.issue(&request), Reply::Pending(_)));
        let other: Vec<(u8, [u8; G1_LEN])> = vec![(0, cash_pending(0).blinded)];
        let blocked = agent.issue(&IssueRequest { account: "alice.test".into(), notes: other.clone(), proof: proof(&alice, "alice.test", &other) });
        assert!(matches!(blocked, Reply::Refused(409, _)), "one unsettled issue per account: {blocked:?}");
    }
    // The agent restarts on the same store and keys: the first tier is confirmed, never sent again.
    let store = FileStore::open(&store_path, &binding).unwrap();
    let mut agent =
        Agent::start(FakeChain(shared.clone()), store, AgentKeys::load(&key_path).unwrap(), POOL, AGENT, Params::default(), quick()).unwrap();
    agent.tick().unwrap();
    let sigs = agent.signatures(&notes.iter().map(|n| n.1).collect::<Vec<_>>());
    assert!(sigs.iter().all(Option::is_some), "both tiers signed after the restart");
    assert_eq!(shared.lock().unwrap().calls.iter().filter(|c| *c == "issue_cash").count(), 2, "one call per tier, none repeated");
    assert_eq!(shared.lock().unwrap().holders["alice.test"].1, 11 * NEAR / 10);
    drop(agent);
    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(&key_path);
}

#[test]
fn an_issue_that_never_landed_frees_the_account_after_the_transaction_expiry() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let notes: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded)];
    shared.lock().unwrap().next = Next::LostUnknown;
    let request = IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: proof(&alice, "alice.test", &notes) };
    assert!(matches!(agent.issue(&request), Reply::Pending(_)));
    agent.tick().unwrap();
    assert_eq!(shared.lock().unwrap().calls.iter().filter(|c| *c == "issue_cash").count(), 1, "never resent");
    shared.lock().unwrap().now = NOW + ona_agent::service::TX_EXPIRY_NS + 1;
    agent.tick().unwrap();
    assert!(matches!(agent.issue(&request), Reply::Refused(409, _)), "given up");
    let fresh: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded)];
    let reply = agent.issue(&IssueRequest { account: "alice.test".into(), notes: fresh.clone(), proof: proof(&alice, "alice.test", &fresh) });
    assert!(matches!(reply, Reply::Signed(_)), "the account can ask again: {reply:?}");
}

#[test]
fn an_issue_both_endpoints_report_failed_frees_the_account_but_one_is_not_enough() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let notes: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded)];
    shared.lock().unwrap().next = Next::LostUnknown;
    let request = IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: proof(&alice, "alice.test", &notes) };
    assert!(matches!(agent.issue(&request), Reply::Pending(_)));
    let hash = {
        let mut s = shared.lock().unwrap();
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&s.tx_count.to_le_bytes());
        s.outcomes.insert(h, false);
        s.second_unsure = true;
        h
    };
    assert!(matches!(agent.issue(&request), Reply::Pending(_)), "one endpoint saying failed does not stop the wait");
    shared.lock().unwrap().second_unsure = false;
    assert_eq!(shared.lock().unwrap().outcomes.get(&hash), Some(&false));
    assert!(matches!(agent.issue(&request), Reply::Refused(409, _)), "no two-day wait for a transaction both report failed");
    assert_eq!(agent.signatures(&[notes[0].1]), vec![None]);
}

#[test]
fn an_account_may_ask_for_a_few_cash_issues_per_hour() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_with(k, &shared, Params::default(), QueueParams { issues_per_hour: 2, ..quick() });
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    for _ in 0..2 {
        let n: Vec<(u8, [u8; G1_LEN])> = vec![(0, cash_pending(0).blinded)];
        assert!(matches!(agent.issue(&IssueRequest { account: "alice.test".into(), notes: n.clone(), proof: proof(&alice, "alice.test", &n) }), Reply::Signed(_)));
    }
    let n: Vec<(u8, [u8; G1_LEN])> = vec![(0, cash_pending(0).blinded)];
    let third = agent.issue(&IssueRequest { account: "alice.test".into(), notes: n.clone(), proof: proof(&alice, "alice.test", &n) });
    assert!(matches!(third, Reply::Refused(429, _)), "{third:?}");
}

fn calls_of(shared: &Shared, name: &str) -> usize {
    shared.lock().unwrap().calls.iter().filter(|c| *c == name).count()
}

#[test]
fn a_note_serves_one_request_and_is_signed_only_once_spent() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();

    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9), (0, 9)]);
    let mut bad = request.clone();
    bad.owner_sig[0] ^= 1;
    assert!(matches!(agent.note_request(&bad), Reply::Refused(400, _)), "checked before any gas is spent");
    assert!(shared.lock().unwrap().calls.iter().all(|c| c == "issue_cash"), "and before any transaction");

    assert!(matches!(agent.note_request(&request), Reply::Pending(_)), "queued");
    assert_eq!(calls_of(&shared, "enter"), 0, "nothing leaves on arrival");
    let (other, _) = enter_request(&token, &owner, 1, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&other), Reply::Refused(409, _)), "the note is taken by the first request");

    shared.lock().unwrap().next = Next::LostUnknown;
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)), "sent, not landed");
    // Resending is safe: the contract spends a note once.
    let log = run_window(&mut agent, &shared, false);
    let reply = agent.note_request(&request);
    let Reply::Signed(sigs) = reply else { panic!("{reply:?}") };
    assert_eq!(sigs.len(), 18);
    assert_eq!(agent.note_request(&request), Reply::Signed(sigs.clone()), "a replay is answered from the record");
    assert_eq!(calls_of(&shared, "enter"), 2);
    let printed = B64.encode(sigs[0]);
    assert!(log.iter().all(|l| !l.contains(&printed)), "no signature in the log: {log:?}");
    assert!(!format!("{:?}", Reply::Signed(sigs)).contains(&printed), "nor in a printed reply");
}

#[test]
fn a_lying_endpoint_gets_no_share_signature_and_an_expired_request_frees_its_note() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    shared.lock().unwrap().next = Next::Lie;
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    assert_eq!(agent.signatures(&request.blinded), vec![None; 9]);

    shared.lock().unwrap().now = request.expires_at + 1;
    let log = agent.tick().unwrap();
    assert!(log.iter().any(|l| l.contains("expired")), "past its deadline it can never land: {log:?}");
    assert_eq!(shared.lock().unwrap().spent.len(), 0);
    // The note is free again: its owner can sign a new request with a later deadline.
    let (again, _) = enter_request_until(&token, &owner, 1, vec![(1, 9)], request.expires_at + 24 * HOUR);
    assert!(matches!(agent.note_request(&again), Reply::Pending(_)));
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&again), Reply::Signed(_)));
}

#[test]
fn an_entry_the_chain_refuses_frees_the_note_and_its_owner_signature_serves_no_other_points() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    shared.lock().unwrap().next = Next::Refuse;
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&request), Reply::Refused(409, _)));
    assert_eq!(agent.signatures(&request.blinded), vec![None; 9]);

    // The refused transaction is public: someone replays the note and its owner's signature with their own points.
    let (_, theirs) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    let stolen = NoteRequest { blinded: theirs.iter().map(|p| p.blinded).collect(), ..request.clone() };
    assert!(matches!(agent.note_request(&stolen), Reply::Refused(409, _)), "the owner's signature serves only its first points");
    run_window(&mut agent, &shared, false);
    assert_eq!(agent.signatures(&stolen.blinded), vec![None; 9], "nothing signed for the thief");

    // The owner signs again, with another deadline.
    let (other, _) = enter_request_until(&token, &owner, 1, vec![(1, 9)], request.expires_at + HOUR);
    assert!(matches!(agent.note_request(&other), Reply::Pending(_)));
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&other), Reply::Signed(_)), "the note can serve another request");
}

#[test]
fn a_stale_vault_is_synced_before_an_entry() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    let now = next_window(&shared, false);
    shared.lock().unwrap().vaults[0].synced_at = now - HOUR;
    agent.tick().unwrap();
    assert!(matches!(agent.note_request(&request), Reply::Signed(_)));
    let calls = shared.lock().unwrap().calls.clone();
    assert_eq!(calls[..3], ["issue_cash", "sync", "enter"], "{calls:?}");
}

#[test]
fn the_planner_places_at_a_settlement_and_the_tick_records_it() {
    let k = keys();
    let shared = world(&k);
    let params = Params { reserve_percent: 20, settlement_period_ns: HOUR, min_active: 1, min_move: NEAR / 10, ..Params::default() };
    let mut agent = agent_with(k, &shared, params, quick());
    let alice = depositor(&shared, "alice.test", 20 * NEAR);
    let notes = issue_notes(&mut agent, &alice, "alice.test", 2, 1);
    let (token, owner) = &notes[0];
    let (request, _) = enter_request(token, owner, 0, vec![(2, 9), (1, 9), (0, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&request), Reply::Signed(_)));
    let now = shared.lock().unwrap().now + 2 * HOUR;
    shared.lock().unwrap().now = now;
    shared.lock().unwrap().vaults[0].synced_at = now;
    let log = agent.tick().unwrap();
    let placed = shared.lock().unwrap().vaults[0].placed;
    assert!(placed > 0, "{log:?}");
    assert_eq!(placed, shared.lock().unwrap().vaults[0].liquid * 4, "a fifth stays liquid");
    assert!(agent.tick().unwrap().iter().all(|l| !l.contains("Place")), "once per settlement");
    let _ = Action::Sync(0);
}

#[test]
fn a_request_waits_its_delay_and_leaves_only_in_a_batch() {
    let k = keys();
    let shared = world(&k);
    let queue = QueueParams { window_ns: HOUR, min_batch: 2, min_delay_ns: 3 * HOUR, jitter_ns: 0, ..QueueParams::default() };
    let mut agent = agent_with(k, &shared, Params::default(), queue);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let mut notes = issue_notes(&mut agent, &alice, "alice.test", 1, 2);
    let (t1, o1) = notes.pop().unwrap();
    let (t2, o2) = notes.pop().unwrap();
    let (first, _) = enter_request(&t1, &o1, 0, vec![(1, 9)]);
    let arrived = shared.lock().unwrap().now;
    assert!(matches!(agent.note_request(&first), Reply::Pending(_)));
    for _ in 0..3 {
        run_window(&mut agent, &shared, false);
    }
    assert_eq!(calls_of(&shared, "enter"), 0, "alone in the queue, past its delay: it still waits for a batch");

    let (second, _) = enter_request(&t2, &o2, 0, vec![(1, 9)]);
    let second_arrived = shared.lock().unwrap().now;
    assert!(matches!(agent.note_request(&second), Reply::Pending(_)));
    run_window(&mut agent, &shared, false);
    assert_eq!(calls_of(&shared, "enter"), 0, "the second has not waited its delay");
    while calls_of(&shared, "enter") == 0 {
        run_window(&mut agent, &shared, false);
    }
    let sent = shared.lock().unwrap().sent_at.clone();
    assert_eq!(sent.len(), 2, "both leave together: {sent:?}");
    assert_eq!(sent[0].1, sent[1].1);
    assert!(sent[0].1 >= second_arrived + 3 * HOUR && sent[0].1 >= arrived + 3 * HOUR);
    assert!(matches!(agent.note_request(&first), Reply::Signed(_)));
    assert!(matches!(agent.note_request(&second), Reply::Signed(_)));
}

#[test]
fn each_request_gets_its_own_random_delay() {
    let k = keys();
    let shared = world(&k);
    let queue = QueueParams { min_delay_ns: HOUR, jitter_ns: HOUR, ..quick() };
    let mut agent = agent_with(k, &shared, Params::default(), queue);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    for (token, owner) in issue_notes(&mut agent, &alice, "alice.test", 0, 6) {
        assert!(matches!(agent.note_request(&enter_request(&token, &owner, 0, vec![(0, 1)]).0), Reply::Pending(_)));
    }
    let delays: BTreeSet<u64> = agent.store.scan("q:").iter().filter_map(|(_, r)| r["not_before"].as_u64()).map(|t| t - NOW).collect();
    assert!(delays.iter().all(|d| (HOUR..=2 * HOUR).contains(d)), "{delays:?}");
    assert!(delays.len() > 1, "not one fixed delay: {delays:?}");
}

#[test]
fn a_cash_exit_is_paid_once_only_as_its_owner_signed_and_never_in_an_entry_window() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let expires_at = NOW + 24 * HOUR;
    let nf = digests::cash_nullifier(token.denom_id, &token.pk, &token.nonce);
    let sig = owner.sign(&digests::cash_exit_digest(POOL, &nf, "alice.test", expires_at)).to_bytes();
    let redirected = PayRequest { note: note_of(&token), owner_sig: sig, to: "mallory.test".into(), expires_at };
    assert!(matches!(agent.pay(&redirected), Reply::Refused(400, _)), "signed for alice, not for mallory");
    let request = PayRequest { to: "alice.test".into(), ..redirected };
    assert!(matches!(agent.pay(&request), Reply::Pending(_)));
    run_window(&mut agent, &shared, false);
    assert_eq!(calls_of(&shared, "pay_exit"), 0, "not in a window of entries and leaves");
    run_window(&mut agent, &shared, true);
    assert_eq!(agent.pay(&request), Reply::Paid);
    assert_eq!(agent.pay(&request), Reply::Paid, "answered from the record");
    assert_eq!(calls_of(&shared, "pay_exit"), 1);
}

#[test]
fn a_cash_exit_waits_for_liquid_funds_instead_of_failing_in_public() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let expires_at = NOW + 24 * HOUR;
    let nf = digests::cash_nullifier(token.denom_id, &token.pk, &token.nonce);
    let sig = owner.sign(&digests::cash_exit_digest(POOL, &nf, "alice.test", expires_at)).to_bytes();
    let request = PayRequest { note: note_of(&token), owner_sig: sig, to: "alice.test".into(), expires_at };
    let liquid = std::mem::replace(&mut shared.lock().unwrap().cash_liquid, 0);
    assert!(matches!(agent.pay(&request), Reply::Pending(_)));
    run_window(&mut agent, &shared, true);
    assert_eq!(calls_of(&shared, "pay_exit"), 0, "no call the contract would refuse");
    assert!(matches!(agent.pay(&request), Reply::Pending(_)));
    shared.lock().unwrap().cash_liquid = liquid;
    run_window(&mut agent, &shared, true);
    assert_eq!(agent.pay(&request), Reply::Paid);
}

#[test]
fn finished_records_and_signatures_are_deleted_after_the_retention() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_with(k, &shared, Params::default(), QueueParams { retention_ns: 2 * HOUR, ..quick() });
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    run_window(&mut agent, &shared, false);
    assert!(agent.signatures(&request.blinded).iter().all(Option::is_some));
    let finished = agent.store.scan("q:");
    assert!(finished.iter().all(|(_, r)| r.get("p").is_none() && r.get("expires_at").is_none()), "a finished record keeps no request");

    shared.lock().unwrap().now += 3 * HOUR;
    agent.tick().unwrap();
    assert_eq!(agent.signatures(&request.blinded), vec![None; 9], "signatures deleted");
    assert!(agent.store.scan("q:").is_empty() && agent.store.scan("i:").is_empty(), "finished records deleted");
    shared.lock().unwrap().now = request.expires_at + 1;
    agent.tick().unwrap();
    assert!(agent.store.scan("o:").is_empty(), "owner-signature bindings deleted after their deadline");
}

fn nf_hex(token: &Token) -> String {
    digests::cash_nullifier(token.denom_id, &token.pk, &token.nonce).iter().map(|b| format!("{b:02x}")).collect()
}

fn pay_request(token: &Token, owner: &SigningKey, to: &str) -> PayRequest {
    let expires_at = NOW + 24 * HOUR;
    let nf = digests::cash_nullifier(token.denom_id, &token.pk, &token.nonce);
    let owner_sig = owner.sign(&digests::cash_exit_digest(POOL, &nf, to, expires_at)).to_bytes();
    PayRequest { note: note_of(token), owner_sig, to: to.into(), expires_at }
}

#[test]
fn a_queued_request_whose_note_the_escape_spent_is_refused_not_signed() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    // The note leaves by `escape_exit` (or a listed request) while the entry waits in the queue.
    shared.lock().unwrap().spent.insert(digests::cash_nullifier(token.denom_id, &token.pk, &token.nonce));
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&request), Reply::Refused(409, _)));
    assert_eq!(agent.signatures(&request.blinded), vec![None; 9], "no shares for an entry that never happened");
    assert_eq!(calls_of(&shared, "enter"), 0);
}

#[test]
fn a_sent_request_is_signed_only_when_its_own_transaction_succeeded() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    shared.lock().unwrap().next = Next::LostUnknown;
    run_window(&mut agent, &shared, true);
    run_window(&mut agent, &shared, false);
    assert_eq!(calls_of(&shared, "enter"), 1, "sent, never landed");
    // Then the escape spends the note: it is spent, but not by the agent's entry.
    shared.lock().unwrap().spent.insert(digests::cash_nullifier(token.denom_id, &token.pk, &token.nonce));
    agent.tick().unwrap();
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)), "its own transaction is not confirmed");
    assert_eq!(agent.signatures(&request.blinded), vec![None; 9]);
    let sent: Vec<[u8; 32]> = {
        let s = shared.lock().unwrap();
        (1..=s.tx_count).map(|n| { let mut h = [0u8; 32]; h[..8].copy_from_slice(&n.to_le_bytes()); h }).filter(|h| !s.outcomes.contains_key(h)).collect()
    };
    for h in sent {
        shared.lock().unwrap().outcomes.insert(h, false);
    }
    agent.tick().unwrap();
    assert!(matches!(agent.note_request(&request), Reply::Refused(409, _)), "both endpoints say its transaction failed");
    assert_eq!(agent.signatures(&request.blinded), vec![None; 9]);
}

#[test]
fn nothing_is_queued_while_the_escape_is_open() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let mut notes = issue_notes(&mut agent, &alice, "alice.test", 1, 2);
    let (t1, o1) = notes.pop().unwrap();
    let (t2, o2) = notes.pop().unwrap();
    shared.lock().unwrap().cash_open = true;
    assert!(matches!(agent.note_request(&enter_request(&t1, &o1, 0, vec![(1, 9)]).0), Reply::Refused(409, _)), "the cash note could leave by the escape");
    assert!(matches!(agent.pay(&pay_request(&t2, &o2, "alice.test")), Reply::Refused(409, _)));
    shared.lock().unwrap().cash_open = false;
    shared.lock().unwrap().vaults[0].open = true;
    assert!(matches!(agent.note_request(&enter_request(&t1, &o1, 0, vec![(1, 9)]).0), Reply::Refused(409, _)), "nor into an open vault");
    assert!(matches!(agent.note_request(&enter_request(&t1, &o1, 1, vec![(1, 9)]).0), Reply::Pending(_)), "another vault is fine");
}

#[test]
fn a_reservation_left_by_a_crash_is_cleared_by_the_next_tick() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    shared.lock().unwrap().next = Next::Refuse;
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&request), Reply::Refused(409, _)));
    // The crash came after the refusal was written and before the note's binding was removed; likewise after an
    // issue finished and before the account's lock was removed.
    let refused = agent.store.scan("q:").pop().unwrap().0;
    agent.store.put(&format!("n:{}", nf_hex(&token)), json!(refused)).unwrap();
    let issue = agent.store.scan("i:").pop().unwrap().0;
    agent.store.put("a:alice.test", json!(issue)).unwrap();
    agent.tick().unwrap();
    assert!(agent.store.scan("n:").is_empty() && agent.store.scan("a:").is_empty(), "both cleared");
    let (other, _) = enter_request_until(&token, &owner, 1, vec![(1, 9)], request.expires_at + HOUR);
    assert!(matches!(agent.note_request(&other), Reply::Pending(_)), "the note serves another request");
    issue_notes(&mut agent, &alice, "alice.test", 0, 1);
}

#[test]
fn a_batch_is_counted_after_its_funds_are_checked() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_with(k, &shared, Params::default(), QueueParams { min_batch: 5, ..quick() });
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    for (token, owner) in issue_notes(&mut agent, &alice, "alice.test", 0, 5) {
        assert!(matches!(agent.pay(&pay_request(&token, &owner, "alice.test")), Reply::Pending(_)));
    }
    // Five are ready, the cash covers one: none leaves, rather than one alone.
    let liquid = std::mem::replace(&mut shared.lock().unwrap().cash_liquid, NEAR / 10);
    run_window(&mut agent, &shared, true);
    assert_eq!(calls_of(&shared, "pay_exit"), 0);
    shared.lock().unwrap().cash_liquid = liquid;
    run_window(&mut agent, &shared, true);
    assert_eq!(calls_of(&shared, "pay_exit"), 5, "all five together");
}

#[test]
fn a_request_is_sent_again_only_in_a_window_of_its_kind() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    shared.lock().unwrap().next = Next::LostUnknown;
    run_window(&mut agent, &shared, false);
    agent.tick().unwrap();
    run_window(&mut agent, &shared, true);
    assert_eq!(calls_of(&shared, "enter"), 1, "not again in the same window, nor in a cash-exit window");
    run_window(&mut agent, &shared, false);
    assert_eq!(calls_of(&shared, "enter"), 2);
    assert!(matches!(agent.note_request(&request), Reply::Signed(_)));
}

#[test]
fn a_failure_reported_by_the_sending_node_alone_frees_nothing() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    // A cash issue: the node says it failed, it landed.
    let notes: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded)];
    let request = IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: proof(&alice, "alice.test", &notes) };
    shared.lock().unwrap().next = Next::FalseFailure;
    assert!(matches!(agent.issue(&request), Reply::Pending(_)), "not closed on one node's word");
    assert!(matches!(agent.issue(&request), Reply::Signed(_)), "the account's issued cash shows it");
    // An entry: the same.
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (entry, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&entry), Reply::Pending(_)));
    shared.lock().unwrap().next = Next::FalseFailure;
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&entry), Reply::Signed(_)), "its own transaction succeeded on both endpoints");
}

#[test]
fn a_transaction_the_node_rejected_before_inclusion_frees_the_note() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (entry, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&entry), Reply::Pending(_)));
    shared.lock().unwrap().next = Next::Rejected;
    run_window(&mut agent, &shared, false);
    assert!(matches!(agent.note_request(&entry), Reply::Refused(409, _)));
}

#[test]
fn a_crash_right_after_sending_still_finds_the_transaction() {
    let (key_path, store_path) = (temp("crash-keys"), temp("crash-store"));
    let k = keys();
    k.save(&key_path).unwrap();
    let shared = world(&k);
    let binding = ona_agent::store_binding(&k, POOL);
    let start = |store| {
        Agent::start(FakeChain(shared.clone()), store, AgentKeys::load(&key_path).unwrap(), POOL, AGENT, Params::default(), quick())
            .unwrap()
            .with_clock(Box::new(|| NOW))
    };
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let mut agent = start(FileStore::create(&store_path, &binding).unwrap());
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (entry, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&entry), Reply::Pending(_)));
    next_window(&shared, false);
    shared.lock().unwrap().crash_after_send = true;
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| agent.tick()));
    assert!(crashed.is_err(), "the agent stopped after the entry left");
    drop(agent);
    assert_eq!(calls_of(&shared, "enter"), 1);
    // Restarted on the same store: the transaction's hash was recorded before it left.
    let mut agent = start(FileStore::open(&store_path, &binding).unwrap());
    agent.tick().unwrap();
    assert!(matches!(agent.note_request(&entry), Reply::Signed(_)));
    assert_eq!(calls_of(&shared, "enter"), 1, "not sent again");
    drop(agent);
    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(&key_path);
}

#[test]
fn an_open_issue_is_served_after_the_wallet_key_was_removed() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let notes: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded)];
    let request = IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: proof(&alice, "alice.test", &notes) };
    shared.lock().unwrap().next = Next::LandsUnknown;
    assert!(matches!(agent.issue(&request), Reply::Pending(_)));
    // The account removes the key it signed with; the client asks again.
    shared.lock().unwrap().full_keys.remove("alice.test");
    assert!(matches!(agent.issue(&request), Reply::Signed(_)), "checked when the issue opened, not on each replay");
    let other: Vec<(u8, [u8; G1_LEN])> = vec![(0, cash_pending(0).blinded)];
    let fresh = agent.issue(&IssueRequest { account: "alice.test".into(), notes: other.clone(), proof: proof(&alice, "alice.test", &other) });
    assert!(matches!(fresh, Reply::Refused(401, _)), "a new issue still needs a key of the account: {fresh:?}");
}

#[test]
fn the_agent_keeps_the_escape_shut_with_nothing_placed() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    // Thirty days with no deposit, nothing placed, a tick every three days.
    for _ in 0..10 {
        shared.lock().unwrap().now += 3 * 24 * HOUR;
        agent.tick().unwrap();
        assert!(!agent.chain.config().unwrap().escape_open, "the agent's own silence never opens the escape");
    }
    assert!(calls_of(&shared, "sync") >= 4, "a sync at least every half escape delay");
}

#[test]
fn a_request_closes_an_escape_the_agents_silence_opened() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    // The agent was down past the escape delay: the escape is open because of it alone.
    shared.lock().unwrap().last_agent_call = NOW - 8 * 24 * HOUR;
    assert!(agent.chain.config().unwrap().escape_open);
    let (entry, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&entry), Reply::Pending(_)), "the agent syncs, the escape closes, the entry is queued");
    assert!(!agent.chain.config().unwrap().escape_open);
}

#[test]
fn a_withdraw_the_staking_pool_refused_is_kept_and_tried_again() {
    use ona_agent::planner::{Memory, VaultMemory};
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    shared.lock().unwrap().vaults[0].placed = 50 * NEAR;
    let unstaked_at = NOW - 5 * 24 * HOUR;
    let memory = Memory { vaults: vec![VaultMemory { unstaked: 10 * NEAR, unstaked_at, last_unstake: unstaked_at, last_steady: 0 }], ..Memory::default() };
    agent.store.put("p:memory", memory.to_json()).unwrap();
    let unstaked = |agent: &Agent<FakeChain, MemoryStore>| Memory::from_json(&agent.store.get("p:memory").unwrap()).vaults[0].unstaked;

    shared.lock().unwrap().withdraw_fails = true;
    agent.tick().unwrap();
    assert_eq!(calls_of(&shared, "withdraw"), 1);
    assert_eq!(unstaked(&agent), 10 * NEAR, "the transaction succeeded, the funds did not come back: still owed");
    assert_eq!(shared.lock().unwrap().vaults[0].liquid, 0);

    agent.tick().unwrap();
    assert_eq!(calls_of(&shared, "withdraw"), 2, "tried again");
    assert_eq!(unstaked(&agent), 0);
    assert_eq!(shared.lock().unwrap().vaults[0].liquid, 10 * NEAR);
}

#[test]
fn a_withdraw_after_a_sync_that_found_rewards_is_counted_once() {
    use ona_agent::planner::{Memory, VaultMemory};
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    {
        let mut s = shared.lock().unwrap();
        s.vaults[0].placed = 50 * NEAR;
        s.vaults[0].total_shares = 1;
        // Read more than 45 minutes ago: this tick syncs the vault, then withdraws.
        s.vaults[0].synced_at = NOW - HOUR;
        s.sync_reward = NEAR;
    }
    let unstaked_at = NOW - 5 * 24 * HOUR;
    let memory = Memory { vaults: vec![VaultMemory { unstaked: 10 * NEAR, unstaked_at, last_unstake: unstaked_at, last_steady: 0 }], ..Memory::default() };
    agent.store.put("p:memory", memory.to_json()).unwrap();
    agent.tick().unwrap();
    let calls = shared.lock().unwrap().calls.clone();
    assert_eq!(calls, vec!["sync", "withdraw"], "{calls:?}");
    assert_eq!(Memory::from_json(&agent.store.get("p:memory").unwrap()).vaults[0].unstaked, 0, "the withdrawal is seen done");
    agent.tick().unwrap();
    assert_eq!(calls_of(&shared, "withdraw"), 1, "and not sent again");
}

#[test]
fn a_purged_signature_is_gone_from_the_file_itself() {
    let store_path = temp("purge");
    let k = keys();
    let shared = world(&k);
    let store = FileStore::create(&store_path, &ona_agent::store_binding(&k, POOL)).unwrap();
    let mut agent = Agent::start(FakeChain(shared.clone()), store, k, POOL, AGENT, Params::default(), QueueParams { retention_ns: HOUR, ..quick() })
        .unwrap()
        .with_clock(Box::new(|| NOW));
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let notes: Vec<(u8, [u8; G1_LEN])> = vec![(1, cash_pending(1).blinded)];
    let reply = agent.issue(&IssueRequest { account: "alice.test".into(), notes: notes.clone(), proof: proof(&alice, "alice.test", &notes) });
    let Reply::Signed(sigs) = reply else { panic!("{reply:?}") };
    let printed = B64.encode(sigs[0]);
    assert!(String::from_utf8_lossy(&std::fs::read(&store_path).unwrap()).contains(&printed));
    shared.lock().unwrap().now += 2 * HOUR;
    agent.tick().unwrap();
    assert!(!String::from_utf8_lossy(&std::fs::read(&store_path).unwrap()).contains(&printed), "rewritten without it");
    drop(agent);
    let _ = std::fs::remove_file(&store_path);
}

#[test]
fn a_crash_between_two_writes_is_repaired_by_the_next_tick() {
    let k = keys();
    let shared = world(&k);
    let mut agent = agent_on(k, &shared);
    let alice = depositor(&shared, "alice.test", 10 * NEAR);
    let (token, owner) = issue_notes(&mut agent, &alice, "alice.test", 1, 1).pop().unwrap();
    let (request, _) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&request), Reply::Pending(_)));
    // The crash came after the record and before its bindings.
    for prefix in ["n:", "o:"] {
        for (key, _) in agent.store.scan(prefix) {
            agent.store.put(&key, Value::Null).unwrap();
        }
    }
    // In a cash-exit window: nothing is sent, the repair runs.
    let now = next_window(&shared, true);
    assert_eq!((now / HOUR) % 2, 1);
    agent.tick().unwrap();
    let (other, _) = enter_request(&token, &owner, 1, vec![(1, 9)]);
    assert!(matches!(agent.note_request(&other), Reply::Refused(409, _)), "the note's binding is back");
    let (_, theirs) = enter_request(&token, &owner, 0, vec![(1, 9)]);
    let stolen = NoteRequest { blinded: theirs.iter().map(|p| p.blinded).collect(), ..request };
    assert!(matches!(agent.note_request(&stolen), Reply::Refused(409, _)), "so is the owner signature's");
}

#[test]
fn a_full_run_through_http_from_the_client_core() {
    let k = keys();
    let shared = world(&k);
    let agent = Arc::new(Mutex::new(agent_on(k, &shared)));
    let limits = Arc::new(Limits::new(1_000));
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let served = Arc::clone(&agent);
    let handler: Arc<ona_server::http::Handler> = Arc::new(move |r: &ona_server::http::Request| {
        let (status, value) = api::handle(&served, &limits, &r.method, &r.target, &r.body);
        (status, value.to_string().into_bytes())
    });
    let pool = ona_server::http::Pool::new(2, 8, ona_server::http::Limits::default(), handler);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            pool.dispatch(stream);
        }
    });

    let wallet_path = std::env::temp_dir().join(format!("ona-agent-e2e-{}", std::process::id()));
    let _ = std::fs::remove_file(&wallet_path);
    let wallet = ona_wallet::Wallet::open(&wallet_path, &[9u8; 32]).unwrap();
    // A final "/" in the agent's address is ignored.
    let http = ona_core::pool_agent::HttpAgent::to_url(&format!("{url}/"));
    let mut client = ona_core::pool::PoolClient::new(wallet, Box::new(ClientView(shared.clone())), Box::new(http), POOL)
        .with_clock(Box::new(|| NOW))
        .with_recommended(vec![11 * NEAR]);
    let mut run = |cmd: &str, request: Value| -> Result<Value, String> { client.run(cmd, &request) };
    // An entry, a leave or a cash exit is queued by the agent: the client hears "outcome unknown", the agent sends it
    // in a later window, and `pool_recover` collects the result.
    let queued = |run: &mut dyn FnMut(&str, Value) -> Result<Value, String>, op: Value, pays: bool| {
        let p = run("pool_prepare", op).unwrap();
        let e = run("pool_execute", json!({"prepared_id": p["prepared_id"]})).unwrap_err();
        assert!(e.contains("outcome unknown"), "{e}");
        run_window(&mut *agent.lock().unwrap(), &shared, pays);
        let r = run("pool_recover", json!({})).unwrap();
        assert_eq!((r["still_spending"].clone(), r["awaiting_signature"].clone()), (json!(0), json!(0)), "{r}");
    };

    // Deposit 11 NEAR from alice's own wallet, then the cash, against her wallet's signature.
    let alice = SigningKey::generate(&mut OsRng);
    shared.lock().unwrap().full_keys.entry("alice.test".into()).or_default().insert(alice.verifying_key().to_bytes());
    let p = run("pool_prepare", json!({"op": "deposit", "account": "alice.test", "amount": (11 * NEAR).to_string()})).unwrap();
    let attached: u128 = p["summary"]["wallet_call"]["attached"].as_str().unwrap().parse().unwrap();
    shared.lock().unwrap().holders.entry("alice.test".into()).or_default().0 += attached;
    let first = run("pool_execute", json!({"prepared_id": p["prepared_id"]})).unwrap();
    let m = &first["sign_message"];
    let nonce: [u8; 32] = B64.decode(m["nonce"].as_str().unwrap()).unwrap().try_into().unwrap();
    let hash = nep413::payload_hash(m["message"].as_str().unwrap(), &nonce, m["recipient"].as_str().unwrap());
    let signature = json!({"public_key": nep413::write_public_key(&alice.verifying_key().to_bytes()), "signature": B64.encode(alice.sign(&hash).to_bytes())});
    let done = run("pool_execute", json!({"prepared_id": p["prepared_id"], "depositor_signature": signature})).unwrap();
    assert_eq!(done["complete"], true, "{done}");
    assert_eq!(run("pool_portfolio", json!({})).unwrap()["cash"]["value"], (11 * NEAR).to_string());

    // Enter vault 0 with 10 NEAR, leave it for cash, pay 1 NEAR of cash back to alice.
    queued(&mut run, json!({"op": "enter", "vault": 0, "amount": (10 * NEAR).to_string()}), false);
    let portfolio = run("pool_portfolio", json!({})).unwrap();
    assert_eq!(portfolio["vaults"][0]["value"], (999 * NEAR / 100).to_string(), "{portfolio}");
    queued(&mut run, json!({"op": "exit", "from": 0, "amount": NEAR.to_string()}), false);
    queued(&mut run, json!({"op": "exit_cash", "to": "alice.test", "amount": NEAR.to_string()}), true);
    assert_eq!(shared.lock().unwrap().holders["alice.test"].2, NEAR, "paid to the account that deposited");

    let s = shared.lock().unwrap();
    assert_eq!(s.calls.iter().filter(|c| *c == "issue_cash").count(), 2, "one call per tier: {:?}", s.calls);
    let window = |name: &str| s.sent_at.iter().filter(|(n, _)| n == name).map(|(_, t)| t / HOUR).collect::<BTreeSet<_>>();
    assert!(!window("pay_exit").is_empty());
    assert!(window("leave").is_disjoint(&window("pay_exit")), "a payment never leaves in the window of a leave");
    drop(s);
    drop(client);
    let _ = std::fs::remove_file(&wallet_path);
    let mut seal = wallet_path.into_os_string();
    seal.push(".seal");
    let _ = std::fs::remove_file(seal);
}
