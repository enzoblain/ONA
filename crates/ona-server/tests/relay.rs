use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use ona_server::*;
use ona_token::{
    blind, claim_digest_until, keygen, sign_blinded, sign_digest, unblind, verify, BlindingFactor,
    PendingToken, SecretKey, Token, G1_LEN, G2_LEN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

const MINT: &str = "mint.test";
const RELAY: &str = "relay.test";
const Q: usize = 3;
const MINT_DST: &[u8] = b"ONA-MINT-V1:sandbox:mint.test:BLS12381G1_XMD:SHA-256_SSWU_RO_";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[derive(Default)]
struct FakeChain {
    spent: BTreeSet<[u8; 32]>,
    by_relay: BTreeSet<[u8; 32]>,
    calls: usize,
    fail: bool,
    /// Claims land on chain, but the reply is lost, as in a crash during the call.
    lose_reply: bool,
    /// The contract's hourly limit: claims come back false and nothing is spent.
    hourly_cap: bool,
    /// An earlier claim by this relay lands just before this one, which comes back false.
    earlier_claim_lands: bool,
    /// Time of the final block, in nanoseconds.
    time: u64,
}

impl Chain for FakeChain {
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        Ok(self.spent.contains(nf))
    }
    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
        if self.fail {
            return Err("rpc down".into());
        }
        self.calls += 1;
        let out = claims
            .iter()
            .map(|c| {
                let nf = c.token.nullifier();
                if self.hourly_cap {
                    return false;
                }
                if self.earlier_claim_lands {
                    self.spent.insert(nf);
                    self.by_relay.insert(nf);
                }
                let fresh = self.spent.insert(nf);
                if fresh {
                    self.by_relay.insert(nf);
                }
                fresh
            })
            .collect();
        if self.lose_reply {
            return Err("connection lost".into());
        }
        Ok(out)
    }
    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        Ok(self.by_relay.contains(nf))
    }
    fn final_timestamp(&mut self) -> Result<u64, String> {
        Ok(self.time)
    }
}

struct FakeModel {
    used: u32,
    fail: bool,
    calls: usize,
}

impl Upstream for FakeModel {
    fn complete(&mut self, prompt: &str, _max: u32) -> Result<ModelReply, String> {
        self.calls += 1;
        if self.fail {
            return Err("down".into());
        }
        Ok(ModelReply { text: format!("echo: {prompt}"), tokens_used: self.used })
    }
}

type TestRelay<S> = Relay<S, FakeChain, FakeModel>;

struct Setup {
    credit_sk: SecretKey,
    credit_pk: [u8; G2_LEN],
}

fn setup() -> Setup {
    let credit_sk = keygen(&mut OsRng);
    let credit_pk = credit_sk.public_key();
    Setup { credit_sk, credit_pk }
}

fn config(credit_pk: [u8; G2_LEN]) -> Config {
    Config {
        mint: MINT.into(),
        relay: RELAY.into(),
        mint_dst: MINT_DST.to_vec(),
        credit_key: credit_pk,
        tokens_per_credit: Q,
        max_tokens_per_request: 100,
        max_prompt_bytes: 100,
    }
}

fn relay_with<S: Store>(store: S, s: &Setup, chain: FakeChain, key: SecretKey) -> TestRelay<S> {
    let mut r = Relay::new(store, chain, FakeModel { used: 10, fail: false, calls: 0 }, config(s.credit_pk), key);
    r.set_clock(fixed_clock(NOW));
    r
}

/// A relay on any chain, at the tests' fixed time.
fn relay_on<C: Chain, U: Upstream>(chain: C, model: U, s: &Setup) -> Relay<MemoryStore, C, U> {
    let mut r = Relay::new(MemoryStore::default(), chain, model, config(s.credit_pk), keygen(&mut OsRng));
    r.set_clock(fixed_clock(NOW));
    r
}

fn relay(s: &Setup) -> TestRelay<MemoryStore> {
    relay_with(MemoryStore::default(), s, FakeChain::default(), keygen(&mut OsRng))
}

fn credit(s: &Setup, denom: u8) -> (Token, SigningKey) {
    let p = PendingToken::new(&mut OsRng, denom, MINT_DST).unwrap();
    let sp = sign_blinded(&s.credit_sk, &p.blinded).unwrap();
    p.finish(&sp, &s.credit_pk).unwrap()
}

struct Wallet {
    xs: Vec<[u8; 32]>,
    factors: Vec<BlindingFactor>,
    blinded: Vec<String>,
}

fn wallet(dst: &[u8]) -> Wallet {
    let mut w = Wallet { xs: vec![], factors: vec![], blinded: vec![] };
    for _ in 0..Q {
        let mut x = [0u8; 32];
        OsRng.fill_bytes(&mut x);
        let (r, b) = blind(&x, dst, &mut OsRng);
        w.xs.push(x);
        w.factors.push(r);
        w.blinded.push(hex(&b));
    }
    w
}

/// The fixed time of the tests' relays, in nanoseconds.
const NOW: u64 = 1_000_000 * 3_600_000_000_000;
const HOUR: u64 = 3_600_000_000_000;

fn exchange_body_until(t: &Token, owner: &SigningKey, blinded: &[String], expires_at: u64) -> Value {
    let d = claim_digest_until(MINT, RELAY, &t.nullifier(), expires_at);
    let raw: Vec<[u8; G1_LEN]> = blinded.iter().filter_map(|b| unhex(b).try_into().ok()).collect();
    let e = exchange_digest(MINT, RELAY, &t.nullifier(), &raw);
    json!({
        "token": hex(&t.to_bytes()),
        "owner_sig": hex(&sign_digest(owner, &d)),
        "expires_at": expires_at.to_string(),
        "exchange_sig": hex(&sign_digest(owner, &e)),
        "blinded": blinded,
    })
}

fn exchange_body(t: &Token, owner: &SigningKey, blinded: &[String]) -> Value {
    exchange_body_until(t, owner, blinded, NOW + 24 * HOUR)
}

fn fixed_clock(now: u64) -> Clock {
    std::sync::Arc::new(move || now)
}

const TEST_BINDING: &str = "test-binding";

/// Opens the store at `path`, creating it on first use.
fn store_at(path: &std::path::Path) -> FileStore {
    if path.exists() {
        FileStore::open(path, TEST_BINDING).unwrap()
    } else {
        FileStore::create(path, TEST_BINDING).unwrap()
    }
}

/// Writes a store file by hand: the header line, then `lines`, readable by its owner only.
fn write_log(path: &std::path::Path, lines: &str) {
    use std::os::unix::fs::PermissionsExt;
    let header = json!({"store": "ona-relay-store-v1", "binding": TEST_BINDING});
    std::fs::write(path, format!("{header}\n{lines}")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn header_text() -> String {
    format!("{}\n", json!({"store": "ona-relay-store-v1", "binding": TEST_BINDING}))
}

/// Runs a whole exchange and returns usable request tokens.
fn request_tokens<S: Store>(r: &mut TestRelay<S>, s: &Setup) -> Vec<String> {
    let (t, owner) = credit(s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    assert_eq!(r.exchange(&body).0, 202);
    r.flush().unwrap();
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 200, "{reply}");
    let pk = r.request_public_key();
    let dst = r.request_dst().to_vec();
    reply["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, sig)| {
            let sp: [u8; G1_LEN] = unhex(sig.as_str().unwrap()).try_into().unwrap();
            let unblinded = unblind(&sp, &w.factors[i]).unwrap();
            assert!(verify(&pk, &w.xs[i], &dst, &unblinded));
            let mut bytes = w.xs[i].to_vec();
            bytes.extend_from_slice(&unblinded);
            hex(&bytes)
        })
        .collect()
}

#[test]
fn exchange_then_chat() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    assert_eq!(tokens.len(), Q);
    let (status, reply) = r.chat(&json!({"token": tokens[0], "prompt": "bonjour"}));
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["mode"], "mock", "the local fake model says so");
    assert_eq!(reply["reply"], "echo: bonjour");
}

#[test]
fn exchange_replies_do_not_claim_to_be_a_mock() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let body = exchange_body(&t, &owner, &wallet(r.request_dst()).blinded);
    let (_, pending) = r.exchange(&body);
    r.flush().unwrap();
    let (_, done) = r.exchange(&body);
    let (_, refused) = r.exchange(&json!({}));
    for reply in [pending, done, refused] {
        assert!(reply.get("mode").is_none(), "{reply}");
    }
}

#[test]
fn the_real_relay_has_no_direct_model() {
    let s = setup();
    let mut r = relay_on(FakeChain::default(), NoModel, &s);
    let tokens = {
        let (t, owner) = credit(&s, 0);
        let w = wallet(r.request_dst());
        let body = exchange_body(&t, &owner, &w.blinded);
        r.exchange(&body);
        r.flush().unwrap();
        let reply = r.exchange(&body).1;
        let sp: [u8; G1_LEN] = unhex(reply["signatures"][0].as_str().unwrap()).try_into().unwrap();
        let mut bytes = w.xs[0].to_vec();
        bytes.extend_from_slice(&unblind(&sp, &w.factors[0]).unwrap());
        hex(&bytes)
    };
    assert_eq!(r.chat(&json!({"token": tokens, "prompt": "a"})).0, 502);
}

#[test]
fn nothing_is_signed_before_the_chain_confirms() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 202);
    assert!(reply.get("signatures").is_none());
    assert_eq!(r.exchange(&body).0, 202, "still pending");
    assert_eq!(r.chain.calls, 0);
}

#[test]
fn claim_refused_on_chain_signs_nothing() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.chain.spent.insert(t.nullifier()); // the owner redeemed it on chain in the meantime
    assert_eq!(r.flush().unwrap(), 0);
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 409);
    assert!(reply.get("signatures").is_none());
}

#[test]
fn replay_is_idempotent_and_other_points_are_refused() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.flush().unwrap();
    let first = r.exchange(&body);
    assert_eq!(first, r.exchange(&body), "same request, same answer");
    assert_eq!(r.chain.calls, 1);

    let other = wallet(r.request_dst());
    let (status, _) = r.exchange(&exchange_body(&t, &owner, &other.blinded));
    assert_eq!(status, 409, "a credit cannot buy a second set of tokens");
}

#[test]
fn other_points_are_refused_while_pending() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    r.exchange(&exchange_body(&t, &owner, &w.blinded));
    let other = wallet(r.request_dst());
    assert_eq!(r.exchange(&exchange_body(&t, &owner, &other.blinded)).0, 409);
}

#[test]
fn exchange_refusals() {
    let s = setup();
    let mut r = relay(&s);
    let dst = r.request_dst().to_vec();
    let (t, owner) = credit(&s, 0);
    let w = wallet(&dst);

    let (high, high_owner) = credit(&s, 1);
    assert_eq!(r.exchange(&exchange_body(&high, &high_owner, &w.blinded)).0, 400, "wrong tier");

    let other = setup();
    let (forged, forged_owner) = credit(&other, 0);
    assert_eq!(r.exchange(&exchange_body(&forged, &forged_owner, &w.blinded)).0, 400, "token from another key");

    let thief = SigningKey::generate(&mut OsRng);
    assert_eq!(r.exchange(&exchange_body(&t, &thief, &w.blinded)).0, 400, "not the owner");

    assert_eq!(r.exchange(&exchange_body(&t, &owner, &w.blinded[..2])).0, 400, "too few points");

    let mut inf = [0u8; G1_LEN];
    inf[0] = 0xc0;
    let mut bad = w.blinded.clone();
    bad[1] = hex(&inf);
    assert_eq!(r.exchange(&exchange_body(&t, &owner, &bad)).0, 400, "invalid point");

    r.chain.spent.insert(t.nullifier());
    assert_eq!(r.exchange(&exchange_body(&t, &owner, &w.blinded)).0, 409, "already spent");
    assert_eq!(r.chain.calls, 0);
    assert_eq!(r.exchange(&json!({"token": "zz"})).0, 400);
}

#[test]
fn request_token_works_once() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "b"})).0, 409);
    assert_eq!(r.upstream.calls, 1, "the second attempt never reaches the model");
}

#[test]
fn forged_request_tokens_are_refused() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    let mut tampered = unhex(&tokens[0]);
    tampered[3] ^= 1;
    assert_eq!(r.chat(&json!({"token": hex(&tampered), "prompt": "a"})).0, 401);

    let other_key = keygen(&mut OsRng);
    let x = [9u8; 32];
    let sig = sign_blinded(&other_key, &request_message_point(&x, r.request_dst())).unwrap();
    let mut forged = x.to_vec();
    forged.extend_from_slice(&sig);
    assert_eq!(r.chat(&json!({"token": hex(&forged), "prompt": "a"})).0, 401);

    assert_eq!(r.chat(&json!({"token": "abcd", "prompt": "a"})).0, 400);
    assert_eq!(r.chat(&json!({"prompt": "a"})).0, 400);
    assert_eq!(r.upstream.calls, 0);
}

#[test]
fn a_reply_over_budget_is_withheld_and_the_token_is_spent() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    r.upstream.used = 101;
    let (status, reply) = r.chat(&json!({"token": tokens[0], "prompt": "a"}));
    assert_eq!(status, 402);
    assert!(reply.get("reply").is_none());
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 409);
}

#[test]
fn a_model_failure_returns_an_error() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    r.upstream.fail = true;
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 502);
}

#[test]
fn oversized_prompt_does_not_consume_the_token() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    let long = "x".repeat(MAX_PROMPT_BYTES + 1);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": long})).0, 413);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
}

#[test]
fn routing() {
    let s = setup();
    let mut r = relay(&s);
    assert_eq!(r.handle("/nothing", "{}").0, 404);
    assert_eq!(r.handle("/chat", "not json").0, 400);
    assert_eq!(r.handle("/chat", "{}").0, 400);
}

#[test]
fn a_failed_flush_keeps_the_credit_for_the_next_one() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.chain.fail = true;
    assert!(r.flush().is_err());
    assert_eq!(r.exchange(&body).0, 202);
    r.chain.fail = false;
    assert_eq!(r.flush().unwrap(), 1);
    assert_eq!(r.exchange(&body).0, 200);
}

#[test]
fn a_lost_reply_does_not_cost_the_user_a_credit() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.chain.lose_reply = true;
    assert!(r.flush().is_err());
    r.chain.lose_reply = false;
    r.flush().unwrap();
    assert_eq!(r.exchange(&body).0, 200, "the claim landed, so the tokens are owed");
    assert_eq!(r.chain.calls, 1, "and it is not sent twice");
}

#[test]
fn batches_are_bounded() {
    let s = setup();
    let mut r = relay(&s);
    for _ in 0..(MAX_BATCH + 2) {
        let (t, owner) = credit(&s, 0);
        let w = wallet(r.request_dst());
        r.exchange(&exchange_body(&t, &owner, &w.blinded));
    }
    assert_eq!(r.flush().unwrap(), MAX_BATCH);
    assert_eq!(r.flush().unwrap(), 2);
}

#[test]
fn crash_after_the_chain_accepted_recovers_the_tokens() {
    let s = setup();
    let path = std::env::temp_dir().join(format!("ona-relay-{}-a.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let (t, owner) = credit(&s, 0);
    let dst = request_dst(RELAY);
    let w = wallet(&dst);
    let body = exchange_body(&t, &owner, &w.blinded);

    let chain = {
        let mut r = relay_with(store_at(&path), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        r.exchange(&body);
        r.chain.lose_reply = true;
        assert!(r.flush().is_err(), "the crash happens during the chain call");
        let mut c = FakeChain::default();
        c.spent = r.chain.spent.clone();
        c.by_relay = r.chain.by_relay.clone();
        c
    };

    let mut r = relay_with(store_at(&path), &s, chain, SecretKey::from_bytes(&key_bytes).unwrap());
    assert_eq!(r.exchange(&body).0, 202, "state survived the restart");
    assert_eq!(r.recover().unwrap(), 1);
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 200, "{reply}");
    assert_eq!(r.chain.calls, 0, "no second claim on chain");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn crash_when_someone_else_spent_it_signs_nothing() {
    let s = setup();
    let path = std::env::temp_dir().join(format!("ona-relay-{}-b.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let (t, owner) = credit(&s, 0);
    let dst = request_dst(RELAY);
    let w = wallet(&dst);
    let body = exchange_body(&t, &owner, &w.blinded);
    {
        let mut r = relay_with(store_at(&path), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        r.exchange(&body);
        r.chain.fail = true;
        let _ = r.flush();
    }
    let mut chain = FakeChain::default();
    chain.spent.insert(t.nullifier());
    let mut r = relay_with(store_at(&path), &s, chain, SecretKey::from_bytes(&key_bytes).unwrap());
    assert_eq!(r.recover().unwrap(), 1);
    assert_eq!(r.exchange(&body).0, 409);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_claim_stopped_by_the_hourly_limit_stays_pending() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    assert_eq!(r.exchange(&body).0, 202);
    r.chain.hourly_cap = true;
    assert_eq!(r.flush().unwrap(), 0);
    assert_eq!(r.exchange(&body).0, 202, "the credit is not lost");

    r.chain.hourly_cap = false;
    assert_eq!(r.flush().unwrap(), 1);
    assert_eq!(r.exchange(&body).0, 200);
}

#[test]
fn a_false_for_a_claim_already_landed_gives_the_tokens() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.chain.earlier_claim_lands = true;
    assert_eq!(r.flush().unwrap(), 1, "the relay really collected this credit");
    assert_eq!(r.exchange(&body).0, 200);
}

#[test]
fn a_replay_with_a_bad_owner_signature_gets_nothing() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.flush().unwrap();
    assert_eq!(r.exchange(&body).0, 200);

    let thief = SigningKey::generate(&mut OsRng);
    let (status, reply) = r.exchange(&exchange_body(&t, &thief, &w.blinded));
    assert_eq!(status, 400);
    assert!(reply.get("signatures").is_none());
}

#[test]
fn the_owner_signature_is_checked_before_the_points() {
    let s = setup();
    let mut r = relay(&s);
    let (t, _) = credit(&s, 0);
    let thief = SigningKey::generate(&mut OsRng);
    let invalid = vec!["00".repeat(G1_LEN); Q];
    let (status, reply) = r.exchange(&exchange_body(&t, &thief, &invalid));
    assert_eq!(status, 400);
    assert_eq!(reply["error"], "invalid owner signature");
    assert_eq!(r.exchange(&exchange_body(&t, &thief, &invalid[..1])).1["error"], "invalid owner signature");
}

type Locked = std::sync::Mutex<TestRelay<MemoryStore>>;

/// A chain whose calls run while the relay is expected to be free.
struct ProbeChain<'a> {
    relay: &'a Locked,
    free_during_calls: bool,
    calls: usize,
    spent: BTreeSet<[u8; 32]>,
    during_is_spent: Option<Value>,
}

impl ProbeChain<'_> {
    fn note_call(&mut self) {
        self.calls += 1;
        self.free_during_calls &= self.relay.try_lock().is_ok();
    }
}

impl Chain for ProbeChain<'_> {
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.note_call();
        if let Some(body) = self.during_is_spent.take() {
            self.relay.lock().unwrap().exchange(&body);
        }
        Ok(self.spent.contains(nf))
    }
    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
        self.note_call();
        Ok(claims.iter().map(|c| self.spent.insert(c.token.nullifier())).collect())
    }
    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.note_call();
        Ok(self.spent.contains(nf))
    }
}

fn probe(relay: &Locked) -> ProbeChain<'_> {
    ProbeChain { relay, free_during_calls: true, calls: 0, spent: BTreeSet::new(), during_is_spent: None }
}

#[test]
fn the_relay_is_not_locked_during_chain_calls() {
    let s = setup();
    let r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    let shared = ona_server::SharedRelay::new(r);
    let mut chain = probe(shared.state());

    assert_eq!(shared.exchange(&mut chain, &body).0, 202);
    assert_eq!(shared.flush(&mut chain).unwrap(), 1);
    assert_eq!(shared.exchange(&mut chain, &body).0, 200);
    assert!(chain.calls >= 2);
    assert!(chain.free_during_calls);
}

#[test]
fn a_credit_is_checked_without_locking_the_relay() {
    let s = setup();
    let r = relay(&s);
    let (t, _) = credit(&s, 0);
    let thief = SigningKey::generate(&mut OsRng);
    let w = wallet(r.request_dst());
    let forged = exchange_body(&t, &thief, &w.blinded);
    let shared = ona_server::SharedRelay::new(r);

    let held = shared.state().lock().unwrap();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut chain = FakeChain::default();
            done.send(shared.exchange(&mut chain, &forged)).unwrap();
            done.send(shared.exchange(&mut chain, &json!({}))).unwrap();
        });
        let first = finished.recv_timeout(std::time::Duration::from_secs(10));
        let second = finished.recv_timeout(std::time::Duration::from_secs(10));
        drop(held);
        let (status, reply) = first.expect("the owner signature must be checked while the relay is locked elsewhere");
        assert_eq!((status, reply["error"].as_str()), (400, Some("invalid owner signature")));
        assert_eq!(second.expect("a malformed body too").0, 400);
    });
}

#[test]
fn a_poisoned_relay_answers_503() {
    let s = setup();
    let r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    let shared = ona_server::SharedRelay::new(r);
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = shared.state().lock().unwrap();
        panic!("simulated panic while the relay is locked");
    }));
    assert!(poisoned.is_err());

    let (status, reply) = shared.exchange(&mut FakeChain::default(), &body);
    assert_eq!((status, reply["error"].as_str()), (503, Some("relay unavailable")));
    assert!(shared.flush(&mut FakeChain::default()).unwrap_err().contains("restart"));
}

#[test]
fn flush_shared_recovers_and_keeps_a_capped_credit_pending() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.chain.fail = true;
    assert!(r.flush().is_err());
    let shared = ona_server::SharedRelay::new(r);

    struct Capped;
    impl Chain for Capped {
        fn is_spent(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Ok(false)
        }
        fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
            Ok(vec![false; claims.len()])
        }
        fn claimed_by_relay(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Ok(false)
        }
    }
    assert_eq!(shared.flush(&mut Capped).unwrap(), 0);
    assert_eq!(shared.state().lock().unwrap().exchange(&body).0, 202);
}

#[test]
fn two_requests_racing_for_one_credit_cannot_both_be_recorded() {
    let s = setup();
    let r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let first = wallet(r.request_dst());
    let second = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &first.blinded);
    let other = exchange_body(&t, &owner, &second.blinded);
    let shared = ona_server::SharedRelay::new(r);
    let mut chain = probe(shared.state());
    // The other request lands while this one waits for the chain.
    chain.during_is_spent = Some(other.clone());

    assert_eq!(shared.exchange(&mut chain, &body).0, 409);
    assert_eq!(shared.state().lock().unwrap().exchange(&other).0, 202, "the first one recorded stays");
}

fn temp_log(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ona-relay-{}-{tag}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn line_count(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path).unwrap().lines().count()
}

#[test]
fn a_torn_last_line_is_cut_and_the_store_keeps_working() {
    let path = temp_log("torn");
    write_log(&path, "{\"x\":\"aa\"}\n{\"x\":\"b");
    let mut store = store_at(&path);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), header_text() + "{\"x\":\"aa\"}\n");
    assert!(!store.use_request_token("aa").unwrap());
    assert!(store.use_request_token("bb").unwrap());
    drop(store);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), header_text() + "{\"x\":\"aa\"}\n{\"x\":\"bb\"}\n");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_last_line_without_a_newline_is_cut_even_if_it_parses() {
    let path = temp_log("no-newline");
    write_log(&path, "{\"x\":\"aa\"}\n{\"x\":\"bb\"}");
    let mut store = store_at(&path);
    assert!(store.use_request_token("bb").unwrap(), "that write was never acknowledged");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn damage_to_a_complete_line_is_refused_and_left_alone() {
    let path = temp_log("damaged");
    write_log(&path, "{\"x\":\"aa\"}\nnot json\n{\"x\":\"bb\"}\ntorn");
    let before = std::fs::read_to_string(&path).unwrap();
    assert!(FileStore::open(&path, TEST_BINDING).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_missing_store_is_not_replaced_by_an_empty_one() {
    let path = temp_log("missing");
    assert!(FileStore::open(&path, TEST_BINDING).err().unwrap().contains("init-key"));
    assert!(!path.exists(), "nothing was created: every used token would be valid again");
}

#[test]
fn a_store_for_another_key_or_without_header_is_refused() {
    let path = temp_log("other-key");
    drop(FileStore::create(&path, "key-a").unwrap());
    assert!(FileStore::open(&path, "key-b").err().unwrap().contains("another request key"));
    assert!(FileStore::open(&path, "key-a").is_ok());

    let old = temp_log("no-header");
    std::fs::write(&old, "{\"x\":\"aa\"}\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(FileStore::open(&old, TEST_BINDING).err().unwrap().contains("header"));
    assert!(FileStore::create(&path, "key-a").is_err(), "an existing store is never overwritten");
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(&old).unwrap();
}

#[test]
fn a_store_is_held_by_one_process_at_a_time() {
    let path = temp_log("locked");
    let first = FileStore::create(&path, TEST_BINDING).unwrap();
    assert!(FileStore::open(&path, TEST_BINDING).err().unwrap().contains("in use"));
    drop(first);
    assert!(FileStore::open(&path, TEST_BINDING).is_ok(), "released when the first one stops");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn the_store_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_log("mode");
    let mut store = FileStore::create(&path, TEST_BINDING).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    store.compact().unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "also after a rewrite");
    drop(store);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(FileStore::open(&path, TEST_BINDING).err().unwrap().contains("other users"));
    std::fs::remove_file(&path).unwrap();
}

fn pending_state(tag: &str) -> ExchangeState {
    ExchangeState::Pending { blinded_hash: "h".into(), token: format!("credit-{tag}"), owner_sig: "s".into(), expires_at: 7, blinded: vec![] }
}

fn submitted_state(tag: &str) -> ExchangeState {
    ExchangeState::Submitted { blinded_hash: "h".into(), token: format!("credit-{tag}"), owner_sig: "s".into(), expires_at: 7, blinded: vec![] }
}

fn done_state() -> ExchangeState {
    ExchangeState::Done { blinded_hash: "h".into(), signatures: vec!["sig".into()] }
}

#[test]
fn compaction_keeps_every_used_token_and_drops_finished_credits() {
    let path = temp_log("compact");
    let mut store = store_at(&path);
    for i in 0..10 {
        let nf = format!("{i}");
        store.put(&nf, pending_state(&nf)).unwrap();
        store.put(&nf, submitted_state(&nf)).unwrap();
        store.put(&nf, done_state()).unwrap();
        assert!(store.use_request_token(&format!("t{i}")).unwrap());
    }
    store.put("open", submitted_state("open")).unwrap();
    assert_eq!(line_count(&path), 42, "the header and 41 records");

    store.compact().unwrap();
    assert_eq!(line_count(&path), 22, "the header, then one line per credit and per used token");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("credit-3"), "a finished exchange no longer holds its credit");
    assert!(text.contains("credit-open"), "an open one still does");

    // Writing still goes to the new file.
    assert!(store.use_request_token("after").unwrap());
    drop(store);

    let mut store = store_at(&path);
    for i in 0..10 {
        assert!(!store.use_request_token(&format!("t{i}")).unwrap(), "t{i} stays used");
        assert_eq!(store.get(&format!("{i}")), Some(done_state()));
    }
    assert!(!store.use_request_token("after").unwrap());
    assert_eq!(store.unfinished().len(), 1);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn the_log_is_compacted_automatically_after_finished_exchanges() {
    let path = temp_log("auto");
    let mut store = store_at(&path);
    let rounds = 200;
    for i in 0..rounds {
        let nf = format!("{i}");
        store.put(&nf, pending_state(&nf)).unwrap();
        store.put(&nf, submitted_state(&nf)).unwrap();
        store.put(&nf, done_state()).unwrap();
    }
    assert!(line_count(&path) < rounds * 2, "{} lines", line_count(&path));
    drop(store);
    let store = store_at(&path);
    for i in 0..rounds {
        assert_eq!(store.get(&format!("{i}")), Some(done_state()));
    }
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn compaction_preserves_a_returned_token_as_usable() {
    let path = temp_log("released");
    let mut store = store_at(&path);
    assert!(store.use_request_token("kept").unwrap());
    assert!(store.use_request_token("returned").unwrap());
    store.release_request_token("returned").unwrap();
    store.compact().unwrap();
    drop(store);
    let mut store = store_at(&path);
    assert!(!store.use_request_token("kept").unwrap());
    assert!(store.use_request_token("returned").unwrap());
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_leftover_compaction_file_is_ignored() {
    let path = temp_log("leftover");
    let leftover = format!("{}.compact", path.display());
    write_log(&path, "{\"x\":\"aa\"}\n");
    std::fs::write(&leftover, "garbage from a crash").unwrap();
    let mut store = store_at(&path);
    assert!(!store.use_request_token("aa").unwrap());
    store.compact().unwrap();
    assert!(!std::path::Path::new(&leftover).exists());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), header_text() + "{\"x\":\"aa\"}\n");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn used_request_tokens_survive_a_restart() {
    let s = setup();
    let path = std::env::temp_dir().join(format!("ona-relay-{}-c.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let token = {
        let mut r = relay_with(store_at(&path), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        let tokens = request_tokens(&mut r, &s);
        assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
        tokens[0].clone()
    };
    let mut r = relay_with(store_at(&path), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
    assert_eq!(r.chat(&json!({"token": token, "prompt": "a"})).0, 409);
    assert_eq!(r.upstream.calls, 0);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn swapped_blinded_points_are_refused_and_the_victim_keeps_the_credit() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let victim = wallet(r.request_dst());
    let victim_body = exchange_body(&t, &owner, &victim.blinded);

    // Someone who saw the request replaces only the blinded points.
    let attacker = wallet(r.request_dst());
    let mut stolen = victim_body.clone();
    stolen["blinded"] = json!(attacker.blinded);
    let (status, reply) = r.exchange(&stolen);
    assert_eq!((status, reply["error"].as_str()), (400, Some("invalid exchange signature")));

    assert_eq!(r.exchange(&victim_body).0, 202, "the victim's own request still goes through");
    r.flush().unwrap();
    assert_eq!(r.exchange(&victim_body).0, 200);
    assert_eq!(r.exchange(&stolen).0, 400);
}

#[test]
fn an_exchange_without_its_signature_is_refused() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let mut body = exchange_body(&t, &owner, &w.blinded);
    body.as_object_mut().unwrap().remove("exchange_sig");
    assert_eq!(r.exchange(&body).0, 400);
}

/// Counts the chain reads.
#[derive(Default)]
struct CountingChain {
    inner: FakeChain,
    reads: usize,
}

impl Chain for CountingChain {
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.reads += 1;
        self.inner.is_spent(nf)
    }
    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
        self.inner.relay_claim(claims)
    }
    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.reads += 1;
        self.inner.claimed_by_relay(nf)
    }
}

#[test]
fn a_spent_credit_replayed_costs_one_chain_read_only() {
    let s = setup();
    let mut chain = CountingChain::default();
    let (t, owner) = credit(&s, 0);
    chain.inner.spent.insert(t.nullifier());
    let mut r = relay_on(chain, FakeModel { used: 10, fail: false, calls: 0 }, &s);
    let body = exchange_body(&t, &owner, &wallet(r.request_dst()).blinded);
    for _ in 0..50 {
        assert_eq!(r.exchange(&body).0, 409);
    }
    assert_eq!(r.chain.reads, 1, "the first refusal is remembered");
}

#[test]
fn a_claim_reported_accepted_is_signed_only_once_a_final_read_confirms_it() {
    /// The endpoint that sends transactions says `true`, but the cross-checked reads see nothing.
    struct LyingClaims;
    impl Chain for LyingClaims {
        fn is_spent(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Ok(false)
        }
        fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
            Ok(vec![true; claims.len()])
        }
        fn claimed_by_relay(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Ok(false)
        }
    }
    let s = setup();
    let mut r = relay_on(LyingClaims, FakeModel { used: 10, fail: false, calls: 0 }, &s);
    let (t, owner) = credit(&s, 0);
    let body = exchange_body(&t, &owner, &wallet(r.request_dst()).blinded);
    assert_eq!(r.exchange(&body).0, 202);
    assert_eq!(r.flush().unwrap(), 0, "nothing is signed on the word of one endpoint");
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 202);
    assert!(reply.get("signatures").is_none());
}

#[test]
fn a_claim_landing_between_the_two_final_reads_is_not_lost() {
    /// The relay's claim is in flight; when armed, it lands on chain right after the next read is answered.
    struct LandsDuringRead {
        landed: bool,
        land_after_next_read: bool,
    }
    impl LandsDuringRead {
        fn read(&mut self) -> bool {
            let seen = self.landed;
            if std::mem::take(&mut self.land_after_next_read) {
                self.landed = true;
            }
            seen
        }
    }
    impl Chain for LandsDuringRead {
        fn is_spent(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Ok(self.read())
        }
        fn relay_claim(&mut self, _: &[Claim]) -> Result<Vec<bool>, String> {
            Err("connection lost".into())
        }
        fn claimed_by_relay(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Ok(self.read())
        }
    }
    let s = setup();
    let chain = LandsDuringRead { landed: false, land_after_next_read: false };
    let mut r = relay_on(chain, FakeModel { used: 10, fail: false, calls: 0 }, &s);
    let (t, owner) = credit(&s, 0);
    let body = exchange_body(&t, &owner, &wallet(r.request_dst()).blinded);
    assert_eq!(r.exchange(&body).0, 202);
    assert!(r.flush().is_err(), "the reply to the claim is lost");

    r.chain.land_after_next_read = true;
    r.recover().unwrap();
    assert_eq!(r.exchange(&body).0, 202, "a credit this relay collected is never read as spent elsewhere");
    r.recover().unwrap();
    assert_eq!(r.exchange(&body).0, 200, "the next read sees it claimed by this relay");
}

#[test]
fn an_expiry_out_of_range_is_refused() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    for expires_at in [NOW - 1, NOW + 10 * 60 * 1_000_000_000, NOW + 8 * 24 * HOUR] {
        assert_eq!(r.exchange(&exchange_body_until(&t, &owner, &w.blinded, expires_at)).0, 400, "{expires_at}");
    }
    let mut unsigned = exchange_body(&t, &owner, &w.blinded);
    unsigned["expires_at"] = json!((NOW + 25 * HOUR).to_string());
    assert_eq!(r.exchange(&unsigned).1["error"], "invalid owner signature", "the expiry is signed");
    assert_eq!(r.exchange(&exchange_body(&t, &owner, &w.blinded)).0, 202);
}

#[test]
fn a_claim_that_expires_before_landing_is_given_up_and_can_be_sent_again() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let soon = exchange_body_until(&t, &owner, &w.blinded, NOW + HOUR);
    assert_eq!(r.exchange(&soon).0, 202);
    r.set_clock(fixed_clock(NOW + HOUR - 60_000_000_000));
    assert_eq!(r.flush().unwrap(), 0);
    assert_eq!(r.chain.calls, 0, "too close to its expiry to be sent");
    assert_eq!(r.exchange(&soon).0, 410);

    let later = exchange_body_until(&t, &owner, &w.blinded, NOW + 24 * HOUR);
    assert_eq!(r.exchange(&later).0, 202, "the credit is not spent, so a new exchange is accepted");
    assert_eq!(r.flush().unwrap(), 1);
    assert_eq!(r.exchange(&later).0, 200);
}

#[test]
fn a_sent_claim_is_given_up_by_the_chain_clock_and_paid_if_it_lands_late() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let expires_at = NOW + HOUR;
    let body = exchange_body_until(&t, &owner, &w.blinded, expires_at);
    assert_eq!(r.exchange(&body).0, 202);
    r.chain.fail = true;
    assert!(r.flush().is_err(), "the claim was sent, its outcome is unknown");

    // This machine's clock is past the expiry, the chain's is not: the claim can still land.
    r.set_clock(fixed_clock(expires_at + 2 * HOUR));
    r.chain.time = expires_at - 1;
    r.recover().unwrap();
    assert_eq!(r.exchange(&body).0, 202, "not given up on the word of the local clock");

    r.chain.time = expires_at + 1;
    r.recover().unwrap();
    assert_eq!(r.exchange(&body).0, 410, "given up once the chain's own time is past the expiry");

    // The transaction was broadcast again and landed after all: the relay was paid.
    r.chain.spent.insert(t.nullifier());
    r.chain.by_relay.insert(t.nullifier());
    let again = exchange_body_until(&t, &owner, &w.blinded, expires_at + 24 * HOUR);
    let (status, reply) = r.exchange(&again);
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["signatures"].as_array().unwrap().len(), Q, "the credit is never lost");
}

#[test]
fn a_given_up_credit_spent_by_someone_else_is_refused() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body_until(&t, &owner, &w.blinded, NOW + HOUR);
    assert_eq!(r.exchange(&body).0, 202);
    r.chain.fail = true;
    assert!(r.flush().is_err());
    r.set_clock(fixed_clock(NOW + 2 * HOUR));
    r.chain.time = NOW + 2 * HOUR;
    r.recover().unwrap();
    r.chain.spent.insert(t.nullifier());
    let again = exchange_body_until(&t, &owner, &w.blinded, NOW + 24 * HOUR);
    assert_eq!(r.exchange(&again).0, 409);
}

#[test]
fn a_finished_exchange_can_be_collected_after_its_claim_expired() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let body = exchange_body_until(&t, &owner, &wallet(r.request_dst()).blinded, NOW + HOUR);
    assert_eq!(r.exchange(&body).0, 202);
    r.flush().unwrap();
    r.set_clock(fixed_clock(NOW + 48 * HOUR));
    assert_eq!(r.exchange(&body).0, 200, "the signatures stay available");
}

#[test]
fn the_expiry_survives_a_restart_and_reaches_the_chain() {
    let s = setup();
    let path = temp_log("expiry");
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let (t, owner) = credit(&s, 0);
    let dst = request_dst(RELAY);
    let w = wallet(&dst);
    let expires_at = NOW + 30 * HOUR;
    let body = exchange_body_until(&t, &owner, &w.blinded, expires_at);
    {
        let mut r = relay_with(store_at(&path), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        assert_eq!(r.exchange(&body).0, 202);
    }
    struct Recording(Vec<u64>);
    impl Chain for Recording {
        fn is_spent(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Ok(false)
        }
        fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
            self.0.extend(claims.iter().map(|c| c.expires_at));
            Err("stop".into())
        }
        fn claimed_by_relay(&mut self, _: &[u8; 32]) -> Result<bool, String> {
            Ok(false)
        }
    }
    let mut r = Relay::new(
        store_at(&path),
        Recording(vec![]),
        FakeModel { used: 10, fail: false, calls: 0 },
        config(s.credit_pk),
        SecretKey::from_bytes(&key_bytes).unwrap(),
    );
    r.set_clock(fixed_clock(NOW));
    assert!(r.flush().is_err());
    assert_eq!(r.chain.0, vec![expires_at], "the same signed expiry is sent after a restart");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_removed_lock_file_stops_the_store() {
    let path = temp_log("lock-removed");
    let mut store = FileStore::create(&path, TEST_BINDING).unwrap();
    assert!(store.use_request_token("aa").unwrap());
    std::fs::remove_file(format!("{}.lock", path.display())).unwrap();
    // A second process could now lock a new file for the same store.
    let second = FileStore::open(&path, TEST_BINDING).unwrap();
    assert!(store.use_request_token("bb").unwrap_err().contains("lock file"));
    drop(second);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_request_token_has_one_spelling() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    assert_eq!(r.chat(&json!({"token": tokens[0].to_uppercase(), "prompt": "a"})).0, 400);
    let odd = format!("+a{}", "00".repeat(79));
    assert_eq!(r.chat(&json!({"token": odd, "prompt": "a"})).0, 400);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
}

#[test]
fn a_second_relay_process_cannot_share_the_store() {
    let s = setup();
    let path = temp_log("two-instances");
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let mut first = relay_with(store_at(&path), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
    let tokens = request_tokens(&mut first, &s);
    assert_eq!(first.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
    assert!(
        FileStore::open(&path, TEST_BINDING).err().unwrap().contains("in use"),
        "a second process would keep its own memory and accept the token again"
    );
    drop(first);
    std::fs::remove_file(&path).unwrap();
}
