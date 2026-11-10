use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use ona_server::*;
use ona_token::{
    blind, claim_digest, keygen, sign_blinded, sign_digest, unblind, verify, BlindingFactor,
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
    }
}

fn relay_with<S: Store>(store: S, s: &Setup, chain: FakeChain, key: SecretKey) -> TestRelay<S> {
    Relay::new(store, chain, FakeModel { used: 10, fail: false, calls: 0 }, config(s.credit_pk), key)
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

fn exchange_body(t: &Token, owner: &SigningKey, blinded: &[String]) -> Value {
    let d = claim_digest(MINT, RELAY, &t.nullifier());
    json!({"token": hex(&t.to_bytes()), "owner_sig": hex(&sign_digest(owner, &d)), "blinded": blinded})
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
    assert_eq!(reply["mode"], "mock");
    assert_eq!(reply["reply"], "echo: bonjour");
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
        let mut r = relay_with(FileStore::open(&path).unwrap(), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        r.exchange(&body);
        r.chain.lose_reply = true;
        assert!(r.flush().is_err(), "the crash happens during the chain call");
        let mut c = FakeChain::default();
        c.spent = r.chain.spent.clone();
        c.by_relay = r.chain.by_relay.clone();
        c
    };

    let mut r = relay_with(FileStore::open(&path).unwrap(), &s, chain, SecretKey::from_bytes(&key_bytes).unwrap());
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
        let mut r = relay_with(FileStore::open(&path).unwrap(), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        r.exchange(&body);
        r.chain.fail = true;
        let _ = r.flush();
    }
    let mut chain = FakeChain::default();
    chain.spent.insert(t.nullifier());
    let mut r = relay_with(FileStore::open(&path).unwrap(), &s, chain, SecretKey::from_bytes(&key_bytes).unwrap());
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

type SharedRelay = std::sync::Mutex<TestRelay<MemoryStore>>;

/// A chain whose calls run while the relay is expected to be free.
struct ProbeChain<'a> {
    relay: &'a SharedRelay,
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
    fn claimed_by_relay(&mut self, _nf: &[u8; 32]) -> Result<bool, String> {
        self.note_call();
        Ok(false)
    }
}

fn probe(relay: &SharedRelay) -> ProbeChain<'_> {
    ProbeChain { relay, free_during_calls: true, calls: 0, spent: BTreeSet::new(), during_is_spent: None }
}

#[test]
fn the_relay_is_not_locked_during_chain_calls() {
    let s = setup();
    let r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    let shared = std::sync::Mutex::new(r);
    let mut chain = probe(&shared);

    assert_eq!(Relay::exchange_shared(&shared, &mut chain, &body).0, 202);
    assert_eq!(Relay::flush_shared(&shared, &mut chain).unwrap(), 1);
    assert_eq!(Relay::exchange_shared(&shared, &mut chain, &body).0, 200);
    assert!(chain.calls >= 2);
    assert!(chain.free_during_calls);
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
    let shared = std::sync::Mutex::new(r);

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
    assert_eq!(Relay::flush_shared(&shared, &mut Capped).unwrap(), 0);
    assert_eq!(shared.lock().unwrap().exchange(&body).0, 202);
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
    let shared = std::sync::Mutex::new(r);
    let mut chain = probe(&shared);
    // The other request lands while this one waits for the chain.
    chain.during_is_spent = Some(other.clone());

    assert_eq!(Relay::exchange_shared(&shared, &mut chain, &body).0, 409);
    assert_eq!(shared.lock().unwrap().exchange(&other).0, 202, "the first one recorded stays");
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
    std::fs::write(&path, "{\"x\":\"aa\"}\n{\"x\":\"b").unwrap();
    let mut store = FileStore::open(&path).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"x\":\"aa\"}\n");
    assert!(!store.use_request_token("aa").unwrap());
    assert!(store.use_request_token("bb").unwrap());
    drop(store);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"x\":\"aa\"}\n{\"x\":\"bb\"}\n");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_last_line_without_a_newline_is_cut_even_if_it_parses() {
    let path = temp_log("no-newline");
    std::fs::write(&path, "{\"x\":\"aa\"}\n{\"x\":\"bb\"}").unwrap();
    let mut store = FileStore::open(&path).unwrap();
    assert!(store.use_request_token("bb").unwrap(), "that write was never acknowledged");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn damage_to_a_complete_line_is_refused_and_left_alone() {
    let path = temp_log("damaged");
    let damaged = "{\"x\":\"aa\"}\nnot json\n{\"x\":\"bb\"}\ntorn";
    std::fs::write(&path, damaged).unwrap();
    assert!(FileStore::open(&path).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), damaged);
    std::fs::remove_file(&path).unwrap();
}

fn pending_state(tag: &str) -> ExchangeState {
    ExchangeState::Pending { blinded_hash: "h".into(), token: format!("credit-{tag}"), owner_sig: "s".into(), blinded: vec![] }
}

fn submitted_state(tag: &str) -> ExchangeState {
    ExchangeState::Submitted { blinded_hash: "h".into(), token: format!("credit-{tag}"), owner_sig: "s".into(), blinded: vec![] }
}

fn done_state() -> ExchangeState {
    ExchangeState::Done { blinded_hash: "h".into(), signatures: vec!["sig".into()] }
}

#[test]
fn compaction_keeps_every_used_token_and_drops_finished_credits() {
    let path = temp_log("compact");
    let mut store = FileStore::open(&path).unwrap();
    for i in 0..10 {
        let nf = format!("{i}");
        store.put(&nf, pending_state(&nf)).unwrap();
        store.put(&nf, submitted_state(&nf)).unwrap();
        store.put(&nf, done_state()).unwrap();
        assert!(store.use_request_token(&format!("t{i}")).unwrap());
    }
    store.put("open", submitted_state("open")).unwrap();
    assert_eq!(line_count(&path), 41);

    store.compact().unwrap();
    assert_eq!(line_count(&path), 21, "one line per credit and per used token");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("credit-3"), "a finished exchange no longer holds its credit");
    assert!(text.contains("credit-open"), "an open one still does");

    // Writing still goes to the new file.
    assert!(store.use_request_token("after").unwrap());
    drop(store);

    let mut store = FileStore::open(&path).unwrap();
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
    let mut store = FileStore::open(&path).unwrap();
    let rounds = 200;
    for i in 0..rounds {
        let nf = format!("{i}");
        store.put(&nf, pending_state(&nf)).unwrap();
        store.put(&nf, submitted_state(&nf)).unwrap();
        store.put(&nf, done_state()).unwrap();
    }
    assert!(line_count(&path) < rounds * 2, "{} lines", line_count(&path));
    drop(store);
    let store = FileStore::open(&path).unwrap();
    for i in 0..rounds {
        assert_eq!(store.get(&format!("{i}")), Some(done_state()));
    }
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn compaction_preserves_a_returned_token_as_usable() {
    let path = temp_log("released");
    let mut store = FileStore::open(&path).unwrap();
    assert!(store.use_request_token("kept").unwrap());
    assert!(store.use_request_token("returned").unwrap());
    store.release_request_token("returned").unwrap();
    store.compact().unwrap();
    drop(store);
    let mut store = FileStore::open(&path).unwrap();
    assert!(!store.use_request_token("kept").unwrap());
    assert!(store.use_request_token("returned").unwrap());
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_leftover_compaction_file_is_ignored() {
    let path = temp_log("leftover");
    let leftover = format!("{}.compact", path.display());
    std::fs::write(&path, "{\"x\":\"aa\"}\n").unwrap();
    std::fs::write(&leftover, "garbage from a crash").unwrap();
    let mut store = FileStore::open(&path).unwrap();
    assert!(!store.use_request_token("aa").unwrap());
    store.compact().unwrap();
    assert!(!std::path::Path::new(&leftover).exists());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"x\":\"aa\"}\n");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn used_request_tokens_survive_a_restart() {
    let s = setup();
    let path = std::env::temp_dir().join(format!("ona-relay-{}-c.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let token = {
        let mut r = relay_with(FileStore::open(&path).unwrap(), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        let tokens = request_tokens(&mut r, &s);
        assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
        tokens[0].clone()
    };
    let mut r = relay_with(FileStore::open(&path).unwrap(), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
    assert_eq!(r.chat(&json!({"token": token, "prompt": "a"})).0, 409);
    assert_eq!(r.upstream.calls, 0);
    std::fs::remove_file(&path).unwrap();
}
