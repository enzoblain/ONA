//! Attacks on the client core and what stops them: what reaches the model, payment confirmation,
//! exposure report, offers read from pages, request tokens, command line. No network: fake model,
//! web, payments and relay.

use std::cell::RefCell;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;

use ed25519_dalek::SigningKey;
use ona_core::e2ee::Transport;
use ona_core::gate::{fields, PaymentIntent};
use ona_core::remote::{RemoteConfig, RemoteModel};
use ona_core::*;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Takes the reported model key without checking its quote: these tests are about the client around the key.
/// The real check is tested in `tests/attestation.rs`.
struct Unverified;
impl ona_core::e2ee::ModelKeyVerifier for Unverified {
    fn model_key(&mut self, report: &Value, nonce: &str) -> Result<[u8; 32], String> {
        ona_core::e2ee::reported_model_key(report, nonce)
    }
}

const SALT: [u8; 32] = [5u8; 32];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------- pseudonyms before the model ----------

#[derive(Default)]
struct Seen {
    plans: Vec<String>,
    pages: Vec<String>,
}

/// Records what reaches the model. The reader copies an excerpt of what it saw, as a model would.
struct Spy(Rc<RefCell<Seen>>);
impl Model for Spy {
    fn plan(&mut self, mission: &str) -> Result<ModelReply, ModelFailure> {
        self.0.borrow_mut().plans.push(mission.to_string());
        Ok(ModelReply { text: DEMO_PLAN.to_string(), mode: "mock", call: None })
    }
    fn read_page(&mut self, page: &str) -> Result<ModelReply, ModelFailure> {
        self.0.borrow_mut().pages.push(page.to_string());
        let span = page.lines().next().unwrap_or_default();
        let offer = json!({"firm_id":"cabinet-a","specialties":["labour"],"price_cents":90000,"delay_days":7,"source_spans":[span]});
        Ok(ModelReply { text: offer.to_string(), mode: "mock", call: None })
    }
}

fn spy_mission(text: &str, web: MockWeb) -> (Mission<Spy, MockWeb, MockPayments>, Rc<RefCell<Seen>>) {
    let seen = Rc::new(RefCell::new(Seen::default()));
    let m = Mission::open(Spy(seen.clone()), web, MockPayments::default(), demo_policy(), SALT, text);
    (m, seen)
}

#[test]
fn protected_terms_are_replaced_before_the_planner_and_the_reader() {
    let mut web = MockWeb::demo();
    web.pages.insert("h1".into(), "Consultation 900 euros, within 7 days, ACME case".into());
    let (mut m, seen) = spy_mission("Find a lawyer for Mr Dupont, dismissed by ACME", web);
    m.protect(&["ACME".to_string()]).unwrap();
    m.propose_plan().unwrap();
    m.accept_plan().unwrap();
    m.search("lawyer", "paris").unwrap();
    let read = m.read("h1").unwrap();

    let seen = seen.borrow();
    for sent in [&seen.plans[0], &seen.pages[0]] {
        assert!(!sent.contains("Dupont") && !sent.contains("ACME"), "a protected term reached the model: {sent}");
        assert!(sent.len() > 20, "{sent}");
    }
    assert!(seen.plans[0].starts_with("Find a lawyer for Mr "), "the rest of the text is unchanged");
    // The reader cited the pseudonymised page; the reply is put back locally and matches the page.
    assert_eq!(read["offer"]["source_spans"][0], "Consultation 900 euros, within 7 days, ACME case");
    assert_eq!(m.exposure()["pseudonyms_replaced"], 3);
}

#[test]
fn the_gate_refuses_a_text_that_still_holds_a_protected_term() {
    // A one-letter term is too short to get a pseudonym, so it cannot be replaced: the gate must
    // refuse the whole text rather than send it.
    let seen = Rc::new(RefCell::new(Seen::default()));
    let mut policy = demo_policy();
    policy.protected_terms.push("q".into());
    let mut m = Mission::open(Spy(seen.clone()), MockWeb::demo(), MockPayments::default(), policy, SALT, "Case Q, urgent");
    assert_eq!(m.propose_plan().unwrap_err(), "text contains a protected term");
    assert!(seen.borrow().plans.is_empty(), "nothing was sent");
    assert_eq!(m.exposure()["refused_by_gate"]["model: text contains a protected term"], 1);
}

#[test]
fn terms_are_declared_before_the_plan_and_through_dispatch() {
    let (mut m, _) = spy_mission("x", MockWeb::demo());
    assert!(m.protect(&["x".to_string()]).is_err(), "too short");
    m.propose_plan().unwrap();
    assert!(m.protect(&["Martin".to_string()]).is_err(), "too late: the planner already saw the text");

    let mut core = Core::new();
    let opened = ask(&mut core, json!({"cmd":"open","mission":"Case of Martin","protected":["Martin"]}));
    assert_eq!(opened["ok"], true, "{opened}");
    assert_eq!(ask(&mut core, json!({"cmd":"propose_plan"}))["ok"], true);
    ask(&mut core, json!({"cmd":"close"}));
    let bad = ask(&mut core, json!({"cmd":"open","mission":"y","protected":"Martin"}));
    assert_eq!(bad["error"], "protected must be a list of strings");
}

// ---------- payment confirmation ----------

fn ask(core: &mut Core, request: Value) -> Value {
    serde_json::from_str(&core.dispatch(&request.to_string())).unwrap()
}

fn up_to_payment(core: &mut Core) -> Value {
    for request in [
        json!({"cmd":"open","mission":"m"}),
        json!({"cmd":"propose_plan"}),
        json!({"cmd":"accept_plan"}),
        json!({"cmd":"search","template":"lawyer","value":"paris"}),
        json!({"cmd":"read","handle":"h1"}),
        json!({"cmd":"read","handle":"h2"}),
        json!({"cmd":"compare"}),
        json!({"cmd":"confirm_recipient","firm":"cabinet-b"}),
        json!({"cmd":"contact","message":"x"}),
    ] {
        assert_eq!(ask(core, request.clone())["ok"], true, "{request}");
    }
    let prepared = ask(core, json!({"cmd":"prepare_payment"}));
    assert_eq!(prepared["ok"], true, "{prepared}");
    prepared
}

#[test]
fn the_digest_binds_network_contract_mission_and_a_random_nonce() {
    let mut core = Core::new();
    let prepared = up_to_payment(&mut core);
    let p = &prepared["payment"];
    let text = |k: &str| p[k].as_str().unwrap().to_string();
    assert_eq!(text("nonce").len(), 32, "16 random bytes");
    let expected = Sha256::digest(fields(&[
        b"ona/pay/v2",
        text("network").as_bytes(),
        text("contract").as_bytes(),
        text("mission_id").as_bytes(),
        text("nonce").as_bytes(),
        text("to").as_bytes(),
        text("amount").as_bytes(),
    ]));
    assert_eq!(prepared["digest"], hex(&expected), "the exact format other components recompute");
    assert_eq!((text("network"), text("contract"), text("to")), ("sandbox".into(), "mint.test".into(), "cabinet-b.testnet".into()));

    // Computed from public values only, without the nonce: refused.
    let guessed = PaymentIntent {
        network: text("network"),
        contract: text("contract"),
        mission_id: text("mission_id"),
        nonce: [0; 16],
        to: text("to"),
        amount: text("amount").parse().unwrap(),
    };
    assert_eq!(ask(&mut core, json!({"cmd":"confirm_payment","digest":guessed.digest()}))["ok"], false);
}

#[test]
fn a_confirmation_is_good_for_one_mission_and_one_payment_only() {
    let mut core = Core::new();
    let first = up_to_payment(&mut core);
    assert_eq!(ask(&mut core, json!({"cmd":"confirm_payment","digest":first["digest"]}))["ok"], true);
    assert_eq!(ask(&mut core, json!({"cmd":"pay"}))["ok"], true);
    assert_eq!(ask(&mut core, json!({"cmd":"pay"}))["ok"], false, "used once");
    ask(&mut core, json!({"cmd":"close"}));

    // Same firm, same amount, next mission: the old confirmation no longer matches.
    let second = up_to_payment(&mut core);
    assert_ne!(second["digest"], first["digest"]);
    let replay = ask(&mut core, json!({"cmd":"confirm_payment","digest":first["digest"]}));
    assert_eq!(replay["ok"], false);
    assert_eq!(ask(&mut core, json!({"cmd":"pay"}))["ok"], false);
}

#[test]
fn the_amount_must_be_the_price_of_the_chosen_offer() {
    let mut core = Core::new();
    for request in [
        json!({"cmd":"open","mission":"m"}),
        json!({"cmd":"propose_plan"}),
        json!({"cmd":"accept_plan"}),
        json!({"cmd":"search","template":"lawyer","value":"paris"}),
        json!({"cmd":"read","handle":"h1"}),
        json!({"cmd":"read","handle":"h2"}),
        json!({"cmd":"compare"}),
        json!({"cmd":"confirm_recipient","firm":"cabinet-b"}),
        json!({"cmd":"contact","message":"x"}),
    ] {
        ask(&mut core, request);
    }
    // The offer said 60000 cents; the caller asks to pay 1000 yocto.
    let wrong = ask(&mut core, json!({"cmd":"prepare_payment","amount":"1000"}));
    assert_eq!(wrong["error"], "amount is not the price of the chosen offer");
    let right = (60_000 * DEMO_YOCTO_PER_CENT).to_string();
    let prepared = ask(&mut core, json!({"cmd":"prepare_payment","amount":right}));
    assert_eq!(prepared["ok"], true);
    assert_eq!(prepared["amount_near"], "0.6");
}

#[test]
fn no_payment_without_a_conversion_rate() {
    let mut policy = demo_policy();
    policy.yocto_per_cent = 0;
    let mut m = Mission::open(MockModel::default(), MockWeb::demo(), MockPayments::default(), policy, SALT, "m");
    m.propose_plan().unwrap();
    m.accept_plan().unwrap();
    m.search("lawyer", "paris").unwrap();
    m.read("h1").unwrap();
    m.read("h2").unwrap();
    m.compare().unwrap();
    m.confirm_recipient("cabinet-b").unwrap();
    m.contact("x").unwrap();
    assert!(m.prepare_payment(1).unwrap_err().contains("conversion rate"));
}

// ---------- exposure report: parties and bytes ----------

#[derive(Clone, Default)]
struct Net(Rc<RefCell<NetState>>);
#[derive(Default)]
struct NetState {
    gets: Vec<String>,
    attestation_status: u16,
}

impl Transport for Net {
    fn get(&mut self, path: &str, _: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        let mut s = self.0.borrow_mut();
        s.gets.push(path.to_string());
        if s.attestation_status != 200 {
            return Ok((s.attestation_status, vec![]));
        }
        let key = SigningKey::generate(&mut OsRng);
        let nonce = path.rsplit("nonce=").next().unwrap_or_default();
        let report = json!({"model_attestations":[{"signing_public_key":hex(key.verifying_key().as_bytes()),"request_nonce":nonce}]});
        Ok((200, report.to_string().into_bytes()))
    }
    fn post(&mut self, _: &str, _: &[(String, String)], _: &[u8]) -> Result<(u16, Vec<u8>), String> {
        Err("connection reset".into())
    }
}

fn config(file: Option<PathBuf>, tokens: Vec<String>) -> RemoteConfig {
    RemoteConfig {
        relay_url: "http://127.0.0.1:8787".into(),
        model: "test/model".into(),
        max_tokens_per_call: 100,
        total_token_budget: 1_000_000,
        request_tokens: tokens,
        request_tokens_file: file,
    }
}

fn party<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["parties"].as_array().unwrap().iter().find(|p| p["party"] == name).unwrap_or(&Value::Null)
}

#[test]
fn requests_that_reached_the_relay_are_exposure_not_refusals() {
    let net = Net::default();
    net.0.borrow_mut().attestation_status = 500;
    let model = RemoteModel::new(net.clone(), Box::new(Unverified), config(None, vec![])).unwrap();
    let mut m = Mission::open(model, MockWeb::demo(), MockPayments::default(), demo_policy(), SALT, "secret mission");
    for _ in 0..3 {
        assert!(m.propose_plan().is_err());
    }
    assert_eq!(net.0.borrow().gets.len(), 3);
    let report = m.exposure();
    assert_eq!(report["refused_by_gate"], json!({}), "nothing that left is filed as refused: {report}");
    let relay = party(&report, "relay http://127.0.0.1:8787");
    assert_eq!(relay["requests"], 3, "{report}");
    assert!(relay["bytes_sent"].as_u64().unwrap() > 0);
    assert_eq!(report["model_calls_real"], 0, "the prompt itself never left");
    assert_eq!(report["content_readable_by_relay"], true);
    assert_eq!(report["warnings"][0], ENCLAVE_TRUST_WARNING);
}

#[test]
fn every_party_of_a_mission_is_named_with_its_bytes() {
    let mut core = Core::new();
    let prepared = up_to_payment(&mut core);
    ask(&mut core, json!({"cmd":"confirm_payment","digest":prepared["digest"]}));
    ask(&mut core, json!({"cmd":"pay"}));
    let report = ask(&mut core, json!({"cmd":"exposure"}));
    let bytes = |name: &str| party(&report, name)["bytes_sent"].as_u64().unwrap_or(0);
    assert_eq!(bytes("search engine"), "employment lawyer paris".len() as u64);
    assert_eq!(bytes("site h1"), 2);
    assert_eq!(bytes("site h2"), 2);
    assert_eq!(bytes("firm cabinet-b"), 1);
    assert!(bytes("chain sandbox, contract mint.test") > 0);
    assert_eq!(report["content_readable_by_relay"], false, "the fake model sends nothing");
}

// ---------- offers belong to the page's own firm ----------

fn reading(reply: &str, web: MockWeb) -> Mission<FixedReader, MockWeb, MockPayments> {
    let mut m = Mission::open(FixedReader(reply.to_string()), web, MockPayments::default(), demo_policy(), SALT, "m");
    m.propose_plan().unwrap();
    m.accept_plan().unwrap();
    m.search("lawyer", "paris").unwrap();
    m
}

struct FixedReader(String);
impl Model for FixedReader {
    fn plan(&mut self, _: &str) -> Result<ModelReply, ModelFailure> {
        Ok(ModelReply { text: DEMO_PLAN.into(), mode: MODE, call: None })
    }
    fn read_page(&mut self, _: &str) -> Result<ModelReply, ModelFailure> {
        Ok(ModelReply { text: self.0.clone(), mode: MODE, call: None })
    }
}

#[test]
fn a_page_cannot_file_an_offer_for_another_firm() {
    // The page of cabinet-a says cabinet-b asks 1 cent, citing its own text.
    let reply = json!({"firm_id":"cabinet-b","specialties":["labour"],"price_cents":90000,"delay_days":7,"source_spans":["Consultation 900 euros, within 7 days"]}).to_string();
    let mut m = reading(&reply, MockWeb::demo());
    assert_eq!(m.read("h1").unwrap_err(), "offer names another firm than the one whose page was read");
}

#[test]
fn an_excerpt_of_one_character_proves_nothing() {
    let reply = json!({"firm_id":"cabinet-a","specialties":["labour"],"price_cents":1,"delay_days":1,"source_spans":["9"]}).to_string();
    assert_eq!(reading(&reply, MockWeb::demo()).read("h1").unwrap_err(), "excerpt too short");
    let unrelated = json!({"firm_id":"cabinet-a","specialties":["labour"],"price_cents":1,"delay_days":2,"source_spans":["Consultation 900 euros"]}).to_string();
    assert_eq!(reading(&unrelated, MockWeb::demo()).read("h1").unwrap_err(), "price or delay is not written in the cited excerpts");
}

#[test]
fn a_page_is_read_once_and_a_firm_has_one_offer() {
    let plan = r#"["search","read","read","compare"]"#;
    let mut m = Mission::open(MockModel { plan_reply: plan.into() }, MockWeb::demo(), MockPayments::default(), demo_policy(), SALT, "m");
    m.propose_plan().unwrap();
    m.accept_plan().unwrap();
    m.search("lawyer", "paris").unwrap();
    m.read("h1").unwrap();
    assert_eq!(m.read("h1").unwrap_err(), "this page was already read");

    let mut web = MockWeb::demo();
    web.pages.insert("h2".into(), web.pages["h1"].clone());
    web.sources.insert("h2".into(), "cabinet-a".into());
    let mut m = Mission::open(MockModel { plan_reply: plan.into() }, web, MockPayments::default(), demo_policy(), SALT, "m");
    m.propose_plan().unwrap();
    m.accept_plan().unwrap();
    m.search("lawyer", "paris").unwrap();
    m.read("h1").unwrap();
    assert_eq!(m.read("h2").unwrap_err(), "this firm already has an offer");
}

// ---------- no web read after the comparison ----------

#[test]
fn reads_come_in_one_block_before_the_comparison() {
    use Step::*;
    for plan in [
        vec![Search, Read, Compare, ConfirmRecipient, PreparePayment, Read, ConfirmPayment, Pay],
        vec![Search, Read, Compare, Read, ConfirmRecipient, Contact, Read],
        vec![Search, Read, Compare, Read],
    ] {
        assert!(validate_plan(&plan).is_err(), "{plan:?}");
    }
    assert!(validate_plan(&[Search, Read, Read, Read, Compare]).is_ok());
}

// ---------- a fetch without an answer is still recorded ----------

struct Flaky(MockWeb);
impl Web for Flaky {
    fn search(&mut self, _: &str) -> Vec<String> {
        vec!["h1".into(), "h9".into()]
    }
    fn fetch(&mut self, handle: &str) -> Option<String> {
        self.0.fetch(handle)
    }
    fn contact(&mut self, firm: &str, message: &str) {
        self.0.contact(firm, message)
    }
    fn source(&self, handle: &str) -> Option<String> {
        self.0.source(handle)
    }
}

#[test]
fn a_failed_fetch_is_journaled_and_counted() {
    let mut m = Mission::open(MockModel::default(), Flaky(MockWeb::demo()), MockPayments::default(), demo_policy(), SALT, "m");
    m.propose_plan().unwrap();
    m.accept_plan().unwrap();
    m.search("lawyer", "paris").unwrap();
    assert_eq!(m.read("h9").unwrap_err(), "page not available");
    let report = m.exposure();
    assert_eq!(report["outputs"]["fetch"], 1);
    assert_eq!(party(&report, "site h9")["requests"], 1);
}

// ---------- request tokens file ----------

fn tokens_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ona-security-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tokens");
    std::fs::write(&path, "tok-1\ntok-2\ntok-3\n").unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn file_config(path: &PathBuf) -> RemoteConfig {
    let tokens = std::fs::read_to_string(path).unwrap().lines().map(String::from).collect();
    config(Some(path.clone()), tokens)
}

#[test]
fn a_second_model_cannot_spend_from_the_same_tokens_file() {
    let path = tokens_path("two");
    let a = RemoteModel::new(Net::default(), Box::new(Unverified), file_config(&path)).unwrap();
    let refused = RemoteModel::new(Net::default(), Box::new(Unverified), file_config(&path));
    assert_eq!(refused.err().unwrap(), "the request tokens file is in use by another process");
    drop(a);
    assert!(RemoteModel::new(Net::default(), Box::new(Unverified), file_config(&path)).is_ok(), "free again once the first one is gone");
}

#[test]
fn tokens_are_read_again_under_the_lock() {
    let path = tokens_path("stale");
    let stale = file_config(&path);
    std::fs::write(&path, "tok-3\n").unwrap();
    let net = Net::default();
    net.0.borrow_mut().attestation_status = 200;
    let mut model = RemoteModel::new(net, Box::new(Unverified), stale).unwrap();
    let _ = model.plan("m");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "", "tok-1 and tok-2, spent elsewhere, did not come back");
}

// Unix only: Windows has no mode to check (`private_fs`).
#[cfg(unix)]
#[test]
fn a_tokens_file_other_accounts_can_read_is_refused() {
    let path = tokens_path("open");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let lookup = |name: &str| match name {
        "ONA_REAL_RELAY_URL" => Some("https://relay.example".to_string()),
        "ONA_REAL_MODEL" => Some("test/model".to_string()),
        "ONA_REAL_MAX_TOKENS" => Some("100".to_string()),
        "ONA_REAL_TOKEN_BUDGET" => Some("1000".to_string()),
        "ONA_REAL_TOKENS_FILE" => Some(path.to_str().unwrap().to_string()),
        _ => None,
    };
    assert!(RemoteConfig::from_lookup(lookup).unwrap_err().contains("owner only"));
    assert!(RemoteModel::new(Net::default(), Box::new(Unverified), config(Some(path.clone()), vec!["tok-1".into()])).is_err());
}

#[test]
fn the_rewritten_tokens_file_stays_private_and_leaves_no_copy() {
    let path = tokens_path("rewrite");
    let net = Net::default();
    net.0.borrow_mut().attestation_status = 200;
    let mut model = RemoteModel::new(net, Box::new(Unverified), file_config(&path)).unwrap();
    let _ = model.plan("m");
    #[cfg(unix)]
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let names: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
}

#[test]
fn a_debug_print_of_the_configuration_hides_the_request_tokens() {
    let printed = format!("{:?}", config(None, vec!["secret-token-value".into()]));
    assert!(!printed.contains("secret-token-value"), "{printed}");
    assert!(printed.contains("1 hidden"));
}

// ---------- the command line survives a bad line ----------

#[test]
fn a_bad_line_gets_an_error_reply_and_the_mission_goes_on() {
    let mut input = Vec::new();
    input.extend_from_slice(b"{\"cmd\":\"open\",\"mission\":\"m\"}\n");
    input.extend_from_slice(b"\xff\xfe not utf-8\n");
    input.extend_from_slice(&vec![b'x'; MAX_REQUEST_BYTES + 10]);
    input.push(b'\n');
    input.extend_from_slice(b"{\"cmd\":\"propose_plan\"}\r\n");
    let mut output = Vec::new();
    let mut core = Core::new();
    serve(&mut core, &input[..], &mut output).unwrap();
    let replies: Vec<Value> = String::from_utf8(output).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(replies.len(), 4);
    assert_eq!(replies[1]["error"], "request is not valid UTF-8");
    assert_eq!(replies[2]["error"], "request too long");
    assert_eq!(replies[3]["ok"], true, "the open mission survived: {}", replies[3]);
}

#[test]
fn an_obfuscated_name_on_a_page_never_reaches_the_reader() {
    for page in ["Consultation 900 euros, within 7 days, for Du&#112;ont", "Consultation 900 euros, within 7 days, for Du\u{AD}pont"] {
        let mut web = MockWeb::demo();
        web.pages.insert("h1".into(), page.into());
        let (mut m, seen) = spy_mission("Find a lawyer", web);
        m.propose_plan().unwrap();
        m.accept_plan().unwrap();
        m.search("lawyer", "paris").unwrap();
        // The excerpt the reader copies holds the pseudonym: it is checked on the text it was given.
        let read = m.read("h1").unwrap();
        let sent = seen.borrow().pages[0].clone();
        assert!(!pseudonym::contains_protected(&sent, &["Dupont".to_string()]), "{sent}");
        assert!(read["offer"]["source_spans"][0].as_str().unwrap().ends_with("for Dupont"), "{read}");
    }
}

#[test]
fn a_page_cannot_inflate_the_price_a_hundred_times() {
    // The page says 900 euros; the reader claims 900 cents (or 90000 claims for "9 euros 00"...).
    let cheap = json!({"specialties":["labour"],"price_cents":900,"delay_days":7,"source_spans":["Consultation 900 euros, within 7 days"]}).to_string();
    assert_eq!(reading(&cheap, MockWeb::demo()).read("h1").unwrap_err(), "price or delay is not written in the cited excerpts");
    let mut web = MockWeb::demo();
    web.pages.insert("h1".into(), "Consultation 9 euros, within 7 days".into());
    let inflated = json!({"specialties":["labour"],"price_cents":90000,"delay_days":7,"source_spans":["Consultation 9 euros, within 7 days"]}).to_string();
    assert!(reading(&inflated, web).read("h1").is_err(), "\"9\" is not 900 euros");
}

#[test]
fn a_delay_must_be_written_as_its_own_number() {
    let mut web = MockWeb::demo();
    web.pages.insert("h1".into(), "Consultation 900 euros, within 12 days".into());
    let one_day = json!({"specialties":["labour"],"price_cents":90000,"delay_days":1,"source_spans":["Consultation 900 euros, within 12 days"]}).to_string();
    assert!(reading(&one_day, web).read("h1").is_err(), "\"1\" inside \"12\" does not count");
}

#[test]
fn the_firm_comes_from_the_search_when_the_reader_gives_none() {
    let reply = json!({"specialties":["labour"],"price_cents":90000,"delay_days":7,"source_spans":["Consultation 900 euros, within 7 days"]}).to_string();
    let read = reading(&reply, MockWeb::demo()).read("h1").unwrap();
    assert_eq!(read["offer"]["firm_id"], "cabinet-a");
}
