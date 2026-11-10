//! Tests on a real NEAR AI model attestation (public, 2026-11-10), cut down to the fields checked.
//! The Intel and NVIDIA checks are faked: no network.

use std::cell::Cell;

use ona_core::quote::{
    observed_2026_11_10, observed_compose_2026_11_10, verify_model_attestation, IntelQuoteVerifier, Measurements,
    NvidiaVerifier, Policy,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};

const REPORT: &str = include_str!("data/model-attestation.json");
// Byte offsets in the quote: header 48 bytes, then the TD report body.
const TD_ATTRIBUTES: usize = 48 + 120;
const MRTD: usize = 48 + 136;
const MR_CONFIG: usize = 48 + 184;
const RTMR0: usize = 48 + 328;
const RTMR3: usize = RTMR0 + 3 * 48;
const REPORT_DATA: usize = 48 + 520;

fn report() -> Value {
    serde_json::from_str(REPORT).unwrap()
}

fn nonce(r: &Value) -> String {
    r["request_nonce"].as_str().unwrap().to_string()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn quote_bytes(r: &Value) -> Vec<u8> {
    unhex(r["intel_quote"].as_str().unwrap())
}

fn set_quote(r: &mut Value, quote: &[u8]) {
    r["intel_quote"] = Value::String(hex(quote));
}

/// Stands for a real signature check: accepts only the exact quote it was given.
struct ExactQuote(Vec<u8>);
impl IntelQuoteVerifier for ExactQuote {
    fn verify(&self, quote: &[u8]) -> Result<(), String> {
        if quote == self.0 { Ok(()) } else { Err("bad quote signature".into()) }
    }
}

/// Accepts any quote: what the code faces until the Intel check exists. Used to show each later
/// check catches a problem on its own.
struct AnyQuote;
impl IntelQuoteVerifier for AnyQuote {
    fn verify(&self, _: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

struct RefuseQuote;
impl IntelQuoteVerifier for RefuseQuote {
    fn verify(&self, _: &[u8]) -> Result<(), String> {
        Err("collateral unavailable".into())
    }
}

struct Nras {
    pass: bool,
    calls: Cell<u32>,
}
impl Nras {
    fn pass() -> Self {
        Self { pass: true, calls: Cell::new(0) }
    }
    fn fail() -> Self {
        Self { pass: false, calls: Cell::new(0) }
    }
}
impl NvidiaVerifier for Nras {
    fn verify(&self, _: &str) -> Result<(), String> {
        self.calls.set(self.calls.get() + 1);
        if self.pass { Ok(()) } else { Err("GPU verdict is a fail".into()) }
    }
}

fn exact() -> ExactQuote {
    ExactQuote(quote_bytes(&report()))
}

fn systems() -> Vec<Measurements> {
    vec![observed_2026_11_10()]
}

fn composes() -> Vec<[u8; 32]> {
    vec![observed_compose_2026_11_10()]
}

fn check_with(r: &Value, intel: &dyn IntelQuoteVerifier, systems: &[Measurements], composes: &[[u8; 32]]) -> Result<[u8; 32], String> {
    let policy = Policy { systems, compose_hashes: composes };
    verify_model_attestation(r, &nonce(&report()), &policy, intel, &Nras::pass())
}

fn check(r: &Value, intel: &dyn IntelQuoteVerifier) -> Result<[u8; 32], String> {
    check_with(r, intel, &systems(), &composes())
}

fn flip_quote_byte(r: &mut Value, offset: usize) {
    let mut q = quote_bytes(r);
    q[offset] ^= 1;
    set_quote(r, &q);
}

fn event_digest(e: &Value) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update((e["event_type"].as_u64().unwrap() as u32).to_le_bytes());
    h.update(b":");
    h.update(e["event"].as_str().unwrap().as_bytes());
    h.update(b":");
    h.update(unhex(e["event_payload"].as_str().unwrap()));
    h.finalize().into()
}

fn replay(log: &[Value]) -> [u8; 48] {
    let mut rtmr = [0u8; 48];
    for e in log.iter().filter(|e| e["imr"] == 3) {
        rtmr = Sha384::new().chain_update(rtmr).chain_update(event_digest(e)).finalize().into();
    }
    rtmr
}

/// Rewrites the event log, then puts its replay into the quote, as an attacker writing both would.
fn forge_log(r: &mut Value, edit: impl FnOnce(&mut Vec<Value>)) {
    let mut log = r["event_log"].as_array().unwrap().clone();
    edit(&mut log);
    let mut q = quote_bytes(r);
    q[RTMR3..RTMR3 + 48].copy_from_slice(&replay(&log));
    set_quote(r, &q);
    r["event_log"] = Value::Array(log);
}

fn set_event_payload(log: &mut [Value], name: &str, payload: &[u8]) {
    let e = log.iter_mut().find(|e| e["event"] == name).unwrap();
    e["event_payload"] = Value::String(hex(payload));
}

fn mr_config_for(compose: &[u8; 32]) -> [u8; 48] {
    let mut m = [0u8; 48];
    m[0] = 1;
    m[1..33].copy_from_slice(compose);
    m
}

#[test]
fn the_real_report_passes_and_gives_the_signing_key() {
    let r = report();
    let key = check(&r, &exact()).unwrap();
    assert_eq!(hex(&key), r["signing_address"].as_str().unwrap());
}

#[test]
fn the_real_log_replays_to_the_quote_rtmr3() {
    let r = report();
    assert_eq!(replay(r["event_log"].as_array().unwrap())[..], quote_bytes(&r)[RTMR3..RTMR3 + 48]);
}

#[test]
fn any_changed_byte_of_the_quote_fails_the_signature() {
    let len = quote_bytes(&report()).len();
    for offset in [0, 100, MRTD, RTMR3, REPORT_DATA, MR_CONFIG + 2, len - 1] {
        let mut r = report();
        flip_quote_byte(&mut r, offset);
        assert!(check(&r, &exact()).is_err(), "offset {offset}");
    }
}

#[test]
fn an_unverifiable_intel_quote_is_refused() {
    assert!(check(&report(), &RefuseQuote).is_err());
}

#[test]
fn system_measurements_must_be_listed() {
    for offset in [MRTD, RTMR0, RTMR0 + 48, RTMR0 + 96 + 47] {
        let mut r = report();
        flip_quote_byte(&mut r, offset);
        assert!(check(&r, &AnyQuote).unwrap_err().contains("system"), "offset {offset}");
    }
    assert!(check_with(&report(), &AnyQuote, &[], &composes()).unwrap_err().contains("system"));
}

#[test]
fn the_os_image_must_be_listed() {
    let mut other = observed_2026_11_10();
    other.os_image_hash[0] ^= 1;
    assert!(check_with(&report(), &exact(), &[other], &composes()).unwrap_err().contains("system"));

    let mut r = report();
    forge_log(&mut r, |log| set_event_payload(log, "os-image-hash", &[7; 32]));
    assert!(check(&r, &AnyQuote).unwrap_err().contains("system"));
}

#[test]
fn the_log_must_replay_to_the_quote_rtmr3() {
    let mut r = report();
    flip_quote_byte(&mut r, RTMR3 + 5);
    assert!(check(&r, &AnyQuote).unwrap_err().contains("RTMR3"));

    let mut r = report();
    let log = r["event_log"].as_array_mut().unwrap();
    let i = log.iter().position(|e| e["event"] == "app-id").unwrap();
    log[i]["event_payload"] = Value::String("00".repeat(20));
    assert!(check(&r, &AnyQuote).unwrap_err().contains("RTMR3"));

    let mut r = report();
    let log = r["event_log"].as_array_mut().unwrap();
    let last = log.iter().rposition(|e| e["imr"] == 3).unwrap();
    log.remove(last);
    assert!(check(&r, &AnyQuote).unwrap_err().contains("RTMR3"));
}

#[test]
fn a_digest_written_in_the_log_must_match_its_event() {
    let mut r = report();
    let log = r["event_log"].as_array_mut().unwrap();
    let i = log.iter().position(|e| e["event"] == "compose-hash").unwrap();
    log[i]["digest"] = Value::String("ab".repeat(48));
    assert!(check(&r, &exact()).unwrap_err().contains("digest"));

    let mut r = report();
    let log = r["event_log"].as_array_mut().unwrap();
    let i = log.iter().position(|e| e["event"] == "compose-hash").unwrap();
    let right = hex(&event_digest(&log[i]));
    log[i]["digest"] = Value::String(right);
    assert!(check(&r, &exact()).is_ok());
}

#[test]
fn the_logged_compose_hash_must_be_the_reported_app_compose() {
    let mut r = report();
    forge_log(&mut r, |log| set_event_payload(log, "compose-hash", &[5; 32]));
    assert!(check(&r, &AnyQuote).unwrap_err().contains("event log does not measure"));

    let mut r = report();
    forge_log(&mut r, |log| log.retain(|e| e["event"] != "compose-hash"));
    assert!(check(&r, &AnyQuote).unwrap_err().contains("no compose-hash"));

    let mut r = report();
    forge_log(&mut r, |log| {
        let copy = log.iter().find(|e| e["event"] == "compose-hash").unwrap().clone();
        log.push(copy);
    });
    assert!(check(&r, &AnyQuote).unwrap_err().contains("several"));
}

#[test]
fn mr_config_must_match_app_compose() {
    let mut r = report();
    flip_quote_byte(&mut r, MR_CONFIG + 10);
    assert!(check(&r, &AnyQuote).unwrap_err().contains("quote does not measure"));
}

#[test]
fn an_edited_app_compose_is_refused() {
    let mut r = report();
    let compose = r["info"]["tcb_info"]["app_compose"].as_str().unwrap().replacen('{', "{ ", 1);
    r["info"]["tcb_info"]["app_compose"] = Value::String(compose);
    assert!(check(&r, &AnyQuote).unwrap_err().contains("app_compose"));
}

#[test]
fn only_listed_deployments_pass() {
    let r = report();
    assert!(check_with(&r, &exact(), &systems(), &[]).unwrap_err().contains("deployment"));
    assert!(check_with(&r, &exact(), &systems(), &[[9; 32]]).is_err());
}

/// An attacker on any TDX machine writes a whole quote: public measurements copied, their own
/// `app_compose`, `mr_config_id` and event log, all consistent with each other.
fn forged_attestation(attacker_compose: &str) -> Value {
    let real = report();
    let compose: [u8; 32] = Sha256::digest(attacker_compose.as_bytes()).into();
    let mut log: Vec<Value> = real["event_log"].as_array().unwrap().clone();
    set_event_payload(&mut log, "compose-hash", &compose);

    let mut q = vec![0u8; 48 + 584];
    q[0..2].copy_from_slice(&4u16.to_le_bytes());
    q[4] = 0x81;
    let system = observed_2026_11_10();
    q[MRTD..MRTD + 48].copy_from_slice(&system.mrtd);
    for (i, rtmr) in system.rtmr.iter().enumerate() {
        q[RTMR0 + 48 * i..RTMR0 + 48 * (i + 1)].copy_from_slice(rtmr);
    }
    q[RTMR3..RTMR3 + 48].copy_from_slice(&replay(&log));
    q[MR_CONFIG..MR_CONFIG + 48].copy_from_slice(&mr_config_for(&compose));
    q[REPORT_DATA..REPORT_DATA + 32].copy_from_slice(&unhex(real["signing_address"].as_str().unwrap()));
    q[REPORT_DATA + 32..REPORT_DATA + 64].copy_from_slice(&unhex(&nonce(&real)));

    let mut r = real.clone();
    set_quote(&mut r, &q);
    r["event_log"] = Value::Array(log);
    r["info"]["tcb_info"] = json!({"app_compose": attacker_compose});
    r
}

#[test]
fn a_forged_quote_with_the_attackers_mr_config_is_refused() {
    let r = forged_attestation("services: {leak: {image: attacker}}");
    assert!(check(&r, &AnyQuote).unwrap_err().contains("deployment"));
    assert!(check(&r, &exact()).is_err());
}

/// Without the Intel check, a forgery copying every listed value passes: this is why the module
/// is worth nothing until `IntelQuoteVerifier` is implemented.
#[test]
fn only_the_intel_signature_stops_a_forgery_of_listed_values() {
    let compose = "services: {leak: {image: attacker}}";
    let r = forged_attestation(compose);
    let theirs: [u8; 32] = Sha256::digest(compose.as_bytes()).into();
    assert!(check_with(&r, &AnyQuote, &systems(), &[theirs]).is_ok());
    assert!(check_with(&r, &exact(), &systems(), &[theirs]).is_err());
}

#[test]
fn report_data_must_hold_the_key_and_our_nonce() {
    for offset in [REPORT_DATA, REPORT_DATA + 32, REPORT_DATA + 63] {
        let mut r = report();
        flip_quote_byte(&mut r, offset);
        assert!(check(&r, &AnyQuote).unwrap_err().contains("bind"), "offset {offset}");
    }
}

#[test]
fn another_signing_key_is_refused() {
    let mut r = report();
    let other = "11".repeat(32);
    r["signing_address"] = Value::String(other.clone());
    r["signing_public_key"] = Value::String(other);
    assert!(check(&r, &AnyQuote).unwrap_err().contains("bind"));

    let mut r = report();
    r["signing_public_key"] = Value::String("11".repeat(32));
    assert!(check(&r, &AnyQuote).is_err());
}

#[test]
fn another_nonce_is_refused() {
    let r = report();
    let policy = Policy { systems: &systems(), compose_hashes: &composes() };
    for bad in ["22".repeat(32), String::new(), "abc".into(), "zz".repeat(32), "22".repeat(33)] {
        assert!(verify_model_attestation(&r, &bad, &policy, &AnyQuote, &Nras::pass()).is_err(), "{bad}");
    }

    let mut r = report();
    let ours = "33".repeat(32);
    r["request_nonce"] = Value::String(ours.clone());
    assert!(verify_model_attestation(&r, &ours, &policy, &AnyQuote, &Nras::pass()).is_err());
}

#[test]
fn the_gpu_evidence_must_answer_our_nonce_and_pass() {
    let r = report();
    let n = nonce(&r);
    let (s, c) = (systems(), composes());
    let policy = Policy { systems: &s, compose_hashes: &c };
    let nras = Nras::fail();
    assert!(verify_model_attestation(&r, &n, &policy, &exact(), &nras).is_err());
    assert_eq!(nras.calls.get(), 1);

    let mut r = report();
    let payload = r["nvidia_payload"].as_str().unwrap().replacen(&n, &"44".repeat(32), 1);
    r["nvidia_payload"] = Value::String(payload);
    let nras = Nras::pass();
    assert!(verify_model_attestation(&r, &n, &policy, &AnyQuote, &nras).unwrap_err().contains("GPU"));
    assert_eq!(nras.calls.get(), 0, "a stale payload is not even sent");
}

#[test]
fn a_debug_enclave_is_refused() {
    let mut r = report();
    // The low bit of the first TD attribute byte is the debug flag.
    flip_quote_byte(&mut r, TD_ATTRIBUTES);
    assert!(check(&r, &AnyQuote).unwrap_err().contains("debug"));
}

#[test]
fn other_quote_layouts_are_refused() {
    let mut r = report();
    flip_quote_byte(&mut r, 0);
    assert!(check(&r, &AnyQuote).unwrap_err().contains("TDX"));

    let mut r = report();
    let short = quote_bytes(&r)[..600].to_vec();
    set_quote(&mut r, &short);
    assert!(check(&r, &AnyQuote).unwrap_err().contains("short"));
}

#[test]
fn tcb_info_given_as_a_json_string_is_read_too() {
    let mut r = report();
    let tcb = r["info"]["tcb_info"].to_string();
    r["info"]["tcb_info"] = Value::String(tcb);
    assert!(check(&r, &exact()).is_ok());
}

#[test]
fn every_missing_field_is_a_refusal() {
    for field in
        ["request_nonce", "signing_algo", "signing_address", "signing_public_key", "intel_quote", "nvidia_payload", "info", "event_log"]
    {
        let mut r = report();
        r.as_object_mut().unwrap().remove(field);
        assert!(check(&r, &AnyQuote).is_err(), "{field}");
    }
    let mut r = report();
    r["info"]["tcb_info"].as_object_mut().unwrap().remove("app_compose");
    assert!(check(&r, &AnyQuote).is_err());

    let mut r = report();
    r["signing_algo"] = Value::String("ecdsa".into());
    assert!(check(&r, &AnyQuote).is_err());

    let mut r = report();
    r["nvidia_payload"] = Value::String("not json".into());
    assert!(check(&r, &AnyQuote).is_err());

    let mut r = report();
    forge_log(&mut r, |log| log.retain(|e| e["event"] != "os-image-hash"));
    assert!(check(&r, &AnyQuote).unwrap_err().contains("os-image-hash"));
}
