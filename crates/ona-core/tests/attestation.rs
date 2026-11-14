//! The model key check of the client: Intel's signature with `dcap-qvl`, then the checks of `quote`.
//!
//! Two kinds of data:
//! - `data/dcap-qvl-sample/`: a real TDX quote and its Intel collateral, copied from the `dcap-qvl` 0.7.1 crate
//!   (MIT, Phala Network; see the LICENSE file next to them). Intel's real signatures, checked offline: this is
//!   where the Intel check itself is tested. The collateral was issued by Intel on 2025-06-19.
//! - `data/model-attestation.json`: a real NEAR AI model attestation (2026-11-10). Intel's collateral for it could
//!   not be fetched on 13/11/2026 (Intel's host could not be reached from the development machine), so the offline tests stand in for the
//!   Intel check with one that accepts only this exact quote, and `the_real_near_ai_quote_passes_with_live_collateral`
//!   (ignored, needs the network) is the one meant to run Intel's check on it.

use dcap_qvl::QuoteCollateralV3;
use ed25519_dalek::SigningKey;
use ona_core::attestation::{
    intel_verdict, near_ai_policy, AttestedModelKey, DcapVerifier, IntelPcs, PcsAnswers, SavedCollateral,
};
use ona_core::e2ee::{E2eeClient, ModelKeyVerifier, Transport};
use ona_core::quote::{IntelQuoteVerifier, IntelVerdict, TcbStatus};
use ona_core::tor::Network;
use rand::rngs::OsRng;
use serde_json::{json, Value};

const SAMPLE_QUOTE: &[u8] = include_bytes!("data/dcap-qvl-sample/tdx_quote");
const SAMPLE_COLLATERAL: &str = include_str!("data/dcap-qvl-sample/tdx_quote_collateral.json");
const NEAR_REPORT: &str = include_str!("data/model-attestation.json");

/// 2025-06-20T00:00:00Z: inside the validity of the sample collateral (issued 2025-06-19, next update 2025-07-19).
const SAMPLE_NOW: u64 = 1_750_377_600;
/// The sample TCB info's `issueDate`, 2025-06-19T10:16:03Z, the older of the TCB info and QE identity dates.
const SAMPLE_TCB_ISSUED: u64 = 1_750_328_163;
const HEADER_LEN: usize = 48;
const BODY_LEN: usize = 584;
const REPORT_DATA: usize = HEADER_LEN + 520;

fn sample_collateral() -> QuoteCollateralV3 {
    serde_json::from_str(SAMPLE_COLLATERAL).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// ---------- Intel's check with dcap-qvl, on a real quote and real collateral ----------

#[test]
fn a_real_quote_with_its_collateral_passes_the_intel_check() {
    let verdict = intel_verdict(SAMPLE_QUOTE, &sample_collateral(), SAMPLE_NOW).unwrap();
    assert_eq!(verdict.tcb_status, TcbStatus::UpToDate);
    assert!(verdict.advisory_ids.is_empty());
    assert_eq!(verdict.collateral_issued_at, SAMPLE_TCB_ISSUED);
    assert_eq!(verdict.report_body, SAMPLE_QUOTE[HEADER_LEN..HEADER_LEN + BODY_LEN], "the verified body is the quote's");
}

#[test]
fn any_changed_byte_of_a_real_quote_is_refused() {
    // Header, MRTD, report_data, the quote signature, the attestation key, the QE report, the PCK leaf and the PCK CA
    // certificates. (The copy of Intel's root certificate at the end of the chain is not used: dcap-qvl trusts only
    // its own built-in copy, so a change there is not a forgery. Nor is turning a PEM line break into other
    // whitespace.)
    for offset in [8, HEADER_LEN + 136, REPORT_DATA, REPORT_DATA + 63, 640, 700, 760, 900, 1400, 2001, 3000, 3500] {
        let mut quote = SAMPLE_QUOTE.to_vec();
        quote[offset] ^= 1;
        assert!(intel_verdict(&quote, &sample_collateral(), SAMPLE_NOW).is_err(), "byte {offset}");
    }
}

#[test]
fn altered_collateral_is_refused() {
    let mut c = sample_collateral();
    c.tcb_info = c.tcb_info.replacen("\"issueDate\":\"2025-06-19", "\"issueDate\":\"2025-06-18", 1);
    assert_ne!(c.tcb_info, sample_collateral().tcb_info, "the edit happened");
    assert!(intel_verdict(SAMPLE_QUOTE, &c, SAMPLE_NOW).is_err(), "TCB info no longer matches Intel's signature");

    let mut c = sample_collateral();
    c.qe_identity_signature[5] ^= 1;
    assert!(intel_verdict(SAMPLE_QUOTE, &c, SAMPLE_NOW).is_err());

    let mut c = sample_collateral();
    c.pck_crl[200] ^= 1;
    assert!(intel_verdict(SAMPLE_QUOTE, &c, SAMPLE_NOW).is_err());
}

#[test]
fn expired_or_not_yet_valid_collateral_is_refused() {
    let day = 86_400;
    assert!(intel_verdict(SAMPLE_QUOTE, &sample_collateral(), SAMPLE_NOW + 40 * day).is_err(), "past nextUpdate");
    assert!(intel_verdict(SAMPLE_QUOTE, &sample_collateral(), SAMPLE_NOW - 2 * day).is_err(), "before issueDate");
}

#[test]
fn the_dcap_verifier_uses_its_collateral_source_and_clock() {
    fn now() -> u64 {
        SAMPLE_NOW
    }
    let verifier = DcapVerifier::new(SavedCollateral(sample_collateral())).with_clock(now);
    assert_eq!(verifier.verify(SAMPLE_QUOTE).unwrap().tcb_status, TcbStatus::UpToDate);
    fn later() -> u64 {
        SAMPLE_NOW + 40 * 86_400
    }
    let verifier = DcapVerifier::new(SavedCollateral(sample_collateral())).with_clock(later);
    assert!(verifier.verify(SAMPLE_QUOTE).is_err());
}

#[test]
fn intel_answers_rebuild_the_collateral_byte_for_byte() {
    let c = sample_collateral();
    let answers = PcsAnswers {
        pck_crl_issuer_chain: c.pck_crl_issuer_chain.clone(),
        pck_crl: c.pck_crl.clone(),
        tcb_info_issuer_chain: c.tcb_info_issuer_chain.clone(),
        tcb_info_body: format!("{{\"tcbInfo\":{},\"signature\":\"{}\"}}", c.tcb_info, hex(&c.tcb_info_signature)).into_bytes(),
        qe_identity_issuer_chain: c.qe_identity_issuer_chain.clone(),
        qe_identity_body: format!("{{\"enclaveIdentity\":{},\"signature\":\"{}\"}}", c.qe_identity, hex(&c.qe_identity_signature))
            .into_bytes(),
        root_ca_crl: c.root_ca_crl.clone(),
    };
    let rebuilt = answers.into_collateral().unwrap();
    assert_eq!(rebuilt, c);
    assert!(intel_verdict(SAMPLE_QUOTE, &rebuilt, SAMPLE_NOW).is_ok());
}

// ---------- The model key check on the real NEAR AI attestation ----------

fn near_attestation() -> Value {
    serde_json::from_str(NEAR_REPORT).unwrap()
}

fn near_nonce() -> String {
    near_attestation()["request_nonce"].as_str().unwrap().to_string()
}

fn report_of(attestation: Value) -> Value {
    json!({ "model_attestations": [attestation] })
}

/// Stands for Intel's check, which needs collateral this test does not have: accepts only the exact quote of the
/// real report, as a valid Intel signature would, and reports it up to date with fresh collateral.
struct OnlyTheRealQuote(Vec<u8>);

impl IntelQuoteVerifier for OnlyTheRealQuote {
    fn verify(&self, quote: &[u8]) -> Result<IntelVerdict, String> {
        if quote != self.0 {
            return Err("quote signature is invalid".into());
        }
        Ok(IntelVerdict {
            tcb_status: TcbStatus::UpToDate,
            advisory_ids: vec![],
            collateral_issued_at: NEAR_NOW - 3_600,
            report_body: quote[HEADER_LEN..HEADER_LEN + BODY_LEN].to_vec(),
        })
    }
}

/// 2026-11-13T00:00:00Z.
const NEAR_NOW: u64 = 1_794_528_000;

fn near_now() -> u64 {
    NEAR_NOW
}

fn near_verifier() -> AttestedModelKey<OnlyTheRealQuote> {
    let quote = unhex(near_attestation()["intel_quote"].as_str().unwrap());
    AttestedModelKey::new(OnlyTheRealQuote(quote), near_ai_policy()).with_clock(near_now)
}

#[test]
fn the_real_attestation_gives_the_key_its_quote_binds() {
    let key = near_verifier().model_key(&report_of(near_attestation()), &near_nonce()).unwrap();
    let a = near_attestation();
    assert_eq!(hex(&key), a["signing_public_key"].as_str().unwrap());
    // What the quote binds: report_data = signing address (here the ed25519 public key itself) || our nonce.
    let quote = unhex(a["intel_quote"].as_str().unwrap());
    assert_eq!(quote[REPORT_DATA..REPORT_DATA + 32], key);
    assert_eq!(hex(&quote[REPORT_DATA + 32..REPORT_DATA + 64]), near_nonce());
}

#[test]
fn another_valid_key_in_the_report_is_refused() {
    let other = hex(SigningKey::generate(&mut OsRng).verifying_key().as_bytes());
    let mut a = near_attestation();
    a["signing_public_key"] = Value::String(other.clone());
    let error = near_verifier().model_key(&report_of(a), &near_nonce()).unwrap_err();
    assert!(error.contains("differ"), "{error}");

    // The relay also rewrites the address: the quote still binds the real key.
    let mut a = near_attestation();
    a["signing_public_key"] = Value::String(other.clone());
    a["signing_address"] = Value::String(other);
    let error = near_verifier().model_key(&report_of(a), &near_nonce()).unwrap_err();
    assert!(error.contains("does not bind this signing key"), "{error}");
}

#[test]
fn a_changed_quote_byte_is_refused() {
    for offset in [HEADER_LEN + 136, REPORT_DATA, REPORT_DATA + 40, 1000] {
        let a = near_attestation();
        let mut quote = unhex(a["intel_quote"].as_str().unwrap());
        quote[offset] ^= 1;
        let mut a = a;
        a["intel_quote"] = Value::String(hex(&quote));
        let error = near_verifier().model_key(&report_of(a), &near_nonce()).unwrap_err();
        assert!(error.contains("Intel signature check"), "byte {offset}: {error}");
    }
}

#[test]
fn another_nonce_is_refused() {
    let ours = "33".repeat(32);
    let error = near_verifier().model_key(&report_of(near_attestation()), &ours).unwrap_err();
    assert!(error.contains("nonce"), "{error}");

    // The relay relabels the old attestation with our nonce: the quote still binds the old one.
    let mut a = near_attestation();
    a["request_nonce"] = Value::String(ours.clone());
    let error = near_verifier().model_key(&report_of(a), &ours).unwrap_err();
    assert!(error.contains("our nonce"), "{error}");
}

#[test]
fn a_status_outside_the_policy_is_refused_with_its_advisories() {
    struct OutOfDate(Vec<u8>);
    impl IntelQuoteVerifier for OutOfDate {
        fn verify(&self, quote: &[u8]) -> Result<IntelVerdict, String> {
            let mut v = OnlyTheRealQuote(self.0.clone()).verify(quote)?;
            v.tcb_status = TcbStatus::OutOfDate;
            v.advisory_ids = vec!["INTEL-SA-00000".into()];
            Ok(v)
        }
    }
    let quote = unhex(near_attestation()["intel_quote"].as_str().unwrap());
    let mut verifier = AttestedModelKey::new(OutOfDate(quote), near_ai_policy()).with_clock(near_now);
    let error = verifier.model_key(&report_of(near_attestation()), &near_nonce()).unwrap_err();
    assert!(error.contains("OutOfDate") && error.contains("INTEL-SA-00000"), "{error}");
}

/// A relay that answers every attestation request with the real report relabelled with our nonce and its own key,
/// to read the prompt. Records whether a chat was sent.
struct KeySwappingRelay {
    chats: u32,
}

impl Transport for KeySwappingRelay {
    fn get(&mut self, path: &str, _: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        let nonce = path.rsplit("nonce=").next().unwrap_or_default();
        let own = hex(SigningKey::generate(&mut OsRng).verifying_key().as_bytes());
        let mut a = near_attestation();
        a["request_nonce"] = Value::String(nonce.to_string());
        a["signing_public_key"] = Value::String(own.clone());
        a["signing_address"] = Value::String(own);
        Ok((200, report_of(a).to_string().into_bytes()))
    }

    fn post(&mut self, _: &str, _: &[(String, String)], _: &[u8]) -> Result<(u16, Vec<u8>), String> {
        self.chats += 1;
        Err("not expected".into())
    }
}

#[test]
fn the_client_sends_nothing_to_a_key_swapping_relay() {
    let mut relay = KeySwappingRelay { chats: 0 };
    let mut client = E2eeClient::new(&mut relay, near_verifier(), "test/model", 100, 1000);
    let error = client.chat("confidential case file").unwrap_err();
    assert!(error.contains("model attestation refused"), "{error}");
    assert_eq!(client.tokens_spent(), 0);
    assert_eq!(relay.chats, 0, "the prompt never left");
}

/// Runs the real check, Intel included, on the NEAR AI report: collateral from Intel's PCS (through Tor when
/// `ONA_TOR_SOCKS` is set), judged now. Not run on 13/11/2026: Intel's host could not be reached from the development machine.
#[test]
#[ignore = "needs the network: fetches Intel's collateral from api.trustedservices.intel.com"]
fn the_real_near_ai_quote_passes_with_live_collateral() {
    let network = Network::from_env().unwrap();
    let mut verifier = AttestedModelKey::new(DcapVerifier::new(IntelPcs::new(network)), near_ai_policy());
    let key = verifier.model_key(&report_of(near_attestation()), &near_nonce()).unwrap();
    assert_eq!(hex(&key), near_attestation()["signing_public_key"].as_str().unwrap());
}
