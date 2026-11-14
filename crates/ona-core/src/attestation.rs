//! The real model key check of the encrypted NEAR AI client: Intel's signature over the TDX quote,
//! with `dcap-qvl`, then the checks of `quote`.
//!
//! `near_ai_verifier` builds it. For each attestation it:
//! 1. takes Intel's collateral (PCK CRL, Intel root CA CRL, TCB info, QE identity) for the quote's
//!    platform from Intel's Provisioning Certification Service, `api.trustedservices.intel.com`, and
//!    the root CA CRL from `certificates.trustedservices.intel.com` (the address written in Intel's
//!    root certificate). These requests leave through the client's `Network`: through Tor when
//!    `ONA_TOR_SOCKS` is set, each on its own circuit. The relay is not involved. Collateral is kept
//!    for `COLLATERAL_REUSE_SECS` and fetched again after that;
//! 2. verifies with `dcap-qvl` the quote's signature chain up to Intel's root certificate (built into
//!    `dcap-qvl`), the collateral's signatures and validity dates, the CRLs, and the TCB level;
//! 3. runs `quote::verify_model_attestation` with `near_ai_policy`.
//!
//! Every network call can fail: the key is then refused and nothing is sent to the model.
//! Fetching from Intel's service could not be tried while writing this (13/11/2026): Intel's host
//! could not be reached from the development machine. The fetch code follows `dcap-qvl`'s own client
//! (version 0.7.1).

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use dcap_qvl::quote::{Quote, Report, TDReport10};
use dcap_qvl::verify::QuoteVerifier;
use dcap_qvl::QuoteCollateralV3;
use serde_json::Value;

use crate::e2ee::{attestation_for_nonce, ModelKeyVerifier, Transport};
use crate::quote::{
    observed_2026_11_10, observed_compose_2026_11_10, verify_model_attestation, IntelQuoteVerifier, IntelVerdict,
    Measurements, Policy, TcbStatus,
};
use crate::tor::Network;

/// Intel's Provisioning Certification Service.
pub const INTEL_PCS: &str = "https://api.trustedservices.intel.com";
/// Where Intel's root CA certificate says its CRL is published.
pub const INTEL_ROOT_CRL_HOST: &str = "https://certificates.trustedservices.intel.com";
const INTEL_ROOT_CRL_PATH: &str = "/IntelSGXRootCA.der";
/// Collateral fetched less than this long ago is used again instead of asking Intel each time.
pub const COLLATERAL_REUSE_SECS: u64 = 3_600;
/// Oldest TCB info or QE identity accepted. Intel dates both and gives them a validity of 30 days
/// (`nextUpdate`) in the collateral samples shipped with `dcap-qvl` 0.7.1; `dcap-qvl` also refuses
/// anything past its `nextUpdate`.
pub const MAX_COLLATERAL_AGE_SECS: u64 = 30 * 86_400;
/// Certification data type of a quote that carries its own PCK certificate chain.
const PCK_CERT_CHAIN_IN_QUOTE: u16 = 5;

/// The TCB statuses the client accepts.
///
/// - `UpToDate`: the platform is at Intel's latest TCB level.
/// - `SwHardeningNeeded`: the platform is at the latest level too; Intel lists advisories whose
///   mitigation is software inside the enclave, which Intel's collateral cannot see either way.
///   The advisory ids are kept in the verdict. Refusing it would refuse current platforms.
///
/// Refused: anything that says the platform itself needs a configuration change or an update
/// (`ConfigurationNeeded`, `ConfigurationAndSwHardeningNeeded`, `OutOfDate`,
/// `OutOfDateConfigurationNeeded`), `Revoked`, and any status not named here.
pub fn accepted_tcb_statuses() -> Vec<TcbStatus> {
    vec![TcbStatus::UpToDate, TcbStatus::SwHardeningNeeded]
}

/// The current time in Unix seconds.
pub fn system_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn tcb_status(name: &str) -> TcbStatus {
    match name {
        "UpToDate" => TcbStatus::UpToDate,
        "SWHardeningNeeded" => TcbStatus::SwHardeningNeeded,
        "ConfigurationNeeded" => TcbStatus::ConfigurationNeeded,
        "ConfigurationAndSWHardeningNeeded" => TcbStatus::ConfigurationAndSwHardeningNeeded,
        "OutOfDate" => TcbStatus::OutOfDate,
        "OutOfDateConfigurationNeeded" => TcbStatus::OutOfDateConfigurationNeeded,
        "Revoked" => TcbStatus::Revoked,
        other => TcbStatus::Other(other.to_string()),
    }
}

/// `YYYY-MM-DDTHH:MM:SS` followed by optional fractions and `Z`, as Intel writes its dates.
fn parse_utc(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let rest = &text[19..];
    let rest = rest.strip_prefix('.').map_or(rest, |f| f.trim_start_matches(|c: char| c.is_ascii_digit()));
    if rest != "Z" {
        return None;
    }
    let num = |range: std::ops::Range<usize>| text.get(range)?.parse::<u64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, min, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || min > 59 || s > 60 || y < 1970 {
        return None;
    }
    // Days from the civil date (H. Hinnant's algorithm), March-based year.
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3_600 + min * 60 + s)
}

fn issue_date(signed_json: &str, what: &str) -> Result<u64, String> {
    let value: Value = serde_json::from_str(signed_json).map_err(|_| format!("Intel {what} is not JSON"))?;
    value["issueDate"].as_str().and_then(parse_utc).ok_or_else(|| format!("Intel {what} has no readable issueDate"))
}

fn td_report_body(report: &TDReport10) -> Vec<u8> {
    let mut body = Vec::with_capacity(584);
    for part in [
        &report.tee_tcb_svn[..],
        &report.mr_seam,
        &report.mr_signer_seam,
        &report.seam_attributes,
        &report.td_attributes,
        &report.xfam,
        &report.mr_td,
        &report.mr_config_id,
        &report.mr_owner,
        &report.mr_owner_config,
        &report.rt_mr0,
        &report.rt_mr1,
        &report.rt_mr2,
        &report.rt_mr3,
        &report.report_data,
    ] {
        body.extend_from_slice(part);
    }
    body
}

/// Verifies `quote` with `collateral` at `now_unix` against Intel's production root certificate,
/// and returns what `quote::Policy` judges. A TDX 1.0 quote (version 4) only.
pub fn intel_verdict(quote: &[u8], collateral: &QuoteCollateralV3, now_unix: u64) -> Result<IntelVerdict, String> {
    let verified = QuoteVerifier::new_prod().verify(quote, collateral, now_unix).map_err(|e| format!("{e:#}"))?;
    let report_body = match &verified.report {
        Report::TD10(report) => td_report_body(report),
        _ => return Err("not a TDX 1.0 quote".into()),
    };
    let issued_at = issue_date(&collateral.tcb_info, "TCB info")?.min(issue_date(&collateral.qe_identity, "QE identity")?);
    Ok(IntelVerdict {
        tcb_status: tcb_status(&verified.status),
        advisory_ids: verified.advisory_ids,
        collateral_issued_at: issued_at,
        report_body,
    })
}

/// Gives Intel's collateral for a quote.
pub trait CollateralSource {
    fn collateral(&self, quote: &[u8]) -> Result<QuoteCollateralV3, String>;
}

/// Collateral obtained earlier, for example saved next to a test report. Every signature in it is
/// still checked, and so are its dates.
pub struct SavedCollateral(pub QuoteCollateralV3);

impl CollateralSource for SavedCollateral {
    fn collateral(&self, _quote: &[u8]) -> Result<QuoteCollateralV3, String> {
        Ok(self.0.clone())
    }
}

/// Decodes `%XX` escapes: Intel URL-encodes the certificate chains it puts in headers.
fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3).ok_or("bad escape in an Intel header")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad escape in an Intel header")?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "an Intel header is not text".into())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Splits Intel's `{"<key>":{...},"signature":"<hex>"}` into the signed JSON, byte for byte as Intel
/// sent it, and the signature. Anything else is refused: the signature covers the exact bytes.
pub fn split_signed_body(body: &[u8], key: &str) -> Result<(String, Vec<u8>), String> {
    let text = std::str::from_utf8(body).map_err(|_| format!("Intel {key} answer is not text"))?.trim();
    let prefix = format!("{{\"{key}\":");
    const SIGNATURE: &str = ",\"signature\":\"";
    let start = text.strip_prefix(&prefix).ok_or_else(|| format!("Intel {key} answer has an unexpected layout"))?;
    let split = start.rfind(SIGNATURE).ok_or_else(|| format!("Intel {key} answer has no signature"))?;
    let signature = start[split + SIGNATURE.len()..]
        .strip_suffix("\"}")
        .and_then(decode_hex)
        .ok_or_else(|| format!("Intel {key} signature is not hex"))?;
    Ok((start[..split].to_string(), signature))
}

/// Builds the collateral from Intel's answers, as received. Used by `IntelPcs` and by tests on
/// answers saved earlier.
pub struct PcsAnswers {
    pub pck_crl_issuer_chain: String,
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info_body: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity_body: Vec<u8>,
    pub root_ca_crl: Vec<u8>,
}

impl PcsAnswers {
    pub fn into_collateral(self) -> Result<QuoteCollateralV3, String> {
        let (tcb_info, tcb_info_signature) = split_signed_body(&self.tcb_info_body, "tcbInfo")?;
        let (qe_identity, qe_identity_signature) = split_signed_body(&self.qe_identity_body, "enclaveIdentity")?;
        Ok(QuoteCollateralV3 {
            pck_crl_issuer_chain: self.pck_crl_issuer_chain,
            root_ca_crl: self.root_ca_crl,
            pck_crl: self.pck_crl,
            tcb_info_issuer_chain: self.tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain: self.qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
            // The quote carries its PCK chain (checked in `IntelPcs::collateral`): dcap-qvl uses it.
            pck_certificate_chain: None,
        })
    }
}

/// Fetches collateral from Intel's PCS through `network` (Tor when configured).
pub struct IntelPcs {
    network: Network,
    clock: fn() -> u64,
    /// FMSPC and CA of the platform, when it was fetched, and the collateral.
    cache: Mutex<Option<(String, u64, QuoteCollateralV3)>>,
}

impl IntelPcs {
    pub fn new(network: Network) -> Self {
        Self { network, clock: system_now, cache: Mutex::new(None) }
    }

    /// GETs `base` + `path` and returns the body and the first of the `chain_headers` present,
    /// URL-decoded (none asked: empty).
    fn get(&self, base: &str, path: &str, chain_headers: &[&str]) -> Result<(Vec<u8>, String), String> {
        let mut transport = self.network.transport(base)?;
        let (status, body, found) = transport
            .get_with_headers(path, &[], chain_headers)
            .map_err(|e| format!("Intel collateral request to {base} failed: {e}"))?;
        if status != 200 {
            return Err(format!("Intel collateral request to {base} failed with status {status}"));
        }
        if chain_headers.is_empty() {
            return Ok((body, String::new()));
        }
        let chain = found
            .into_iter()
            .flatten()
            .next()
            .ok_or_else(|| format!("Intel answer has no {} header", chain_headers.join(" or ")))?;
        Ok((body, percent_decode(&chain)?))
    }

    fn fetch(&self, fmspc: &str, ca: &str) -> Result<QuoteCollateralV3, String> {
        let (pck_crl, pck_crl_issuer_chain) =
            self.get(INTEL_PCS, &format!("/sgx/certification/v4/pckcrl?ca={ca}&encoding=der"), &["SGX-PCK-CRL-Issuer-Chain"])?;
        let (tcb_info_body, tcb_info_issuer_chain) = self.get(
            INTEL_PCS,
            &format!("/tdx/certification/v4/tcb?fmspc={fmspc}&update=standard"),
            &["TCB-Info-Issuer-Chain", "SGX-TCB-Info-Issuer-Chain"],
        )?;
        let (qe_identity_body, qe_identity_issuer_chain) = self.get(
            INTEL_PCS,
            "/tdx/certification/v4/qe/identity?update=standard",
            &["SGX-Enclave-Identity-Issuer-Chain"],
        )?;
        let (root_ca_crl, _) = self.get(INTEL_ROOT_CRL_HOST, INTEL_ROOT_CRL_PATH, &[])?;
        PcsAnswers {
            pck_crl_issuer_chain,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info_body,
            qe_identity_issuer_chain,
            qe_identity_body,
            root_ca_crl,
        }
        .into_collateral()
    }
}

impl CollateralSource for IntelPcs {
    fn collateral(&self, quote: &[u8]) -> Result<QuoteCollateralV3, String> {
        let parsed = Quote::parse(quote).map_err(|e| format!("quote cannot be parsed: {e}"))?;
        if parsed.header.is_sgx() {
            return Err("not a TDX quote".into());
        }
        if parsed.inner_cert_type() != PCK_CERT_CHAIN_IN_QUOTE {
            return Err("quote does not carry its PCK certificate chain".into());
        }
        let fmspc = dcap_qvl::intel::quote_fmspc(&parsed).map_err(|e| format!("quote has no readable FMSPC: {e}"))?;
        let fmspc: String = fmspc.iter().map(|b| format!("{b:02X}")).collect();
        let ca = dcap_qvl::intel::quote_ca(&parsed).map_err(|e| format!("quote has no readable PCK CA: {e}"))?.as_id_str();
        let key = format!("{fmspc}/{ca}");
        let now = (self.clock)();
        let mut cache = self.cache.lock().map_err(|_| "collateral cache is poisoned")?;
        if let Some((cached_key, fetched_at, collateral)) = cache.as_ref() {
            if *cached_key == key && now.saturating_sub(*fetched_at) < COLLATERAL_REUSE_SECS {
                return Ok(collateral.clone());
            }
        }
        let collateral = self.fetch(&fmspc, ca)?;
        *cache = Some((key, now, collateral.clone()));
        Ok(collateral)
    }
}

/// Intel's check of a quote with `dcap-qvl`, with the collateral from `source`, judged at `clock()`.
pub struct DcapVerifier<C> {
    source: C,
    clock: fn() -> u64,
}

impl<C: CollateralSource> DcapVerifier<C> {
    pub fn new(source: C) -> Self {
        Self { source, clock: system_now }
    }

    /// Judges the collateral's dates at the time `clock` gives instead of now. For tests on saved collateral.
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }
}

impl<C: CollateralSource> IntelQuoteVerifier for DcapVerifier<C> {
    fn verify(&self, quote: &[u8]) -> Result<IntelVerdict, String> {
        let collateral = self.source.collateral(quote)?;
        intel_verdict(quote, &collateral, (self.clock)())
    }
}

/// What the client accepts: see `accepted_tcb_statuses`, `MAX_COLLATERAL_AGE_SECS`, and the
/// observed system and deployment of `quote::observed_2026_11_10`.
pub struct OwnedPolicy {
    pub systems: Vec<Measurements>,
    pub compose_hashes: Vec<[u8; 32]>,
    pub accepted_tcb: Vec<TcbStatus>,
    pub max_collateral_age_secs: u64,
}

pub fn near_ai_policy() -> OwnedPolicy {
    OwnedPolicy {
        systems: vec![observed_2026_11_10()],
        compose_hashes: std::iter::once(observed_compose_2026_11_10()).chain(crate::quote::observed_composes_2026_11_14()).collect(),
        accepted_tcb: accepted_tcb_statuses(),
        max_collateral_age_secs: MAX_COLLATERAL_AGE_SECS,
    }
}

/// A model key check: the attestation answering our nonce must pass `verify_model_attestation`
/// with this Intel verifier and policy.
pub struct AttestedModelKey<I> {
    intel: I,
    policy: OwnedPolicy,
    clock: fn() -> u64,
}

impl<I: IntelQuoteVerifier> AttestedModelKey<I> {
    pub fn new(intel: I, policy: OwnedPolicy) -> Self {
        Self { intel, policy, clock: system_now }
    }

    /// Judges the collateral age at the time `clock` gives instead of now. For tests on saved collateral.
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }
}

impl<I: IntelQuoteVerifier> ModelKeyVerifier for AttestedModelKey<I> {
    fn model_key(&mut self, report: &Value, nonce: &str) -> Result<[u8; 32], String> {
        let attestation = attestation_for_nonce(report, nonce)?;
        let policy = Policy {
            systems: &self.policy.systems,
            compose_hashes: &self.policy.compose_hashes,
            accepted_tcb: &self.policy.accepted_tcb,
            max_collateral_age_secs: self.policy.max_collateral_age_secs,
            now_unix: (self.clock)(),
        };
        verify_model_attestation(attestation, nonce, &policy, &self.intel)
            .map_err(|e| format!("model attestation refused, nothing was sent: {e}"))
    }
}

/// The client's model key check: Intel collateral from Intel's PCS through `network`, `dcap-qvl`,
/// and `near_ai_policy`.
pub fn near_ai_verifier(network: &Network) -> AttestedModelKey<DcapVerifier<IntelPcs>> {
    AttestedModelKey::new(DcapVerifier::new(IntelPcs::new(network.clone())), near_ai_policy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intel_dates_are_read_as_utc() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc("2025-06-19T10:16:03Z"), Some(1_750_328_163));
        assert_eq!(parse_utc("2026-11-13T00:00:00.123Z"), Some(1_794_528_000));
        for bad in ["2026-11-13T00:00:00", "2026-13-01T00:00:00Z", "2026-11-13 00:00:00Z", "", "2026-11-13T00:00:00+01:00"] {
            assert_eq!(parse_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn header_chains_are_url_decoded() {
        assert_eq!(percent_decode("-----BEGIN%20CERTIFICATE-----%0A").unwrap(), "-----BEGIN CERTIFICATE-----\n");
        assert!(percent_decode("%4").is_err());
        assert!(percent_decode("%zz").is_err());
    }

    #[test]
    fn the_signed_json_is_kept_byte_for_byte() {
        let body = br#"{"tcbInfo":{"b":1,"a":[2]},"signature":"0aff"}"#;
        let (json, signature) = split_signed_body(body, "tcbInfo").unwrap();
        assert_eq!(json, r#"{"b":1,"a":[2]}"#);
        assert_eq!(signature, vec![0x0a, 0xff]);
        assert!(split_signed_body(br#"{"other":{},"signature":"00"}"#, "tcbInfo").is_err());
        assert!(split_signed_body(br#"{"tcbInfo":{}}"#, "tcbInfo").is_err());
        assert!(split_signed_body(br#"{"tcbInfo":{},"signature":"zz"}"#, "tcbInfo").is_err());
    }

    #[test]
    fn only_the_two_justified_statuses_are_accepted() {
        let accepted = accepted_tcb_statuses();
        for name in ["UpToDate", "SWHardeningNeeded"] {
            assert!(accepted.contains(&tcb_status(name)), "{name}");
        }
        for name in [
            "ConfigurationNeeded",
            "ConfigurationAndSWHardeningNeeded",
            "OutOfDate",
            "OutOfDateConfigurationNeeded",
            "Revoked",
            "TDRelaunchAdvised",
            "Something",
        ] {
            assert!(!accepted.contains(&tcb_status(name)), "{name}");
        }
    }
}
