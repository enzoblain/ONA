//! Checks a NEAR AI model attestation before its key is trusted.
//!
//! `verify_model_attestation` accepts a quote only if:
//! - the `IntelQuoteVerifier` verified its signature chain up to Intel's root with Intel's collateral
//!   (`attestation::DcapVerifier`, built on `dcap-qvl`), the TCB status it found is one the caller
//!   accepts, and its collateral is not older than the caller allows. The report fields below are read
//!   from the body the verifier returns, and that body must be the quote's own;
//! - the system measurements (MRTD, RTMR0 to RTMR2) are on the caller's list;
//! - the event log replays to the quote's RTMR3, and its `os-image-hash` and `compose-hash` events
//!   name a listed OS image and the hash of the reported `app_compose`;
//! - `report_data` is `signing_address || nonce`, and `mr_config_id` is `0x01 || compose hash ||
//!   zeros`. On the real report of 2026-11-10 the signing address is the ed25519 public key itself;
//!   the check requires the two fields to be equal, so the key used to encrypt is the one bound;
//! - the enclave is not in debug mode.
//!
//! The accepted measurements are values observed on one real report, not references published by
//! NEAR AI: another machine or a new image is refused until its values are added.
//!
//! **The GPU evidence is not bound to the TDX quote.** Its nonce only shows it is fresh. A relay can
//! copy a genuine payload from another machine next to its own quote, so NVIDIA's verdict says nothing
//! about the machine that holds the model key. `check_gpu_evidence` is therefore separate, and the
//! client does not call it: NVIDIA's service is not contacted.
//!
//! Formats were checked on one real report (2026-11-10) that NEAR AI's official verifier accepted.
//! The verifier's source could not be read while writing this. RTMR3 events carry no digest in the
//! log: each is `sha384(event_type as u32 little-endian || ":" || event || ":" || payload)`, and with
//! that the log replays to the quote's RTMR3 exactly.

use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};

const TDX_QUOTE_VERSION: u16 = 4;
const TEE_TYPE_TDX: [u8; 4] = [0x81, 0, 0, 0];
const HEADER_LEN: usize = 48;
const BODY_LEN: usize = 584;
const TD_ATTRIBUTES: usize = 120;
const MRTD: usize = 136;
const MR_CONFIG_ID: usize = 184;
const RTMR0: usize = 328;
const REPORT_DATA: usize = 520;
const MR_CONFIG_TAG: u8 = 0x01;
const COMPOSE_EVENT: &str = "compose-hash";
const OS_IMAGE_EVENT: &str = "os-image-hash";

/// The TCB levels an Intel verifier reports, named as in Intel's DCAP documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcbStatus {
    UpToDate,
    SwHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSwHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
    /// Any other value, kept as written by the verifier. Never accepted unless listed.
    Other(String),
}

/// What a full Intel verification returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntelVerdict {
    pub tcb_status: TcbStatus,
    /// Intel security advisory ids that apply to this platform, as reported.
    pub advisory_ids: Vec<String>,
    /// When the collateral used (TCB info, QE identity) was issued, in Unix seconds.
    pub collateral_issued_at: u64,
    /// The TD report body (584 bytes) the verifier checked the signature over.
    pub report_body: Vec<u8>,
}

/// Verifies a TDX quote's signature chain up to Intel's root, with Intel's collateral, and returns
/// what it found. Must return `Ok` only for a quote whose signature chain it fully verified; the
/// TCB status and the collateral date are then judged by `Policy`. Implemented with `dcap-qvl` by
/// `attestation::DcapVerifier`.
pub trait IntelQuoteVerifier {
    fn verify(&self, quote: &[u8]) -> Result<IntelVerdict, String>;
}

/// Sends the GPU evidence to NVIDIA's attestation service (NRAS). Must return `Ok` only when the
/// overall verdict is a pass.
pub trait NvidiaVerifier {
    fn verify(&self, payload: &str) -> Result<(), String>;
}

/// One accepted system image: firmware and kernel (MRTD, RTMR0 to RTMR2) and the image's hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurements {
    pub mrtd: [u8; 48],
    pub rtmr: [[u8; 48]; 3],
    pub os_image_hash: [u8; 32],
}

/// What the caller trusts. Empty lists refuse everything.
pub struct Policy<'a> {
    pub systems: &'a [Measurements],
    pub compose_hashes: &'a [[u8; 32]],
    /// TCB statuses accepted from the Intel verifier.
    pub accepted_tcb: &'a [TcbStatus],
    /// Oldest collateral accepted, in seconds before `now_unix`.
    pub max_collateral_age_secs: u64,
    /// The time the collateral age is judged at, in Unix seconds.
    pub now_unix: u64,
}

/// Collateral dated more than this after `now_unix` is refused: the clocks disagree too much.
const MAX_CLOCK_SKEW_SECS: u64 = 300;

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    decode_hex(s).and_then(|b| b.try_into().ok()).expect("constant is valid hex of the right length")
}

/// The system seen in the report of 2026-11-10 (`dstack-nvidia-0.5.11`). Observed, not published by
/// NEAR AI as a reference: it changes whenever they update the image.
pub fn observed_2026_11_10() -> Measurements {
    Measurements {
        mrtd: unhex("df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b"),
        rtmr: [
            unhex("bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590"),
            unhex("4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec"),
            unhex("bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71"),
        ],
        os_image_hash: unhex("91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829"),
    }
}

/// The deployment hash seen in the same report. Observed, not a published reference.
pub fn observed_compose_2026_11_10() -> [u8; 32] {
    unhex("a0e3c6f4f21a60ea3f5c96bc7ef319b03a184ca2049605399275fbcea74e8c5f")
}

fn hex32(value: &Value, field: &str) -> Result<[u8; 32], String> {
    value[field]
        .as_str()
        .and_then(decode_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{field} is missing or not 32 bytes of hex"))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// The fields of a TDX version 4 quote that this check reads. Other layouts are refused.
struct TdReport<'a> {
    td_attributes: &'a [u8],
    mrtd: &'a [u8],
    mr_config_id: &'a [u8],
    rtmr: [&'a [u8]; 4],
    report_data: &'a [u8],
}

fn check_quote_header(quote: &[u8]) -> Result<(), String> {
    if quote.len() < HEADER_LEN + BODY_LEN {
        return Err("quote is too short".into());
    }
    if u16::from_le_bytes([quote[0], quote[1]]) != TDX_QUOTE_VERSION || quote[4..8] != TEE_TYPE_TDX {
        return Err("not a TDX version 4 quote".into());
    }
    Ok(())
}

/// Reads the fields from a TD report body, the one the Intel verifier returned.
fn parse_body(body: &[u8]) -> Result<TdReport<'_>, String> {
    if body.len() != BODY_LEN {
        return Err("the verified report body has the wrong length".into());
    }
    let field = |offset: usize, len: usize| &body[offset..offset + len];
    Ok(TdReport {
        td_attributes: field(TD_ATTRIBUTES, 8),
        mrtd: field(MRTD, 48),
        mr_config_id: field(MR_CONFIG_ID, 48),
        rtmr: [0, 1, 2, 3].map(|i| field(RTMR0 + 48 * i, 48)),
        report_data: field(REPORT_DATA, 64),
    })
}

fn app_compose(attestation: &Value) -> Result<String, String> {
    let tcb = &attestation["info"]["tcb_info"];
    let tcb = match tcb.as_str() {
        Some(text) => serde_json::from_str(text).map_err(|_| "tcb_info is not JSON".to_string())?,
        None => tcb.clone(),
    };
    tcb["app_compose"].as_str().map(str::to_string).ok_or_else(|| "app_compose is missing".into())
}

struct RuntimeEvent {
    name: String,
    payload: Vec<u8>,
}

/// Replays the RTMR3 events of the log and returns them. Each digest is recomputed from the event
/// itself; a digest written in the log must agree with it.
fn replay_rtmr3(attestation: &Value, quote_rtmr3: &[u8]) -> Result<Vec<RuntimeEvent>, String> {
    let log = attestation["event_log"].as_array().ok_or("event_log is missing")?;
    let mut rtmr = [0u8; 48];
    let mut events = Vec::new();
    for entry in log {
        let imr = entry["imr"].as_u64().ok_or("event without imr")?;
        if imr != 3 {
            continue;
        }
        let event_type = entry["event_type"].as_u64().and_then(|t| u32::try_from(t).ok()).ok_or("bad event_type")?;
        let name = entry["event"].as_str().ok_or("event without a name")?;
        let payload = entry["event_payload"].as_str().and_then(decode_hex).ok_or("event payload is not hex")?;
        let mut hasher = Sha384::new();
        hasher.update(event_type.to_le_bytes());
        hasher.update(b":");
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(&payload);
        let digest = hasher.finalize();
        match entry["digest"].as_str() {
            Some("") | None => {}
            Some(written) if decode_hex(written).as_deref() == Some(&digest[..]) => {}
            Some(_) => return Err("an event digest does not match its content".into()),
        }
        rtmr = Sha384::new().chain_update(rtmr).chain_update(digest).finalize().into();
        events.push(RuntimeEvent { name: name.to_string(), payload });
    }
    if rtmr[..] != *quote_rtmr3 {
        return Err("event log does not replay to the quote's RTMR3".into());
    }
    Ok(events)
}

/// The payload of the one event with this name. Absent or repeated is a refusal.
fn single_event<'a>(events: &'a [RuntimeEvent], name: &str) -> Result<&'a [u8], String> {
    let mut found = events.iter().filter(|e| e.name == name);
    match (found.next(), found.next()) {
        (Some(event), None) => Ok(&event.payload),
        (None, _) => Err(format!("event log has no {name} event")),
        _ => Err(format!("event log has several {name} events")),
    }
}

/// Returns the model's signing key if every check passes. `nonce` is the one we sent, as 64 hex
/// characters. See the module documentation for what a pass does and does not prove. The GPU
/// evidence is not looked at here: see `check_gpu_evidence`.
pub fn verify_model_attestation(
    attestation: &Value,
    nonce: &str,
    policy: &Policy,
    intel: &dyn IntelQuoteVerifier,
) -> Result<[u8; 32], String> {
    let nonce_bytes: [u8; 32] = decode_hex(nonce)
        .filter(|_| nonce.len() == 64)
        .and_then(|b| b.try_into().ok())
        .ok_or("our nonce must be 32 bytes of hex")?;
    if attestation["request_nonce"].as_str().map(str::to_ascii_lowercase) != Some(nonce.to_ascii_lowercase()) {
        return Err("attestation does not answer our nonce".into());
    }
    if attestation["signing_algo"].as_str() != Some("ed25519") {
        return Err("signing algorithm is not ed25519".into());
    }
    let address = hex32(attestation, "signing_address")?;
    if hex32(attestation, "signing_public_key")? != address {
        return Err("signing key and signing address differ".into());
    }

    let quote = attestation["intel_quote"].as_str().and_then(decode_hex).ok_or("intel_quote is missing or not hex")?;
    let verdict = intel.verify(&quote).map_err(|e| format!("Intel signature check of the quote failed: {e}"))?;
    check_quote_header(&quote)?;
    if !policy.accepted_tcb.contains(&verdict.tcb_status) {
        let advisories =
            if verdict.advisory_ids.is_empty() { "none".to_string() } else { verdict.advisory_ids.join(", ") };
        return Err(format!("TCB status {:?} is not accepted (Intel advisories: {advisories})", verdict.tcb_status));
    }
    if verdict.collateral_issued_at > policy.now_unix.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err("Intel collateral is dated in the future".into());
    }
    if policy.now_unix.saturating_sub(verdict.collateral_issued_at) > policy.max_collateral_age_secs {
        return Err("Intel collateral is too old".into());
    }
    if verdict.report_body[..] != quote[HEADER_LEN..HEADER_LEN + BODY_LEN] {
        return Err("the verifier returned another report than the quote's".into());
    }
    let report = parse_body(&verdict.report_body)?;
    if report.td_attributes[0] & 1 != 0 {
        return Err("enclave runs in debug mode".into());
    }
    if report.report_data[..32] != address || report.report_data[32..] != nonce_bytes {
        return Err("quote does not bind this signing key and our nonce".into());
    }

    let events = replay_rtmr3(attestation, report.rtmr[3])?;
    let os_image = single_event(&events, OS_IMAGE_EVENT)?;
    let system_listed = policy.systems.iter().any(|s| {
        report.mrtd == s.mrtd
            && (0..3).all(|i| report.rtmr[i] == s.rtmr[i])
            && os_image == s.os_image_hash
    });
    if !system_listed {
        return Err("system measurements are not on our list".into());
    }

    let compose: [u8; 32] = Sha256::digest(app_compose(attestation)?.as_bytes()).into();
    if single_event(&events, COMPOSE_EVENT)? != compose {
        return Err("event log does not measure this app_compose".into());
    }
    let mut expected = [0u8; 48];
    expected[0] = MR_CONFIG_TAG;
    expected[1..33].copy_from_slice(&compose);
    if report.mr_config_id != expected {
        return Err("quote does not measure this app_compose".into());
    }
    if !policy.compose_hashes.contains(&compose) {
        return Err("this deployment is not on our list".into());
    }
    Ok(address)
}

/// Checks that the GPU evidence answers our nonce and that NVIDIA's service accepts it. Even when it
/// passes, it does not show that this GPU sits in the machine of the TDX quote: see the module
/// documentation. Not called by the client.
pub fn check_gpu_evidence(attestation: &Value, nonce: &str, nvidia: &dyn NvidiaVerifier) -> Result<(), String> {
    let payload = attestation["nvidia_payload"].as_str().ok_or("nvidia_payload is missing")?;
    let parsed: Value = serde_json::from_str(payload).map_err(|_| "nvidia_payload is not JSON".to_string())?;
    if parsed["nonce"].as_str().map(str::to_ascii_lowercase) != Some(nonce.to_ascii_lowercase()) {
        return Err("GPU evidence does not answer our nonce".into());
    }
    nvidia.verify(payload)
}
