//! The agent's HTTP API, served on `127.0.0.1` only by the relay's strict HTTP front (`ona_server::http`). Every
//! route is `POST` with a JSON body; binary fields are base64, as in the contract's own arguments.
//!
//! | Route | Body | Reply |
//! |---|---|---|
//! | `/issue_cash` | `account`, `notes` (`tier`, `blinded`), `proof` (`public_key` `ed25519:…`, `signature`, `nonce`) | `signatures` |
//! | `/enter`, `/leave` | `vault`, `note` (`tier`, `pk`, `nonce`, `sig`), `owner_sig`, `expires_at`, `outputs` (`tier`, `count`), `blinded` | `signatures` |
//! | `/pay_exit` | `note`, `owner_sig`, `expires_at`, `to` | `paid` |
//! | `/signatures` | `blinded` | `signatures`, `null` where none was made |
//!
//! 200 is done, 202 means sent or waiting for the chain (ask again with the same body), 4xx is a certain refusal,
//! 503 the chain or the storage is unavailable. Each route has its own limit per minute, for all clients together:
//! the agent is reached through an onion service or a local front, so it cannot tell clients apart.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use crate::chain::PoolChain;
use crate::nep413;
use crate::service::{parse_note, Agent, IssueRequest, Kind, NoteRequest, PayRequest, Proof, Reply};
use crate::store::Store;

/// Requests per minute per route, for all clients together.
pub const DEFAULT_PER_MINUTE: u32 = 120;
const ROUTES: [&str; 5] = ["/issue_cash", "/enter", "/leave", "/pay_exit", "/signatures"];
const MAX_POINTS: usize = 512;

struct Window {
    start: Option<Instant>,
    count: u32,
}

/// Counts calls per route in fixed one-minute windows.
pub struct Limits {
    windows: Mutex<Vec<Window>>,
    per_minute: u32,
}

impl Limits {
    pub fn new(per_minute: u32) -> Self {
        Self { windows: Mutex::new(ROUTES.iter().map(|_| Window { start: None, count: 0 }).collect()), per_minute }
    }

    fn allow(&self, route: usize, now: Instant) -> bool {
        let Ok(mut windows) = self.windows.lock() else {
            return false;
        };
        let w = &mut windows[route];
        if w.start.is_none_or(|s| now.duration_since(s) >= Duration::from_secs(60)) {
            *w = Window { start: Some(now), count: 0 };
        }
        if w.count >= self.per_minute {
            return false;
        }
        w.count += 1;
        true
    }
}

fn error(status: u16, message: &str) -> (u16, Value) {
    (status, json!({"error": message}))
}

fn bytes<const N: usize>(v: &Value) -> Option<[u8; N]> {
    v.as_str().and_then(|s| B64.decode(s).ok()).and_then(|b| b.try_into().ok())
}

fn points(v: &Value) -> Option<Vec<[u8; 48]>> {
    let list = v.as_array()?;
    if list.len() > MAX_POINTS {
        return None;
    }
    list.iter().map(bytes::<48>).collect()
}

fn outputs(v: &Value) -> Option<Vec<(u8, u64)>> {
    v.as_array()?.iter().map(|o| Some((u8::try_from(o["tier"].as_u64()?).ok()?, o["count"].as_u64()?))).collect()
}

pub fn parse_issue(v: &Value) -> Option<IssueRequest> {
    let mut notes = Vec::new();
    for group in v["notes"].as_array()? {
        let tier = u8::try_from(group["tier"].as_u64()?).ok()?;
        for b in points(&group["blinded"])? {
            notes.push((tier, b));
        }
    }
    let proof = &v["proof"];
    Some(IssueRequest {
        account: v["account"].as_str()?.to_string(),
        notes,
        proof: Proof {
            public_key: nep413::parse_public_key(proof["public_key"].as_str()?).ok()?,
            signature: bytes(&proof["signature"])?,
            nonce: bytes(&proof["nonce"])?,
        },
    })
}

pub fn parse_note_request(kind: Kind, v: &Value) -> Option<NoteRequest> {
    Some(NoteRequest {
        kind,
        vault: u32::try_from(v["vault"].as_u64()?).ok()?,
        note: parse_note(&v["note"])?,
        owner_sig: bytes(&v["owner_sig"])?,
        outputs: outputs(&v["outputs"])?,
        blinded: points(&v["blinded"])?,
        expires_at: v["expires_at"].as_u64()?,
    })
}

pub fn parse_pay(v: &Value) -> Option<PayRequest> {
    Some(PayRequest {
        note: parse_note(&v["note"])?,
        owner_sig: bytes(&v["owner_sig"])?,
        to: v["to"].as_str()?.to_string(),
        expires_at: v["expires_at"].as_u64()?,
    })
}

fn reply(r: Reply) -> (u16, Value) {
    match r {
        Reply::Signed(sigs) => (200, json!({"signatures": sigs.iter().map(|s| B64.encode(s)).collect::<Vec<_>>()})),
        Reply::Paid => (200, json!({"paid": true})),
        Reply::Pending(why) => (202, json!({"pending": why})),
        Reply::Refused(status, why) => error(status, &why),
    }
}

/// Answers one request. The agent's state is locked for the whole request, chain calls included: requests are
/// served one at a time.
pub fn handle<C: PoolChain, S: Store>(agent: &Mutex<Agent<C, S>>, limits: &Limits, method: &str, target: &str, body: &[u8]) -> (u16, Value) {
    let Some(route) = ROUTES.iter().position(|r| *r == target) else {
        return error(404, "not found");
    };
    if method != "POST" {
        return error(405, "only POST is accepted");
    }
    if !limits.allow(route, Instant::now()) {
        return error(429, "too many requests");
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return error(400, "body is not JSON");
    };
    let Ok(mut agent) = agent.lock() else {
        return error(503, "agent unavailable: restart it");
    };
    let malformed = || error(400, "malformed request");
    match target {
        "/issue_cash" => parse_issue(&value).map_or_else(malformed, |r| reply(agent.issue(&r))),
        "/enter" => parse_note_request(Kind::Enter, &value).map_or_else(malformed, |r| reply(agent.note_request(&r))),
        "/leave" => parse_note_request(Kind::Leave, &value).map_or_else(malformed, |r| reply(agent.note_request(&r))),
        "/pay_exit" => parse_pay(&value).map_or_else(malformed, |r| reply(agent.pay(&r))),
        _ => match points(&value["blinded"]) {
            Some(blinded) => {
                let sigs: Vec<Value> = agent.signatures(&blinded).iter().map(|s| s.map_or(Value::Null, |s| json!(B64.encode(s)))).collect();
                (200, json!({"signatures": sigs}))
            }
            None => malformed(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_route_has_its_own_limit() {
        let limits = Limits::new(2);
        let now = Instant::now();
        assert!(limits.allow(0, now) && limits.allow(0, now));
        assert!(!limits.allow(0, now));
        assert!(limits.allow(1, now), "another route is not affected");
        assert!(limits.allow(0, now + Duration::from_secs(60)));
    }

    #[test]
    fn requests_are_parsed_strictly() {
        let p = B64.encode([1u8; 48]);
        let note = json!({"tier": 0, "pk": B64.encode([2u8; 32]), "nonce": B64.encode([3u8; 32]), "sig": p});
        let enter = json!({"vault": 1, "note": note, "owner_sig": B64.encode([4u8; 64]), "expires_at": 9,
                           "outputs": [{"tier": 0, "count": 1}], "blinded": [p]});
        assert!(parse_note_request(Kind::Enter, &enter).is_some());
        let mut short = enter.clone();
        short["owner_sig"] = json!(B64.encode([4u8; 63]));
        assert!(parse_note_request(Kind::Enter, &short).is_none());
        let mut big = enter;
        big["vault"] = json!(u64::MAX);
        assert!(parse_note_request(Kind::Enter, &big).is_none());
        assert!(parse_pay(&json!({"note": note, "owner_sig": B64.encode([4u8; 64]), "to": "a.test"})).is_none(), "expires_at is required");
        let issue = json!({"account": "a.test", "notes": [{"tier": 0, "blinded": [p]}],
                           "proof": {"public_key": "ed25519:11111111111111111111111111111111", "signature": B64.encode([0u8; 64]), "nonce": B64.encode([0u8; 32])}});
        assert_eq!(parse_issue(&issue).unwrap().notes.len(), 1);
    }
}
