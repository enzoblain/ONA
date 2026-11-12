//! `HttpAgent`: the client's side of `ona-agent`'s HTTP API (see `crates/ona-agent/src/api.rs`). Every operation opens
//! a new transport, so no connection is kept from one operation to the next (a cash issue and the entry that follows
//! do not share one). `HttpAgent::to_url` uses `HttpTransport` (no redirect, no proxy from the environment, no
//! `User-Agent`). `HttpAgent::through` takes the client's `tor::Network`: through Tor every request draws new SOCKS
//! credentials, so Tor (`IsolateSOCKSAuth`, its default) keeps each operation on its own circuit.
//!
//! 200 is done; 202 (queued, sent or waiting for the chain), a transport failure and any 5xx are "outcome unknown";
//! any other status is a certain refusal.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_token::G1_LEN;
use serde_json::{json, Value};

use crate::e2ee::{HttpTransport, Transport};
use crate::pool::{AgentError, DepositorProof, PoolAgent, SignedNote};
use crate::tor::Network;

type Connect = Box<dyn FnMut() -> Result<Box<dyn Transport>, String>>;

pub struct HttpAgent {
    connect: Connect,
}

impl HttpAgent {
    /// `connect` makes a new transport for each operation.
    pub fn new(connect: impl FnMut() -> Result<Box<dyn Transport>, String> + 'static) -> Self {
        Self { connect: Box::new(connect) }
    }

    /// Plain HTTPS (or HTTP to this machine) to `url`, a new connection per operation. A final `/` is ignored.
    pub fn to_url(url: &str) -> Self {
        let url = url.trim_end_matches('/').to_string();
        Self::new(move || Ok(Box::new(HttpTransport::new(&url)) as Box<dyn Transport>))
    }

    /// `url` reached through `network`: through Tor, every request on its own circuit, so a cash issue (which names the
    /// account) and an entry into a vault never share one. The address is checked for that network here, before any
    /// operation.
    pub fn through(network: &Network, url: &str) -> Result<Self, String> {
        let url = url.trim_end_matches('/').to_string();
        network.check(&url)?;
        let network = network.clone();
        Ok(Self::new(move || Ok(Box::new(network.transport(&url)?) as Box<dyn Transport>)))
    }

    fn call(&mut self, route: &str, body: &Value) -> Result<Value, AgentError> {
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let mut transport = (self.connect)().map_err(AgentError::Refused)?;
        let (status, raw) = transport.post(route, &headers, body.to_string().as_bytes()).map_err(AgentError::Unknown)?;
        let reply: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let why = || reply["error"].as_str().or(reply["pending"].as_str()).unwrap_or("no reason given").to_string();
        match status {
            200 => Ok(reply),
            202 => Err(AgentError::Unknown(format!("the agent is waiting for the chain: {}", why()))),
            500..=599 => Err(AgentError::Unknown(format!("agent error {status}: {}", why()))),
            _ => Err(AgentError::Refused(format!("refused by the agent ({status}): {}", why()))),
        }
    }

    fn signatures_of(reply: &Value, expected: usize) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        let sigs: Option<Vec<[u8; G1_LEN]>> = reply["signatures"]
            .as_array()
            .and_then(|a| a.iter().map(|s| s.as_str().and_then(|s| B64.decode(s).ok()).and_then(|b| b.try_into().ok())).collect());
        match sigs {
            Some(sigs) if sigs.len() == expected => Ok(sigs),
            // Done on the agent's side: the signatures can be asked again (`pool_recover`).
            _ => Err(AgentError::Unknown("the agent's answer has no usable signatures".into())),
        }
    }

    fn note_body(vault: u32, note: &SignedNote, outputs: &[(u8, u64)], blinded: &[[u8; G1_LEN]]) -> Value {
        let mut body = note.contract_args();
        body["vault"] = json!(vault);
        body["outputs"] = json!(outputs.iter().map(|(t, c)| json!({"tier": t, "count": c})).collect::<Vec<_>>());
        body["blinded"] = json!(blinded.iter().map(|b| B64.encode(b)).collect::<Vec<_>>());
        body
    }
}

impl PoolAgent for HttpAgent {
    fn issue_cash(&mut self, account: &str, notes: &[(u8, [u8; G1_LEN])], proof: &DepositorProof) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        let mut groups: Vec<(u8, Vec<String>)> = Vec::new();
        for (tier, b) in notes {
            match groups.last_mut() {
                Some((t, list)) if t == tier => list.push(B64.encode(b)),
                _ => groups.push((*tier, vec![B64.encode(b)])),
            }
        }
        let body = json!({
            "account": account,
            "notes": groups.iter().map(|(t, b)| json!({"tier": t, "blinded": b})).collect::<Vec<_>>(),
            "proof": {"public_key": proof.public_key_text(), "signature": B64.encode(proof.signature), "nonce": B64.encode(proof.nonce)},
        });
        let reply = self.call("/issue_cash", &body)?;
        Self::signatures_of(&reply, notes.len())
    }

    fn enter(&mut self, vault: u32, note: &SignedNote, outputs: &[(u8, u64)], blinded: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        let reply = self.call("/enter", &Self::note_body(vault, note, outputs, blinded))?;
        Self::signatures_of(&reply, blinded.len())
    }

    fn leave(&mut self, vault: u32, note: &SignedNote, outputs: &[(u8, u64)], blinded: &[[u8; G1_LEN]]) -> Result<Vec<[u8; G1_LEN]>, AgentError> {
        let reply = self.call("/leave", &Self::note_body(vault, note, outputs, blinded))?;
        Self::signatures_of(&reply, blinded.len())
    }

    fn pay_exit(&mut self, note: &SignedNote, to: &str) -> Result<(), AgentError> {
        let mut body = note.contract_args();
        body["to"] = json!(to);
        let reply = self.call("/pay_exit", &body)?;
        if reply["paid"] == json!(true) {
            Ok(())
        } else {
            Err(AgentError::Unknown("the agent did not say the note was paid".into()))
        }
    }

    fn signatures(&mut self, blinded: &[[u8; G1_LEN]]) -> Result<Vec<Option<[u8; G1_LEN]>>, AgentError> {
        let reply = self.call("/signatures", &json!({"blinded": blinded.iter().map(|b| B64.encode(b)).collect::<Vec<_>>()}))?;
        let list = reply["signatures"].as_array().ok_or_else(|| AgentError::Unknown("no signatures in the answer".into()))?;
        if list.len() != blinded.len() {
            return Err(AgentError::Unknown("the agent returned a wrong number of signatures".into()));
        }
        list.iter()
            .map(|s| match s {
                Value::Null => Ok(None),
                s => s
                    .as_str()
                    .and_then(|s| B64.decode(s).ok())
                    .and_then(|b| b.try_into().ok())
                    .map(Some)
                    .ok_or_else(|| AgentError::Unknown("a signature is not valid base64".into())),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Canned(u16, Value);

    impl Transport for Canned {
        fn get(&mut self, _: &str, _: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
            Err("not used".into())
        }
        fn post(&mut self, _: &str, _: &[(String, String)], _: &[u8]) -> Result<(u16, Vec<u8>), String> {
            Ok((self.0, self.1.to_string().into_bytes()))
        }
    }

    fn agent(s: u16, v: Value) -> HttpAgent {
        HttpAgent::new(move || Ok(Box::new(Canned(s, v.clone())) as Box<dyn Transport>))
    }

    #[test]
    fn each_operation_opens_a_new_transport() {
        use std::cell::Cell;
        use std::rc::Rc;
        let opened = Rc::new(Cell::new(0));
        let count = opened.clone();
        let mut a = HttpAgent::new(move || {
            count.set(count.get() + 1);
            Ok(Box::new(Canned(200, json!({"signatures": [null]}))) as Box<dyn Transport>)
        });
        a.signatures(&[[1u8; G1_LEN]]).unwrap();
        a.signatures(&[[1u8; G1_LEN]]).unwrap();
        assert_eq!(opened.get(), 2, "no connection is kept between two operations");
    }

    #[test]
    fn statuses_map_to_done_unknown_or_refused() {
        let ok = |s: u16, v: Value| agent(s, v).signatures(&[[1u8; G1_LEN]]);
        assert_eq!(ok(200, json!({"signatures": [null]})).unwrap(), vec![None]);
        assert!(matches!(ok(202, json!({"pending": "x"})), Err(AgentError::Unknown(_))));
        assert!(matches!(ok(503, json!({"error": "x"})), Err(AgentError::Unknown(_))));
        assert!(matches!(ok(409, json!({"error": "x"})), Err(AgentError::Refused(_))));
        assert!(matches!(ok(200, json!({"signatures": []})), Err(AgentError::Unknown(_))), "wrong count");
    }
}
