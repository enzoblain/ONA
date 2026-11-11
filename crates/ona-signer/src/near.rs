//! The `Chain` used in production: reads `ona-mint` through two RPC endpoints that must agree on a
//! final block, and sends transactions through the first one. All reads of one pass are made at the
//! block pinned by `begin_pass`, so a deposit is signed only if both endpoints show it, locked, at that
//! one block.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_near::{Client, TxUnknown};
use ona_token::{g2_from_raw, G1_LEN, G2_LEN, G2_RAW_LEN};
use serde_json::{json, Value};

use crate::crossrpc::{Block, CrossRpc, HttpRpc, Rpc};
use crate::{Chain, Pass, PendingRecord};

// `lock` and `unlock` update one counter per token. About 2 Tgas were measured for `lock` on the earlier
// contract, which did not; the budget below for 32 tokens (10 + 2 x 32 = 74 Tgas) is not measured.
const LOCK_BASE_TGAS: u64 = 10;
const LOCK_TGAS_PER_TOKEN: u64 = 2;
// Measured on near-sandbox 2.13.4 with the earlier contract: 6.9 Tgas per token for issue (222.5 for 32).
const ISSUE_BASE_TGAS: u64 = 10;
const ISSUE_TGAS_PER_TOKEN: u64 = 8;

/// `client` sends transactions only. Every read goes through `reads`.
pub struct NearChain<A = HttpRpc, B = HttpRpc> {
    client: Client,
    reads: CrossRpc<A, B>,
    account: String,
    mint: String,
    /// The block of the current pass.
    pinned: Option<Block>,
    /// `issue` transactions whose outcome the node could not give, by deposit.
    unknown_issues: HashMap<u64, [u8; 32]>,
}

impl<A: Rpc, B: Rpc> NearChain<A, B> {
    pub fn new(client: Client, reads: CrossRpc<A, B>, account: String, mint: String) -> Self {
        Self { client, reads, account, mint, pinned: None, unknown_issues: HashMap::new() }
    }

    fn block(&mut self) -> Result<Block, String> {
        match &self.pinned {
            Some(block) => Ok(block.clone()),
            None => self.reads.agreed_final_block(),
        }
    }

    fn view(&mut self, method: &str, args: Value) -> Result<Value, String> {
        let block = self.block()?;
        self.reads.view_at(&block, &self.mint, method, args)
    }

    fn call(&mut self, method: &str, args: Value, gas_tgas: u64) -> Result<(), String> {
        send(self, method, args, gas_tgas).map_err(|(e, _)| e)
    }
}

/// Sends a call and maps its outcome. A `TxUnknown` error carries the transaction hash.
fn send<A, B>(chain: &NearChain<A, B>, method: &str, args: Value, gas_tgas: u64) -> Result<(), (String, Option<[u8; 32]>)> {
    match chain.client.call_with_gas(&chain.account, &chain.mint, method, args, gas_tgas, 0) {
        Ok(outcome) => match outcome.failure {
            Some(failure) => Err((failure, None)),
            None => Ok(()),
        },
        Err(e) => {
            let hash = e.downcast_ref::<TxUnknown>().map(|u| u.hash);
            Err((e.to_string(), hash))
        }
    }
}

fn parse_u64(value: &Value) -> Option<u64> {
    value.as_str()?.parse().ok()
}

/// Parses one record list. A malformed record fails the whole read rather than being skipped.
pub fn parse_pending(value: &Value) -> Result<Vec<PendingRecord>, String> {
    let bad = || format!("unexpected pending reply: {value}");
    value
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|record| {
            let items = record["items"]
                .as_array()
                .ok_or_else(bad)?
                .iter()
                .map(|item| {
                    let denom = item["denom_id"].as_u64().and_then(|d| u8::try_from(d).ok()).ok_or_else(bad)?;
                    let blinded: [u8; G1_LEN] = item["blinded"]
                        .as_str()
                        .and_then(|b| B64.decode(b).ok())
                        .and_then(|b| b.try_into().ok())
                        .ok_or_else(bad)?;
                    Ok((denom, blinded))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(PendingRecord {
                id: parse_u64(&record["id"]).ok_or_else(bad)?,
                depositor: record["depositor"].as_str().ok_or_else(bad)?.to_string(),
                items,
                deadline: parse_u64(&record["deadline"]).ok_or_else(bad)?,
                locked_until: parse_u64(&record["locked_until"]).ok_or_else(bad)?,
            })
        })
        .collect()
}

/// Parses `pending_scan`: `{records, next}`. `next` must not go backwards.
pub fn parse_scan(value: &Value, from: u64) -> Result<(Vec<PendingRecord>, u64), String> {
    let records = parse_pending(&value["records"])?;
    let next = parse_u64(&value["next"]).ok_or_else(|| format!("unexpected pending_scan reply: {value}"))?;
    if next < from || records.iter().any(|r| r.id < from || r.id >= next.max(from + 1)) {
        return Err(format!("pending_scan answered outside the range asked: {value}"));
    }
    Ok((records, next))
}

impl<A: Rpc, B: Rpc> Chain for NearChain<A, B> {
    fn begin_pass(&mut self, floor: u64) -> Result<Pass, String> {
        self.pinned = None;
        let block = self.reads.agreed_final_block_from(floor)?;
        let pass = Pass { height: block.height, now: block.timestamp };
        self.pinned = Some(block);
        Ok(pass)
    }

    fn pending_scan(&mut self, from: u64, limit: u16) -> Result<(Vec<PendingRecord>, u64), String> {
        let value = self.view("pending_scan", json!({"from": from.to_string(), "limit": limit}))?;
        parse_scan(&value, from)
    }

    fn lock(&mut self, id: u64, tokens: usize) -> Result<(), String> {
        let gas = LOCK_BASE_TGAS + LOCK_TGAS_PER_TOKEN * tokens as u64;
        self.call("lock", json!({"deposit_id": id.to_string()}), gas)
    }

    fn unlock(&mut self, id: u64, tokens: usize) -> Result<(), String> {
        let gas = LOCK_BASE_TGAS + LOCK_TGAS_PER_TOKEN * tokens as u64;
        self.call("unlock", json!({"deposit_id": id.to_string()}), gas)
    }

    fn denom_key(&mut self, denom_id: u8) -> Result<[u8; G2_LEN], String> {
        let value = self.view("get_denom", json!({"denom_id": denom_id}))?;
        let raw: [u8; G2_RAW_LEN] = value["pk_raw"]
            .as_str()
            .and_then(|k| B64.decode(k).ok())
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| format!("unexpected get_denom reply: {value}"))?;
        g2_from_raw(&raw).map_err(|e| e.to_string())
    }

    /// An earlier `issue` of this deposit whose outcome was unknown is looked up first: if it landed,
    /// nothing is sent again. Sending again is harmless otherwise: the signatures are the same, and the
    /// contract refuses a second issue of one deposit.
    fn issue(&mut self, id: u64, sigs: Vec<[u8; G1_LEN]>) -> Result<(), String> {
        if let Some(hash) = self.unknown_issues.get(&id).copied() {
            match self.client.tx_status(&hash, &self.account) {
                Ok(Some(outcome)) => {
                    self.unknown_issues.remove(&id);
                    if outcome.failure.is_none() {
                        return Ok(());
                    }
                }
                Ok(None) => {
                    self.unknown_issues.remove(&id);
                }
                Err(e) => return Err(format!("cannot learn the fate of an earlier issue: {e}")),
            }
        }
        let gas = ISSUE_BASE_TGAS + ISSUE_TGAS_PER_TOKEN * sigs.len() as u64;
        let encoded: Vec<String> = sigs.iter().map(|s| B64.encode(s)).collect();
        match send(self, "issue", json!({"deposit_id": id.to_string(), "sigs": encoded}), gas) {
            Ok(()) => Ok(()),
            Err((e, unknown)) => {
                if let Some(hash) = unknown {
                    self.unknown_issues.insert(id, hash);
                }
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A local stand-in for a NEAR node: answers key lookups, and any transaction with `tx_result`.
    fn fake_rpc(tx_result: Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let read = stream.read(&mut chunk).unwrap();
                    request.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&request);
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        if body.len() >= length {
                            break;
                        }
                    }
                    if read == 0 {
                        break;
                    }
                }
                let result = if String::from_utf8_lossy(&request).contains("view_access_key") {
                    json!({"nonce": 1, "block_hash": "11111111111111111111111111111111"})
                } else {
                    tx_result.clone()
                };
                let body = json!({"jsonrpc": "2.0", "id": "1", "result": result}).to_string();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).unwrap();
            }
        });
        url
    }

    fn chain_against(tx_result: Value) -> NearChain {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let mut bytes = key.to_bytes().to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        let text = format!("ed25519:{}", bs58::encode(bytes).into_string());
        let url = fake_rpc(tx_result);
        let client = Client::new(&url, ona_near::parse_account_key(&text).unwrap())
            .with_status_checks(1, std::time::Duration::ZERO);
        let timeout = std::time::Duration::from_secs(5);
        let reads = CrossRpc::new(HttpRpc::new(&url, timeout).unwrap(), HttpRpc::new(&url, timeout).unwrap());
        NearChain::new(client, reads, "signer.test".into(), "mint.test".into())
    }

    #[test]
    fn issue_only_succeeds_on_an_explicit_success() {
        let success = json!({"final_execution_status": "FINAL", "status": {"SuccessValue": ""}, "receipts_outcome": []});
        assert!(chain_against(success).issue(1, vec![]).is_ok());
        assert!(chain_against(json!({"status": {"Failure": {}}})).issue(1, vec![]).is_err());
        // The signer marks a record done when `issue` returns Ok, so this must be an error.
        assert!(chain_against(json!({"status": "Started"})).issue(1, vec![]).is_err());
        assert!(chain_against(json!({})).issue(1, vec![]).is_err());
    }

    /// An endpoint at a fixed final block, whose `pending_scan` answer is `scan`.
    struct Node {
        scan: Value,
    }

    impl Rpc for Node {
        fn post(&self, method: &str, _params: Value) -> Result<Value, String> {
            match method {
                "block" => Ok(json!({"header": {"height": 10, "hash": "h10", "timestamp_nanosec": "10"}})),
                "query" => {
                    let bytes: Vec<Value> = self.scan.to_string().bytes().map(Value::from).collect();
                    Ok(json!({"result": bytes, "block_hash": "h10"}))
                }
                _ => Err("unknown".into()),
            }
        }
    }

    fn chain_on(first: Node, second: Node) -> NearChain<Node, Node> {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        NearChain::new(Client::new("http://127.0.0.1:9", key), CrossRpc::new(first, second), "signer.test".into(), "mint.test".into())
    }

    /// One endpoint invents a locked deposit, the other does not know it: the signer gets an error,
    /// never a record to sign.
    #[test]
    fn a_deposit_shown_by_one_endpoint_only_is_never_signed() {
        let invented = json!({"records": [{
            "id": "7", "depositor": "thief.test", "deadline": "100", "locked_until": "18446744073709551615",
            "items": [{"denom_id": 7, "blinded": B64.encode([7u8; G1_LEN])}],
        }], "next": "8"});
        let mut chain = chain_on(Node { scan: invented }, Node { scan: json!({"records": [], "next": "8"}) });
        let mut signer = crate::Signer::new(crate::KeyStore::generate(8), crate::MemoryDurable::default());
        assert!(signer.tick(&mut chain).unwrap_err().contains("disagree"));
    }

    #[test]
    fn a_pass_refuses_a_block_below_the_floor() {
        let mut chain = chain_on(Node { scan: json!({}) }, Node { scan: json!({}) });
        assert_eq!(chain.begin_pass(10).unwrap(), Pass { height: 10, now: 10 });
        assert!(chain.begin_pass(11).unwrap_err().contains("below block 11"));
    }

    #[test]
    fn pending_records_are_parsed() {
        let value = json!({"records": [{
            "id": "4", "depositor": "a.test", "deadline": "100", "locked_until": "0", "total": "1", "is_change": false,
            "items": [{"denom_id": 2, "blinded": B64.encode([7u8; G1_LEN])}],
        }], "next": "9"});
        let (records, next) = parse_scan(&value, 4).unwrap();
        assert_eq!(next, 9);
        assert_eq!(records[0].id, 4);
        assert_eq!(records[0].deadline, 100);
        assert_eq!(records[0].locked_until, 0);
        assert_eq!(records[0].items, vec![(2, [7u8; G1_LEN])]);
    }

    #[test]
    fn malformed_records_fail_the_read() {
        let short = json!([{"id":"1","depositor":"a","deadline":"1","locked_until":"0","items":[{"denom_id":0,"blinded":B64.encode([1u8; 3])}]}]);
        assert!(parse_pending(&short).is_err());
        assert!(parse_pending(&json!({"not": "a list"})).is_err());
        assert!(parse_pending(&json!([{"id":"x","depositor":"a","deadline":"1","locked_until":"0","items":[]}])).is_err());
        assert!(parse_pending(&json!([{"id":"1","depositor":"a","deadline":"1","items":[]}])).is_err(), "a missing lock field must not read as unlocked");
        assert!(parse_scan(&json!({"records": [], "next": "3"}), 5).is_err(), "next must not go backwards");
        assert!(parse_scan(&json!({"records": []}), 5).is_err());
    }

    #[test]
    fn gas_covers_the_largest_batch_as_measured() {
        let measured_tgas_for_32 = 222.5;
        assert!((ISSUE_BASE_TGAS + ISSUE_TGAS_PER_TOKEN * 32) as f64 > measured_tgas_for_32 * 1.1);
        assert!(ISSUE_BASE_TGAS + ISSUE_TGAS_PER_TOKEN * 32 <= 300, "within one transaction's gas");
    }
}
