//! Reads the chain through two independent RPC endpoints, and acts only when both agree on the same
//! final block. One lying endpoint, or an attacker between this program and one endpoint, then
//! produces an error instead of a signature. Two endpoints that lie together are not detected.
//!
//! A lying endpoint could still try to impose an old block, where the state was different. So the two
//! final heights may differ by at most `MAX_HEIGHT_GAP` blocks, every view of one decision is read at
//! one pinned block (`view_at`), and a caller can refuse any block below the highest it already used.
//!
//! Shared by the relay and the signer: `ona-signer` includes this file as its own module.
//!
//! Formats used here, from the NEAR RPC documentation (docs.near.org/api/rpc), not verified against a
//! live node in this repository: `block` with `{"finality":"final"}` or `{"block_id": <height>}`,
//! `query` `call_function` with `block_id` set to a block hash, and the `block_hash` field of its reply.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

/// Most blocks between the two endpoints' final heights. Final blocks come about once a second on
/// NEAR, so honest endpoints rarely differ by more than a few; a larger gap stops the read.
pub const MAX_HEIGHT_GAP: u64 = 20;

/// One JSON-RPC endpoint. Returns the `result` field, or an error for an RPC error.
pub trait Rpc {
    fn post(&self, method: &str, params: Value) -> Result<Value, String>;
}

/// The address an RPC endpoint is reached at, as `host:port` in lowercase.
fn authority(url: &str) -> Result<(bool, String), String> {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!("RPC URL must start with https:// : {url}"));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default().to_ascii_lowercase();
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("RPC URL has no usable host: {url}"));
    }
    Ok((secure, authority))
}

fn host(authority: &str) -> &str {
    if authority.starts_with('[') {
        authority.split_inclusive(']').next().unwrap_or(authority)
    } else {
        authority.split(':').next().unwrap_or(authority)
    }
}

/// Accepts `https`, or plain `http` to this machine only: an RPC answer decides what gets signed, so
/// it must not cross a network in the clear.
pub fn check_rpc_url(url: &str) -> Result<(), String> {
    let (secure, authority) = authority(url)?;
    if secure || matches!(host(&authority), "127.0.0.1" | "localhost" | "[::1]") {
        Ok(())
    } else {
        Err(format!("RPC URL must use https, or http to this machine only: {url}"))
    }
}

/// Both URLs must be acceptable and must not name the same endpoint. Whether two endpoints are run by
/// independent operators cannot be checked here: it is the operator's choice.
pub fn check_rpc_pair(first: &str, second: &str) -> Result<(), String> {
    check_rpc_url(first)?;
    check_rpc_url(second)?;
    if authority(first)?.1 == authority(second)?.1 {
        return Err("the two RPC URLs name the same endpoint".into());
    }
    Ok(())
}

/// A read-only JSON-RPC endpoint over HTTP. It holds no key, follows no redirect, and reads at most
/// 10 MiB of reply (the default limit of `ureq` 3.5 `read_to_string`).
#[derive(Clone)]
pub struct HttpRpc {
    url: String,
    agent: ureq::Agent,
}

/// An agent for RPC traffic: one deadline for the whole call, no redirect and no proxy taken from the
/// environment, so nothing can send the request elsewhere.
pub fn rpc_agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(timeout)).max_redirects(0).proxy(None).build().into()
}

impl HttpRpc {
    pub fn new(url: &str, timeout: Duration) -> Result<Self, String> {
        check_rpc_url(url)?;
        Ok(Self { url: url.to_string(), agent: rpc_agent(timeout) })
    }
}

impl Rpc for HttpRpc {
    fn post(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc":"2.0","id":"1","method":method,"params":params}).to_string();
        let text = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .send(body)
            .map_err(|e| format!("RPC request failed: {e}"))?
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("cannot read RPC response: {e}"))?;
        let value: Value = serde_json::from_str(&text).map_err(|_| "RPC response is not JSON".to_string())?;
        if let Some(err) = value.get("error") {
            return Err(format!("rpc error: {err}"));
        }
        Ok(value["result"].clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    pub hash: String,
    /// Nanoseconds.
    pub timestamp: u64,
}

fn parse_block(value: &Value) -> Result<Block, String> {
    let header = &value["header"];
    let bad = || "unexpected block reply".to_string();
    Ok(Block {
        height: header["height"].as_u64().ok_or_else(bad)?,
        hash: header["hash"].as_str().filter(|h| !h.is_empty()).ok_or_else(bad)?.to_string(),
        timestamp: header["timestamp_nanosec"]
            .as_str()
            .and_then(|t| t.parse().ok())
            .or_else(|| header["timestamp"].as_u64())
            .ok_or_else(bad)?,
    })
}

fn view_at<R: Rpc>(rpc: &R, block: &Block, account: &str, method: &str, args: &Value) -> Result<Value, String> {
    let result = rpc.post(
        "query",
        json!({
            "request_type": "call_function", "block_id": block.hash, "account_id": account,
            "method_name": method, "args_base64": B64.encode(args.to_string()),
        }),
    )?;
    if result["block_hash"].as_str() != Some(block.hash.as_str()) {
        return Err(format!("RPC answered {method} for another block"));
    }
    let bytes: Vec<u8> = result["result"]
        .as_array()
        .ok_or_else(|| format!("view {method} failed"))?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("view {method} returned bytes out of range"))?;
    serde_json::from_slice(&bytes).map_err(|_| format!("view {method} did not return JSON"))
}

/// Two endpoints read as one. Every read is made at one final block known to both.
pub struct CrossRpc<A, B> {
    pub first: A,
    pub second: B,
}

impl<A: Rpc, B: Rpc> CrossRpc<A, B> {
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }

    /// The lower of the two final blocks, checked on the other endpoint by height: both must give it
    /// the same hash and time. A block final on one endpoint is final on any honest one. The two final
    /// heights may differ by at most `MAX_HEIGHT_GAP`, and the block must not be below `floor`.
    pub fn agreed_final_block_from(&self, floor: u64) -> Result<Block, String> {
        let final_block = json!({"finality": "final"});
        let a = parse_block(&self.first.post("block", final_block.clone())?)?;
        let b = parse_block(&self.second.post("block", final_block)?)?;
        if a.height.abs_diff(b.height) > MAX_HEIGHT_GAP {
            return Err(format!(
                "the two RPC endpoints are {} blocks apart, more than {MAX_HEIGHT_GAP}",
                a.height.abs_diff(b.height)
            ));
        }
        if a.height.min(b.height) < floor {
            return Err(format!("the RPC endpoints offer block {}, below block {floor} already used", a.height.min(b.height)));
        }
        let (low, seen) = if a.height <= b.height {
            let seen = parse_block(&self.second.post("block", json!({"block_id": a.height}))?)?;
            (a, seen)
        } else {
            let seen = parse_block(&self.first.post("block", json!({"block_id": b.height}))?)?;
            (b, seen)
        };
        if seen != low {
            return Err("the two RPC endpoints disagree on a final block".into());
        }
        Ok(low)
    }

    pub fn agreed_final_block(&self) -> Result<Block, String> {
        self.agreed_final_block_from(0)
    }

    /// A contract view, made on both endpoints at `block`, which both have agreed on. Any difference
    /// is an error. Read every view of one decision at the same block.
    pub fn view_at(&self, block: &Block, account: &str, method: &str, args: Value) -> Result<Value, String> {
        let a = view_at(&self.first, block, account, method, &args)?;
        let b = view_at(&self.second, block, account, method, &args)?;
        if a != b {
            return Err(format!("the two RPC endpoints disagree on {method}"));
        }
        Ok(a)
    }

    /// Any other `query` (for example `view_access_key`), made on both endpoints at `block`. Any
    /// difference is an error.
    pub fn query_at(&self, block: &Block, mut params: Value) -> Result<Value, String> {
        params["block_id"] = json!(block.hash);
        let a = self.first.post("query", params.clone())?;
        let b = self.second.post("query", params)?;
        if a != b {
            return Err("the two RPC endpoints disagree on a query".into());
        }
        if a["block_hash"].as_str() != Some(block.hash.as_str()) {
            return Err("RPC answered a query for another block".into());
        }
        Ok(a)
    }

    /// A contract view at a newly agreed final block.
    pub fn view(&self, account: &str, method: &str, args: Value) -> Result<Value, String> {
        let block = self.agreed_final_block()?;
        self.view_at(&block, account, method, args)
    }

    /// Time of the agreed final block, in nanoseconds.
    pub fn final_timestamp(&self) -> Result<u64, String> {
        Ok(self.agreed_final_block()?.timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// An endpoint that knows a chain of blocks and the value of each view at each block.
    #[derive(Default)]
    struct FakeRpc {
        blocks: Vec<Block>,
        final_height: u64,
        views: BTreeMap<(String, String), Value>,
        calls: RefCell<Vec<String>>,
    }

    fn block(height: u64) -> Block {
        Block { height, hash: format!("hash{height}"), timestamp: height * 1_000 }
    }

    fn block_json(b: &Block) -> Value {
        json!({"header": {"height": b.height, "hash": b.hash, "timestamp_nanosec": b.timestamp.to_string()}})
    }

    impl Rpc for FakeRpc {
        fn post(&self, method: &str, params: Value) -> Result<Value, String> {
            self.calls.borrow_mut().push(method.to_string());
            match method {
                "block" => {
                    let height = params["block_id"].as_u64().unwrap_or(self.final_height);
                    self.blocks.iter().find(|b| b.height == height).map(block_json).ok_or_else(|| "unknown block".into())
                }
                "query" => {
                    let hash = params["block_id"].as_str().unwrap_or_default().to_string();
                    let value = self
                        .views
                        .get(&(hash.clone(), params["method_name"].as_str().unwrap_or_default().to_string()))
                        .ok_or("unknown view")?;
                    let bytes: Vec<Value> = value.to_string().bytes().map(Value::from).collect();
                    Ok(json!({"result": bytes, "block_hash": hash, "block_height": 0}))
                }
                _ => Err("unknown method".into()),
            }
        }
    }

    fn node(final_height: u64, pending: &[(u64, Value)]) -> FakeRpc {
        let mut views = BTreeMap::new();
        for (height, value) in pending {
            views.insert((format!("hash{height}"), "pending_deposits".to_string()), value.clone());
        }
        FakeRpc { blocks: (0..=final_height).map(block).collect(), final_height, views, ..Default::default() }
    }

    #[test]
    fn urls_must_be_https_or_local() {
        assert!(check_rpc_url("https://rpc.testnet.near.org").is_ok());
        assert!(check_rpc_url("http://127.0.0.1:3030").is_ok());
        assert!(check_rpc_url("http://localhost:3030/").is_ok());
        assert!(check_rpc_url("http://[::1]:3030").is_ok());
        for bad in [
            "http://rpc.testnet.near.org",
            "http://127.0.0.1.evil.test",
            "http://localhost@evil.test",
            "ftp://x",
            "https://",
            "rpc.testnet.near.org",
        ] {
            assert!(check_rpc_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_two_urls_must_name_different_endpoints() {
        assert!(check_rpc_pair("https://a.test", "https://b.test").is_ok());
        assert!(check_rpc_pair("https://a.test", "https://A.test/other").is_err());
        assert!(check_rpc_pair("http://127.0.0.1:3030", "http://127.0.0.1:3031").is_ok());
        assert!(check_rpc_pair("https://a.test", "http://b.test").is_err());
    }

    #[test]
    fn agreeing_endpoints_are_read_at_the_lower_final_block() {
        let value = json!([{"id": "1"}]);
        let ahead = node(12, &[(10, value.clone()), (12, json!([]))]);
        let behind = node(10, &[(10, value.clone())]);
        let rpc = CrossRpc::new(ahead, behind);
        assert_eq!(rpc.agreed_final_block().unwrap(), block(10));
        assert_eq!(rpc.view("mint.test", "pending_deposits", json!({})).unwrap(), value);
        assert_eq!(rpc.final_timestamp().unwrap(), 10_000);
    }

    #[test]
    fn an_invented_deposit_is_refused() {
        let invented = json!([{"id": "7", "locked_until": "999"}]);
        let liar = node(10, &[(10, invented)]);
        let honest = node(10, &[(10, json!([]))]);
        let rpc = CrossRpc::new(liar, honest);
        assert!(rpc.view("mint.test", "pending_deposits", json!({})).unwrap_err().contains("disagree"));
    }

    #[test]
    fn an_invented_block_or_time_is_refused() {
        let mut liar = node(10, &[]);
        liar.blocks[10].hash = "forged".into();
        assert!(CrossRpc::new(liar, node(10, &[])).agreed_final_block().unwrap_err().contains("disagree"));

        let mut late = node(10, &[]);
        late.blocks[10].timestamp += 1;
        assert!(CrossRpc::new(node(10, &[]), late).final_timestamp().is_err());
    }

    #[test]
    fn one_endpoint_cannot_impose_an_old_block() {
        // A liar reports an old final block: the honest endpoint holds it too, but it is far behind.
        let old = node(100, &[]);
        let honest = node(100 + MAX_HEIGHT_GAP + 1, &[]);
        assert!(CrossRpc::new(old, honest).agreed_final_block().unwrap_err().contains("blocks apart"));
        assert!(CrossRpc::new(node(100, &[]), node(100 + MAX_HEIGHT_GAP, &[])).agreed_final_block().is_ok());
    }

    #[test]
    fn a_block_below_the_floor_is_refused() {
        let rpc = CrossRpc::new(node(50, &[]), node(52, &[]));
        assert_eq!(rpc.agreed_final_block_from(50).unwrap().height, 50);
        assert!(rpc.agreed_final_block_from(51).unwrap_err().contains("below block 51"));
    }

    #[test]
    fn views_of_one_decision_are_read_at_the_pinned_block() {
        let value = json!([{"id": "1"}]);
        let a = node(12, &[(10, value.clone()), (12, json!([]))]);
        let b = node(12, &[(10, value.clone()), (12, json!([]))]);
        let rpc = CrossRpc::new(a, b);
        assert_eq!(rpc.view_at(&block(10), "mint.test", "pending_deposits", json!({})).unwrap(), value);
    }

    #[test]
    fn a_reply_for_another_block_is_refused() {
        struct OtherBlock(FakeRpc);
        impl Rpc for OtherBlock {
            fn post(&self, method: &str, params: Value) -> Result<Value, String> {
                let mut reply = self.0.post(method, params)?;
                if method == "query" {
                    reply["block_hash"] = json!("hash3");
                }
                Ok(reply)
            }
        }
        let value = json!([]);
        let rpc = CrossRpc::new(OtherBlock(node(10, &[(10, value.clone())])), node(10, &[(10, value)]));
        assert!(rpc.view("mint.test", "pending_deposits", json!({})).unwrap_err().contains("another block"));
    }
}
