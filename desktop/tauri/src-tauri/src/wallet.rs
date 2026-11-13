//! Pool deposits with the person's own NEAR wallet (docs/desktop/wallet.md).
//!
//! The deposit is sent and signed by the person's wallet, never by ONA (docs/desktop/pool-commands.md). This module
//! serves the page of `desktop/wallet-page` on 127.0.0.1, under a random path that works for one deposit, opens it in
//! the browser, and follows the deposit: the page sends the `deposit` transaction with NEAR Wallet Selector, the app
//! runs the first `pool_execute` (the cash notes, and the message the agent wants signed), the page has that message
//! signed by the same wallet, and the app runs the second `pool_execute` with the signature.

use serde_json::{Value, json};

use crate::http::{Request, Response};

const INDEX: &[u8] = include_bytes!("../../../wallet-page/dist/index.html");
const SCRIPT: &[u8] = include_bytes!("../../../wallet-page/dist/wallet.js");
const STYLE: &[u8] = include_bytes!("../../../wallet-page/dist/wallet.css");

#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// The deposit transaction is still to be sent.
    Deposit,
    /// Sent; the agent's message (`sign_message` of the first `pool_execute`) is to be signed.
    Sign(Value),
    Done,
}

/// One deposit in progress.
#[derive(Clone, Debug)]
pub struct Session {
    /// The secret part of the page's address: 16 random bytes in hex.
    pub token: String,
    pub prepared_id: String,
    /// The account that deposits: only its wallet may sign.
    pub account: String,
    pub network: String,
    /// `summary.wallet_call` of `pool_prepare`: receiver, method, args, attached.
    pub wallet_call: Value,
    /// `summary.expires_at`, nanoseconds: the preparation and both `pool_execute` calls end then.
    pub expires_at: u64,
    pub step: Step,
    /// A `pool_execute` of this session is running: a second request waits for it instead of running another.
    pub executing: bool,
}

impl Session {
    /// From a deposit's `pool_prepare` reply. Err when it is not a deposit or lacks what the page needs.
    pub fn from_prepared(prepared: &Value) -> Result<Self, String> {
        let summary = &prepared["summary"];
        if summary["op"] != "deposit" {
            return Err("only a deposit goes through the wallet page".into());
        }
        let text = |v: &Value, what: &str| v.as_str().map(String::from).ok_or_else(|| format!("deposit without {what}"));
        let call = &summary["wallet_call"];
        for key in ["receiver", "method", "attached"] {
            text(&call[key], key)?;
        }
        Ok(Self {
            token: crate::protocol::random_hex16(),
            prepared_id: text(&prepared["prepared_id"], "prepared_id")?,
            account: text(&summary["account"], "account")?,
            network: text(&summary["network"], "network")?,
            wallet_call: call.clone(),
            expires_at: summary["expires_at"].as_u64().ok_or("deposit without expires_at")?,
            step: Step::Deposit,
            executing: false,
        })
    }

    pub fn expired(&self, now_ns: u64) -> bool {
        now_ns >= self.expires_at
    }

    /// What the page reads (`state`): never the prepared id, which is the app's.
    pub fn state(&self) -> Value {
        let (step, message) = match &self.step {
            Step::Deposit => ("deposit", Value::Null),
            Step::Sign(message) => ("sign", message.clone()),
            Step::Done => ("done", Value::Null),
        };
        json!({"ok": true, "step": step, "account": self.account, "network": self.network,
               "wallet_call": self.wallet_call, "sign_message": message})
    }
}

/// What the page asked, once its address, `Host` and `Origin` were checked.
#[derive(Debug, PartialEq)]
pub enum Ask {
    Asset(&'static str, &'static [u8]),
    State,
    Deposited,
    Signed { public_key: String, signature: String },
}

/// Checks a request to the wallet page: `/wallet/<token>/…`, `Host` this server, and for a POST an `Origin` that is this
/// server too (a page of another site cannot drive the deposit, even if it guessed the address).
pub fn parse(request: &Request, token: &str, host: &str) -> Result<Ask, Response> {
    let refuse = |status: u16, error: &str| Response::new(status, json!({"ok": false, "error": error}));
    match request.header("host") {
        Ok(Some(h)) if h.eq_ignore_ascii_case(host) => {}
        _ => return Err(refuse(403, "host not allowed")),
    }
    let prefix = format!("/wallet/{token}");
    let rest = request.path.split(['?', '#']).next().unwrap_or("");
    let Some(rest) = rest.strip_prefix(&prefix) else { return Err(refuse(404, "not found")) };
    if request.method == "GET" {
        return match rest {
            "" | "/" => Ok(Ask::Asset("text/html; charset=utf-8", INDEX)),
            "/wallet.js" => Ok(Ask::Asset("text/javascript; charset=utf-8", SCRIPT)),
            "/wallet.css" => Ok(Ask::Asset("text/css; charset=utf-8", STYLE)),
            _ => Err(refuse(404, "not found")),
        };
    }
    if request.method != "POST" {
        return Err(refuse(400, "method not allowed"));
    }
    match request.header("origin") {
        Ok(Some(origin)) if origin.eq_ignore_ascii_case(&format!("http://{host}")) => {}
        _ => return Err(refuse(403, "origin not allowed")),
    }
    let body: Value = serde_json::from_slice(&request.body).map_err(|_| refuse(400, "body is not JSON"))?;
    match rest {
        "/state" => Ok(Ask::State),
        "/deposited" => Ok(Ask::Deposited),
        "/signed" => {
            let field = |k: &str| body[k].as_str().filter(|s| !s.is_empty() && s.len() < 512).map(String::from);
            match (field("public_key"), field("signature")) {
                (Some(public_key), Some(signature)) => Ok(Ask::Signed { public_key, signature }),
                _ => Err(refuse(400, "public_key and signature are required")),
            }
        }
        _ => Err(refuse(404, "not found")),
    }
}

/// The first `pool_execute` and what it gives: the agent's message to sign. Err with ona-core's error.
pub fn after_first_execute(reply: &Value) -> Result<Step, String> {
    if reply["ok"] != true {
        return Err(reply["error"].as_str().unwrap_or("pool_execute failed").to_owned());
    }
    if reply["complete"] == true {
        return Ok(Step::Done);
    }
    let m = &reply["sign_message"];
    if m["message"].is_string() && m["recipient"].is_string() && m["nonce"].is_string() {
        Ok(Step::Sign(m.clone()))
    } else {
        Err(format!("no message to sign in {reply}"))
    }
}

/// The second `pool_execute`: done, queued by the agent (the cash comes through `pool_recover`), or refused.
pub fn after_second_execute(reply: &Value) -> Result<Step, String> {
    if reply["ok"] == true {
        return Ok(Step::Done);
    }
    let error = reply["error"].as_str().unwrap_or("pool_execute failed");
    if error.contains("outcome unknown") { Ok(Step::Done) } else { Err(error.to_owned()) }
}

/// Opens `url` in the default browser, with the system's own command (no extra library).
pub fn open_in_browser(url: &str) -> std::io::Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.spawn().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "127.0.0.1:5555";

    fn prepared() -> Value {
        json!({"ok": true, "prepared_id": "p1", "summary": {"op": "deposit", "account": "alice.testnet", "network": "testnet",
            "expires_at": 2_000_000_000_000_000_000u64,
            "wallet_call": {"receiver": "pool.testnet", "method": "deposit", "args": {}, "attached": "11010000000000000000000000"}}})
    }

    fn request(method: &str, path: &str, origin: Option<&str>, body: &str) -> Request {
        let mut headers = vec![("host".into(), HOST.into())];
        if let Some(o) = origin {
            headers.push(("origin".into(), o.into()));
        }
        Request { method: method.into(), path: path.into(), headers, body: body.as_bytes().to_vec() }
    }

    #[test]
    fn a_session_comes_from_a_deposit_only() {
        let session = Session::from_prepared(&prepared()).unwrap();
        assert_eq!((session.account.as_str(), session.network.as_str()), ("alice.testnet", "testnet"));
        assert_eq!(session.token.len(), 32);
        assert!(session.state().get("prepared_id").is_none(), "the page never sees the prepared id");
        let mut enter = prepared();
        enter["summary"]["op"] = json!("enter");
        assert!(Session::from_prepared(&enter).is_err());
        assert!(session.expired(2_000_000_000_000_000_000) && !session.expired(1));
    }

    #[test]
    fn only_this_server_and_this_page_drive_the_deposit() {
        let t = "abc";
        let page = format!("/wallet/{t}");
        assert!(matches!(parse(&request("GET", &page, None, ""), t, HOST), Ok(Ask::Asset("text/html; charset=utf-8", _))));
        assert!(matches!(parse(&request("GET", &format!("{page}/wallet.js"), None, ""), t, HOST), Ok(Ask::Asset(_, _))));
        // A wallet that sends the browser back adds a query or a fragment.
        assert!(matches!(parse(&request("GET", &format!("{page}?transactionHashes=x"), None, ""), t, HOST), Ok(Ask::Asset(_, _))));
        assert_eq!(parse(&request("GET", "/wallet/other", None, ""), t, HOST).unwrap_err().status, 404);
        let origin = Some("http://127.0.0.1:5555");
        assert_eq!(parse(&request("POST", &format!("{page}/state"), origin, "{}"), t, HOST), Ok(Ask::State));
        assert_eq!(parse(&request("POST", &format!("{page}/state"), None, "{}"), t, HOST).unwrap_err().status, 403);
        assert_eq!(parse(&request("POST", &format!("{page}/state"), Some("https://evil.example"), "{}"), t, HOST).unwrap_err().status, 403);
        let mut rebinding = request("GET", &page, None, "");
        rebinding.headers[0].1 = "evil.example:5555".into();
        assert_eq!(parse(&rebinding, t, HOST).unwrap_err().status, 403);
        let signed = parse(&request("POST", &format!("{page}/signed"), origin, r#"{"public_key":"ed25519:K","signature":"S"}"#), t, HOST);
        assert_eq!(signed, Ok(Ask::Signed { public_key: "ed25519:K".into(), signature: "S".into() }));
        assert_eq!(parse(&request("POST", &format!("{page}/signed"), origin, "{}"), t, HOST).unwrap_err().status, 400);
    }

    #[test]
    fn follows_the_two_pool_executes() {
        let first = json!({"ok": true, "complete": false, "sign_message": {"message": "m", "recipient": "pool.testnet", "nonce": "bg=="}});
        assert!(matches!(after_first_execute(&first), Ok(Step::Sign(_))));
        assert!(after_first_execute(&json!({"ok": false, "error": "expired"})).is_err());
        assert_eq!(after_second_execute(&json!({"ok": true, "complete": true})), Ok(Step::Done));
        assert_eq!(after_second_execute(&json!({"ok": false, "error": "outcome unknown, run pool_recover later"})), Ok(Step::Done));
        assert!(after_second_execute(&json!({"ok": false, "error": "signature refused"})).is_err());
    }
}
