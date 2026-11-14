//! The phone protocol v1 (docs/ios/protocol-draft.md) on top of the pairing authority and the chat engine.
//! Every request is a POST with a JSON body; every reply is signed with the computer's key. Reads need the token
//! given at pairing; requests that change something are also signed by the phone's key, with a counter.

use serde_json::{Map, Value, json};

use crate::engine::ChatEngine;
use crate::http::{Request, Response};
use crate::pairing::{PairingAuthority, ProtocolError};
use crate::protocol;

/// Longest request nonce copied into the reply signature.
const MAX_NONCE: usize = 64;
/// Largest counter accepted, 2^53 − 1 (exact in every JSON implementation). Same bound in the macOS app.
pub const MAX_COUNTER: u64 = 9_007_199_254_740_991;

/// A request counter: a JSON integer from 0 to `MAX_COUNTER`. Fractions (`1.0`), booleans, negatives refused.
pub fn counter(value: &Value) -> Option<u64> {
    value.as_u64().filter(|c| *c <= MAX_COUNTER)
}

/// Answers one request. `allowed_hosts`: the `Host` values this computer answers to (`127.0.0.1:port`, the onion
/// address, the local address in local mode). Anything else is refused (DNS rebinding).
pub fn handle(request: &Request, pairing: &mut PairingAuthority, engine: &mut ChatEngine, allowed_hosts: &[String])
              -> Response {
    let body: Option<Map<String, Value>> = if request.body.is_empty() {
        Some(Map::new())
    } else {
        match serde_json::from_slice(&request.body) {
            Ok(Value::Object(body)) => Some(body),
            _ => None,
        }
    };
    let nonce = body.as_ref().and_then(|b| b.get("nonce")).and_then(Value::as_str)
        .filter(|n| n.len() <= MAX_NONCE).unwrap_or("").to_owned();
    let mut response = route(request, body, pairing, engine, allowed_hosts);
    response.signature = pairing.sign_reply(&nonce, &request.method, &request.path, response.status,
                                            &response.json.to_string());
    response
}

fn route(request: &Request, body: Option<Map<String, Value>>, pairing: &mut PairingAuthority, engine: &mut ChatEngine,
         allowed_hosts: &[String]) -> Response {
    // Browsers always send one of these on cross-site or scripted requests; the phone never does.
    for name in ["origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"] {
        if request.header(name) != Ok(None) {
            return error(engine, 403, ProtocolError::Browser.code());
        }
    }
    match request.header("host") {
        Ok(Some(host)) if allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) => {}
        _ => return error(engine, 403, ProtocolError::BadHost.code()),
    }
    let parts: Vec<&str> = request.path.split('/').collect();
    // parts: ["", "v1", …]
    if parts.len() < 3 || !parts[0].is_empty() || parts[1] != "v1" || request.method != "POST" {
        return error(engine, 404, "not found");
    }
    let Some(body) = body else { return error(engine, 400, "body is not a JSON object") };
    post(&parts[2..], &body, pairing, engine)
}

fn post(rest: &[&str], body: &Map<String, Value>, pairing: &mut PairingAuthority, engine: &mut ChatEngine) -> Response {
    let text = |key: &str| body.get(key).and_then(Value::as_str);
    let token = text("token");
    let pairing_id = text("pairing_id");
    let signature = text("signature");
    let counter = body.get("counter").and_then(counter);

    match rest {
        ["pair"] => match pairing.commit(text("code"), text("commitment")) {
            Ok((id, computer_nonce)) => ok(engine, json!({"pairing_id": id, "computer_nonce": computer_nonce})),
            Err(failure) => error(engine, 403, failure.code()),
        },
        ["pair", "reveal"] => match pairing.reveal(pairing_id, text("phone_key"), text("phone_nonce"), signature) {
            Ok((id, token)) => ok(engine, json!({"pairing_id": id, "token": token})),
            Err(failure) => error(engine, 403, failure.code()),
        },
        ["chats", "list"] => match pairing.authorize(token) {
            Ok(_) => Response::new(200, engine.list_json()),
            Err(failure) => error(engine, 403, failure.code()),
        },
        ["pool", "portfolio"] => match pairing.authorize(token) {
            Ok(_) => match engine.pool_portfolio() {
                Ok(view) => Response::new(200, view),
                Err(failure) => error(engine, 409, &failure),
            },
            Err(failure) => error(engine, 403, failure.code()),
        },
        ["chats", id, "view"] => match pairing.authorize(token) {
            Ok(_) => match engine.chat_json(id) {
                Some(view) => Response::new(200, view),
                None => error(engine, 404, ProtocolError::UnknownChat.code()),
            },
            Err(failure) => error(engine, 403, failure.code()),
        },
        ["confirm"] => {
            let (id, decision, firm, digest) = (text("id"), text("decision"), text("firm"), text("digest"));
            if let Err(failure) = pairing.authorize(token) {
                return error(engine, 403, failure.code());
            }
            // The phone signs the digest of what it showed; the computer uses the digest of what it asked.
            let Some(content) = id.and_then(|id| engine.pending_content(id)) else {
                return error(engine, 409, ProtocolError::Stale.code());
            };
            let signed = |p: &str, c: u64| protocol::confirm_message(p, c, id, decision, firm, digest, &content);
            if let Err(failure) = pairing.check(token, pairing_id, counter, signature, id, signed) {
                return error(engine, 409, failure.code());
            }
            match engine.confirm(id, decision, firm, digest) {
                Ok(()) => {
                    if let Some(id) = id {
                        pairing.record_confirmation(id);
                    }
                    ok(engine, json!({}))
                }
                Err(failure) => error(engine, 409, &failure),
            }
        }
        ["chats"] => {
            let message = text("text");
            let signed = |p: &str, c: u64| protocol::chat_message(p, c, None, message);
            if let Err(failure) = pairing.check(token, pairing_id, counter, signature, None, signed) {
                return error(engine, 409, failure.code());
            }
            match engine.create(message.unwrap_or("")) {
                Ok(chat_id) => ok(engine, json!({"chat_id": chat_id})),
                Err(failure) => error(engine, 409, failure.code()),
            }
        }
        ["chats", chat_id, "messages"] => {
            let message = text("text");
            let signed = |p: &str, c: u64| protocol::chat_message(p, c, Some(chat_id), message);
            if let Err(failure) = pairing.check(token, pairing_id, counter, signature, None, signed) {
                return error(engine, 409, failure.code());
            }
            match engine.post(message.unwrap_or(""), chat_id) {
                Ok(()) => ok(engine, json!({})),
                Err(failure) => error(engine, 409, failure.code()),
            }
        }
        ["chats", chat_id, "delete"] => {
            let signed = |p: &str, c: u64| protocol::delete_message(p, c, chat_id);
            if let Err(failure) = pairing.check(token, pairing_id, counter, signature, None, signed) {
                return error(engine, 409, failure.code());
            }
            match engine.delete(chat_id) {
                Ok(()) => ok(engine, json!({})),
                Err(failure) => error(engine, 409, failure.code()),
            }
        }
        _ => error(engine, 404, "not found"),
    }
}

fn ok(engine: &ChatEngine, mut json: Value) -> Response {
    if let Some(object) = json.as_object_mut() {
        object.insert("ok".into(), Value::Bool(true));
        object.insert("mode".into(), Value::String(engine.mode.clone()));
    }
    Response::new(200, json)
}

fn error(engine: &ChatEngine, status: u16, message: &str) -> Response {
    Response::new(status, json!({"ok": false, "error": message, "mode": engine.mode}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::tests::{Paired, Phone};

    const HOST: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn hosts() -> Vec<String> {
        vec![HOST.to_owned(), "127.0.0.1:8790".to_owned()]
    }

    fn request(path: &str, body: Value) -> Request {
        Request { method: "POST".into(), path: path.into(), headers: vec![("host".into(), HOST.into())],
                  body: body.to_string().into_bytes() }
    }

    struct Setup {
        pairing: PairingAuthority,
        engine: ChatEngine,
        phone: Phone,
        paired: Paired,
    }

    impl Setup {
        fn new() -> Self {
            let mut pairing = PairingAuthority::new("PC", None);
            let phone = Phone::new();
            let paired = phone.pair(&mut pairing);
            pairing.confirm_code().unwrap();
            Self { pairing, engine: ChatEngine::with_ona_core(Default::default()), phone, paired }
        }

        fn send(&mut self, request: &Request) -> Response {
            handle(request, &mut self.pairing, &mut self.engine, &hosts())
        }

        fn post(&mut self, path: &str, body: Value) -> Response {
            self.send(&request(path, body))
        }

        fn create(&mut self, text: &str) -> (Value, Response) {
            let counter = self.phone.next();
            let signature = self.phone.sign(&protocol::chat_message(&self.paired.id, counter, None, Some(text)));
            let body = json!({"token": self.paired.token, "pairing_id": self.paired.id, "counter": counter,
                              "text": text, "signature": signature});
            let response = self.post("/v1/chats", body.clone());
            (body, response)
        }

        fn pending(&mut self, chat: &str) -> Value {
            let view = self.post(&format!("/v1/chats/{chat}/view"), json!({"token": self.paired.token}));
            view.json["chat"]["items"].as_array().unwrap().iter().rev().find(|i| i["kind"] == "confirmation").unwrap()["pending"].clone()
        }

        fn confirm_body(&self, pending: &Value, content: &str) -> Value {
            let counter = self.phone.next();
            let id = pending["id"].as_str().unwrap();
            let signature = self.phone.sign(&protocol::confirm_message(&self.paired.id, counter, Some(id), Some("accept"),
                                                                       None, None, content));
            json!({"token": self.paired.token, "pairing_id": self.paired.id, "counter": counter, "id": id,
                   "decision": "accept", "signature": signature})
        }
    }

    #[test]
    fn pairs_over_the_routes_and_signs_every_reply() {
        let mut pairing = PairingAuthority::new("PC", None);
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let phone = Phone::new();
        let code = pairing.pairing_code.clone().unwrap().value;
        let nonce = protocol::random_hex16();
        let request_nonce = protocol::random_hex16();
        let commit = handle(&request("/v1/pair", json!({
            "code": code, "commitment": protocol::commitment(&phone.public_key(), &nonce), "nonce": request_nonce,
        })), &mut pairing, &mut engine, &hosts());
        assert_eq!(commit.status, 200);
        // The phone checks the reply with the key from the QR code.
        let text = commit.json.to_string();
        let key = pairing.computer_public_key();
        let signed = protocol::reply_message(&request_nonce, "POST", "/v1/pair", 200, &text);
        assert!(protocol::verify(commit.signature.as_deref(), &signed, &key));
        // Not valid for another nonce, nor as the reply to another request with the same nonce.
        for other in [protocol::reply_message("other", "POST", "/v1/pair", 200, &text),
                      protocol::reply_message(&request_nonce, "POST", "/v1/chats/list", 200, &text),
                      protocol::reply_message(&request_nonce, "GET", "/v1/pair", 200, &text)] {
            assert!(!protocol::verify(commit.signature.as_deref(), &other, &key));
        }
        let envelope: Value = serde_json::from_str(&commit.body()).unwrap();
        assert_eq!(envelope["reply"], commit.json.to_string());

        let id = commit.json["pairing_id"].as_str().unwrap().to_owned();
        let computer_nonce = commit.json["computer_nonce"].as_str().unwrap().to_owned();
        let proof = phone.sign(&protocol::pair_message(&id, &code, &phone.public_key(), &pairing.computer_public_key(),
                                                       &nonce, &computer_nonce));
        let reveal = handle(&request("/v1/pair/reveal", json!({
            "pairing_id": id, "phone_key": protocol::b64(&phone.public_key()), "phone_nonce": nonce, "signature": proof,
        })), &mut pairing, &mut engine, &hosts());
        assert_eq!(reveal.status, 200);
        let token = reveal.json["token"].as_str().unwrap().to_owned();
        // Not trusted before the codes are compared on the computer.
        let early = handle(&request("/v1/chats/list", json!({"token": token})), &mut pairing, &mut engine, &hosts());
        assert_eq!(early.json["error"], "not paired");
        pairing.confirm_code().unwrap();
        let list = handle(&request("/v1/chats/list", json!({"token": token})), &mut pairing, &mut engine, &hosts());
        assert_eq!(list.status, 200);
    }

    /// Reads need the token; browsers and foreign Host values are refused.
    #[test]
    fn reads_need_the_token_and_browsers_are_refused() {
        let mut setup = Setup::new();
        let (_, created) = setup.create("Find a lawyer");
        let chat = created.json["chat_id"].as_str().unwrap().to_owned();

        for body in [json!({}), json!({"token": "x"})] {
            assert_eq!(setup.post("/v1/chats/list", body.clone()).status, 403);
            assert_eq!(setup.post(&format!("/v1/chats/{chat}/view"), body).status, 403);
        }
        let token = json!({"token": setup.paired.token});
        assert_eq!(setup.post("/v1/chats/list", token.clone()).status, 200);

        let mut rebinding = request("/v1/chats/list", token.clone());
        rebinding.headers = vec![("host".into(), "evil.example:8790".into())];
        assert_eq!(setup.send(&rebinding).json["error"], "unexpected host");
        let mut no_host = request("/v1/chats/list", token.clone());
        no_host.headers.clear();
        assert_eq!(setup.send(&no_host).status, 403);
        let mut browser = request("/v1/chats/list", token.clone());
        browser.headers.push(("origin".into(), "http://evil.example".into()));
        assert_eq!(setup.send(&browser).json["error"], "browser requests are refused");
        let mut fetch = request("/v1/chats/list", token.clone());
        fetch.headers.push(("sec-fetch-site".into(), "same-origin".into()));
        assert_eq!(setup.send(&fetch).status, 403);
        let mut get = request("/v1/chats/list", token);
        get.method = "GET".into();
        assert_eq!(setup.send(&get).status, 404);
        // The protocol v0 routes are gone.
        assert_eq!(setup.post("/v0/chats", json!({})).status, 404);
    }

    /// A recorded request replayed as is (new mission, old confirmations) is refused.
    #[test]
    fn refuses_a_replayed_message_and_a_replayed_confirmation() {
        let mut setup = Setup::new();
        let (body, created) = setup.create("Find a lawyer");
        assert_eq!(created.status, 200);
        assert_eq!(setup.post("/v1/chats", body).json["error"], "replayed request");

        let chat = created.json["chat_id"].as_str().unwrap().to_owned();
        let pending = setup.pending(&chat);
        let content = pending["content"].as_str().unwrap().to_owned();
        let accept = setup.confirm_body(&pending, &content);
        assert_eq!(setup.post("/v1/confirm", accept.clone()).status, 200);
        let again = setup.post("/v1/confirm", accept);
        assert_eq!((again.status, again.json["error"].as_str()), (409, Some("stale confirmation")));
    }

    /// A confirmation signed over other content (another plan, other prices) does not verify.
    #[test]
    fn a_confirmation_signed_over_other_content_is_refused() {
        let mut setup = Setup::new();
        let (_, created) = setup.create("Find a lawyer");
        let chat = created.json["chat_id"].as_str().unwrap().to_owned();
        let pending = setup.pending(&chat);
        let id = pending["id"].as_str().unwrap();
        let shown = protocol::plan_digest(id, &["search".into()]);
        let refused = setup.post("/v1/confirm", setup.confirm_body(&pending, &shown));
        assert_eq!(refused.json["error"], "signature does not verify");
        let content = pending["content"].as_str().unwrap().to_owned();
        assert_eq!(setup.post("/v1/confirm", setup.confirm_body(&pending, &content)).status, 200);
    }

    /// Counters are JSON integers from 0 to 2^53 − 1, as in the macOS app.
    #[test]
    fn counters_are_integers_within_the_shared_bound() {
        let values: Value = serde_json::from_str("[1.0, true, -1, 9007199254740992, 9007199254740991, 7, \"7\"]").unwrap();
        let read: Vec<Option<u64>> = values.as_array().unwrap().iter().map(counter).collect();
        assert_eq!(read, [None, None, None, None, Some(MAX_COUNTER), Some(7), None]);
    }

    /// A header sent with an empty value counts as sent.
    #[test]
    fn an_empty_origin_header_is_still_a_browser() {
        let mut setup = Setup::new();
        let crate::http::Parse::Request(mut request) = crate::http::parse(b"POST /v1/chats/list HTTP/1.0\r\nOrigin:\r\n\r\n") else {
            panic!()
        };
        request.headers.push(("host".into(), HOST.into()));
        request.body = json!({"token": setup.paired.token}).to_string().into_bytes();
        assert_eq!(setup.send(&request).json["error"], "browser requests are refused");
    }

    /// An answer the agent refuses does not block the next answer to the same confirmation.
    #[test]
    fn a_refused_answer_does_not_block_the_confirmation() {
        let mut setup = Setup::new();
        let (_, created) = setup.create("Find a lawyer");
        let chat = created.json["chat_id"].as_str().unwrap().to_owned();
        let pending = setup.pending(&chat);
        let (id, content) = (pending["id"].as_str().unwrap().to_owned(), pending["content"].as_str().unwrap().to_owned());
        let counter = setup.phone.next();
        let signature = setup.phone.sign(&protocol::confirm_message(&setup.paired.id, counter, Some(&id), Some("maybe"),
                                                                    None, None, &content));
        let refused = setup.post("/v1/confirm", json!({"token": setup.paired.token, "pairing_id": setup.paired.id,
            "counter": counter, "id": id, "decision": "maybe", "signature": signature}));
        assert_eq!(refused.json["error"], "bad request");
        assert_eq!(setup.post("/v1/confirm", setup.confirm_body(&pending, &content)).status, 200);
    }

    #[test]
    fn writes_need_the_phone_signature_with_its_counter() {
        let mut setup = Setup::new();
        let (mut body, created) = setup.create("Find a lawyer");
        let chat = created.json["chat_id"].as_str().unwrap().to_owned();
        body["text"] = json!("Paye tout");
        body["counter"] = json!(setup.phone.next());
        assert_eq!(setup.post("/v1/chats", body).json["error"], "signature does not verify");

        let counter = setup.phone.next();
        let wrong_counter = setup.phone.sign(&protocol::delete_message(&setup.paired.id, counter + 1, &chat));
        let body = json!({"token": setup.paired.token, "pairing_id": setup.paired.id, "counter": counter,
                          "signature": wrong_counter});
        assert_eq!(setup.post(&format!("/v1/chats/{chat}/delete"), body).status, 409);
        let deletion = setup.phone.sign(&protocol::delete_message(&setup.paired.id, counter, &chat));
        let body = json!({"token": setup.paired.token, "pairing_id": setup.paired.id, "counter": counter,
                          "signature": deletion});
        assert_eq!(setup.post(&format!("/v1/chats/{chat}/delete"), body).status, 200);
        let gone = setup.post(&format!("/v1/chats/{chat}/view"), json!({"token": setup.paired.token}));
        assert_eq!(gone.status, 404);
    }

    /// A research's queries: the phone signs the digest of the queries it shows and accepts them as shown. The answer
    /// and the actions are shown on the phone; there is no route to carry out an action.
    #[test]
    fn the_phone_accepts_the_queries_it_shows() {
        let mut setup = Setup::new();
        let (_, created) = setup.create("How much does a plumber cost in Lyon? Write to them");
        let chat = created.json["chat_id"].as_str().unwrap().to_owned();
        let pending = setup.pending(&chat);
        assert_eq!(pending["kind"], "queries");
        let id = pending["id"].as_str().unwrap();
        let shown: Vec<String> = pending["queries"].as_array().unwrap().iter().map(|q| q.as_str().unwrap().into()).collect();
        let other = protocol::queries_digest(id, &["something else".into()]);
        assert_eq!(setup.post("/v1/confirm", setup.confirm_body(&pending, &other)).json["error"], "signature does not verify");
        let content = protocol::queries_digest(id, &shown);
        assert_eq!(pending["content"], content);
        assert_eq!(setup.post("/v1/confirm", setup.confirm_body(&pending, &content)).status, 200);

        for _ in 0..40 {
            setup.engine.tick();
        }
        let view = setup.post(&format!("/v1/chats/{chat}/view"), json!({"token": setup.paired.token}));
        let items = view.json["chat"]["items"].as_array().unwrap();
        assert_eq!(view.json["chat"]["status"], "idle");
        assert!(items.iter().any(|i| i["kind"] == "answer"));
        assert!(items.iter().any(|i| i["kind"] == "action" && i["state"] == "suggested"));
        for path in [format!("/v1/chats/{chat}/actions"), "/v1/actions".to_owned(), format!("/v1/chats/{chat}/action")] {
            assert_eq!(setup.post(&path, json!({"token": setup.paired.token, "index": 0, "to": "a@b.example"})).status, 404);
        }
    }

    #[test]
    fn the_pool_portfolio_needs_the_token() {
        let mut setup = Setup::new();
        assert_eq!(setup.post("/v1/pool/portfolio", json!({"token": "x"})).status, 403);
        let token = json!({"token": setup.paired.token});
        let reply = setup.post("/v1/pool/portfolio", token);
        // The real ona-core has no pool wallet here: a signed refusal that names the reason.
        assert_eq!(reply.status, 409);
        assert_eq!(reply.json["error"], "no pool wallet configured");
    }
}
