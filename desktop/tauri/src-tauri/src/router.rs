//! The phone protocol (docs/ios/protocol-draft.md) on top of the pairing authority and the chat engine.
//! Every request that changes something must be signed by the paired, verified phone.

use serde_json::{Map, Value, json};

use crate::engine::ChatEngine;
use crate::http::{Request, Response};
use crate::pairing::{PairingAuthority, ProtocolError};
use crate::protocol;

pub fn handle(request: &Request, pairing: &mut PairingAuthority, engine: &mut ChatEngine) -> Response {
    let parts: Vec<&str> = request.path.split('/').collect();
    // parts: ["", "v0", …]
    if parts.len() < 3 || !parts[0].is_empty() || parts[1] != "v0" {
        return error(engine, 404, "not found");
    }
    let rest = &parts[2..];
    match (request.method.as_str(), rest) {
        ("GET", ["chats"]) => match pairing.read_refusal() {
            Some(failure) => error(engine, 403, failure.code()),
            None => Response::new(200, engine.list_json()),
        },
        ("GET", ["chats", id]) => match pairing.read_refusal() {
            Some(failure) => error(engine, 403, failure.code()),
            None => match engine.chat_json(id) {
                Some(view) => Response::new(200, view),
                None => error(engine, 404, ProtocolError::UnknownChat.code()),
            },
        },
        ("POST", _) => {
            let body = if request.body.is_empty() { Ok(Value::Object(Map::new())) } else { serde_json::from_slice(&request.body) };
            match body {
                Ok(Value::Object(body)) => post(rest, &body, pairing, engine),
                _ => error(engine, 400, "body is not a JSON object"),
            }
        }
        _ => error(engine, 404, "not found"),
    }
}

fn post(rest: &[&str], body: &Map<String, Value>, pairing: &mut PairingAuthority, engine: &mut ChatEngine) -> Response {
    let text = |key: &str| body.get(key).and_then(Value::as_str);
    let pairing_id = text("pairing_id");
    let signature = text("signature");

    match rest {
        ["pair"] => match pairing.pair(text("code"), text("phone_key"), signature) {
            Ok(id) => ok(engine, json!({"pairing_id": id})),
            Err(failure) => error(engine, 403, failure.code()),
        },
        ["confirm"] => {
            let (id, decision, firm, digest) = (text("id"), text("decision"), text("firm"), text("digest"));
            if let Err(failure) = pairing.check(pairing_id, signature, |p| protocol::confirm_message(p, id, decision, firm, digest)) {
                return error(engine, 409, failure.code());
            }
            match engine.confirm(id, decision, firm, digest) {
                Ok(()) => ok(engine, json!({})),
                Err(failure) => error(engine, 409, &failure),
            }
        }
        ["chats"] => {
            let message = text("text");
            if let Err(failure) = pairing.check(pairing_id, signature, |p| protocol::chat_message(p, None, message)) {
                return error(engine, 409, failure.code());
            }
            match engine.create(message.unwrap_or("")) {
                Ok(chat_id) => ok(engine, json!({"chat_id": chat_id})),
                Err(failure) => error(engine, 409, failure.code()),
            }
        }
        ["chats", chat_id, "messages"] => {
            let message = text("text");
            if let Err(failure) = pairing.check(pairing_id, signature, |p| protocol::chat_message(p, Some(chat_id), message)) {
                return error(engine, 409, failure.code());
            }
            match engine.post(message.unwrap_or(""), chat_id) {
                Ok(()) => ok(engine, json!({})),
                Err(failure) => error(engine, 409, failure.code()),
            }
        }
        ["chats", chat_id, "delete"] => {
            if let Err(failure) = pairing.check(pairing_id, signature, |p| protocol::delete_message(p, chat_id)) {
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
    use crate::pairing::tests::Phone;

    fn request(method: &str, path: &str, body: Value) -> Request {
        Request { method: method.into(), path: path.into(), body: body.to_string().into_bytes() }
    }

    #[test]
    fn serves_a_paired_phone_and_refuses_everyone_else() {
        let mut pairing = PairingAuthority::new("PC", None);
        let mut engine = ChatEngine::with_ona_core();
        let phone = Phone::new();

        let refused = handle(&request("GET", "/v0/chats", json!({})), &mut pairing, &mut engine);
        assert_eq!((refused.status, refused.json["error"].as_str()), (403, Some("not paired")));

        let code = pairing.pairing_code.clone().unwrap();
        let proof = phone.sign(&protocol::pair_message(&code, &phone.public_key(), &pairing.computer_public_key()));
        let paired = handle(&request("POST", "/v0/pair", json!({
            "code": code, "phone_key": protocol::b64(&phone.public_key()), "signature": proof,
        })), &mut pairing, &mut engine);
        assert_eq!(paired.status, 200);
        let id = paired.json["pairing_id"].as_str().unwrap().to_owned();

        let text = "Trouve un avocat";
        let signature = phone.sign(&protocol::chat_message(&id, None, Some(text)));
        let body = json!({"pairing_id": id, "text": text, "signature": signature});
        let early = handle(&request("POST", "/v0/chats", body.clone()), &mut pairing, &mut engine);
        assert_eq!(early.json["error"], "pairing not verified");

        pairing.confirm_code();
        let created = handle(&request("POST", "/v0/chats", body), &mut pairing, &mut engine);
        assert_eq!((created.status, created.json["chat_id"].as_str()), (200, Some("chat-1")));

        let forged = json!({"pairing_id": id, "text": "Paye tout", "signature": signature});
        let refused = handle(&request("POST", "/v0/chats", forged), &mut pairing, &mut engine);
        assert_eq!((refused.status, refused.json["error"].as_str()), (409, Some("signature does not verify")));

        let list = handle(&request("GET", "/v0/chats", json!({})), &mut pairing, &mut engine);
        assert_eq!(list.json["chats"][0]["status"], "waiting");
        let view = handle(&request("GET", "/v0/chats/chat-1", json!({})), &mut pairing, &mut engine);
        let pending = view.json["chat"]["items"].as_array().unwrap().iter().find(|i| i["kind"] == "confirmation").unwrap()["pending"].clone();
        let pending_id = pending["id"].as_str().unwrap();

        let signature = phone.sign(&protocol::confirm_message(&id, Some(pending_id), Some("accept"), None, None));
        let confirmed = handle(&request("POST", "/v0/confirm", json!({
            "pairing_id": id, "id": pending_id, "decision": "accept", "signature": signature,
        })), &mut pairing, &mut engine);
        assert_eq!(confirmed.status, 200);

        let signature = phone.sign(&protocol::delete_message(&id, "chat-1"));
        let deleted = handle(&request("POST", "/v0/chats/chat-1/delete", json!({"pairing_id": id, "signature": signature})),
                             &mut pairing, &mut engine);
        assert_eq!(deleted.status, 200);
        let gone = handle(&request("GET", "/v0/chats/chat-1", json!({})), &mut pairing, &mut engine);
        assert_eq!(gone.status, 404);
    }
}
