//! The money guardrails through `Core::dispatch`, as the apps reach them: a research pays only a recipient the person
//! allowed with `payees`, and `research_open` checks that list.

use ona_core::Core;
use serde_json::{json, Value};

fn call(core: &mut Core, request: Value) -> Value {
    serde_json::from_str(&core.dispatch(&request.to_string())).unwrap()
}

const QUESTION: &str = "Trouve un plombier à Lyon et écris-lui pour un devis, paie 0.1 NEAR d'acompte";

/// A research run to its answer, with `payees` as given; returns the payment action's index.
fn answered(core: &mut Core, payees: Value) -> u64 {
    let opened = call(core, json!({"cmd": "research_open", "question": QUESTION, "payees": payees}));
    assert_eq!(opened["ok"], true, "{opened}");
    assert_eq!(call(core, json!({"cmd": "research_propose"}))["ok"], true);
    assert_eq!(call(core, json!({"cmd": "research_accept", "queries": ["plombier Lyon"]}))["ok"], true);
    for _ in 0..20 {
        if call(core, json!({"cmd": "research_step"}))["done"] == true {
            break;
        }
    }
    let result = call(core, json!({"cmd": "research_result"}));
    let actions = result["actions"].as_array().expect("actions");
    actions.iter().find(|a| a["kind"] == "payment").expect("a payment is suggested")["index"].as_u64().unwrap()
}

#[test]
fn an_allowed_payee_is_paid_and_another_is_refused() {
    let mut core = Core::new();
    let index = answered(&mut core, json!([" Plomberie.testnet "]));
    let refused = call(&mut core, json!({"cmd": "research_action_prepare", "index": index, "to": "autre.testnet"}));
    assert_eq!(refused["ok"], false);
    assert!(refused["error"].as_str().unwrap().contains("not in the list"), "{refused}");
    let prepared = call(&mut core, json!({"cmd": "research_action_prepare", "index": index, "to": "plomberie.testnet"}));
    assert_eq!(prepared["ok"], true, "the allowed name was trimmed and lowercased: {prepared}");
    let confirmed = call(&mut core, json!({"cmd": "research_action_confirm", "digest": prepared["digest"]}));
    assert_eq!(confirmed["ok"], true);
    let done = call(&mut core, json!({"cmd": "research_action_do"}));
    assert_eq!(done["done"], "payment", "{done}");
}

#[test]
fn without_payees_only_the_directory_can_be_paid() {
    let mut core = Core::new();
    let index = answered(&mut core, json!([]));
    let refused = call(&mut core, json!({"cmd": "research_action_prepare", "index": index, "to": "plomberie.testnet"}));
    assert_eq!(refused["ok"], false, "{refused}");
}

#[test]
fn a_bad_payee_list_is_refused_at_open() {
    let mut core = Core::new();
    let too_many: Vec<String> = (0..=ona_core::MAX_PAYEES).map(|i| format!("p{i}.testnet")).collect();
    for payees in [json!(too_many), json!([42]), json!(["pas un compte!"])] {
        let opened = call(&mut core, json!({"cmd": "research_open", "question": QUESTION, "payees": payees}));
        assert_eq!(opened["ok"], false, "{opened}");
    }
}
