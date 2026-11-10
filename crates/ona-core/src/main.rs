//! `ona`: reads one JSON request per line on stdin and prints one JSON reply per line.
//! `ona demo` runs a full mission against the fakes. `ona real` uses the real model, configured by
//! the `ONA_REAL_*` variables: only then does anything here touch a network. Never a chain.

use std::io::{self, BufRead};

use ona_core::remote::RemoteConfig;
use ona_core::Core;
use serde_json::{json, Value};

fn run_demo() {
    let mut core = Core::new();
    let mut send = |request: Value| -> Value {
        let reply = core.dispatch(&request.to_string());
        println!("> {request}\n< {reply}");
        serde_json::from_str(&reply).unwrap_or(Value::Null)
    };
    send(json!({"cmd":"open","mission":"Trouver un avocat en droit du travail"}));
    send(json!({"cmd":"propose_plan"}));
    send(json!({"cmd":"accept_plan"}));
    send(json!({"cmd":"search","template":"lawyer","value":"paris"}));
    send(json!({"cmd":"read","handle":"h1"}));
    send(json!({"cmd":"read","handle":"h2"}));
    send(json!({"cmd":"compare"}));
    send(json!({"cmd":"confirm_recipient","firm":"cabinet-b"}));
    send(json!({"cmd":"contact","message":"Bonjour, demande de devis pour un litige prud'homal."}));
    let prepared = send(json!({"cmd":"prepare_payment","amount":"1000000000000000000000000"}));
    send(json!({"cmd":"confirm_payment","digest":prepared["digest"]}));
    send(json!({"cmd":"pay"}));
    send(json!({"cmd":"close"}));
    send(json!({"cmd":"exposure"}));
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("demo") {
        run_demo();
        return;
    }
    let mut core = Core::new();
    if std::env::args().nth(1).as_deref() == Some("real") {
        if let Err(e) = RemoteConfig::from_env().and_then(|config| core.use_real_model(config)) {
            eprintln!("cannot use the real model: {e}");
            std::process::exit(1);
        }
    }
    for line in io::stdin().lock().lines() {
        match line {
            Ok(request) => println!("{}", core.dispatch(&request)),
            Err(e) => {
                eprintln!("cannot read stdin: {e}");
                std::process::exit(1);
            }
        }
    }
}
