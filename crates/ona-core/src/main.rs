//! `ona`: reads one JSON request per line on stdin and prints one JSON reply per line.
//! `ona demo` runs a full mission against the fakes. `ona real` uses the real model, configured by
//! the `ONA_REAL_*` variables. With `ONA_WALLET_FILE` set, the pool commands read the pool contract (`ONA_POOL`)
//! through `ONA_RPC_URL` and reach the pool agent at `ONA_POOL_AGENT_URL`. Nothing else touches a network.
//! With `ONA_TOR_SOCKS` set, all of it goes through that local Tor port; without it `ona` says so on stderr, and
//! `ONA_REQUIRE_TOR=1` makes it refuse to start.

use std::io;

use ona_core::pool::PoolClient;
use ona_core::remote::RemoteConfig;
use ona_core::tor::Network;
use ona_core::{serve, Core};
use serde_json::{json, Value};

fn run_demo() {
    let mut core = Core::new();
    let mut send = |request: Value| -> Value {
        let reply = core.dispatch(&request.to_string());
        println!("> {request}\n< {reply}");
        serde_json::from_str(&reply).unwrap_or(Value::Null)
    };
    send(json!({"cmd":"open","mission":"Find an employment lawyer for Mr Dupont","protected":["Mr Dupont"]}));
    send(json!({"cmd":"propose_plan"}));
    send(json!({"cmd":"accept_plan"}));
    send(json!({"cmd":"search","template":"lawyer","value":"paris"}));
    send(json!({"cmd":"read","handle":"h1"}));
    send(json!({"cmd":"read","handle":"h2"}));
    send(json!({"cmd":"compare"}));
    send(json!({"cmd":"confirm_recipient","firm":"cabinet-b"}));
    send(json!({"cmd":"contact","message":"Hello, I would like a quote for an employment dispute."}));
    // No amount: the chosen offer's price, converted with the demo rate.
    let prepared = send(json!({"cmd":"prepare_payment"}));
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
    // Read once: the relay, the pool agent and the RPC nodes all go the same way.
    let network = match Network::from_env() {
        Ok(network) => network,
        Err(e) => {
            eprintln!("cannot start: {e}");
            std::process::exit(1);
        }
    };
    let mut core = Core::new();
    let mut online = false;
    if std::env::args().nth(1).as_deref() == Some("real") {
        if let Err(e) = RemoteConfig::from_env().and_then(|config| core.use_real_model(config, &network)) {
            eprintln!("cannot use the real model: {e}");
            std::process::exit(1);
        }
        online = true;
    }
    match PoolClient::from_env(&network) {
        Ok(Some(pool)) => {
            core.set_pool(pool);
            online = true;
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("cannot open the pool wallet: {e}");
            std::process::exit(1);
        }
    }
    match network.warning() {
        Some(warning) if online => eprintln!("warning: {warning}"),
        _ if online => eprintln!("network: every connection goes through Tor, each request on its own circuit (one per model call)"),
        _ => {}
    }
    if let Err(e) = serve(&mut core, io::stdin().lock(), io::stdout().lock()) {
        eprintln!("cannot read stdin or write stdout: {e}");
        std::process::exit(1);
    }
}
