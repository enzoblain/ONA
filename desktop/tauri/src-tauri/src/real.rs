//! The real model: ona-core's planner and page reader call NEAR AI through the relay, and every connection the core
//! opens goes through this app's own tor.
//!
//! It is chosen by a file, `model.json`, in the app's data folder (docs/desktop/tauri.md, "Real model"). Without the
//! file, the core keeps its fake model (`mode: mock`) and the app shows the simulation banner. With the file, a core is
//! real or it is not made: a wrong setting, or tor not running yet, gives a core that refuses every command with the
//! reason, never a silent fake. The NEAR AI key is not here: the relay holds it. The app only spends request tokens.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::engine::{Guarded, MissionCore};

pub const FILE: &str = "model.json";
pub const POOL_FILE: &str = "pool.json";

/// Reads a settings file of the data folder: None when it does not exist, Err when it cannot be read.
fn load_settings<T: serde::de::DeserializeOwned>(data_dir: &Path, name: &str) -> Result<Option<T>, String> {
    let text = match std::fs::read_to_string(data_dir.join(name)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{name} : {e}")),
    };
    serde_json::from_str(&text).map(Some).map_err(|e| format!("{name} : {e}"))
}

/// `pool.json`: the pool wallet (docs/desktop/pool-commands.md, "Setup"; the names of `ona`'s variables).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolSettings {
    /// `ONA_WALLET_FILE`: the encrypted wallet, created if missing.
    pub wallet_file: PathBuf,
    /// `ONA_WALLET_KEY_FILE`: 64 hex characters, readable by its owner only.
    pub wallet_key_file: PathBuf,
    /// `ONA_POOL`: the pool contract account.
    pub pool: String,
    /// `ONA_RPC_URL`.
    pub rpc_url: String,
    /// `ONA_RPC_URL_2`, a second endpoint run by another operator.
    #[serde(default)]
    pub rpc_url_2: Option<String>,
    /// `ONA_POOL_RECOMMENDED_NEAR`.
    #[serde(default)]
    pub recommended_near: Option<String>,
    /// `ONA_POOL_AGENT_URL`.
    #[serde(default)]
    pub agent_url: Option<String>,
    /// A local test node and agent on this computer (for example Hugo's `ona-sandbox-pool`): no Tor, `http` to
    /// 127.0.0.1. Development builds only; a release build refuses it.
    #[serde(default)]
    pub local_node: bool,
}

impl PoolSettings {
    pub fn load(data_dir: &Path) -> Result<Option<Self>, String> {
        load_settings(data_dir, POOL_FILE)
    }

    fn lookup(&self, name: &str) -> Option<String> {
        match name {
            "ONA_WALLET_FILE" => Some(self.wallet_file.to_string_lossy().into_owned()),
            "ONA_WALLET_KEY_FILE" => Some(self.wallet_key_file.to_string_lossy().into_owned()),
            "ONA_POOL" => Some(self.pool.clone()),
            "ONA_RPC_URL" => Some(self.rpc_url.clone()),
            "ONA_RPC_URL_2" => self.rpc_url_2.clone(),
            "ONA_POOL_RECOMMENDED_NEAR" => self.recommended_near.clone(),
            "ONA_POOL_AGENT_URL" => self.agent_url.clone(),
            _ => None,
        }
    }
}

/// `model.json`. The names are those of `ona real` (docs/INSTALL.md, "Use the real model").
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSettings {
    /// `ONA_REAL_RELAY_URL`.
    pub relay_url: String,
    /// `ONA_REAL_MODEL`.
    pub model: String,
    /// `ONA_REAL_MAX_TOKENS`.
    pub max_tokens: u32,
    /// `ONA_REAL_TOKEN_BUDGET`, for each conversation.
    pub token_budget: u64,
    /// `ONA_REAL_TOKENS_FILE`: one request token per line, readable by its owner only. Optional: a test relay may ask
    /// for none (`ona-relay` refuses a chat without one).
    #[serde(default)]
    pub tokens_file: Option<PathBuf>,
}

impl ModelSettings {
    /// None when there is no file (the fake model); Err when there is one that cannot be read.
    pub fn load(data_dir: &Path) -> Result<Option<Self>, String> {
        load_settings(data_dir, FILE)
    }

    /// The relay's onion address without `.onion`, when it is one: the app's tor presents its client key to it, in
    /// case the relay is published for named clients only (docs/TOR.md, "onion client authorization").
    pub fn relay_onion(&self) -> Option<String> {
        let rest = self.relay_url.strip_prefix("http://")?;
        let host = rest.split(['/', ':']).next()?;
        ona_core::tor::is_onion_v3(host).then(|| host.trim_end_matches(".onion").to_owned())
    }

    fn lookup(&self, name: &str) -> Option<String> {
        Some(match name {
            "ONA_REAL_RELAY_URL" => self.relay_url.clone(),
            "ONA_REAL_MODEL" => self.model.clone(),
            "ONA_REAL_MAX_TOKENS" => self.max_tokens.to_string(),
            "ONA_REAL_TOKEN_BUDGET" => self.token_budget.to_string(),
            "ONA_REAL_TOKENS_FILE" => self.tokens_file.as_ref()?.to_string_lossy().into_owned(),
            _ => return None,
        })
    }
}

/// What a new core needs, shared between the worker (which knows tor's port) and the chat engine (which makes cores).
pub struct CoreSetup {
    /// `model.json`: None for the fake model, Err when the file is unreadable.
    pub model: Result<Option<ModelSettings>, String>,
    /// `pool.json`: None without a pool wallet, Err when the file is unreadable.
    pub pool: Result<Option<PoolSettings>, String>,
    /// tor's SOCKS port for the core's own traffic, once tor runs.
    pub core_socks: Option<u16>,
}

impl Default for CoreSetup {
    fn default() -> Self {
        Self { model: Ok(None), pool: Ok(None), core_socks: None }
    }
}

pub type SharedSetup = Arc<Mutex<CoreSetup>>;

/// Makes one ona-core as `setup` says: the fake model, or the real one through tor.
pub fn make_core(setup: &CoreSetup) -> Box<dyn MissionCore> {
    let settings = match &setup.model {
        Ok(None) => return Box::new(Guarded::new(ona_core::Core::new())),
        Ok(Some(settings)) => settings,
        Err(e) => return Box::new(Refusing(e.clone())),
    };
    match real_core(settings, setup.core_socks) {
        Ok(core) => Box::new(Guarded::new(core)),
        Err(e) => Box::new(Refusing(e)),
    }
}

/// Through the app's tor only (`ONA_REQUIRE_TOR`): nothing the core sends may go straight to its destination.
fn network(core_socks: Option<u16>, what: &str) -> Result<ona_core::tor::Network, String> {
    let socks = core_socks.ok_or_else(|| format!("{what} passe par Tor : choisissez le mode Tor, et attendez que le code QR apparaisse"))?;
    ona_core::tor::Network::from_values(Some(&format!("127.0.0.1:{socks}")), Some("1"))
}

/// The core that answers the pool commands: one for the whole app (the wallet file is locked by the core that opens
/// it). Without `pool.json` it answers `no pool wallet configured`, like `ona` without a wallet.
pub fn make_pool_core(setup: &CoreSetup) -> Box<dyn MissionCore> {
    let settings = match &setup.pool {
        Ok(None) => return Box::new(Guarded::new(ona_core::Core::new())),
        Ok(Some(settings)) => settings,
        Err(e) => return Box::new(Refusing(e.clone())),
    };
    let network = if settings.local_node {
        if cfg!(debug_assertions) {
            ona_core::tor::Network::from_values(None, Some("0"))
        } else {
            Err("pool.json : local_node est réservé aux versions de développement".to_owned())
        }
    } else {
        network(setup.core_socks, "le pool")
    };
    let made = network.and_then(|network| {
        let client = ona_core::pool::PoolClient::from_lookup(|name| Ok(settings.lookup(name)), &network)?
            .ok_or("pool.json : no wallet file")?;
        let mut core = ona_core::Core::new();
        core.set_pool(client);
        Ok(core)
    });
    match made {
        Ok(core) => Box::new(Guarded::new(core)),
        Err(e) => Box::new(Refusing(e)),
    }
}

fn real_core(settings: &ModelSettings, core_socks: Option<u16>) -> Result<ona_core::Core, String> {
    let network = network(core_socks, "le vrai modèle")?;
    let config = ona_core::remote::RemoteConfig::from_lookup(|name| settings.lookup(name))?;
    let mut core = ona_core::Core::new();
    core.use_real_model(config, &network)?;
    Ok(core)
}

/// A core that could not be made real: it answers every command with the reason, in real mode.
struct Refusing(String);

impl MissionCore for Refusing {
    fn dispatch(&mut self, _request: Value) -> Value {
        json!({"ok": false, "error": self.0, "mode": "real"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ona-real-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn settings(tokens_file: PathBuf) -> ModelSettings {
        ModelSettings {
            relay_url: "https://relay.example.org".into(),
            model: "test-model".into(),
            max_tokens: 200,
            token_budget: 2000,
            tokens_file: Some(tokens_file),
        }
    }

    #[test]
    fn no_file_means_the_fake_model() {
        let dir = temp_dir("none");
        assert_eq!(ModelSettings::load(&dir), Ok(None));
        let mut core = make_core(&CoreSetup::default());
        assert_eq!(core.dispatch(json!({"cmd": "exposure"}))["mode"], "mock");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_broken_file_is_reported_not_ignored() {
        let dir = temp_dir("broken");
        std::fs::write(dir.join(FILE), r#"{"relay_url": "x", "unknown": 1}"#).unwrap();
        let model = ModelSettings::load(&dir);
        assert!(model.as_ref().is_err_and(|e| e.starts_with(FILE)), "{model:?}");
        let mut core = make_core(&CoreSetup { model, pool: Ok(None), core_socks: Some(9050) });
        let reply = core.dispatch(json!({"cmd": "exposure"}));
        assert_eq!((reply["ok"].clone(), reply["mode"].clone()), (json!(false), json!("real")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_real_model_waits_for_tor() {
        let mut core = make_core(&CoreSetup { model: Ok(Some(settings("/nonexistent".into()))), pool: Ok(None), core_socks: None });
        let reply = core.dispatch(json!({"cmd": "open", "mission": "x"}));
        assert_eq!(reply["mode"], "real");
        assert!(reply["error"].as_str().unwrap().contains("Tor"), "{reply}");
    }

    #[test]
    fn the_real_model_goes_through_tor_with_its_tokens() {
        let dir = temp_dir("real");
        let tokens = dir.join("tokens");
        std::fs::write(&tokens, "token-1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tokens, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(dir.join(FILE), serde_json::to_string(&json!({
            "relay_url": "https://relay.example.org", "model": "test-model", "max_tokens": 200, "token_budget": 2000,
            "tokens_file": tokens,
        })).unwrap()).unwrap();
        let model = ModelSettings::load(&dir);
        assert_eq!(model, Ok(Some(settings(tokens.clone()))));
        // Nothing listens on that port: the core is made (real), and fails only when it calls the relay.
        let real = real_core(&settings(tokens), Some(9));
        assert!(real.is_ok(), "{:?}", real.err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn without_pool_json_the_pool_is_not_configured() {
        let mut core = make_pool_core(&CoreSetup::default());
        assert_eq!(core.dispatch(json!({"cmd": "pool_portfolio"}))["error"], "no pool wallet configured");
    }

    #[test]
    fn the_pool_waits_for_tor_and_reads_its_settings() {
        let dir = temp_dir("pool");
        std::fs::write(dir.join(POOL_FILE), r#"{"wallet_file": "/w", "wallet_key_file": "/k", "pool": "pool.testnet",
            "rpc_url": "https://rpc.testnet.near.org"}"#).unwrap();
        let pool = PoolSettings::load(&dir);
        assert_eq!(pool.as_ref().map(|p| p.as_ref().map(|p| p.pool.clone())), Ok(Some("pool.testnet".into())));
        let mut waiting = make_pool_core(&CoreSetup { model: Ok(None), pool: pool.clone(), core_socks: None });
        assert!(waiting.dispatch(json!({"cmd": "pool_portfolio"}))["error"].as_str().unwrap().contains("Tor"));
        // With tor, ona-core reads the key file: missing here, so refused with ona-core's reason.
        let mut refused = make_pool_core(&CoreSetup { model: Ok(None), pool, core_socks: Some(9) });
        let reply = refused.dispatch(json!({"cmd": "pool_portfolio"}));
        assert_eq!((reply["ok"].clone(), reply["mode"].clone()), (json!(false), json!("real")));
        assert!(reply["error"].as_str().unwrap().contains("wallet key"), "{reply}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_relay_without_request_tokens_and_its_onion() {
        let onion = format!("{}.onion", "a".repeat(56));
        let settings: ModelSettings = serde_json::from_value(json!({
            "relay_url": format!("http://{onion}/"), "model": "m", "max_tokens": 200, "token_budget": 2000,
        })).unwrap();
        assert_eq!(settings.tokens_file, None);
        assert_eq!(settings.relay_onion(), Some("a".repeat(56)));
        assert!(real_core(&settings, Some(9)).is_ok(), "no tokens file is allowed");
        let https = ModelSettings { relay_url: "https://relay.example.org".into(), ..settings };
        assert_eq!(https.relay_onion(), None);
    }

    /// A local test node: no Tor (development builds), `http` to 127.0.0.1 accepted by ona-core.
    #[test]
    fn a_local_node_pool_goes_direct_in_development_builds() {
        let settings = PoolSettings {
            wallet_file: "/w".into(), wallet_key_file: "/nonexistent/key".into(), pool: "pool.test.near".into(),
            rpc_url: "http://127.0.0.1:3030".into(), rpc_url_2: None, recommended_near: None,
            agent_url: Some("http://127.0.0.1:8790".into()), local_node: true,
        };
        let mut core = make_pool_core(&CoreSetup { model: Ok(None), pool: Ok(Some(settings)), core_socks: None });
        let error = core.dispatch(json!({"cmd": "pool_portfolio"}))["error"].as_str().unwrap().to_owned();
        assert!(error.contains("wallet key"), "past the network checks, stopped at the key file: {error}");
    }

    /// Against a running local pool (`ona-sandbox-pool --serve`, docs/INSTALL.md): the window's path, from `pool.json`
    /// through the engine's pool thread to the contract and the agent. Run by hand:
    /// `ONA_TEST_POOL_DIR=<its folder> cargo test -- --ignored local_pool`.
    #[test]
    #[ignore]
    fn local_pool_through_the_engine() {
        let dir = std::path::PathBuf::from(std::env::var("ONA_TEST_POOL_DIR").expect("ONA_TEST_POOL_DIR"));
        let pool = PoolSettings::load(&dir).unwrap().expect("pool.json");
        assert!(pool.local_node);
        let setup = std::sync::Arc::new(std::sync::Mutex::new(CoreSetup { model: Ok(None), pool: Ok(Some(pool)), core_socks: None }));
        let mut engine = crate::engine::ChatEngine::with_ona_core(setup);
        let sender = engine.pool_sender();
        let ask = |request: Value| -> Value {
            let (reply, answer) = std::sync::mpsc::channel();
            sender.send((request.clone(), reply)).unwrap();
            let value = answer.recv().unwrap();
            println!("{request} -> {value}");
            value
        };
        let portfolio = ask(json!({"cmd": "pool_portfolio"}));
        assert_eq!(portfolio["ok"], true);
        assert_eq!(portfolio["cash"]["value"], "12000000000000000000000000", "the 12 NEAR deposited by --serve");
        // Only this wallet's notes are in circulation: each hides among the notes of its value, its own included.
        let privacy = ask(json!({"cmd": "pool_privacy"}));
        assert_eq!(privacy["ok"], true);
        assert!(privacy["wallet"]["smallest_set"].as_u64().is_some_and(|n| n >= 1), "{privacy}");
        assert!(privacy["vaults"][0]["if_entered"].as_u64().is_some(), "{privacy}");
        let prepared = ask(json!({"cmd": "pool_prepare", "op": "enter", "vault": 0, "amount": "10000000000000000000000000"}));
        assert_eq!(prepared["ok"], true);
        let executed = ask(json!({"cmd": "pool_execute", "prepared_id": prepared["prepared_id"]}));
        let queued = executed["error"].as_str().is_some_and(|e| e.contains("outcome unknown"));
        assert!(executed["complete"] == true || queued, "{executed}");
        // The agent sends the entry in its next batch: --serve ticks it every two seconds.
        let mut entered = false;
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let recover = ask(json!({"cmd": "pool_recover"}));
            let portfolio = ask(json!({"cmd": "pool_portfolio"}));
            if recover["still_spending"] == 0 && portfolio["vaults"].as_array().is_some_and(|v| !v.is_empty()) {
                entered = true;
                break;
            }
        }
        assert!(entered, "the entry into vault 0 did not complete");
    }
}
