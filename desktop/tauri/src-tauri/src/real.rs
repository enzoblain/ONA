//! The real model: ona-core's planner and page reader call NEAR AI through the relay, and every connection the core
//! opens goes through this app's own tor.
//!
//! It is chosen by a file, `model.json`, in the app's data folder (docs/desktop/tauri.md, "Real model"). Without the
//! file, the core keeps its fake model (`mode: mock`) and the app shows the simulation banner. With the file, a core is
//! real or it is not made: a wrong setting, or tor not running yet, gives a core that refuses every command with the
//! reason, never a silent fake. The NEAR AI key is not here: the relay holds it. The app only spends request tokens.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::engine::{Guarded, MissionCore};

pub const FILE: &str = "model.json";

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
    /// `ONA_REAL_TOKENS_FILE`: one request token per line, readable by its owner only.
    pub tokens_file: PathBuf,
}

impl ModelSettings {
    /// None when there is no file (the fake model); Err when there is one that cannot be read.
    pub fn load(data_dir: &Path) -> Result<Option<Self>, String> {
        let text = match std::fs::read_to_string(data_dir.join(FILE)) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{FILE} : {e}")),
        };
        serde_json::from_str(&text).map(Some).map_err(|e| format!("{FILE} : {e}"))
    }

    fn lookup(&self, name: &str) -> Option<String> {
        Some(match name {
            "ONA_REAL_RELAY_URL" => self.relay_url.clone(),
            "ONA_REAL_MODEL" => self.model.clone(),
            "ONA_REAL_MAX_TOKENS" => self.max_tokens.to_string(),
            "ONA_REAL_TOKEN_BUDGET" => self.token_budget.to_string(),
            "ONA_REAL_TOKENS_FILE" => self.tokens_file.to_string_lossy().into_owned(),
            _ => return None,
        })
    }
}

/// What a new core needs, shared between the worker (which knows tor's port) and the chat engine (which makes cores).
pub struct CoreSetup {
    /// `model.json`: None for the fake model, Err when the file is unreadable.
    pub model: Result<Option<ModelSettings>, String>,
    /// tor's SOCKS port for the core's own traffic, once tor runs.
    pub core_socks: Option<u16>,
}

impl Default for CoreSetup {
    fn default() -> Self {
        Self { model: Ok(None), core_socks: None }
    }
}

pub type SharedSetup = Rc<RefCell<CoreSetup>>;

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

fn real_core(settings: &ModelSettings, core_socks: Option<u16>) -> Result<ona_core::Core, String> {
    let socks = core_socks.ok_or("le vrai modèle passe par Tor : choisissez le mode Tor, et attendez que le code QR apparaisse")?;
    // ONA_REQUIRE_TOR: nothing the core sends may go straight to its destination.
    let network = ona_core::tor::Network::from_values(Some(&format!("127.0.0.1:{socks}")), Some("1"))?;
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
            tokens_file,
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
        let mut core = make_core(&CoreSetup { model, core_socks: Some(9050) });
        let reply = core.dispatch(json!({"cmd": "exposure"}));
        assert_eq!((reply["ok"].clone(), reply["mode"].clone()), (json!(false), json!("real")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_real_model_waits_for_tor() {
        let mut core = make_core(&CoreSetup { model: Ok(Some(settings("/nonexistent".into()))), core_socks: None });
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
}
