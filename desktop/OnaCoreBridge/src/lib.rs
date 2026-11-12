//! C ABI around `ona-core`, linked as a static library into the ONA macOS app.
//!
//! One `Core` per conversation: the app creates it with `ona_core_new`, sends JSON commands with `ona_core_dispatch`
//! (the same commands as `ona-core`'s `Core::dispatch`, e.g. `{"cmd":"open","mission":"…"}`) and releases it with
//! `ona_core_free`. Strings returned by the library are released with `ona_core_string_free`.
//!
//! `ona_core_new` keeps `ona-core`'s default model (the fake, labelled `mode: mock`). `ona_core_new_with` takes the
//! app's settings and makes the core use the real model through the relay, every connection through the app's tor; a
//! setting that cannot be used gives a core that refuses every command with the reason (never a silent fake). Calls
//! are synchronous; the app runs them off the main thread. A handle must not be used from two threads at once.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use ona_core::Core as OnaCore;

/// What the C side holds (`OnaCore *`, opaque): the core, and whether a panic left it unusable.
pub struct Core {
    core: OnaCore,
    /// Why the real model could not be set up: every command is refused with it.
    refusal: Option<String>,
    /// Set after a panic inside ona-core: its state (gate, journal) may be half changed, so it is not used again.
    poisoned: bool,
}

const POISONED: &str = r#"{"ok":false,"error":"ona-core stopped after an internal error: start a new mission","mode":"mock"}"#;
const PANIC: &str = r#"{"ok":false,"error":"panic inside ona-core","mode":"mock"}"#;

impl Core {
    /// Runs `run` on the core unless it is poisoned; a panic poisons it.
    fn guarded(&mut self, run: impl FnOnce(&mut OnaCore) -> String) -> String {
        if let Some(reason) = &self.refusal {
            return serde_json::json!({"ok": false, "error": reason, "mode": "real"}).to_string();
        }
        if self.poisoned {
            return POISONED.to_owned();
        }
        let core = &mut self.core;
        match catch_unwind(AssertUnwindSafe(|| run(core))) {
            Ok(reply) => reply,
            Err(_) => {
                self.poisoned = true;
                PANIC.to_owned()
            }
        }
    }
}

/// Creates a core. Never null.
#[unsafe(no_mangle)]
pub extern "C" fn ona_core_new() -> *mut Core {
    Box::into_raw(Box::new(Core { core: OnaCore::new(), refusal: None, poisoned: false }))
}

/// Creates a core from the app's settings, a JSON object: `{"model": null}` for the fake model, or
/// `{"model": {"relay_url", "model", "max_tokens", "token_budget", "tokens_file"}, "core_socks": <tor's port or null>}`
/// for the real one (the names of `ona real`, docs/INSTALL.md), or `{"error": "<why>"}` when the app could not read its
/// settings. Never null.
///
/// # Safety
/// `setup` must be a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ona_core_new_with(setup: *const c_char) -> *mut Core {
    let made = if setup.is_null() {
        Err("null argument".to_owned())
    } else {
        // SAFETY: see function contract.
        let text = unsafe { CStr::from_ptr(setup) }.to_string_lossy().into_owned();
        catch_unwind(|| core_from_setup(&text)).unwrap_or_else(|_| Err("panic inside ona-core".to_owned()))
    };
    let core = match made {
        Ok(core) => Core { core, refusal: None, poisoned: false },
        Err(reason) => Core { core: OnaCore::new(), refusal: Some(reason), poisoned: false },
    };
    Box::into_raw(Box::new(core))
}

fn core_from_setup(text: &str) -> Result<OnaCore, String> {
    let setup: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("settings: {e}"))?;
    // The app could not read its settings file: it says why, and the core refuses rather than run the fake.
    if let Some(reason) = setup["error"].as_str() {
        return Err(reason.to_owned());
    }
    let model = &setup["model"];
    if model.is_null() {
        return Ok(OnaCore::new());
    }
    let socks = setup["core_socks"]
        .as_u64()
        .ok_or("le vrai modèle passe par Tor : choisissez le mode Tor, et attendez que le code QR apparaisse")?;
    // ONA_REQUIRE_TOR: nothing the core sends may go straight to its destination.
    let network = ona_core::tor::Network::from_values(Some(&format!("127.0.0.1:{socks}")), Some("1"))?;
    let field = |key: &str| -> Option<String> {
        match &model[key] {
            serde_json::Value::String(text) => Some(text.clone()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        }
    };
    let config = ona_core::remote::RemoteConfig::from_lookup(|name| match name {
        "ONA_REAL_RELAY_URL" => field("relay_url"),
        "ONA_REAL_MODEL" => field("model"),
        "ONA_REAL_MAX_TOKENS" => field("max_tokens"),
        "ONA_REAL_TOKEN_BUDGET" => field("token_budget"),
        "ONA_REAL_TOKENS_FILE" => field("tokens_file"),
        _ => None,
    })?;
    let mut core = OnaCore::new();
    core.use_real_model(config, &network)?;
    Ok(core)
}

/// Releases a core created by `ona_core_new`. Null is accepted.
///
/// # Safety
/// `core` must be null or a pointer returned by `ona_core_new`, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ona_core_free(core: *mut Core) {
    if !core.is_null() {
        // SAFETY: see function contract.
        drop(unsafe { Box::from_raw(core) });
    }
}

/// Runs one JSON command and returns the JSON reply (always an object with `"ok"`).
///
/// # Safety
/// `core` must come from `ona_core_new`; `request` must be a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ona_core_dispatch(core: *mut Core, request: *const c_char) -> *mut c_char {
    let reply = if core.is_null() || request.is_null() {
        r#"{"ok":false,"error":"null argument","mode":"mock"}"#.to_owned()
    } else {
        // SAFETY: see function contract.
        let request = unsafe { CStr::from_ptr(request) }.to_string_lossy().into_owned();
        // SAFETY: see function contract; no other thread uses this handle meanwhile.
        let core = unsafe { &mut *core };
        core.guarded(|core| core.dispatch(&request))
    };
    // JSON escapes U+0000, so the reply holds no interior NUL.
    CString::new(reply).unwrap_or_else(|_| CString::from(c"{\"ok\":false,\"error\":\"encoding\"}")).into_raw()
}

/// Releases a string returned by `ona_core_dispatch`. Null is accepted.
///
/// # Safety
/// `s` must be null or a pointer returned by this library, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ona_core_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: see function contract.
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(core: *mut Core, request: &str) -> serde_json::Value {
        let request = CString::new(request).unwrap();
        let reply = unsafe { ona_core_dispatch(core, request.as_ptr()) };
        let text = unsafe { CStr::from_ptr(reply) }.to_string_lossy().into_owned();
        unsafe { ona_core_string_free(reply) };
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn runs_the_demo_mission_through_the_c_abi() {
        let core = ona_core_new();
        assert_eq!(call(core, r#"{"cmd":"open","mission":"Trouver un avocat"}"#)["ok"], true);
        let plan = call(core, r#"{"cmd":"propose_plan"}"#);
        assert_eq!(plan["plan"][0], "search");
        assert_eq!(call(core, r#"{"cmd":"accept_plan"}"#)["ok"], true);
        let handles = call(core, r#"{"cmd":"search","template":"lawyer","value":"paris"}"#);
        assert_eq!(handles["handles"].as_array().unwrap().len(), 2);
        let prepared = {
            call(core, r#"{"cmd":"read","handle":"h1"}"#);
            call(core, r#"{"cmd":"read","handle":"h2"}"#);
            call(core, r#"{"cmd":"compare"}"#);
            call(core, r#"{"cmd":"confirm_recipient","firm":"cabinet-b"}"#);
            call(core, r#"{"cmd":"contact","message":"Bonjour"}"#);
            // No amount: ona-core takes the chosen offer's price × the policy's rate.
            call(core, r#"{"cmd":"prepare_payment"}"#)
        };
        // Payment digest v2: bound to the mission and to a fresh nonce, so it changes at every payment.
        let digest = prepared["digest"].as_str().unwrap();
        assert!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()), "{prepared}");
        assert_eq!(prepared["payment"]["to"], "cabinet-b.testnet");
        assert_eq!(prepared["payment"]["nonce"].as_str().map(str::len), Some(32));
        assert!(prepared["payment"]["mission_id"].is_string());
        // The gate refuses a confirmation that does not match the payment screen.
        assert_eq!(call(core, r#"{"cmd":"confirm_payment","digest":"00"}"#)["ok"], false);
        unsafe { ona_core_free(core) };
    }

    /// After a panic, the same core is not used again.
    #[test]
    fn a_core_that_panicked_is_not_used_again() {
        let core = ona_core_new();
        // SAFETY: pointer from ona_core_new, not shared.
        let handle = unsafe { &mut *core };
        let reply = handle.guarded(|_| panic!("inside ona-core"));
        assert!(reply.contains("panic inside ona-core"));
        assert!(call(core, r#"{"cmd":"open","mission":"Trouver un avocat"}"#)["error"].as_str().unwrap().contains("stopped"));
        unsafe { ona_core_free(core) };
    }

    fn new_with(setup: serde_json::Value) -> *mut Core {
        let setup = CString::new(setup.to_string()).unwrap();
        unsafe { ona_core_new_with(setup.as_ptr()) }
    }

    #[test]
    fn without_a_model_setting_the_core_is_the_fake() {
        let core = new_with(serde_json::json!({"model": null}));
        assert_eq!(call(core, r#"{"cmd":"exposure"}"#)["mode"], "mock");
        unsafe { ona_core_free(core) };
    }

    #[test]
    fn a_real_model_that_cannot_be_set_up_refuses_everything() {
        let model = serde_json::json!({"relay_url": "https://relay.example.org", "model": "m", "max_tokens": 200,
            "token_budget": 2000, "tokens_file": "/nonexistent/tokens"});
        for (setup, reason) in [
            (serde_json::json!({"model": model, "core_socks": null}), "Tor"),
            (serde_json::json!({"model": model, "core_socks": 9050}), "ONA_REAL_TOKENS_FILE"),
            (serde_json::json!({"model": {"relay_url": "http://example.org"}, "core_socks": 9050}), "missing"),
            (serde_json::json!({"error": "model.json : unreadable"}), "unreadable"),
        ] {
            let core = new_with(setup);
            let reply = call(core, r#"{"cmd":"open","mission":"Trouver un avocat"}"#);
            assert_eq!(reply["mode"], "real");
            assert!(reply["error"].as_str().unwrap().contains(reason), "{reply}");
            unsafe { ona_core_free(core) };
        }
    }

    #[test]
    fn the_real_model_is_set_up_through_tor() {
        let tokens = std::env::temp_dir().join(format!("ona-bridge-tokens-{}", std::process::id()));
        std::fs::write(&tokens, "token-1\n").unwrap();
        std::fs::set_permissions(&tokens, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let core = new_with(serde_json::json!({"model": {"relay_url": "https://relay.example.org", "model": "m",
            "max_tokens": 200, "token_budget": 2000, "tokens_file": tokens}, "core_socks": 9}));
        // SAFETY: pointer from ona_core_new_with, not shared.
        assert_eq!(unsafe { &*core }.refusal, None);
        unsafe { ona_core_free(core) };
        let _ = std::fs::remove_file(tokens);
    }

    #[test]
    fn refuses_bad_input_without_crashing() {
        let core = ona_core_new();
        assert_eq!(call(core, "not json")["ok"], false);
        assert_eq!(call(core, r#"{"cmd":"pay"}"#)["ok"], false);
        let reply = unsafe { ona_core_dispatch(std::ptr::null_mut(), c"{}".as_ptr()) };
        assert!(!reply.is_null());
        unsafe { ona_core_string_free(reply) };
        unsafe { ona_core_free(core) };
    }
}
