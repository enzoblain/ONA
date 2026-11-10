//! C ABI around `arti-client`, linked as a static library into the ONA iOS app.
//!
//! Scope: the Tor spike (step 1 of the iOS plan). The Swift side calls these functions from a background thread;
//! every call blocks until done. Every function that returns a `char *` returns a JSON object that the caller must
//! release with `arti_bridge_string_free`. The object always has a boolean `"ok"`; on failure it has `"error"`.
//!
//! The bridge holds one Tor client per process. It never sees an ONA key: it only opens Tor streams.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DormantMode, HasKind, TorClient};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_rtcompat::PreferredRuntime;

type Client = TorClient<PreferredRuntime>;

/// Version of `arti-client` this bridge is built against (kept equal to the pin in Cargo.toml).
const ARTI_CLIENT_VERSION: &str = "0.48.0";

/// Largest response body returned to Swift, in bytes. The rest is counted, not copied.
const MAX_BODY_RETURNED: usize = 4096;

static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
static CLIENT: Mutex<Option<Arc<Client>>> = Mutex::new(None);
static LOGGING: OnceLock<()> = OnceLock::new();

fn runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("arti-bridge")
                .enable_all()
                .build()
                .map_err(|e| format!("tokio runtime: {e}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn current_client() -> Option<Arc<Client>> {
    CLIENT.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

fn set_client(client: Option<Arc<Client>>) {
    *CLIENT.lock().unwrap_or_else(|p| p.into_inner()) = client;
}

/// Runs `f`, turns its result (or a panic) into a JSON C string. Panics must not cross the FFI boundary.
fn ffi(f: impl FnOnce() -> Result<Value, String>) -> *mut c_char {
    let value = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(mut v)) => {
            if !v.is_object() {
                v = json!({ "value": v });
            }
            v["ok"] = Value::Bool(true);
            v
        }
        Ok(Err(error)) => json!({ "ok": false, "error": error }),
        Err(_) => json!({ "ok": false, "error": "panic inside arti-bridge" }),
    };
    // serde_json escapes U+0000, so the string never holds an interior NUL.
    CString::new(value.to_string())
        .unwrap_or_else(|_| CString::from(c"{\"ok\":false,\"error\":\"encoding\"}"))
        .into_raw()
}

/// Reads a C string argument. `name` is only used in the error message.
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated string valid for the duration of the call.
unsafe fn arg(ptr: *const c_char, name: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{name} is null"));
    }
    // SAFETY: guaranteed by the caller (see function contract).
    let s = unsafe { CStr::from_ptr(ptr) };
    s.to_str().map(str::to_owned).map_err(|_| format!("{name} is not UTF-8"))
}

fn arti_error(context: &str, e: &arti_client::Error) -> String {
    format!("{context}: {e} (kind: {:?})", e.kind())
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Sends Arti's logs to stderr (visible in the Xcode console). `filter` uses the `RUST_LOG` syntax, e.g. "info".
/// Only the first call has an effect.
///
/// # Safety
/// `filter` must be null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arti_bridge_init_logging(filter: *const c_char) {
    let filter = unsafe { arg(filter, "filter") }.unwrap_or_else(|_| "info".to_owned());
    LOGGING.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .try_init();
    });
}

/// `{"ok":true,"bridge":"…","arti_client":"…"}`
#[unsafe(no_mangle)]
pub extern "C" fn arti_bridge_version() -> *mut c_char {
    ffi(|| Ok(json!({ "bridge": env!("CARGO_PKG_VERSION"), "arti_client": ARTI_CLIENT_VERSION })))
}

/// Creates the Tor client and bootstraps it. Blocks until the client can carry traffic.
///
/// `state_dir` and `cache_dir` must be writable directories inside the app sandbox. Arti's file-permission checks
/// (fs-mistrust) are disabled: on iOS the sandbox already isolates the app, and the app does not control the
/// permissions of the container's parent directories.
///
/// Returns `{"ok":true,"bootstrap_ms":N}`, or `{"ok":true,"already_started":true}` if a client exists.
///
/// # Safety
/// Both arguments must be NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arti_bridge_bootstrap(state_dir: *const c_char, cache_dir: *const c_char) -> *mut c_char {
    let state_dir = unsafe { arg(state_dir, "state_dir") };
    let cache_dir = unsafe { arg(cache_dir, "cache_dir") };
    ffi(move || {
        let (state_dir, cache_dir) = (PathBuf::from(state_dir?), PathBuf::from(cache_dir?));
        if current_client().is_some() {
            return Ok(json!({ "already_started": true }));
        }
        let rt = runtime()?;
        let started = Instant::now();

        let client = rt.block_on(async {
            let mut builder = TorClientConfigBuilder::from_directories(&state_dir, &cache_dir);
            builder.storage().permissions().dangerously_trust_everyone();
            let config = builder.build().map_err(|e| format!("config: {e}"))?;
            TorClient::builder()
                .config(config)
                .create_unbootstrapped_async()
                .await
                .map_err(|e| arti_error("create client", &e))
        })?;
        // Stored before bootstrapping so that `arti_bridge_status` can report progress meanwhile.
        set_client(Some(client.clone()));

        if let Err(e) = rt.block_on(client.bootstrap()) {
            set_client(None);
            return Err(arti_error("bootstrap", &e));
        }
        Ok(json!({ "bootstrap_ms": millis(started.elapsed()) }))
    })
}

/// `{"ok":true,"started":bool,"progress":0.0..1.0,"ready":bool,"description":"…"}`. Never blocks for long.
#[unsafe(no_mangle)]
pub extern "C" fn arti_bridge_status() -> *mut c_char {
    ffi(|| {
        Ok(match current_client() {
            None => json!({ "started": false, "progress": 0.0, "ready": false, "description": "not started" }),
            Some(client) => {
                let status = client.bootstrap_status();
                json!({
                    "started": true,
                    "progress": status.as_frac(),
                    "ready": status.ready_for_traffic(),
                    "description": status.to_string(),
                })
            }
        })
    })
}

/// Opens a Tor stream to `host:port` (a `.onion` address or a regular host), sends a plain HTTP/1.0 GET for `path`
/// and reads the whole response. Gives up after `timeout_ms`.
///
/// Returns `{"ok":true,"connect_ms":N,"total_ms":N,"status_line":"…","bytes":N,"body":"…"}`. `body` holds at most
/// the first 4096 bytes of the response body (lossy UTF-8).
///
/// # Safety
/// `host` and `path` must be NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arti_bridge_http_get(
    host: *const c_char,
    port: u16,
    path: *const c_char,
    timeout_ms: u64,
) -> *mut c_char {
    let host = unsafe { arg(host, "host") };
    let path = unsafe { arg(path, "path") };
    ffi(move || {
        let (host, path) = (host?, path?);
        if host.contains(['\r', '\n']) || path.contains(['\r', '\n']) || !path.starts_with('/') {
            return Err("invalid host or path".to_owned());
        }
        let client = current_client().ok_or("Tor client not started")?;
        let rt = runtime()?;

        rt.block_on(async {
            let started = Instant::now();
            let request = async {
                let mut stream = client
                    .connect((host.as_str(), port))
                    .await
                    .map_err(|e| arti_error("connect", &e))?;
                let connect_ms = millis(started.elapsed());

                let request = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                stream.write_all(request.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
                stream.flush().await.map_err(|e| format!("flush: {e}"))?;

                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.map_err(|e| format!("read: {e}"))?;
                Ok::<_, String>((connect_ms, response))
            };
            let (connect_ms, response) = tokio::time::timeout(Duration::from_millis(timeout_ms), request)
                .await
                .map_err(|_| format!("timed out after {timeout_ms} ms"))??;

            let text = String::from_utf8_lossy(&response);
            let status_line = text.lines().next().unwrap_or_default().to_owned();
            let body = match text.split_once("\r\n\r\n") {
                Some((_, body)) => body,
                None => "",
            };
            let body: String = body.chars().scan(0usize, |n, c| {
                *n += c.len_utf8();
                (*n <= MAX_BODY_RETURNED).then_some(c)
            }).collect();
            Ok(json!({
                "connect_ms": connect_ms,
                "total_ms": millis(started.elapsed()),
                "status_line": status_line,
                "bytes": response.len(),
                "body": body,
            }))
        })
    })
}

/// Soft dormant mode suspends Arti's background tasks (to call when the app goes to the background).
/// Using the client wakes it up again. No effect if no client exists.
#[unsafe(no_mangle)]
pub extern "C" fn arti_bridge_set_dormant(dormant: bool) {
    if let Some(client) = current_client() {
        client.set_dormant(if dormant { DormantMode::Soft } else { DormantMode::Normal });
    }
}

/// Drops the process's Tor client. A later `arti_bridge_bootstrap` creates a new one (warm start if the directories
/// still hold Arti's cache).
#[unsafe(no_mangle)]
pub extern "C" fn arti_bridge_shutdown() {
    set_client(None);
}

/// Releases a string returned by this library. Null is accepted.
///
/// # Safety
/// `s` must be null or a pointer returned by this library, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arti_bridge_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: the pointer comes from `CString::into_raw` in `ffi` (see function contract).
        drop(unsafe { CString::from_raw(s) });
    }
}
