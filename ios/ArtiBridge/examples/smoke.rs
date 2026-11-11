//! Smoke test of the C ABI on the Mac: bootstrap Arti, then GET http://<host>/ over Tor.
//! Usage: cargo run --release --example smoke -- <host> [port] [state-root]
//! (host can be a .onion address; default port 80; default state root: a temporary directory)

use std::ffi::{CStr, CString, c_char};

use arti_bridge::*;

fn take(s: *mut c_char) -> String {
    let out = unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned();
    unsafe { arti_bridge_string_free(s) };
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).expect("usage: smoke <host> [port] [state-root]");
    let port: u16 = args.get(2).map_or(80, |p| p.parse().expect("port"));
    let root = args
        .get(3)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("arti-bridge-smoke"));

    unsafe { arti_bridge_init_logging(c"warn".as_ptr()) };
    println!("{}", take(arti_bridge_version()));

    let state = CString::new(root.join("state").to_str().unwrap()).unwrap();
    let cache = CString::new(root.join("cache").to_str().unwrap()).unwrap();
    println!("bootstrap: {}", take(unsafe { arti_bridge_bootstrap(state.as_ptr(), cache.as_ptr()) }));
    println!("status: {}", take(arti_bridge_status()));

    let host = CString::new(host.as_str()).unwrap();
    for i in 1..=2 {
        let r = take(unsafe { arti_bridge_http_get(host.as_ptr(), port, c"/".as_ptr(), 120_000) });
        println!("get #{i}: {r}");
    }
    arti_bridge_shutdown();
}
