use ona_tor::{TorProxy, TorTransport};

fn accepted(base: &str) -> bool {
    let proxy = TorProxy::new("127.0.0.1:9050").unwrap();
    TorTransport::new(base, &proxy).is_ok()
}

#[test]
fn numeric_hosts_written_as_names_are_refused() {
    for host in ["https://127.1", "https://2130706433", "https://0x7f.1", "https://example.0x7f"] {
        assert!(!accepted(host), "{host}");
    }
}

#[test]
fn empty_labels_are_refused() {
    let onion = "a".repeat(56);
    for host in [format!("https://{onion}.onion."), "https://example..com".to_string(), "https://.example.com".to_string()] {
        assert!(!accepted(&host), "{host}");
    }
}

#[test]
fn ordinary_names_still_pass() {
    assert!(accepted("https://rpc.testnet.near.org"));
    assert!(accepted(&format!("http://{}.onion", "a".repeat(56))));
}

#[test]
fn ports_with_signs_local_names_and_queries_are_refused() {
    for base in [
        "https://example.com:+443",
        "https://example.com:-1",
        "https://localhost",
        "https://LOCALHOST:443",
        "https://relay.localhost",
        "https://intranet",
        "https://example.com?x",
        "https://example.com/#x",
    ] {
        assert!(!accepted(base), "{base}");
    }
    assert!(accepted("https://example.com:443/v1"));
}
