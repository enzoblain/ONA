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
