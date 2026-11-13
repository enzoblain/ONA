//! Where the client's traffic goes: through a local Tor daemon over SOCKS5, with name resolution left to Tor, or straight
//! to its destinations. `Network::from_env` reads `ONA_TOR_SOCKS` (and `ONA_REQUIRE_TOR`); every connection the client
//! opens to the relay, the pool agent or a NEAR RPC node is then built by the `Network`. See `docs/TOR.md`.
//!
//! Through Tor there is no direct path: every agent built here has the proxy set, so if Tor is down or refuses a
//! connection the request fails, and nothing is tried another way. Every request gets its own random SOCKS username and
//! password: with Tor's `IsolateSOCKSAuth` (on by default) streams with different credentials use different circuits,
//! so no two requests, and in particular no two operations of the pool (a cash issue naming an account, an entry into
//! a vault), share a circuit. This is Tor's documented behaviour, not verified here on the real network. No
//! `User-Agent` header is sent, no redirect is followed, no proxy is read from the environment.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use ureq::config::AutoHeaderValue;
use ureq::{Agent, Proxy};

use crate::e2ee::{HttpTransport, ResponseWithHeaders, Transport};

/// Tor's usual SOCKS port. See `docs/torrc.client.example`.
pub const DEFAULT_SOCKS: &str = "127.0.0.1:9050";
/// Said on stderr by `ona` when it starts the real model or the pool without Tor.
pub const DIRECT_WARNING: &str =
    "Tor is not configured (ONA_TOR_SOCKS is not set): the relay, Intel's collateral service, the pool agent and the NEAR RPC nodes see this computer's IP address";
/// Reaching the destination through Tor. The first connection to an onion service fetches its descriptor and builds
/// a rendezvous circuit: measured at about a minute on 13/11/2026, and the first try went past 120 s.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(240);
/// Each later step of a request: sending it, waiting for the reply (a model thinking), reading the reply.
const STEP_TIMEOUT: Duration = Duration::from_secs(120);
const ONION_V3_LEN: usize = 56;

/// A version 3 onion address (56 base32 characters, then `.onion`), in lowercase.
pub fn is_onion_v3(host: &str) -> bool {
    host.strip_suffix(".onion").is_some_and(|name| {
        name.len() == ONION_V3_LEN && name.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    })
}

/// Whether `url` names a `.onion` host, in any case, with or without a port or a user name.
fn names_onion(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h).trim_end_matches('.');
    host.to_ascii_lowercase().ends_with(".onion")
}

/// Allows only destinations that stay private over Tor: `http` to an onion service, whose
/// transport is already encrypted by Tor, or `https` to a host name. Plain `http` to the public
/// internet would be readable at the Tor exit, and an IP address cannot pass Tor's `SafeSocks`.
pub fn check_destination(url: &str) -> Result<(), String> {
    let (scheme, rest) = url.split_once("://").ok_or("destination has no scheme")?;
    // A base address needs no query or fragment; appended paths would land inside them.
    if rest.contains(['?', '#']) {
        return Err("destination must not have a query or a fragment".into());
    }
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        // Digits only: `"+443".parse::<u16>()` succeeds.
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok() => host,
        Some(_) => return Err("destination has an invalid port".into()),
        None => authority,
    }
    .to_ascii_lowercase();

    let valid_name = !host.is_empty()
        && host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && host.split('.').all(|label| !label.is_empty());
    if !valid_name {
        return Err("destination must be a plain host name".into());
    }
    // `127.1`, `2130706433` and `0x7f.1` are IP addresses to many resolvers.
    let last = host.rsplit('.').next().unwrap_or_default();
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return Err("destination must be a host name, not an IP address".into());
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err("destination must be a host name, not an IP address".into());
    }
    // These name this machine or a local network, never a destination reached through Tor.
    if host == "localhost" || host.ends_with(".localhost") || !host.contains('.') {
        return Err("destination must be a public host name or an onion address".into());
    }
    if host.ends_with(".onion") && !is_onion_v3(&host) {
        return Err("not a valid version 3 onion address".into());
    }
    match scheme {
        "https" => Ok(()),
        "http" if is_onion_v3(&host) => Ok(()),
        "http" => Err("plain http is only allowed to an onion service".into()),
        _ => Err("destination scheme must be http or https".into()),
    }
}

/// A Tor SOCKS port on this machine. A remote proxy is refused: the link to it is not encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorProxy {
    addr: SocketAddr,
}

impl TorProxy {
    pub fn new(addr: &str) -> Result<Self, String> {
        let addr: SocketAddr = addr.parse().map_err(|_| "Tor proxy must be ip:port".to_string())?;
        if !addr.ip().is_loopback() {
            return Err("Tor proxy must be on this machine".into());
        }
        Ok(Self { addr })
    }

    /// Opens one connection to `url` through Tor and returns the HTTP status, reading no body. Meant for an onion
    /// service about to be used (the relay): Tor then has its descriptor and introduction circuits ready, so the first
    /// real request does not wait about a minute for them. Sends a bare `GET` with no header the caller chose.
    pub fn warm_up(&self, url: &str) -> Result<u16, String> {
        check_destination(url)?;
        let response = self.agent()?.get(url).call().map_err(|e| e.to_string())?;
        Ok(response.status().as_u16())
    }

    /// Redirects are off: following one could send a request somewhere the caller did not check.
    /// New random SOCKS credentials for each agent, so Tor keeps its streams on their own circuit.
    fn agent(&self) -> Result<Agent, String> {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let (user, password) = hex.split_at(16);
        let proxy = Proxy::new(&format!("socks5h://{user}:{password}@{}", self.addr)).map_err(|e| e.to_string())?;
        Ok(Agent::config_builder()
            .proxy(Some(proxy))
            .user_agent(AutoHeaderValue::None)
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_send_request(Some(STEP_TIMEOUT))
            .timeout_send_body(Some(STEP_TIMEOUT))
            .timeout_recv_response(Some(STEP_TIMEOUT))
            .timeout_recv_body(Some(STEP_TIMEOUT))
            .build()
            .into())
    }
}

/// The encrypted model client's transport, through Tor. Compression stays off, as in `HttpTransport`, because the
/// reply signature covers the exact bytes. Each request draws new SOCKS credentials, so each has its own circuit.
pub struct TorTransport {
    base: String,
    proxy: TorProxy,
}

impl TorTransport {
    pub fn new(base: &str, proxy: &TorProxy) -> Result<Self, String> {
        check_destination(base)?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), proxy: proxy.clone() })
    }

    /// A path not starting with `/` could extend the host name once appended to the base.
    fn url(&self, path: &str) -> Result<String, String> {
        if !path.starts_with('/') {
            return Err("path must start with /".into());
        }
        Ok(format!("{}{path}", self.base))
    }
}

impl Transport for TorTransport {
    fn get(&mut self, path: &str, headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        let mut request = self.proxy.agent()?.get(self.url(path)?);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let mut response = request.call().map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let body = response.body_mut().read_to_vec().map_err(|e| e.to_string())?;
        Ok((status, body))
    }

    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        let mut request = self.proxy.agent()?.post(self.url(path)?);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let mut response = request.send(body).map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let reply = response.body_mut().read_to_vec().map_err(|e| e.to_string())?;
        Ok((status, reply))
    }

    fn get_with_headers(
        &mut self,
        path: &str,
        headers: &[(String, String)],
        wanted: &[&str],
    ) -> Result<ResponseWithHeaders, String> {
        crate::e2ee::ureq_get(&self.proxy.agent()?, &self.url(path)?, headers, wanted)
    }
}

/// A NEAR RPC client whose reads and signed transactions all leave through Tor, with credentials of its own: one
/// circuit for this client.
pub fn near_client(url: &str, key: SigningKey, proxy: &TorProxy) -> Result<ona_near::Client, String> {
    check_destination(url)?;
    Ok(ona_near::Client::with_agent(url, key, proxy.agent()?))
}

/// How the client reaches the network, chosen once at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    /// Straight to each destination. An onion address is refused: resolving it here would leak the name.
    Direct,
    /// Everything through this local Tor SOCKS port, each request on its own circuit.
    Tor(TorProxy),
}

impl Network {
    /// `ONA_TOR_SOCKS` (`ip:port` on this machine) sends everything through Tor. `ONA_REQUIRE_TOR=1` refuses to start
    /// without it.
    pub fn from_env() -> Result<Self, String> {
        let read = |name: &str| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{name} is not valid text")),
        };
        Self::from_values(read("ONA_TOR_SOCKS")?.as_deref(), read("ONA_REQUIRE_TOR")?.as_deref())
    }

    /// `from_env` on given values.
    pub fn from_values(socks: Option<&str>, require: Option<&str>) -> Result<Self, String> {
        let require = match require.map(str::trim) {
            None | Some("" | "0") => false,
            Some("1") => true,
            Some(_) => return Err("ONA_REQUIRE_TOR must be 0 or 1".into()),
        };
        match socks.map(str::trim).filter(|s| !s.is_empty()) {
            Some(addr) => Ok(Self::Tor(TorProxy::new(addr).map_err(|e| format!("ONA_TOR_SOCKS: {e}"))?)),
            None if require => Err("ONA_REQUIRE_TOR=1 but ONA_TOR_SOCKS is not set: refusing to start without Tor".into()),
            None => Ok(Self::Direct),
        }
    }

    /// What to tell the user at start when nothing goes through Tor.
    pub fn warning(&self) -> Option<&'static str> {
        matches!(self, Self::Direct).then_some(DIRECT_WARNING)
    }

    pub fn is_tor(&self) -> bool {
        matches!(self, Self::Tor(_))
    }

    /// Checks a destination for this network: through Tor, `check_destination`; directly, anything but an onion address.
    pub fn check(&self, url: &str) -> Result<(), String> {
        match self {
            Self::Tor(_) => check_destination(url),
            Self::Direct if names_onion(url) => Err("an onion address is reached only through Tor: set ONA_TOR_SOCKS".into()),
            Self::Direct => Ok(()),
        }
    }

    /// A transport to `base`.
    pub fn transport(&self, base: &str) -> Result<NetTransport, String> {
        self.check(base)?;
        Ok(match self {
            Self::Direct => NetTransport::Direct(HttpTransport::new(base)),
            Self::Tor(proxy) => NetTransport::Tor(TorTransport::new(base, proxy)?),
        })
    }

    /// A NEAR RPC client to `url`. Directly, `url` must pass `ona_near::check_rpc_url`.
    pub fn near_client(&self, url: &str, key: SigningKey) -> Result<ona_near::Client, String> {
        self.check(url)?;
        match self {
            Self::Direct => ona_near::Client::connect(url, key).map_err(|e| e.to_string()),
            Self::Tor(proxy) => near_client(url, key, proxy),
        }
    }
}

/// A transport built by a `Network`.
pub enum NetTransport {
    Direct(HttpTransport),
    Tor(TorTransport),
}

impl Transport for NetTransport {
    fn get(&mut self, path: &str, headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        match self {
            Self::Direct(t) => t.get(path, headers),
            Self::Tor(t) => t.get(path, headers),
        }
    }
    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        match self {
            Self::Direct(t) => t.post(path, headers, body),
            Self::Tor(t) => t.post(path, headers, body),
        }
    }
    fn get_with_headers(
        &mut self,
        path: &str,
        headers: &[(String, String)],
        wanted: &[&str],
    ) -> Result<ResponseWithHeaders, String> {
        match self {
            Self::Direct(t) => t.get_with_headers(path, headers, wanted),
            Self::Tor(t) => t.get_with_headers(path, headers, wanted),
        }
    }
}

#[cfg(test)]
mod tests {
    //! These need a destination that would reach a local canary if traffic escaped the proxy, which
    //! the destination check refuses, so they build the transport without it.
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn canary() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    fn assert_untouched(listener: &TcpListener) {
        thread::sleep(Duration::from_millis(200));
        assert!(listener.accept().is_err(), "a connection bypassed the proxy");
    }

    fn dead_proxy() -> TorProxy {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        TorProxy::new(&format!("127.0.0.1:{port}")).unwrap()
    }

    /// A fake proxy: answers the greeting with `reply`, then refuses the connection if asked.
    /// Returns the proxy and the number of connections it received.
    fn socks(reply: &'static [u8], refuse_connect: bool) -> (TorProxy, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                counted.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(reply);
                if refuse_connect {
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
                }
            }
        });
        (TorProxy::new(&addr.to_string()).unwrap(), connections)
    }

    fn unchecked(port: u16, proxy: &TorProxy) -> TorTransport {
        TorTransport { base: format!("https://localhost:{port}"), proxy: proxy.clone() }
    }

    #[test]
    fn fails_closed_when_tor_is_not_running() {
        let (listener, port) = canary();
        let mut transport = unchecked(port, &dead_proxy());
        assert!(transport.get("/", &[]).is_err());
        assert!(transport.post("/", &[], b"secret").is_err());
        assert_untouched(&listener);
    }

    #[test]
    fn fails_closed_when_tor_refuses_the_connection() {
        let (listener, port) = canary();
        let (proxy, connections) = socks(&[5, 0], true);
        let mut transport = unchecked(port, &proxy);
        assert!(transport.post("/", &[], b"secret").is_err());
        thread::sleep(Duration::from_millis(100));
        assert_eq!(connections.load(Ordering::SeqCst), 1, "a refusal must not be retried another way");
        assert_untouched(&listener);
    }

    const ONION: &str = "http://sjhetbu5onalbe2fviq2xbtxrzni3km4bygbqmo33ac5ap2t5yepolyd.onion";

    #[test]
    fn the_first_connection_to_an_onion_may_take_longer_than_one_step() {
        let timeouts = dead_proxy().agent().unwrap().config().timeouts();
        assert_eq!(timeouts.global, None, "a global limit would also cover the connection");
        assert_eq!(timeouts.connect, Some(CONNECT_TIMEOUT));
        assert!(CONNECT_TIMEOUT > STEP_TIMEOUT);
        for step in [timeouts.send_request, timeouts.send_body, timeouts.recv_response, timeouts.recv_body] {
            assert_eq!(step, Some(STEP_TIMEOUT), "every step after the connection stays bounded");
        }
    }

    #[test]
    fn a_warm_up_goes_through_tor_only() {
        let (proxy, connections) = socks(&[5, 0], true);
        assert!(proxy.warm_up(ONION).is_err());
        thread::sleep(Duration::from_millis(100));
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert!(dead_proxy().warm_up(ONION).is_err(), "no direct fallback when tor is down");
    }

    #[test]
    fn a_warm_up_refuses_what_tor_cannot_carry_privately() {
        let (proxy, connections) = socks(&[5, 0], true);
        for url in ["http://example.com", "https://127.0.0.1", "http://localhost:8080"] {
            assert!(proxy.warm_up(url).is_err(), "{url}");
        }
        assert_eq!(connections.load(Ordering::SeqCst), 0, "refused before anything is sent");
    }

    #[test]
    fn fails_closed_when_the_proxy_does_not_speak_socks() {
        let (listener, port) = canary();
        let (proxy, _) = socks(b"HTTP/1.1 400 Bad Request\r\n\r\n", false);
        let mut transport = unchecked(port, &proxy);
        assert!(transport.get("/", &[]).is_err());
        assert_untouched(&listener);
    }

    #[test]
    fn near_rpc_fails_closed_when_tor_is_not_running() {
        let (listener, port) = canary();
        let agent = dead_proxy().agent().unwrap();
        let client = ona_near::Client::with_agent(&format!("https://localhost:{port}"), SigningKey::from_bytes(&[7; 32]), agent);
        assert!(client.post("status", serde_json::json!([])).is_err());
        assert_untouched(&listener);
    }

    // The environment's proxy variables are ignored: the agent's proxy is the Tor port, set explicitly.
    #[test]
    fn each_agent_gets_its_own_socks_credentials() {
        let proxy = TorProxy::new("127.0.0.1:9050").unwrap();
        let (a, b) = (proxy.agent().unwrap(), proxy.agent().unwrap());
        let user = |agent: &Agent| agent.config().proxy().and_then(|p| p.username()).map(String::from);
        let host = |agent: &Agent| agent.config().proxy().map(|p| (p.host().to_string(), p.port()));
        assert!(user(&a).is_some());
        assert_ne!(user(&a), user(&b), "two agents must not share a circuit");
        assert_eq!(host(&a), Some(("127.0.0.1".to_string(), 9050)));
    }

    #[test]
    fn the_network_comes_from_two_variables() {
        assert_eq!(Network::from_values(None, None).unwrap(), Network::Direct);
        assert_eq!(Network::from_values(Some(" "), Some("0")).unwrap(), Network::Direct);
        assert!(Network::from_values(None, None).unwrap().warning().is_some(), "said at start");
        let tor = Network::from_values(Some("127.0.0.1:9050"), None).unwrap();
        assert!(tor.is_tor() && tor.warning().is_none());
        assert!(Network::from_values(None, Some("1")).unwrap_err().contains("refusing to start without Tor"));
        assert!(Network::from_values(Some("127.0.0.1:9050"), Some("1")).unwrap().is_tor());
        assert!(Network::from_values(Some("10.0.0.2:9050"), None).is_err(), "a proxy on another machine");
        assert!(Network::from_values(Some("localhost:9050"), None).is_err());
        assert!(Network::from_values(None, Some("yes")).is_err());
    }

    // Without Tor an onion name is never handed to the local resolver.
    #[test]
    fn a_direct_network_refuses_onion_addresses() {
        let onion = format!("{}.onion", "a".repeat(56));
        for url in [format!("http://{onion}"), format!("https://{}:443/x", onion.to_uppercase()), format!("http://u@{onion}."), "https://x.onion".into()] {
            assert!(Network::Direct.check(&url).is_err(), "{url}");
            assert!(Network::Direct.transport(&url).is_err(), "{url}");
            assert!(Network::Direct.near_client(&url, SigningKey::from_bytes(&[7; 32])).is_err(), "{url}");
        }
        assert!(Network::Direct.check("http://127.0.0.1:8787").is_ok());
        assert!(Network::Direct.near_client("http://example.com", SigningKey::from_bytes(&[7; 32])).is_err(), "plain http off this machine");
    }

    // Through Tor a local address, a plain http host or an IP is refused before anything is sent.
    #[test]
    fn a_tor_network_refuses_what_tor_cannot_carry_privately() {
        let tor = Network::Tor(TorProxy::new("127.0.0.1:9050").unwrap());
        for url in ["http://127.0.0.1:8787", "http://localhost:3030", "http://rpc.example.org", "https://1.2.3.4"] {
            assert!(tor.transport(url).is_err(), "{url}");
            assert!(tor.near_client(url, SigningKey::from_bytes(&[7; 32])).is_err(), "{url}");
        }
        assert!(tor.transport(&format!("http://{}.onion", "a".repeat(56))).is_ok());
        assert!(tor.near_client("https://rpc.testnet.near.org", SigningKey::from_bytes(&[7; 32])).is_ok());
    }
}
