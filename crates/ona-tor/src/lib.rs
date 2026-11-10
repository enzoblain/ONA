//! Sends ONA's traffic through a local Tor daemon, over SOCKS5 with name resolution left to Tor.
//!
//! There is no direct path in this crate: every agent it builds has the proxy set, so if Tor is
//! down or refuses a connection the request fails. See `docs/TOR.md`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ona_core::e2ee::Transport;
use ureq::{Agent, Proxy};

/// Tor's usual SOCKS port. See `docs/torrc.client.example`.
pub const DEFAULT_SOCKS: &str = "127.0.0.1:9050";
const TIMEOUT: Duration = Duration::from_secs(120);
const ONION_V3_LEN: usize = 56;

fn is_onion_v3(host: &str) -> bool {
    host.strip_suffix(".onion").is_some_and(|name| {
        name.len() == ONION_V3_LEN && name.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    })
}

/// Allows only destinations that stay private over Tor: `http` to an onion service, whose
/// transport is already encrypted by Tor, or `https` to a host name. Plain `http` to the public
/// internet would be readable at the Tor exit, and an IP address cannot pass Tor's `SafeSocks`.
fn check_destination(url: &str) -> Result<(), String> {
    let (scheme, rest) = url.split_once("://").ok_or("destination has no scheme")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
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

    /// Redirects are off: following one could send a request somewhere the caller did not check.
    fn agent(&self) -> Result<Agent, String> {
        let proxy = Proxy::new(&format!("socks5h://{}", self.addr)).map_err(|e| e.to_string())?;
        Ok(Agent::config_builder()
            .proxy(Some(proxy))
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(TIMEOUT))
            .build()
            .into())
    }
}

/// The encrypted model client's transport, through Tor. Compression stays off, as in
/// `HttpTransport`, because the reply signature covers the exact bytes.
pub struct TorTransport {
    base: String,
    agent: Agent,
}

impl TorTransport {
    pub fn new(base: &str, proxy: &TorProxy) -> Result<Self, String> {
        check_destination(base)?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), agent: proxy.agent()? })
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
        let mut request = self.agent.get(self.url(path)?);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let mut response = request.call().map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let body = response.body_mut().read_to_vec().map_err(|e| e.to_string())?;
        Ok((status, body))
    }

    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        let mut request = self.agent.post(self.url(path)?);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let mut response = request.send(body).map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let reply = response.body_mut().read_to_vec().map_err(|e| e.to_string())?;
        Ok((status, reply))
    }
}

/// A NEAR RPC client whose reads and signed transactions all leave through Tor.
pub fn near_client(url: &str, key: SigningKey, proxy: &TorProxy) -> Result<ona_near::Client, String> {
    check_destination(url)?;
    Ok(ona_near::Client::with_agent(url, key, proxy.agent()?))
}
