//! Publishes the phone server as an onion service with the `tor` program installed on this computer, like docs/TOR.md
//! does for the relay. The onion key stays in the app's data folder.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

/// How long tor may take to publish the onion service before the app gives up.
const PUBLISH_LIMIT: Duration = Duration::from_secs(600);
/// No attempt before this: the service needs its introduction circuits before it uploads its descriptor. Each attempt
/// that finds no descriptor uses up one of the directories that hold it, and tor does not ask that directory again
/// for 15 minutes: attempts made too early, or too often, leave tor answering "not found" (0xF0) long after the
/// descriptor is there (seen on 2026-11-12: 5 s apart from the start, still "not found" after 15 minutes).
const PROBE_START: Duration = Duration::from_secs(45);
/// Pause between two attempts to reach our own onion address.
const PROBE_INTERVAL: Duration = Duration::from_secs(30);
/// One attempt: Tor may need a while to find the descriptor and build the circuits.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq)]
pub enum TorState {
    Off,
    /// No `tor` program found.
    Missing,
    /// tor runs; the onion service is not reachable yet (the QR code is not shown).
    Starting,
    /// The onion address answered through Tor: the phone can reach it.
    Published(String),
    Failed(String),
}

pub struct TorService {
    pub state: TorState,
    root: PathBuf,
    child: Option<Child>,
    started: Option<Instant>,
    /// tor's SOCKS port on 127.0.0.1, used only to check that our own onion address answers.
    socks_port: u16,
    /// A second SOCKS port on 127.0.0.1, for everything ona-core sends (the relay, the pool agent, NEAR RPC nodes).
    core_socks_port: u16,
    /// The relay's onion address (56 characters, without `.onion`) when it is restricted to named clients: tor then
    /// presents this app's client key to it (`ClientOnionAuthDir`).
    relay_onion: Option<String>,
    /// An attempt to reach the onion address, running on its own thread.
    probe: Option<Receiver<Result<(), String>>>,
    last_probe: Option<Instant>,
}

/// Where `tor` is installed by the system's packages. Searched before PATH: a folder put early in PATH (by another
/// program, or writable by the user) must not decide which `tor` holds the onion key.
const CANDIDATES: &[&str] = &[
    "/usr/bin/tor",
    "/usr/sbin/tor",
    "/usr/local/bin/tor",
    "/opt/homebrew/bin/tor",
    "C:\\Program Files\\Tor\\tor.exe",
];

pub fn binary() -> Option<PathBuf> {
    let name = if cfg!(windows) { "tor.exe" } else { "tor" };
    let path: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    find_binary(CANDIDATES.iter().map(PathBuf::from), &path, name)
}

/// The first existing file among `candidates`, then among `name` in the `path` folders.
fn find_binary(candidates: impl Iterator<Item = PathBuf>, path: &[PathBuf], name: &str) -> Option<PathBuf> {
    candidates.chain(path.iter().map(|dir| dir.join(name))).find(|p| p.is_file())
}

impl TorService {
    pub fn new(root: PathBuf) -> Self {
        Self { state: TorState::Off, root, child: None, started: None, socks_port: 0, core_socks_port: 0, relay_onion: None, probe: None, last_probe: None }
    }

    /// The relay to present this app's client key to, from the next start of tor.
    pub fn set_relay_onion(&mut self, onion: Option<String>) {
        self.relay_onion = onion;
    }

    /// The line to give the relay's operator, for `authorized_clients/` of the relay's onion service: made once and
    /// kept in `tor/relay-client/` (the secret half stays there, tor reads it from that folder).
    pub fn relay_client_auth(&self) -> std::io::Result<String> {
        let secret = self.relay_client_secret()?;
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        Ok(format!("descriptor:x25519:{}", crate::protocol::base32(public.as_bytes())))
    }

    fn relay_client_dir(&self) -> PathBuf {
        self.root.join("relay-client")
    }

    /// This app's x25519 secret for restricted relays, made on first use.
    fn relay_client_secret(&self) -> std::io::Result<[u8; 32]> {
        let dir = self.relay_client_dir();
        private_dir(&dir)?;
        let file = dir.join("key");
        if let Ok(bytes) = std::fs::read(&file) {
            if let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(secret);
            }
        }
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        crate::pairing::write_private(&file, &secret)?;
        Ok(secret)
    }

    /// The `ClientOnionAuthDir` tor reads, holding the key for `relay_onion` only. None without a restricted relay.
    fn relay_auth_dir(&self) -> std::io::Result<Option<PathBuf>> {
        let Some(onion) = &self.relay_onion else { return Ok(None) };
        let secret = self.relay_client_secret()?;
        let dir = self.relay_client_dir().join("auth");
        let _ = std::fs::remove_dir_all(&dir);
        private_dir(&dir)?;
        let line = format!("{onion}:descriptor:x25519:{}\n", crate::protocol::base32(&secret));
        crate::pairing::write_private(&dir.join("relay.auth_private"), line.as_bytes())?;
        Ok(Some(dir))
    }

    pub fn onion(&self) -> Option<&str> {
        match &self.state {
            TorState::Published(host) => Some(host),
            _ => None,
        }
    }

    /// Starts tor with an onion service whose port 80 goes to 127.0.0.1:`port`. With `client_auth` (a line
    /// `descriptor:x25519:<key>`), the service is published for that client key only (restricted discovery): a Tor
    /// client without the key cannot even find it.
    pub fn start(&mut self, port: u16, client_auth: Option<&str>) {
        self.stop();
        let Some(binary) = binary() else {
            self.state = TorState::Missing;
            return;
        };
        let ports = free_local_port().and_then(|probe| Ok((probe, free_local_port()?)));
        (self.socks_port, self.core_socks_port) = match ports {
            Ok((probe, core)) if probe != core => (probe, core),
            Ok(_) => {
                self.state = TorState::Failed("no two free local ports".into());
                return;
            }
            Err(e) => {
                self.state = TorState::Failed(e.to_string());
                return;
            }
        };
        match self.spawn(&binary, port, client_auth) {
            Ok(child) => {
                self.child = Some(child);
                self.started = Some(Instant::now());
                self.state = TorState::Starting;
            }
            Err(e) => self.state = TorState::Failed(e.to_string()),
        }
    }

    fn spawn(&self, binary: &Path, port: u16, client_auth: Option<&str>) -> std::io::Result<Child> {
        let (hs, data) = (self.root.join("hs"), self.root.join("data"));
        for dir in [&hs, &data] {
            private_dir(dir)?;
        }
        // tor reads the authorized clients when it starts: the folder holds the current phone's key only.
        let clients = hs.join("authorized_clients");
        let _ = std::fs::remove_dir_all(&clients);
        if let Some(line) = client_auth {
            private_dir(&clients)?;
            crate::pairing::write_private(&clients.join("phone.auth"), format!("{line}\n").as_bytes())?;
        }
        let relay_auth = match self.relay_auth_dir()? {
            Some(dir) => format!("ClientOnionAuthDir \"{}\"\n", escape(&dir)),
            None => String::new(),
        };
        let torrc = self.root.join("torrc");
        // Paths quoted: they may contain spaces (Windows user folders). __OwningControllerProcess makes tor exit when
        // this app exits, even after a crash, so no orphan keeps the data folder locked. The SOCKS port listens on
        // 127.0.0.1 only: the app uses it to check that its onion address answers before showing the QR code.
        // OnionTrafficOnly keeps other local programs from using it as a general anonymous proxy; ExtendedErrors makes
        // tor say "missing client authorization" for a restricted service it found (see `reach_through_socks`). The second port is
        // ona-core's: the relay and the NEAR RPC nodes are ordinary host names, so it cannot be onion-only. SocksTimeout
        // matches ona-core's connection limit: the first connection to an onion relay can wait past tor's default 120 s.
        std::fs::write(&torrc, format!(
            "SocksPort 127.0.0.1:{} OnionTrafficOnly ExtendedErrors\nSocksPort 127.0.0.1:{}\nSocksTimeout 240\nDataDirectory \"{}\"\nHiddenServiceDir \"{}\"\nHiddenServicePort 80 127.0.0.1:{port}\n\
             __OwningControllerProcess {}\nLog notice stdout\n{relay_auth}",
            self.socks_port, self.core_socks_port, escape(&data), escape(&hs), std::process::id()
        ))?;
        let mut command = Command::new(binary);
        command.arg("-f").arg(&torrc).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        command.spawn()
    }

    /// Checks on tor; called on the worker's timer.
    pub fn poll(&mut self) {
        if self.state != TorState::Starting {
            return;
        }
        if let Some(child) = self.child.as_mut() {
            if let Ok(Some(_)) = child.try_wait() {
                self.child = None;
                self.state = TorState::Failed("tor s'est arrêté".into());
                return;
            }
        }
        // The `hostname` file stays from one launch to the next: it does not mean the service is published. The QR code
        // waits until the onion address answers through Tor.
        if let Some(probe) = &self.probe {
            let result = probe.try_recv();
            #[cfg(debug_assertions)]
            if let Ok(outcome) = &result {
                println!("ONA_TOR_PROBE {:?} after {:?}", outcome, self.started.map(|t| t.elapsed()));
            }
            match result {
                Ok(Ok(())) => {
                    self.probe = None;
                    if let Some(host) = self.hostname() {
                        self.state = TorState::Published(host);
                        return;
                    }
                }
                Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => self.probe = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.started.is_some_and(|t| t.elapsed() > PUBLISH_LIMIT) {
            self.state = TorState::Failed("le service .onion ne répond pas par Tor".into());
            return;
        }
        let started_long_enough = self.started.is_some_and(|t| t.elapsed() >= PROBE_START);
        let due = started_long_enough && self.last_probe.is_none_or(|t| t.elapsed() >= PROBE_INTERVAL);
        if self.probe.is_none() && due {
            if let Some(host) = self.hostname() {
                let (send, receive) = mpsc::channel();
                let socks = SocketAddr::from((Ipv4Addr::LOCALHOST, self.socks_port));
                thread::spawn(move || {
                    let _ = send.send(reach_through_socks(socks, &host, 80, PROBE_TIMEOUT));
                });
                self.probe = Some(receive);
                self.last_probe = Some(Instant::now());
            }
        }
    }

    fn hostname(&self) -> Option<String> {
        let host = std::fs::read_to_string(self.root.join("hs").join("hostname")).ok()?;
        let host = host.trim();
        host.ends_with(".onion").then(|| host.to_owned())
    }

    /// The SOCKS port for ona-core's traffic, once the onion service answers (so tor is connected to the network).
    pub fn core_socks(&self) -> Option<u16> {
        matches!(self.state, TorState::Published(_)).then_some(self.core_socks_port)
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.started = None;
        self.probe = None;
        self.last_probe = None;
        self.state = TorState::Off;
    }
}

/// A port free on 127.0.0.1 right now, for tor's SOCKS port.
fn free_local_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port())
}

const MISSING_CLIENT_AUTH: u8 = 0xF4;

/// Opens a stream to `host:port` through the SOCKS5 proxy at `socks` (RFC 1928, no authentication, name resolved by
/// the proxy), then closes it. Ok once the proxy reports the stream as connected: for an onion address, the service is
/// published and answers.
fn reach_through_socks(socks: SocketAddr, host: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let name = host.as_bytes();
    if name.is_empty() || name.len() > 255 {
        return Err("bad host".into());
    }
    let mut stream = TcpStream::connect_timeout(&socks, timeout).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    stream.write_all(&[5, 1, 0]).map_err(|e| e.to_string())?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).map_err(|e| e.to_string())?;
    if choice != [5, 0] {
        return Err("SOCKS proxy refused".into());
    }
    let mut request = vec![5, 1, 0, 3, name.len() as u8];
    request.extend_from_slice(name);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).map_err(|e| e.to_string())?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).map_err(|e| e.to_string())?;
    // 0xF4 (ExtendedErrors): "onion service missing client authorization". tor fetched the descriptor and found it
    // restricted to client keys this app does not hold: the service is published, and the phone's key opens it.
    if reply[0] != 5 || !matches!(reply[1], 0 | MISSING_CLIENT_AUTH) {
        return Err(format!("SOCKS reply {}", reply[1]));
    }
    Ok(())
}

impl Drop for TorService {
    fn drop(&mut self) {
        self.stop();
    }
}

/// torrc strings: backslashes and quotes escaped.
fn escape(path: &Path) -> String {
    path.display().to_string().replace('\\', "\\\\").replace('"', "\\\"")
}

/// tor refuses an onion service folder readable by others.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The system's `tor` wins over one placed earlier in PATH.
    #[test]
    fn prefers_the_installed_tor_over_path() {
        let root = std::env::temp_dir().join(format!("ona-tor-binary-{}", std::process::id()));
        let (system, early) = (root.join("system"), root.join("early"));
        for dir in [&system, &early] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("tor"), b"").unwrap();
        }
        let found = find_binary(std::iter::once(system.join("tor")), std::slice::from_ref(&early), "tor");
        assert_eq!(found, Some(system.join("tor")));
        let fallback = find_binary(std::iter::once(root.join("absent/tor")), std::slice::from_ref(&early), "tor");
        assert_eq!(fallback, Some(early.join("tor")));
        let _ = std::fs::remove_dir_all(root);
    }

    /// A minimal SOCKS5 proxy answering `reply` to one CONNECT; returns its address and the host it was asked for.
    fn fake_socks(reply: u8) -> (SocketAddr, thread::JoinHandle<String>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(&head[..4], &[5, 1, 0, 3]);
            let mut rest = vec![0u8; head[4] as usize + 2];
            stream.read_exact(&mut rest).unwrap();
            assert_eq!(&rest[rest.len() - 2..], &[0, 80]);
            stream.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            String::from_utf8(rest[..rest.len() - 2].to_vec()).unwrap()
        });
        (address, handle)
    }

    #[test]
    fn the_onion_counts_as_published_only_when_it_answers() {
        let onion = format!("{}.onion", "a".repeat(56));
        let (proxy, asked) = fake_socks(0);
        assert_eq!(reach_through_socks(proxy, &onion, 80, Duration::from_secs(5)), Ok(()));
        assert_eq!(asked.join().unwrap(), onion);
        // Tor answers 4 (host unreachable) while the descriptor is not published.
        // A restricted onion service tor found: published, only for client keys this app does not hold.
        let (proxy, _) = fake_socks(MISSING_CLIENT_AUTH);
        assert_eq!(reach_through_socks(proxy, &onion, 80, Duration::from_secs(5)), Ok(()));
        let (proxy, _) = fake_socks(4);
        assert_eq!(reach_through_socks(proxy, &onion, 80, Duration::from_secs(5)), Err("SOCKS reply 4".into()));
    }

    #[test]
    fn a_hostname_file_alone_does_not_publish() {
        let root = std::env::temp_dir().join(format!("ona-tor-hostname-{}", std::process::id()));
        std::fs::create_dir_all(root.join("hs")).unwrap();
        std::fs::write(root.join("hs").join("hostname"), format!("{}.onion\n", "b".repeat(56))).unwrap();
        let mut service = TorService::new(root.clone());
        service.state = TorState::Starting;
        service.started = Some(Instant::now());
        service.socks_port = free_local_port().unwrap(); // nothing listens there
        service.poll();
        assert_eq!(service.state, TorState::Starting);
        assert!(service.onion().is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn escapes_windows_paths_for_torrc() {
        assert_eq!(escape(Path::new("C:\\Users\\A B\\hs")), "C:\\\\Users\\\\A B\\\\hs");
    }

    /// The relay's client key is made once and kept; tor gets the secret half for that relay only, the operator the
    /// public half.
    #[test]
    fn keeps_one_client_key_for_a_restricted_relay() {
        let root = std::env::temp_dir().join(format!("ona-tor-relay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut service = TorService::new(root.clone());
        assert_eq!(service.relay_auth_dir().unwrap(), None);
        let onion = "b".repeat(56);
        service.set_relay_onion(Some(onion.clone()));
        let dir = service.relay_auth_dir().unwrap().unwrap();
        let line = std::fs::read_to_string(dir.join("relay.auth_private")).unwrap();
        assert!(line.starts_with(&format!("{onion}:descriptor:x25519:")) && line.ends_with('\n'), "{line}");
        let public = service.relay_client_auth().unwrap();
        assert!(public.starts_with("descriptor:x25519:") && public.len() == 18 + 52, "{public}");
        assert_eq!(TorService::new(root.clone()).relay_client_auth().unwrap(), public, "the same key after a restart");
        let _ = std::fs::remove_dir_all(root);
    }
}
