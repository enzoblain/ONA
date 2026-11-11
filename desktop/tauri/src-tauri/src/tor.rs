//! Publishes the phone server as an onion service with the `tor` program installed on this computer, like docs/TOR.md
//! does for the relay. The onion key stays in the app's data folder.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq)]
pub enum TorState {
    Off,
    /// No `tor` program found.
    Missing,
    Starting,
    Published(String),
    Failed(String),
}

pub struct TorService {
    pub state: TorState,
    root: PathBuf,
    child: Option<Child>,
    started: Option<Instant>,
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
        Self { state: TorState::Off, root, child: None, started: None }
    }

    pub fn onion(&self) -> Option<&str> {
        match &self.state {
            TorState::Published(host) => Some(host),
            _ => None,
        }
    }

    /// Starts tor with an onion service whose port 80 goes to 127.0.0.1:`port`.
    pub fn start(&mut self, port: u16) {
        self.stop();
        let Some(binary) = binary() else {
            self.state = TorState::Missing;
            return;
        };
        match self.spawn(&binary, port) {
            Ok(child) => {
                self.child = Some(child);
                self.started = Some(Instant::now());
                self.state = TorState::Starting;
            }
            Err(e) => self.state = TorState::Failed(e.to_string()),
        }
    }

    fn spawn(&self, binary: &Path, port: u16) -> std::io::Result<Child> {
        let (hs, data) = (self.root.join("hs"), self.root.join("data"));
        for dir in [&hs, &data] {
            private_dir(dir)?;
        }
        let torrc = self.root.join("torrc");
        // Paths quoted: they may contain spaces (Windows user folders). __OwningControllerProcess makes tor exit when
        // this app exits, even after a crash, so no orphan keeps the data folder locked.
        std::fs::write(&torrc, format!(
            "SocksPort 0\nDataDirectory \"{}\"\nHiddenServiceDir \"{}\"\nHiddenServicePort 80 127.0.0.1:{port}\n\
             __OwningControllerProcess {}\nLog notice stdout\n",
            escape(&data), escape(&hs), std::process::id()
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
        let hostname = self.root.join("hs").join("hostname");
        if let Ok(host) = std::fs::read_to_string(hostname) {
            let host = host.trim();
            if host.ends_with(".onion") {
                self.state = TorState::Published(host.to_owned());
                return;
            }
        }
        if self.started.is_some_and(|t| t.elapsed() > Duration::from_secs(120)) {
            self.state = TorState::Failed("l'adresse .onion n'est pas apparue".into());
        }
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.started = None;
        self.state = TorState::Off;
    }
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

    #[test]
    fn escapes_windows_paths_for_torrc() {
        assert_eq!(escape(Path::new("C:\\Users\\A B\\hs")), "C:\\\\Users\\\\A B\\\\hs");
    }
}
