//! One thread owns everything: pairing, the conversations (ona-core is not `Send`), the phone server and tor.
//! The phone's connections and the window's commands send it jobs and wait for the answer.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::engine::ChatEngine;
use crate::pairing::{PairingAuthority, SecretStore, SystemStore};
use crate::server::{self, Exposure, PhoneServer};
use crate::real::{ModelSettings, PoolSettings, SharedSetup};
use crate::tor::{TorService, TorState};
use crate::{http, router};

/// The local-network mode (plain HTTP on every interface) exists in debug builds only.
pub const LOCAL_MODE_ALLOWED: bool = cfg!(debug_assertions);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    /// The phone reaches this computer through Tor (onion service). The server listens on 127.0.0.1 only.
    Tor,
    /// The phone reaches this computer on the local network, in plain HTTP. Debug builds only.
    LocalNetwork,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Tor => "tor",
            Mode::LocalNetwork => "local",
        }
    }

    /// `allow_local`: whether this build may use the local-network mode (`LOCAL_MODE_ALLOWED`).
    pub fn parse(text: &str, allow_local: bool) -> Option<Self> {
        match text {
            "tor" => Some(Mode::Tor),
            "local" if allow_local => Some(Mode::LocalNetwork),
            _ => None,
        }
    }
}

pub struct App {
    pub pairing: PairingAuthority,
    pub engine: ChatEngine,
    tor: TorService,
    server: Option<PhoneServer>,
    server_error: Option<String>,
    mode: Mode,
    /// Port asked for: 0 lets the system choose (Tor mode). `server.port` is the one in use.
    port: u16,
    data_dir: PathBuf,
    last_request: Option<String>,
    /// QR code of the current payload, as SVG, rebuilt when the payload changes.
    qr: Option<(String, String)>,
    jobs: Sender<Job>,
    /// What new cores are made with: `model.json`, and tor's port for the core once tor is ready.
    setup: SharedSetup,
    /// The client key tor was started with: when pairing replaces it (a phone forgotten), tor starts again.
    tor_auth: Option<String>,
    name: String,
    /// The secret store being read on its own thread; None once the pairing is loaded.
    secrets: Option<Receiver<Result<(SystemStore, Option<Vec<u8>>), String>>>,
}

type Job = Box<dyn FnOnce(&mut App) + Send>;

/// Handle used by the window and the phone server to reach the worker thread.
#[derive(Clone)]
pub struct Worker {
    jobs: Sender<Job>,
}

impl Worker {
    /// Starts the worker thread: loads the pairing record and the mode from `data_dir` and starts serving.
    /// `port`: 0 for a port chosen by the system (Tor mode); the local-network mode uses `server::PORT` when 0.
    pub fn start(name: String, data_dir: PathBuf, port: u16) -> Self {
        let (jobs, inbox) = mpsc::channel::<Job>();
        let sender = jobs.clone();
        thread::spawn(move || {
            let mode = stored_mode(&data_dir, LOCAL_MODE_ALLOWED);
            let setup = SharedSetup::default();
            if let Ok(mut setup) = setup.lock() {
                setup.model = ModelSettings::load(&data_dir);
                setup.pool = PoolSettings::load(&data_dir);
            }
            // The secret store is read on a thread of its own: macOS may ask the person first (a Keychain dialog), and
            // this thread serves the window meanwhile. Nothing is served to the phone until the pairing is loaded.
            let (loaded, secrets) = mpsc::channel();
            thread::spawn(move || {
                let _ = loaded.send(read_secret_store());
            });
            let mut app = App {
                pairing: PairingAuthority::waiting(&name),
                name,
                secrets: Some(secrets),
                engine: ChatEngine::with_ona_core(setup.clone()),
                tor: TorService::new(data_dir.join("tor")),
                server: None,
                server_error: None,
                mode,
                port,
                data_dir,
                last_request: None,
                qr: None,
                jobs: sender,
                setup,
                tor_auth: None,
            };
            app.load_pairing();
            run(app, inbox);
        });
        Self { jobs }
    }

    /// Runs `job` on the worker thread and returns its result.
    pub fn call<T: Send + 'static>(&self, job: impl FnOnce(&mut App) -> T + Send + 'static) -> Option<T> {
        let (reply, answer) = mpsc::channel();
        self.jobs.send(Box::new(move |app: &mut App| {
            let _ = reply.send(job(app));
        })).ok()?;
        answer.recv().ok()
    }
}

/// The system's credential store. Development builds skip it with `ONA_NO_KEYCHAIN=1`: macOS asks again for the
/// Keychain item after every rebuild, and the app waits for that answer.
fn read_secret_store() -> Result<(SystemStore, Option<Vec<u8>>), String> {
    if cfg!(test) {
        return Err("tests: no system credential store".into());
    }
    if cfg!(debug_assertions) && std::env::var("ONA_NO_KEYCHAIN").as_deref() == Ok("1") {
        return Err("désactivé pour le développement (ONA_NO_KEYCHAIN)".into());
    }
    let store = SystemStore::new()?;
    let got = store.get()?;
    Ok((store, got))
}

fn run(mut app: App, inbox: Receiver<Job>) {
    let tick = Duration::from_millis(1500);
    let mut next = Instant::now() + tick;
    loop {
        // A panic in a job (ona-core included) fails that job only: this thread, which owns everything, keeps going.
        match inbox.recv_timeout(next.saturating_duration_since(Instant::now())) {
            Ok(job) => {
                let _ = catch_unwind(AssertUnwindSafe(|| job(&mut app)));
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    app.engine.tick();
                    app.pairing.tick();
                    app.tor.poll();
                    if app.mode == Mode::Tor && app.server.is_some() && app.pairing.onion_client_auth() != app.tor_auth {
                        app.serve(); // published again for the new phone's key only
                    }
                    let socks = app.tor.core_socks();
                    let changed = app.setup.lock().map(|mut setup| std::mem::replace(&mut setup.core_socks, socks) != socks);
                    if changed.unwrap_or(false) {
                        app.engine.reset_pool(); // made again through the new port (or refusing without tor)
                    }
                    app.load_pairing();
                    if app.server.is_none() && app.secrets.is_none() {
                        app.serve(); // listening failed: try again
                    }
                }));
                next = Instant::now() + tick;
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

impl App {
    /// Once the secret store was read: the real pairing replaces the waiting one, and serving starts.
    fn load_pairing(&mut self) {
        let Some(secrets) = &self.secrets else { return };
        let loaded = match secrets.try_recv() {
            Ok(result) => result.map(|(store, got)| (Box::new(store) as Box<dyn SecretStore>, got)),
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err("la lecture du trousseau s'est arrêtée".into()),
        };
        self.secrets = None;
        self.pairing = PairingAuthority::with_loaded_secrets(&self.name, self.data_dir.join("pairing.json"), loaded);
        self.serve();
    }

    /// (Re)starts the phone server, and the onion service in Tor mode once the server listens. If listening fails,
    /// tor stays stopped: nothing else can receive the phone's traffic through the onion address.
    fn serve(&mut self) {
        self.server = None;
        self.tor.stop();
        let worker = Worker { jobs: self.jobs.clone() };
        let handler: server::Handler = Arc::new(move |request: http::Request| {
            worker.call(move |app| app.phone(request))
                .unwrap_or_else(|| http::Response::new(503, json!({"ok": false, "error": "stopped"})))
        });
        let (exposure, port) = match self.mode {
            Mode::Tor => (Exposure::Localhost, self.port),
            Mode::LocalNetwork => (Exposure::LocalNetwork, if self.port == 0 { server::PORT } else { self.port }),
        };
        match PhoneServer::start(exposure, port, handler, server::Limits::default()) {
            Ok(server) => {
                self.server_error = None;
                if self.mode == Mode::Tor {
                    self.tor_auth = self.pairing.onion_client_auth();
                    self.tor.start(server.port, self.tor_auth.as_deref());
                }
                self.server = Some(server);
            }
            Err(e) => self.server_error = Some(format!("Écoute impossible : {e}. Nouvel essai…")),
        }
    }

    /// The `Host` values this computer answers to: anything else may be a web page that renamed itself (DNS rebinding).
    fn allowed_hosts(&self) -> Vec<String> {
        let Some(port) = self.server.as_ref().map(|s| s.port) else { return Vec::new() };
        let mut hosts = vec![format!("127.0.0.1:{port}")];
        match self.mode {
            Mode::Tor => {
                if let Some(onion) = self.tor.onion() {
                    hosts.push(onion.to_owned());
                    hosts.push(format!("{onion}:80"));
                }
            }
            Mode::LocalNetwork => hosts.extend(local_ipv4().map(|ip| format!("{ip}:{port}"))),
        }
        hosts
    }

    fn phone(&mut self, request: http::Request) -> http::Response {
        let hosts = self.allowed_hosts();
        let response = router::handle(&request, &mut self.pairing, &mut self.engine, &hosts);
        self.last_request = Some(format!("{} {} → {}", request.method, request.path, response.status));
        response
    }

    pub fn set_mode(&mut self, mode: Mode) -> Result<(), String> {
        if mode == Mode::LocalNetwork && !LOCAL_MODE_ALLOWED {
            return Err("mode réservé aux versions de développement".into());
        }
        if mode == self.mode {
            return Ok(());
        }
        self.mode = mode;
        let saved = std::fs::create_dir_all(&self.data_dir).and_then(|_| std::fs::write(self.data_dir.join("mode"), mode.name()));
        self.serve();
        saved.map_err(|e| format!("Choix non enregistré : {e}"))
    }

    pub fn stop(&mut self) {
        self.server = None;
        self.tor.stop();
    }

    /// Where the phone reaches this computer, as shown to the person.
    fn reachable_at(&self) -> Option<String> {
        match self.mode {
            Mode::Tor => self.tor.onion().map(String::from),
            Mode::LocalNetwork => Some(format!("http://{}:{}", local_ipv4()?, self.server.as_ref()?.port)),
        }
    }

    /// Text of the pairing QR code for the current mode, or None while it cannot be built yet.
    pub fn payload(&self) -> Option<String> {
        match self.mode {
            Mode::Tor => self.pairing.payload(None, Some(self.tor.onion()?)),
            Mode::LocalNetwork => self.pairing.payload(Some(&self.reachable_at()?), None),
        }
    }

    fn qr_svg(&mut self, payload: &str) -> Option<String> {
        if let Some((text, svg)) = &self.qr {
            if text == payload {
                return Some(svg.clone());
            }
        }
        let code = qrcode::QrCode::with_error_correction_level(payload, qrcode::EcLevel::M).ok()?;
        let svg = code.render::<qrcode::render::svg::Color>()
            .min_dimensions(240, 240)
            .dark_color(qrcode::render::svg::Color("#000000"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build();
        self.qr = Some((payload.to_owned(), svg.clone()));
        Some(svg)
    }

    /// Everything the window shows, except one conversation's content.
    pub fn view(&mut self) -> Value {
        let (tor_state, tor_message) = match &self.tor.state {
            TorState::Off => ("off", None),
            TorState::Missing => ("missing", None),
            TorState::Starting => ("starting", None),
            TorState::Published(_) => ("published", None),
            TorState::Failed(message) => ("failed", Some(message.clone())),
        };
        // Only the QR image goes to the window, not the pairing text (it would sit in the window's state).
        let payload = if self.pairing.record.phone.is_none() && self.pairing.awaiting.is_none() { self.payload() } else { None };
        let qr = payload.as_deref().and_then(|p| self.qr_svg(p));
        let phone = self.pairing.record.phone.as_ref().map(|p| json!({"paired_at": p.paired_at, "verified": true}));
        let error = self.server_error.clone().or_else(|| self.pairing.storage_error.clone());
        json!({
            "name": self.pairing.name,
            "mode": self.mode.name(),
            "local_mode_available": LOCAL_MODE_ALLOWED,
            "port": self.server.as_ref().map(|s| s.port),
            "reachable": self.reachable_at(),
            "qr": qr,
            "phone": phone,
            "awaiting_code": self.pairing.awaiting.as_ref().map(|a| a.code.clone()),
            "server_error": error,
            "tor": {"state": tor_state, "message": tor_message},
            "last_request": self.last_request,
            "chats": self.engine.list_json(),
        })
    }
}

/// The mode saved in `data_dir`, Tor when absent or not allowed in this build (a "local" saved by a debug build is not
/// honoured by a release build).
pub fn stored_mode(data_dir: &std::path::Path, allow_local: bool) -> Mode {
    std::fs::read_to_string(data_dir.join("mode")).ok().and_then(|m| Mode::parse(m.trim(), allow_local)).unwrap_or(Mode::Tor)
}

/// This computer's IPv4 address on the local network: the address the system would use to leave it. Nothing is sent
/// (UDP connect only picks a route; 192.0.2.1 is a documentation address).
pub fn local_ipv4() -> Option<String> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::tests::Phone;
    use crate::protocol;
    use std::io::{Read, Write};

    /// Sends one request; returns the reply after checking the computer's signature over it.
    fn http(port: u16, path: &str, body: &Value, computer_key: &[u8]) -> Value {
        let nonce = protocol::random_hex16();
        let mut body = body.clone();
        body["nonce"] = json!(nonce);
        let body = body.to_string();
        for _ in 0..100 {
            if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                write!(stream, "POST {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).unwrap();
                let status: u16 = reply[9..12].parse().unwrap();
                let envelope: Value = serde_json::from_str(reply.split("\r\n\r\n").nth(1).unwrap()).unwrap();
                let text = envelope["reply"].as_str().unwrap();
                assert!(protocol::verify(envelope["signature"].as_str(), &protocol::reply_message(&nonce, "POST", path, status, text), computer_key));
                return serde_json::from_str(text).unwrap();
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("server never listened");
    }

    #[test]
    fn a_phone_pairs_and_chats_over_http() {
        let dir = std::env::temp_dir().join(format!("ona-worker-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mode"), "local").unwrap();
        let port = 18791;
        // While the secret store is read, the window is served and the phone is not.
        let waiting = PairingAuthority::waiting("PC");
        assert!(waiting.payload(Some("http://x"), None).is_none() && waiting.storage_error.is_some());
        let worker = Worker::start("PC".into(), dir.clone(), port);
        // The pairing loads once the secret store was read, on its own thread.
        let mut loaded = None;
        for _ in 0..100 {
            loaded = worker.call(|app| app.pairing.pairing_code.clone().map(|c| (c.value, app.pairing.computer_public_key()))).unwrap();
            if loaded.is_some() { break }
            thread::sleep(Duration::from_millis(50));
        }
        let (code, key) = loaded.expect("pairing loaded");

        let phone = Phone::new();
        let nonce = protocol::random_hex16();
        let commit = http(port, "/v1/pair", &json!({"code": code, "commitment": protocol::commitment(&phone.public_key(), &nonce)}), &key);
        let id = commit["pairing_id"].as_str().unwrap().to_owned();
        let computer_nonce = commit["computer_nonce"].as_str().unwrap().to_owned();
        let proof = phone.sign(&protocol::pair_message(&id, &code, &phone.public_key(), &key, &nonce, &computer_nonce));
        let revealed = http(port, "/v1/pair/reveal", &json!({
            "pairing_id": id, "phone_key": protocol::b64(&phone.public_key()), "phone_nonce": nonce, "signature": proof,
        }), &key);
        let token = revealed["token"].as_str().unwrap().to_owned();
        let view = worker.call(|app| app.view()).unwrap();
        let shown = protocol::verification_code(&key, &phone.public_key(), &code, &nonce, &computer_nonce);
        assert_eq!(view["awaiting_code"].as_str(), Some(shown.as_str()));
        assert!(view.get("payload").is_none());
        worker.call(|app| app.pairing.confirm_code()).unwrap().unwrap();

        let counter = phone.next();
        let signature = phone.sign(&protocol::chat_message(&id, counter, None, Some("Trouve un avocat")));
        let created = http(port, "/v1/chats", &json!({"token": token, "pairing_id": id, "counter": counter,
                                                     "text": "Trouve un avocat", "signature": signature}), &key);
        assert_eq!(created["ok"], true);
        let list = http(port, "/v1/chats/list", &json!({"token": token}), &key);
        assert_eq!(list["chats"][0]["title"], "Trouve un avocat");
        assert_eq!(worker.call(|app| app.view()["last_request"].clone()).unwrap(), "POST /v1/chats/list → 200");
        worker.call(|app| app.stop()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A panicking job fails alone: the worker thread keeps answering.
    #[test]
    fn the_worker_survives_a_panicking_job() {
        let dir = std::env::temp_dir().join(format!("ona-worker-panic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mode"), "local").unwrap(); // no tor in a test
        let worker = Worker::start("PC".into(), dir.clone(), 18795);
        assert_eq!(worker.call(|_| -> u8 { panic!("inside a job") }), None);
        assert_eq!(worker.call(|app| app.pairing.name.clone()), Some("PC".to_owned()));
        worker.call(|app| app.stop()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A release build ignores and refuses the local-network mode.
    #[test]
    fn the_local_network_mode_is_for_debug_builds_only() {
        assert_eq!(Mode::parse("local", false), None);
        assert_eq!(Mode::parse("local", true), Some(Mode::LocalNetwork));
        let dir = std::env::temp_dir().join(format!("ona-worker-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mode"), "local").unwrap();
        assert_eq!(stored_mode(&dir, false), Mode::Tor);
        assert_eq!(stored_mode(&dir, true), Mode::LocalNetwork);
        let _ = std::fs::remove_dir_all(dir);
    }
}
