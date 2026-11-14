//! One thread owns everything: pairing, the conversations (ona-core is not `Send`), the phone server and tor.
//! The phone's connections and the window's commands send it jobs and wait for the answer.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// The wallet page's server (127.0.0.1, port chosen by the system) and the deposit it serves.
    wallet_server: Option<PhoneServer>,
    wallet: Option<crate::wallet::Session>,
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
            let mut tor = TorService::new(data_dir.join("tor"));
            if let Ok(setup) = setup.lock() {
                tor.set_relay_onion(setup.model.as_ref().ok().and_then(|m| m.as_ref()).and_then(|m| m.relay_onion()));
            }
            let mut app = App {
                pairing: PairingAuthority::waiting(&name),
                name,
                secrets: Some(secrets),
                engine: {
                    let mut engine = ChatEngine::with_ona_core(setup.clone());
                    engine.payees = crate::real::load_payees(&data_dir);
                    engine.wallet_account = load_wallet_account(&data_dir);
                    engine
                },
                tor,
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
                wallet_server: None,
                wallet: None,
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
        return Err("disabled for development (ONA_NO_KEYCHAIN)".into());
    }
    let store = SystemStore::new()?;
    let got = store.get()?;
    Ok((store, got))
}

/// The file of the data folder that remembers the connected wallet's account (its name only: no key).
pub const WALLET_ACCOUNT_FILE: &str = "wallet_account";
/// The wallet page's port, tried first so that the browser keeps the wallet connected across restarts (NEAR Wallet
/// Selector remembers it per address); another one chosen by the system when it is taken.
const WALLET_PORT: u16 = 8797;

/// Why no new wallet page opens while a deposit is in progress on the current one.
pub const WALLET_BUSY: &str = "Finish or cancel the deposit in your wallet page first";
pub const WALLET_SENT: &str = "Finish the deposit in your wallet page first: it was sent, and the pool agent's message \
    still needs your signature there to issue your cash notes (cancelling now would leave the deposit in the contract \
    until its refund delay)";

fn load_wallet_account(data_dir: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(data_dir.join(WALLET_ACCOUNT_FILE)).ok()?;
    Some(text.trim().to_owned()).filter(|a| crate::wallet::is_account(a))
}

/// What a wallet page request needs.
enum WalletWork {
    Reply(http::Response),
    /// A `pool_execute`, sent to the pool's own thread from the connection's thread: the worker is not held meanwhile.
    Execute { sender: Sender<(Value, Sender<Value>)>, request: Value, second: bool, token: String },
}

/// Answers one request of the wallet page, on the connection's thread.
fn wallet_request(worker: &Worker, request: http::Request) -> http::Response {
    let stopped = || http::Response::new(503, json!({"ok": false, "error": "stopped"}));
    let Some(work) = worker.call(move |app| app.wallet_ask(request)) else { return stopped() };
    match work {
        WalletWork::Reply(response) => response,
        WalletWork::Execute { sender, request, second, token } => {
            let (reply, answer) = mpsc::channel();
            let value = match sender.send((request, reply)) {
                Ok(()) => answer.recv().unwrap_or_else(|_| json!({"ok": false, "error": "ona-core stopped"})),
                Err(_) => json!({"ok": false, "error": "ona-core stopped"}),
            };
            worker.call(move |app| app.wallet_after(&token, second, &value)).unwrap_or_else(stopped)
        }
    }
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
                    // Deposits asked in a chat (pool requests): the same wallet page as the Pool screen's.
                    for (chat, card, prepared) in app.engine.take_wallet_requests() {
                        let opened = app.open_wallet_for(&prepared, Some((chat.clone(), card.clone())));
                        app.engine.pool_wallet_opened(&chat, &card, opened);
                    }
                    app.pairing.tick();
                    app.tor.poll();
                    if app.mode == Mode::Tor && app.server.is_some() && app.pairing.onion_client_auth() != app.tor_auth {
                        app.serve(); // published again for the new phone's key only
                    }
                    let socks = app.tor.core_socks();
                    let changed = app.setup.lock().map(|mut setup| std::mem::replace(&mut setup.core_socks, socks) != socks);
                    if changed.unwrap_or(false) {
                        app.engine.reset_pool(); // made again through the new port (or refusing without tor)
                        if let (Some(socks), Ok(setup)) = (socks, app.setup.lock()) {
                            if let Ok(Some(model)) = &setup.model {
                                let _ = model.warm_up(socks); // in the background, result ignored
                            }
                        }
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
            Err(mpsc::TryRecvError::Disconnected) => Err("reading the credential store stopped".into()),
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
            Err(e) => self.server_error = Some(format!("Cannot listen: {e}. Trying again…")),
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
            return Err("this mode is for development builds only".into());
        }
        if mode == self.mode {
            return Ok(());
        }
        self.mode = mode;
        let saved = std::fs::create_dir_all(&self.data_dir).and_then(|_| std::fs::write(self.data_dir.join("mode"), mode.name()));
        self.serve();
        saved.map_err(|e| format!("Choice not saved: {e}"))
    }

    /// Opens the wallet page for a deposit prepared in the pool window (its `pool_prepare` reply), and returns its
    /// address. One deposit at a time: a new one replaces the previous page.
    pub fn open_wallet(&mut self, prepared: &Value) -> Result<String, String> {
        self.open_wallet_for(prepared, None)
    }

    /// The same, for a deposit asked in a chat (`chat`: the chat and its card), whose steps the chat reports.
    pub fn open_wallet_for(&mut self, prepared: &Value, chat: Option<(String, String)>) -> Result<String, String> {
        let mut session = crate::wallet::Session::from_prepared(prepared)?;
        session.chat = chat;
        self.open_session(session)
    }

    /// Opens the wallet page to connect a wallet (no deposit): the page tells the app the account, which the app
    /// remembers and shows. Returns the page's address.
    pub fn open_wallet_connect(&mut self) -> Result<String, String> {
        let network = match self.setup.lock().ok().and_then(|s| s.pool.as_ref().ok().cloned().flatten()) {
            Some(pool) if pool.pool.ends_with(".near") => "mainnet",
            _ => "testnet",
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or_default();
        self.open_session(crate::wallet::Session::connect(network, now))
    }

    /// Forgets the connected wallet's account (the browser may still keep its own connection).
    pub fn forget_wallet(&mut self) -> Result<(), String> {
        self.engine.wallet_account = None;
        match std::fs::remove_file(self.data_dir.join(WALLET_ACCOUNT_FILE)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("not forgotten on disk: {e}")),
            _ => Ok(()),
        }
    }

    /// The deposit the wallet page is in the middle of: still to be sent, or sent and waiting for the agent's message
    /// to be signed, and not expired. Another page must not replace it (its last step would then be refused).
    fn deposit_in_progress(&self) -> Option<&crate::wallet::Session> {
        use crate::wallet::Step;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(u64::MAX);
        self.wallet.as_ref().filter(|s| matches!(s.step, Step::Deposit | Step::Sign(_)) && !s.expired(now))
    }

    /// Cancels the wallet page's deposit, only while it has not been sent: once sent, cancelling would leave the money
    /// in the contract without its cash notes, so the person is told to sign instead.
    pub fn cancel_wallet(&mut self) -> Result<(), String> {
        use crate::wallet::Step;
        let Some(session) = self.deposit_in_progress() else {
            self.wallet = None;
            return Ok(());
        };
        if session.executing || matches!(session.step, Step::Sign(_)) {
            return Err(WALLET_SENT.into());
        }
        let chat = session.chat.clone();
        self.wallet = None;
        if let Some((chat, card)) = chat {
            self.engine.pool_wallet_cancelled(&chat, &card);
        }
        Ok(())
    }

    fn open_session(&mut self, session: crate::wallet::Session) -> Result<String, String> {
        if let Some(current) = self.deposit_in_progress() {
            return Err(if matches!(current.step, crate::wallet::Step::Sign(_)) { WALLET_SENT } else { WALLET_BUSY }.into());
        }
        if self.wallet_server.is_none() {
            let worker = Worker { jobs: self.jobs.clone() };
            let handler: server::Handler = Arc::new(move |request: http::Request| wallet_request(&worker, request));
            let server = PhoneServer::start(Exposure::Localhost, WALLET_PORT, handler.clone(), server::Limits::default())
                .or_else(|_| PhoneServer::start(Exposure::Localhost, 0, handler, server::Limits::default()))
                .map_err(|e| format!("wallet page: {e}"))?;
            self.wallet_server = Some(server);
        }
        let port = self.wallet_server.as_ref().map(|s| s.port).unwrap_or_default();
        // Ends with "/": the page loads wallet.js and wallet.css next to it.
        let url = format!("http://127.0.0.1:{port}/wallet/{}/", session.token);
        self.wallet = Some(session);
        // The address is also shown in the window, in case no browser opens. Tests open no browser.
        if !cfg!(test) {
            let _ = crate::wallet::open_in_browser(&url);
        }
        Ok(url)
    }

    /// A request of the wallet page, answered here, or a `pool_execute` to run on the pool's thread (not this one).
    fn wallet_ask(&mut self, request: http::Request) -> WalletWork {
        use crate::wallet::{Ask, Step};
        let reply = |status: u16, error: &str| WalletWork::Reply(http::Response::new(status, json!({"ok": false, "error": error})));
        let host = format!("127.0.0.1:{}", self.wallet_server.as_ref().map(|s| s.port).unwrap_or_default());
        let Some(session) = self.wallet.as_mut() else { return reply(404, "no deposit in progress") };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(u64::MAX);
        if session.expired(now) && session.step != Step::Done {
            self.wallet = None;
            return reply(410, "this deposit expired: prepare it again in the app");
        }
        let ask = match crate::wallet::parse(&request, &session.token, &host) {
            Ok(ask) => ask,
            Err(response) => return WalletWork::Reply(response),
        };
        // A connect page: the account is remembered, nothing is run.
        let ask = match ask {
            Ask::Connected { account } if session.step == Step::Connect => {
                session.step = Step::Done;
                session.account = account.clone();
                let state = session.state();
                self.remember_wallet(account);
                return WalletWork::Reply(http::Response::new(200, state));
            }
            other => other,
        };
        let execute = match (ask, &session.step) {
            (Ask::Asset(content_type, bytes), _) => return WalletWork::Reply(http::Response::asset(content_type, bytes)),
            (Ask::State, _) => return WalletWork::Reply(http::Response::new(200, session.state())),
            (Ask::Deposited, Step::Deposit) => json!({"cmd": "pool_execute", "prepared_id": session.prepared_id}),
            (Ask::Signed { public_key, signature }, Step::Sign(_)) => json!({"cmd": "pool_execute", "prepared_id": session.prepared_id,
                "depositor_signature": {"public_key": public_key, "signature": signature}}),
            // Sent twice (a page reloaded), or not this page's step: the current state, nothing run again.
            (Ask::Deposited | Ask::Signed { .. } | Ask::Connected { .. }, _) =>
                return WalletWork::Reply(http::Response::new(200, session.state())),
        };
        if session.executing {
            return reply(409, "the previous step is still running");
        }
        session.executing = true;
        let second = execute.get("depositor_signature").is_some();
        WalletWork::Execute { sender: self.engine.pool_sender(), request: execute, second, token: session.token.clone() }
    }

    /// The account connected on the wallet page: shown in the window, used by the chat's pool requests, and kept in
    /// the data folder (its name only) for the next start.
    fn remember_wallet(&mut self, account: String) {
        let _ = std::fs::create_dir_all(&self.data_dir)
            .and_then(|_| std::fs::write(self.data_dir.join(WALLET_ACCOUNT_FILE), &account));
        self.engine.wallet_account = Some(account);
    }

    fn wallet_after(&mut self, token: &str, second: bool, reply: &Value) -> http::Response {
        let Some(session) = self.wallet.as_mut().filter(|s| s.token == token) else {
            return http::Response::new(410, json!({"ok": false, "error": "this deposit is no longer in progress"}));
        };
        session.executing = false;
        // A deposit asked in a chat: the chat reports each step.
        if let Some((chat, card)) = session.chat.clone() {
            self.engine.pool_wallet_step(&chat, &card, second, reply);
        }
        let Some(session) = self.wallet.as_mut().filter(|s| s.token == token) else {
            return http::Response::new(410, json!({"ok": false, "error": "this deposit is no longer in progress"}));
        };
        let next = if second { crate::wallet::after_second_execute(reply) } else { crate::wallet::after_first_execute(reply) };
        match next {
            Ok(step) => {
                session.step = step;
                http::Response::new(200, session.state())
            }
            Err(error) => http::Response::new(409, json!({"ok": false, "error": error})),
        }
    }

    pub fn stop(&mut self) {
        self.wallet_server = None;
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
        // With a relay on an onion address: the line its operator adds so that this computer may reach it.
        let relay_onion = self.setup.lock().ok().and_then(|s| s.model.as_ref().ok().and_then(|m| m.as_ref()).and_then(|m| m.relay_onion()));
        let relay_client = relay_onion.and_then(|_| self.tor.relay_client_auth().ok());
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
            "relay_client": relay_client,
            "wallet_account": self.engine.wallet_account,
            // "deposit" or "sign" while the wallet page holds a deposit in progress (no new page opens meanwhile).
            "wallet_page": self.deposit_in_progress().map(|s| s.state()["step"].clone()),
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
        // Conversations stay in memory: once the chat has run a little, its text is in no file of the data folder.
        thread::sleep(Duration::from_millis(500));
        for file in files_under(&dir) {
            let bytes = std::fs::read(&file).unwrap();
            assert!(!bytes.windows(b"avocat".len()).any(|w| w == b"avocat"), "the conversation reached {file:?}");
        }
        worker.call(|app| app.stop()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() { found.extend(files_under(&path)) } else { found.push(path) }
        }
        found
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

    /// "Connect wallet": the page reports the account, the app shows it and remembers it across a restart.
    #[test]
    fn the_wallet_page_connects_an_account() {
        let dir = std::env::temp_dir().join(format!("ona-worker-wallet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mode"), "local").unwrap(); // no tor in a test
        let worker = Worker::start("PC".into(), dir.clone(), 18797);
        let url = worker.call(|app| app.open_wallet_connect()).unwrap().unwrap();
        let rest = url.strip_prefix("http://127.0.0.1:").unwrap();
        let (port, path) = rest.split_once('/').unwrap();
        let post = |step: &str, body: &str| -> (u16, Value) {
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap())).unwrap();
            write!(stream, "POST /{path}{step} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\n\
                            Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            (reply[9..12].parse().unwrap(), serde_json::from_str(reply.split("\r\n\r\n").nth(1).unwrap()).unwrap())
        };
        assert_eq!(post("state", "{}").1["step"], "connect");
        assert_eq!(post("deposited", "{}").1["step"], "connect", "no deposit on a connect page");
        assert_eq!(post("connected", r#"{"account":"Not An Account"}"#).0, 400);
        let (status, state) = post("connected", r#"{"account":"alice.testnet"}"#);
        assert_eq!((status, state["step"].as_str(), state["account"].as_str()), (200, Some("done"), Some("alice.testnet")));
        assert_eq!(worker.call(|app| app.view()["wallet_account"].clone()).unwrap(), "alice.testnet");
        // Once done, the page cannot change the account.
        post("connected", r#"{"account":"mallory.testnet"}"#);
        assert_eq!(worker.call(|app| app.engine.wallet_account.clone()).unwrap().as_deref(), Some("alice.testnet"));
        assert_eq!(load_wallet_account(&dir).as_deref(), Some("alice.testnet"));
        worker.call(|app| app.forget_wallet()).unwrap().unwrap();
        assert!(worker.call(|app| app.view()["wallet_account"].is_null()).unwrap());
        assert_eq!(load_wallet_account(&dir), None);
        worker.call(|app| app.stop()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// No wallet page replaces a deposit in progress: before it is sent it can be cancelled; once sent, only the
    /// signature on that page finishes it (a new page would make its last step refused).
    #[test]
    fn a_deposit_in_progress_is_not_replaced() {
        let dir = std::env::temp_dir().join(format!("ona-worker-busy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mode"), "local").unwrap(); // no tor in a test
        let worker = Worker::start("PC".into(), dir.clone(), 18798);
        let prepared = json!({"ok": true, "prepared_id": "p1", "summary": {"op": "deposit", "account": "alice.testnet",
            "network": "testnet", "expires_at": 4_000_000_000_000_000_000u64,
            "wallet_call": {"receiver": "pool.testnet", "method": "deposit", "args": {}, "attached": "1010000000000000000000000"}}});
        let first = prepared.clone();
        worker.call(move |app| app.open_wallet(&first)).unwrap().unwrap();
        assert_eq!(worker.call(|app| app.view()["wallet_page"].clone()).unwrap(), "deposit");
        assert_eq!(worker.call(|app| app.open_wallet_connect()).unwrap(), Err(WALLET_BUSY.to_owned()));
        let again = prepared.clone();
        assert_eq!(worker.call(move |app| app.open_wallet(&again)).unwrap(), Err(WALLET_BUSY.to_owned()));
        // Not sent yet: cancelled, and a new page opens.
        worker.call(|app| app.cancel_wallet()).unwrap().unwrap();
        assert!(worker.call(|app| app.view()["wallet_page"].is_null()).unwrap());
        let second = prepared.clone();
        worker.call(move |app| app.open_wallet(&second)).unwrap().unwrap();
        // Sent, waiting for the signature: neither replaced nor cancelled.
        worker.call(|app| app.wallet.as_mut().unwrap().step = crate::wallet::Step::Sign(json!({"message": "m"}))).unwrap();
        assert_eq!(worker.call(|app| app.view()["wallet_page"].clone()).unwrap(), "sign");
        assert_eq!(worker.call(|app| app.open_wallet_connect()).unwrap(), Err(WALLET_SENT.to_owned()));
        assert_eq!(worker.call(|app| app.cancel_wallet()).unwrap(), Err(WALLET_SENT.to_owned()));
        // Done: a new page may open.
        worker.call(|app| app.wallet.as_mut().unwrap().step = crate::wallet::Step::Done).unwrap();
        assert!(worker.call(|app| app.open_wallet_connect()).unwrap().is_ok());
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
