//! One thread owns everything: pairing, the conversations (ona-core is not `Send`), the phone server and tor.
//! The phone's connections and the window's commands send it jobs and wait for the answer.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::engine::ChatEngine;
use crate::pairing::PairingAuthority;
use crate::server::{self, Exposure, PhoneServer};
use crate::tor::{TorService, TorState};
use crate::{http, router};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    /// The phone reaches this computer through Tor (onion service). The server listens on 127.0.0.1 only.
    Tor,
    /// The phone reaches this computer on the local network. For tests.
    LocalNetwork,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Tor => "tor",
            Mode::LocalNetwork => "local",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "tor" => Some(Mode::Tor),
            "local" => Some(Mode::LocalNetwork),
            _ => None,
        }
    }
}

pub struct App {
    pub pairing: PairingAuthority,
    pub engine: ChatEngine,
    tor: TorService,
    server: Option<PhoneServer>,
    mode: Mode,
    port: u16,
    data_dir: PathBuf,
    last_request: Option<String>,
    /// QR code of the current payload, as SVG, rebuilt when the payload changes.
    qr: Option<(String, String)>,
    jobs: Sender<Job>,
}

type Job = Box<dyn FnOnce(&mut App) + Send>;

/// Handle used by the window and the phone server to reach the worker thread.
#[derive(Clone)]
pub struct Worker {
    jobs: Sender<Job>,
}

impl Worker {
    /// Starts the worker thread: loads the pairing record and the mode from `data_dir` and starts serving.
    pub fn start(name: String, data_dir: PathBuf, port: u16) -> Self {
        let (jobs, inbox) = mpsc::channel::<Job>();
        let sender = jobs.clone();
        thread::spawn(move || {
            let mode = std::fs::read_to_string(data_dir.join("mode")).ok().and_then(|m| Mode::parse(m.trim())).unwrap_or(Mode::Tor);
            let mut app = App {
                pairing: PairingAuthority::new(&name, Some(data_dir.join("pairing.json"))),
                engine: ChatEngine::with_ona_core(),
                tor: TorService::new(data_dir.join("tor")),
                server: None,
                mode,
                port,
                data_dir,
                last_request: None,
                qr: None,
                jobs: sender,
            };
            app.serve();
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

fn run(mut app: App, inbox: Receiver<Job>) {
    let tick = Duration::from_millis(1500);
    let mut next = Instant::now() + tick;
    loop {
        match inbox.recv_timeout(next.saturating_duration_since(Instant::now())) {
            Ok(job) => job(&mut app),
            Err(RecvTimeoutError::Timeout) => {
                app.engine.tick();
                app.tor.poll();
                next = Instant::now() + tick;
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

impl App {
    /// (Re)starts the phone server, and the onion service in Tor mode.
    fn serve(&mut self) {
        self.server = None;
        self.tor.stop();
        let worker = Worker { jobs: self.jobs.clone() };
        let handler: server::Handler = Arc::new(move |request: http::Request| {
            worker.call(move |app| app.phone(request))
                .unwrap_or_else(|| http::Response::new(500, json!({"ok": false, "error": "stopped"})))
        });
        let exposure = if self.mode == Mode::Tor { Exposure::Localhost } else { Exposure::LocalNetwork };
        self.server = Some(PhoneServer::start(exposure, self.port, handler));
        if self.mode == Mode::Tor {
            self.tor.start(self.port);
        }
    }

    fn phone(&mut self, request: http::Request) -> http::Response {
        let response = router::handle(&request, &mut self.pairing, &mut self.engine);
        self.last_request = Some(format!("{} {} → {}", request.method, request.path, response.status));
        response
    }

    pub fn set_mode(&mut self, mode: Mode) {
        if mode == self.mode {
            return;
        }
        self.mode = mode;
        let _ = std::fs::create_dir_all(&self.data_dir);
        let _ = std::fs::write(self.data_dir.join("mode"), mode.name());
        self.serve();
    }

    pub fn stop(&mut self) {
        self.server = None;
        self.tor.stop();
    }

    /// Where the phone reaches this computer, as shown to the person.
    fn reachable_at(&self) -> Option<String> {
        match self.mode {
            Mode::Tor => self.tor.onion().map(String::from),
            Mode::LocalNetwork => local_ipv4().map(|ip| format!("http://{ip}:{}", self.port)),
        }
    }

    /// Text of the pairing QR code for the current mode, or None while it cannot be built yet.
    pub fn payload(&self) -> Option<String> {
        match self.mode {
            Mode::Tor => self.pairing.payload(None, Some(self.tor.onion()?)),
            Mode::LocalNetwork => self.pairing.payload(Some(&format!("http://{}:{}", local_ipv4()?, self.port)), None),
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
        let payload = if self.pairing.record.phone.is_none() { self.payload() } else { None };
        let qr = payload.as_deref().and_then(|p| self.qr_svg(p));
        let phone = self.pairing.record.phone.as_ref().map(|p| json!({"paired_at": p.paired_at, "verified": p.verified}));
        json!({
            "name": self.pairing.name,
            "mode": self.mode.name(),
            "port": self.port,
            "reachable": self.reachable_at(),
            "payload": payload,
            "qr": qr,
            "phone": phone,
            "awaiting_code": self.pairing.awaiting.as_ref().map(|a| a.code.clone()),
            "server_error": self.server.as_ref().and_then(PhoneServer::error),
            "tor": {"state": tor_state, "message": tor_message},
            "last_request": self.last_request,
            "chats": self.engine.list_json(),
        })
    }
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

    fn http(port: u16, method: &str, path: &str, body: &Value) -> Value {
        let body = body.to_string();
        for _ in 0..100 {
            if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                write!(stream, "{method} {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).unwrap();
                let json = reply.split("\r\n\r\n").nth(1).unwrap();
                return serde_json::from_str(json).unwrap();
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
        let worker = Worker::start("PC".into(), dir.clone(), port);
        let (code, computer_key) = worker.call(|app| (app.pairing.pairing_code.clone().unwrap(), app.pairing.computer_public_key())).unwrap();

        let phone = Phone::new();
        let proof = phone.sign(&protocol::pair_message(&code, &phone.public_key(), &computer_key));
        let paired = http(port, "POST", "/v0/pair", &json!({
            "code": code, "phone_key": protocol::b64(&phone.public_key()), "signature": proof,
        }));
        let id = paired["pairing_id"].as_str().unwrap().to_owned();
        let view = worker.call(|app| app.view()).unwrap();
        assert_eq!(view["awaiting_code"].as_str(), Some(protocol::verification_code(&computer_key, &phone.public_key(), &code).as_str()));
        worker.call(|app| app.pairing.confirm_code()).unwrap();

        let signature = phone.sign(&protocol::chat_message(&id, None, Some("Trouve un avocat")));
        let created = http(port, "POST", "/v0/chats", &json!({"pairing_id": id, "text": "Trouve un avocat", "signature": signature}));
        assert_eq!(created["ok"], true);
        let list = http(port, "GET", "/v0/chats", &json!({}));
        assert_eq!(list["chats"][0]["title"], "Trouve un avocat");
        assert_eq!(worker.call(|app| app.view()["last_request"].clone()).unwrap(), "GET /v0/chats → 200");
        worker.call(|app| app.stop()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
