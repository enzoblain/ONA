//! Listens for the phone: one HTTP request per connection, answered by the worker thread.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::http::{self, Response};
use serde_json::json;

pub const PORT: u16 = 8790;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Exposure {
    /// 127.0.0.1 only: reachable through the onion service (Tor) running on this computer.
    Localhost,
    /// All interfaces: reachable from the local network. For tests only.
    LocalNetwork,
}

/// Answers one parsed request. Called from the connection's thread.
pub type Handler = Arc<dyn Fn(http::Request) -> Response + Send + Sync>;

pub struct PhoneServer {
    stop: Arc<AtomicBool>,
    /// None while listening; a message when listening failed (the server retries by itself).
    pub error: Arc<Mutex<Option<String>>>,
}

impl PhoneServer {
    pub fn start(exposure: Exposure, port: u16, handler: Handler) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let error = Arc::new(Mutex::new(None));
        let (stop_flag, error_slot) = (stop.clone(), error.clone());
        thread::spawn(move || {
            let address: SocketAddr = match exposure {
                Exposure::Localhost => ([127, 0, 0, 1], port).into(),
                Exposure::LocalNetwork => ([0, 0, 0, 0], port).into(),
            };
            while !stop_flag.load(Ordering::Relaxed) {
                let listener = match TcpListener::bind(address).and_then(|l| l.set_nonblocking(true).map(|_| l)) {
                    Ok(listener) => listener,
                    Err(e) => {
                        set(&error_slot, Some(format!("Écoute impossible sur le port {port} : {e}. Nouvel essai…")));
                        thread::sleep(Duration::from_secs(3));
                        continue;
                    }
                };
                set(&error_slot, None);
                while !stop_flag.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let handler = handler.clone();
                            thread::spawn(move || serve(stream, handler));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(40)),
                        Err(_) => thread::sleep(Duration::from_millis(200)),
                    }
                }
            }
        });
        Self { stop, error }
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().ok().and_then(|e| e.clone())
    }
}

impl Drop for PhoneServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn set(slot: &Mutex<Option<String>>, value: Option<String>) {
    if let Ok(mut slot) = slot.lock() {
        *slot = value;
    }
}

fn serve(mut stream: TcpStream, handler: Handler) {
    let _ = stream.set_nonblocking(false);
    // A connection that never completes its request is dropped.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let response = loop {
        match http::parse(&buffer) {
            http::Parse::Request(request) => break handler(request),
            http::Parse::Invalid(status) => break Response::new(status, json!({"ok": false, "error": "bad request"})),
            http::Parse::Incomplete => match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            },
        }
    };
    let _ = stream.write_all(&response.bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_over_tcp() {
        let handler: Handler = Arc::new(|request| Response::new(200, json!({"path": request.path})));
        let server = PhoneServer::start(Exposure::Localhost, 18790, handler);
        let mut reply = String::new();
        for _ in 0..50 {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", 18790)) {
                stream.write_all(b"GET /v0/chats HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                stream.read_to_string(&mut reply).unwrap();
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(reply.starts_with("HTTP/1.0 200 OK"), "{reply}");
        assert!(reply.ends_with(r#"{"path":"/v0/chats"}"#));
        drop(server);
    }
}
