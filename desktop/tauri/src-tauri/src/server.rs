//! Listens for the phone: one HTTP request per connection, answered by the worker thread. Connections are capped and
//! each request has an overall deadline.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::http::{self, Response};
use serde_json::json;

/// Port of the local-network mode (debug builds). In Tor mode the port is chosen by the system at each start.
pub const PORT: u16 = 8790;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Exposure {
    /// 127.0.0.1 only: reachable through the onion service (Tor) running on this computer.
    Localhost,
    /// All interfaces: reachable from the local network. Debug builds only.
    LocalNetwork,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connections served at the same time; more are closed at once.
    pub max_connections: usize,
    /// Time allowed to receive a whole request and send the reply.
    pub deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_connections: 16, deadline: Duration::from_secs(10) }
    }
}

/// Answers one parsed request. Called from the connection's thread.
pub type Handler = Arc<dyn Fn(http::Request) -> Response + Send + Sync>;

pub struct PhoneServer {
    stop: Arc<AtomicBool>,
    /// The port actually listened on.
    pub port: u16,
}

impl PhoneServer {
    /// Binds now (port 0: a port chosen by the system) and serves on a thread. Fails if the port cannot be bound: the
    /// caller must not publish the onion service then.
    pub fn start(exposure: Exposure, port: u16, handler: Handler, limits: Limits) -> std::io::Result<Self> {
        let address: SocketAddr = match exposure {
            Exposure::Localhost => ([127, 0, 0, 1], port).into(),
            Exposure::LocalNetwork => ([0, 0, 0, 0], port).into(),
        };
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let active = Arc::new(AtomicUsize::new(0));
        thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if active.fetch_add(1, Ordering::SeqCst) >= limits.max_connections {
                            active.fetch_sub(1, Ordering::SeqCst);
                            drop(stream); // over the cap: closed at once
                            continue;
                        }
                        let (handler, active) = (handler.clone(), active.clone());
                        thread::spawn(move || {
                            serve(stream, handler, limits.deadline);
                            active.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(40)),
                    Err(_) => thread::sleep(Duration::from_millis(200)),
                }
            }
        });
        Ok(Self { stop, port })
    }
}

impl Drop for PhoneServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(mut stream: TcpStream, handler: Handler, deadline: Duration) {
    let started = Instant::now();
    let _ = stream.set_nonblocking(false);
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let response = loop {
        match http::parse(&buffer) {
            http::Parse::Request(request) => break handler(request),
            http::Parse::Invalid(status) => break Response::new(status, json!({"ok": false, "error": "bad request"})),
            http::Parse::Incomplete => {
                // The whole request must arrive before the deadline, however slowly the bytes come.
                let left = deadline.saturating_sub(started.elapsed());
                if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
                    return;
                }
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                }
            }
        }
    };
    let left = deadline.saturating_sub(started.elapsed()).max(Duration::from_secs(1));
    let _ = stream.set_write_timeout(Some(left));
    let _ = stream.write_all(&response.bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(port: u16) -> TcpStream {
        for _ in 0..50 {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
                return stream;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("server never listened");
    }

    #[test]
    fn answers_over_tcp_on_a_port_chosen_by_the_system() {
        let handler: Handler = Arc::new(|request| Response::new(200, json!({"path": request.path})));
        let server = PhoneServer::start(Exposure::Localhost, 0, handler, Limits::default()).unwrap();
        assert_ne!(server.port, 0);
        let mut stream = connect(server.port);
        stream.write_all(b"POST /v1/chats/list HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.0 200 OK"), "{reply}");
        assert!(reply.ends_with(r#"{"path":"/v1/chats/list"}"#));
    }

    /// A request trickled one byte at a time is dropped at the overall deadline.
    #[test]
    fn drops_a_slow_request_at_the_deadline() {
        let handler: Handler = Arc::new(|_| Response::new(200, json!({})));
        let limits = Limits { max_connections: 4, deadline: Duration::from_millis(400) };
        let server = PhoneServer::start(Exposure::Localhost, 0, handler, limits).unwrap();
        let mut stream = connect(server.port);
        let started = Instant::now();
        let mut closed = false;
        for byte in b"POST /v1/chats/list HTTP/1.1\r\nHost: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" {
            if stream.write_all(&[*byte]).is_err() {
                closed = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
            if started.elapsed() > Duration::from_secs(2) {
                break;
            }
        }
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500))); // fails on some systems once closed
        let mut rest = Vec::new();
        let read = stream.read_to_end(&mut rest);
        let reset = read.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset);
        assert!(closed || reset || matches!(read, Ok(0)), "connection still open after the deadline: {read:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    /// Connections over the cap are closed at once.
    #[test]
    fn closes_connections_over_the_cap() {
        let handler: Handler = Arc::new(|_| Response::new(200, json!({})));
        let limits = Limits { max_connections: 2, deadline: Duration::from_secs(5) };
        let server = PhoneServer::start(Exposure::Localhost, 0, handler, limits).unwrap();
        let _idle = [connect(server.port), connect(server.port)];
        thread::sleep(Duration::from_millis(150));
        let mut third = connect(server.port);
        third.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
        let mut buffer = [0u8; 16];
        let read = third.read(&mut buffer);
        let closed = matches!(read, Ok(0)) || read.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset);
        assert!(closed, "third connection was served: {read:?}");
    }
}
