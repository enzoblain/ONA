//! Sends ONA's traffic through a local Tor daemon, over SOCKS5 with name resolution left to Tor.
//!
//! The code lives in `ona_core::tor`, so that `ona-core` itself sends the relay traffic, the pool agent's calls and its
//! NEAR RPC reads through Tor when `ONA_TOR_SOCKS` is set (`ona_core::tor::Network`). This crate re-exports it for the
//! programs that build a transport or an RPC client themselves. See `docs/TOR.md`.

pub use ona_core::tor::{check_destination, near_client, Network, TorProxy, TorTransport, DEFAULT_SOCKS};
