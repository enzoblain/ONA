# Tor

`ona_core::tor` (re-exported by `crates/ona-tor`) sends the client's traffic through a local `tor` daemon. `ona` uses it when
`ONA_TOR_SOCKS` is set: the relay (`ona real`), the pool agent and the NEAR RPC reads of the pool commands all go through Tor, each
request on its own circuit, and nothing goes directly (docs/INSTALL.md, "Go through Tor"). Without it `ona` says at start that it
connects directly; `ONA_REQUIRE_TOR=1` makes it refuse to start. The desktop and phone apps do not set it yet.

**Do not publish the relay as an onion service yet.** It handles one connection at a time, so an anonymous client can stall it. Never
run `ona-mock-relay` with the onion service active: it hands out free test credits. The `/opt/homebrew` paths below are for Apple
Silicon Macs.

## Choice: SOCKS5 to a local `tor`

| | SOCKS5 to a local `tor` | Arti embedded |
|---|---|---|
| Code | `ureq`'s `socks-proxy` feature, no new crate in `Cargo.lock` | a large new dependency, and a custom connector for `ureq` (size not measured) |
| Status | C tor, 0.4.9.15 tested here for configuration | [FAQ](https://arti.torproject.org/FAQs): ready as a proxy and for embedding, onion services supported, some C tor features missing (read through a search summary on 2026-11-10) |
| Cost to the user | must install and run `tor` | nothing to install |

We use SOCKS5 because it is the smallest thing that works on macOS. The compromise is that the user has to run a separate program,
and the app cannot start or supervise it yet. This replaces the Arti plan: if a one-click install matters later, Arti can sit behind
the same `Transport` trait.

## What the code guarantees

Each point has a test in `crates/ona-tor/tests`, `crates/ona-core/tests/tor.rs` or the unit tests of `crates/ona-core/src/tor.rs`,
run against a fake SOCKS5 server on localhost.

- Host names go to Tor unresolved (`socks5h`), as a SOCKS domain name.
- **Fails closed.** If Tor is down, refuses the connection, or is not speaking SOCKS, the request returns an error and nothing is
  attempted directly. A listener standing for the destination confirms it receives no connection.
- The proxy must be on this machine.
- Destinations must be `http://` to a version 3 onion address or `https://` to a public host name. Plain `http` to the public internet,
  IP addresses (also written as names: `127.1`, `0x7f.1`, `2130706433`), `localhost` and `*.localhost`, names without a dot, a port that
  is not plain digits (`:+443`), and a query or fragment in the base address are refused.
- Redirects are not followed. No `User-Agent` header is sent.
- Every request of a `TorTransport`, and each `near_client`, gets its own random SOCKS username and password; `ona`'s RPC reads make a
  new client each. Tor's `IsolateSOCKSAuth`, on by default according to the Tor manual, puts streams with different credentials on
  different circuits; this is not verified on the real network. A cash issue and a vault entry therefore never share a circuit.
- Without Tor, `ona` refuses an onion address, so the name never reaches the local resolver.

## Run the relay as an onion service

The relay listens on `127.0.0.1:8787` only. `docs/torrc.relay.example` publishes it on port 80 of an onion address.

```
brew install tor
mkdir -p /opt/homebrew/var/lib/tor
tor -f docs/torrc.relay.example --DataDirectory "$HOME/.ona-tor-relay"
```

Tor creates the service's directory on first start. The address is in its `hostname` file:

```
cat /opt/homebrew/var/lib/tor/ona-relay/hostname
```

The same directory holds the service's private key, which is the address's identity. Keep it private and never commit it.

## Run the client side

```
tor -f docs/torrc.client.example --DataDirectory "$HOME/.ona-tor-client"
```

Wait for `Bootstrapped 100%` in its output. The template opens two ports, so that relay traffic and NEAR transactions do not share a
circuit: Tor [keeps separate SOCKS ports apart by default](https://2019.www.torproject.org/docs/tor-manual.html.en) (read through a
search summary on 2026-11-10, on an older copy of the manual). `SafeSocks 1` makes Tor itself refuse a request carrying an IP address.

`ona` uses one port for everything, its requests kept apart by their credentials: `ONA_TOR_SOCKS=127.0.0.1:9050 ona real`. A program
that builds its own transport or RPC client can use the two ports:

```rust
use ona_tor::{near_client, TorProxy, TorTransport};

let relay = TorProxy::new("127.0.0.1:9050")?;
let transport = TorTransport::new("http://<address>.onion", &relay)?;

let near = TorProxy::new("127.0.0.1:9052")?;
let client = near_client("https://<near-rpc-host>", signing_key, &near)?;
```

## Not verified

Tor could not reach the network where this was built (`Operation not permitted`, stuck at 0%), so none of this has run on the real
Tor network:

- reaching a real onion service, or an `https` RPC endpoint through a Tor exit, including TLS through the tunnel;
- whether a public NEAR RPC endpoint accepts connections from Tor exits;
- that the two SOCKS ports really get separate circuits, and that different SOCKS credentials do too;
- publishing the onion service. Locally, `tor --verify-config` accepted both templates, and Tor created the service's `hostname`
  file while offline. The relay template was validated with a temporary directory in place of its `HiddenServiceDir`.

Traffic timing and size are not protected by this crate: Tor does not hide them from an observer of both ends.
