<img src="assets/logo.png" alt="ONA logo" width="120">

# ONA: a private AI assistant, built so that no one links who you are to what you ask

Built at NEAR HACKATHON · Tracks: to be confirmed · Network: NEAR testnet (planned) · Not audited

> **Status: early prototype, not audited.** The token crypto, the two contracts, the signer and relay logic, the wallet and the
> local mission core exist and pass their tests. The mint contract has run on a local NEAR node, with measured gas. The model and the
> web are still fake, and nothing is deployed on testnet. **Do not use real funds.** See [what works today](#what-works-today).

## What it is

ONA is an AI assistant for sensitive matters: legal, medical, financial or professional questions you would not want
tied to your name. You talk to it from your computer or your phone. It can also act on your behalf (search the web,
contact a professional, make a payment), and asks for your explicit confirmation before each of these actions.

The difference is who sees what. ONA is designed so that no single party gets both who you are and what you asked:

- **the model** reads your request with the names and identifiers you declare replaced by pseudonyms, inside an enclave (NEAR AI
  Cloud). Until this client verifies the enclave's quotes, the relay in front of the model can read the request and make up replies;
- **websites and the people the agent contacts** see Tor traffic and a generic message, not you;
- **payments** use blind tokens: the mint that holds your deposit cannot link it to what you pay for;
- **your phone** talks to your own computer over Tor, and the agent runs on that computer, not on our servers.
- **the pool** (planned, testnet only): you deposit from your own wallet, your money becomes blind cash notes, and an exit pays
  your account without naming the vault you chose. Deposit, enter, switch, exit and the portfolio run end to end only against a
  fake contract and a fake agent so far.

After each mission, ONA shows an **exposure report**: every party that received something, how many requests and how many bytes
it received (not the content itself).

### What pseudonyms cover

Before any text goes to the model (the planner and the page reader), `ona-core` replaces every occurrence of each protected term
(the terms of the policy and those declared when the mission is opened: names, case numbers, company names) with a random 12-letter
pseudonym such as `KQXMZBTRWLDN` (letters only, so it can never be read as a price). The model's reply is put back locally, whatever
the case of the pseudonym. The table stays on the computer and is forgotten when the mission closes. A text that still contains a
protected term after replacement is refused, not sent.

Texts and terms are compared on a normalized view:

- HTML tags and comments are removed (`<br>`, `<p>`, `<div>`, `<li>`, `<tr>` count as a line break). Pages reach the reader exactly as
  the web layer returns them: today the web is a fake that returns plain text, and a real one may return HTML, so tags are handled
  either way.
- One level of decoding: numeric HTML references (with or without `;`, any number of leading zeros, `&#128;` to `&#159;` read as
  Windows-1252 like browsers do); named references of Latin-1 (also without `;`), Latin Extended-A, common punctuation and invisible
  characters (`&ZeroWidthSpace;`, `&NoBreak;`, `&it;`...); URL escapes (`%70`), bytes that are not valid UTF-8 being dropped.
- Unicode default-ignorable characters (soft hyphens, zero-width spaces and joiners, direction marks, variation selectors...) and the
  line separators U+2028, U+2029, U+0085 are removed.
- A dash or a soft hyphen at the end of a line, between letters, may be there or not: `Du-` / `pont` matches "Dupont", and `Jean-` /
  `Luc` matches "Jean-Luc".
- These dashes become `-`: U+002D, U+058A, U+05BE, U+1400, U+1806, U+2010 to U+2015, U+2043, U+2053, U+207B, U+208B, U+2212, U+2E17,
  U+2E1A, U+2E3A, U+2E3B, U+2E40, U+2E5D, U+301C, U+3030, U+30A0, U+FE31, U+FE32, U+FE58, U+FE63, U+FF0D, U+10EAD, U+02D7, U+2796.
  These apostrophes become `'`: U+0027, U+0060, U+00B4, U+02B9, U+02BB to U+02BE, U+0384, U+055A, U+05F3, U+1FBD, U+1FBF, U+1FEF,
  U+1FFD, U+2018, U+2019, U+201B, U+2032, U+2035, U+A78B, U+A78C, U+FF07, U+FF40.
- Unicode NFKD (full-width and mathematical letters, ligatures), every combining mark removed (accents never matter: "ELODIE" matches
  "Élodie"; stray underline or strike-through marks are ignored), lowercase, `ß` read as `ss`.
- Every run of white space (spaces, tabs, line breaks, no-break spaces) is one space: "Jean\nDupont" matches "Jean Dupont".

A term matches as a whole word ("Ali" is not replaced in "alibi"); a term written `*between asterisks*` matches inside words too.

**Not covered:** a term you did not declare; a term written another way (misspelled, abbreviated, inflected, initials, nickname,
transliterated, a rephrasing); a name split by a line break without a hyphen (`Du` / `pont`); look-alike letters from another script
(Cyrillic `у` in "Dupont"); small capitals and other letters that NFKD does not fold; escapes nested twice or more (`%2570`,
`&amp;#112;`, `%26%23112%3B`); `+` written for a space in a URL; HTML named references outside the sets above (such as `&Dopf;`); a
numeric reference whose digits run into the next letters (`&#x2019Brien` reads `&#x2019B`, as a browser does); and the context around
a name (job, city, dates, a rare situation), which can be enough to identify someone.

This is the design. Today the model, the web and the payments in the app are still fakes; see
[what works today](#what-works-today) and the [known limitations](#known-limitations).

Example: find a labour lawyer and compare fees on a generic version of your case, without the firms you did not pick
learning who you are.

## The problem

A hosted AI chat links your identity, your conversations and your actions at one operator. Encrypted inference helps
with the content, but the account, the network address, the payment and the agent's actions still identify you.

## Planned architecture

| Component | Role | Language |
|---|---|---|
| `ona-core` | Runs on the user's computer: mission state machine, payment gate, pseudonyms, E2EE client for NEAR AI Cloud, wallet tokens, sealed state, journal, exposure report. Reaches the relay, the pool agent and the NEAR RPC nodes through a local `tor` over SOCKS5 when `ONA_TOR_SOCKS` is set, one circuit per request; otherwise directly, and says so at start | Rust |
| Desktop app | Connects a NEAR wallet for deposits, starts missions, asks for confirmations, shows the exposure report | Swift (SwiftUI) on macOS; Rust + Tauri with HTML/JavaScript on Windows and Linux; both on `ona-core` (to be confirmed) |
| iOS app | Remote control of the computer over Tor: mission progress and confirmations. Holds no tokens and no pseudonym table | Swift |
| `ona-server` | Thin relay in a TEE (Phala dstack): holds the NEAR AI Cloud key, enforces a flat request size, submits transactions | Rust |
| `ona-signer` | Blind-signs tokens after on-chain deposits; no inbound network | Rust |
| `ona-mint` | NEAR contract: holds the reserve, verifies blind BLS12-381 tokens, pays recipients directly, returns blinded change | Rust |
| `ona-registry` | NEAR contract: published measurements, journal anchors, incident level | Rust |
| `ona-pool` | NEAR contract with no access key: holds the funds the agent places, only in listed vaults, and pays exits only to accounts that deposited | Rust |
| `ona-agent` | The pool's agent: blind-signs cash and share notes after the contract has done what they stand for, calls the contract with the agent's key, and moves the vaults' money on a schedule | Rust |

## How paying works (planned)

1. **Top up.** Connect a NEAR wallet and confirm one deposit to `ona-mint`. This is the only time the wallet signs.
2. **Send a mission.** The app shows the plan and the price. You confirm. Blind tokens are spent locally, with no transaction.
3. **Pay a third party.** You confirm the recipient and the amount. `ona-mint` pays directly and returns blinded change.

## What works today

| Part | State | Tested on |
|---|---|---|
| `ona-token` blind BLS tokens | done | native tests |
| `ona-mint` contract | done, gas measured ([SPEC](SPEC.md#measured-gas)) | mocked NEAR VM with real BLS and ed25519 host functions, and a local NEAR node |
| `ona-registry` contract | done | mocked NEAR VM only |
| `ona-pool` contract: listed staking vaults, cash notes with no vault and share notes, exits that name no vault, only to depositors, exit limits that grow only on money still in the pool, 7-day escape | done, never deployed, lending not implemented | mocked NEAR VM only, never against a real staking pool |
| `ona-crowd` crowd simulator for the pool demo | simulation and vault-privacy measure done; the NEAR runner has never run | in-memory chain only |
| `ona-anchor` hourly journal anchoring, chained checkpoints and their audit, auditor key sealing in `ona-core` | library done, no program receives leaves yet, the agent does not submit checkpoints yet | fake registry only, never on a NEAR node |
| `ona-deploy` deployment tool | done; refuses mainnet from the names, the parent account and the chain id the node reports; checks the roles and the deployed code hash; testnet not tried yet | unit tests |
| `ona-near` RPC client | done; https only (except a local node, or an onion address through Tor), only final results are read, failed receipts are listed apart from the transaction status, an unclear send is looked up by its hash and never sent twice. Trusts its RPC node | unit tests against a fake node, and a local NEAR node through `ona-sandbox` before these changes |
| `ona-signer` issuing loop | done, keys in a local file | fake chain, and a local NEAR node |
| `ona-server` relay | logic, HTTP, chain client and encrypted NEAR AI gateway done; the `ona-relay` program has not run yet | fake chain and fake NEAR AI, and a local NEAR node for the chain path |
| `ona-wallet` encrypted wallet file | done, keychain not wired in; a wallet without its seal file is refused by design (`open_adopting_unsealed` adopts one explicitly) | native tests |
| `ona-core` mission, gate, sealed journal, 24-hour chat deletion | done | fake model, web and payments, each labelled `mode: mock` |
| `ona-core` pool commands (deposit, enter, switch, exit to cash, cash payout, portfolio, recovery; prepare then execute once) and pool notes in `ona-wallet` | done; the HTTP client of the agent is built (`ONA_POOL_AGENT_URL`); the bridge's wallet setup is not ([commands](docs/desktop/pool-commands.md)) | fake pool contract with a fake agent, and with the real agent over HTTP on this machine |
| `ona-agent` pool agent: blind-signing keys, HTTP API, durable store with retention and purge, checks before any gas, depositor check by wallet signature (NEP-413), queue sending entries, leaves and cash exits in delayed batches, planner (reserve, net settlement, steady withdrawals on a fixed grid) | done, **never run against a real chain**, not in an enclave; the NEP-413 format is not verified against a wallet; the agent itself sees every request | fake pool contract only, and the client core against it over HTTP on this machine |
| `ona-core` encrypted NEAR AI client | done, quote verification missing, not yet connected to missions | simulated enclave. The same protocol passed one real call from a test script |
| Desktop app (`desktop/`, macOS) | conversations and confirmations driven by `ona-core` (fake model, web and payments), phone pairing and the phone protocol v1 (commit-then-reveal pairing, signed replies, token for reads, counter against replays, signed content of each confirmation); local-network mode in debug builds only; no wallet yet | Core tests with the real `ona-core` (compiled with `swiftc`, not `swift test`); one end-to-end run with protocol v1 against the iOS app in the simulator, on the local network ([notes](docs/desktop/app.md)) |
| Desktop app (`desktop/tauri`, Windows and Linux) | same features and protocol v1 as the macOS app, in Rust with Tauri; no wallet yet | Rust tests of every module but `main.rs` with the real `ona-core`, run on macOS; one end-to-end run with protocol v1 against the iOS app in the simulator, on the local network, on macOS. Never built or run on Windows or Linux ([notes](docs/desktop/tauri.md)) |
| iOS app (`ios/`) | Tor (Arti embedded): an earlier test build reached a test onion service; the Tor screen is now a tab of the app | one iPhone 16, one series of measurements ([notes](docs/ios/tor-spike.md)) |
| iOS app (`ios/`) | chat-style conversations with the agent, and a read-only Pool tab (portfolio from the computer, labelled `mock` until a pool runs), over protocol v1: commit-then-reveal QR pairing, every reply of the computer checked with its key, a token for reads, a counter and a low-s signature for writes, confirmations signed over the digest of what the phone shows, payment digest v2. The mock computer speaks v1 too, labelled `mode: mock`. Over Tor (Arti), one full v1 mission passed against the Tauri app; the first connections to the onion often took more than 60 s. The Secure Enclave key path has not run on a device yet | iOS simulator (software key) against the Tauri app (local network and Tor) and the mock, unit tests on the Mac, vectors shared with the desktop apps ([notes](docs/ios/app.md)) |
| Client through Tor (`ona_core::tor`, re-exported by `ona-tor`) | wired into `ona`: relay, pool agent and NEAR RPC reads go through a local `tor` when `ONA_TOR_SOCKS` is set, each request with its own SOCKS credentials, no direct fallback; `ONA_REQUIRE_TOR=1` refuses to start without it. Never tested on the real Tor network ([docs/TOR.md](docs/TOR.md)) | fake SOCKS server only, never on the real Tor network |
| Phala enclave | not built | none |

## Run it

Setup and details are in [docs/INSTALL.md](docs/INSTALL.md). To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md).

`./verify.sh` runs every test, compiles the three contracts (and a test staking pool used only on a local node) without local
paths and prints their SHA-256. It needs Rust 1.99.1 and the
`wasm32-unknown-unknown` target, and no key, no funded account, no Docker and no browser.

```
cargo run -p ona-core --bin ona -- demo     # a full mission against the fakes
cargo run -p ona-server --bin ona-mock-relay -- 8787     # a fake relay on localhost for front-end work
```

To measure gas on a local node, run `verify.sh`, set `NEAR_SANDBOX_BIN_PATH` to a `near-sandbox` binary you have checked (required: the
program refuses to let the library download one), and run `cargo run -p ona-sandbox`. `cargo run -p ona-sandbox --bin
ona-sandbox-pool` is written to run the pool, its agent and the pool commands on a local node against a test staking pool, fallback
included, and print the gas of each call; it has not been run yet.

## Next steps (product direction, not built yet)

**Privacy metrics in a side panel of the app.**
- Show a privacy figure next to the chat, for example: "for similar amounts, your privacy is at X% with ONA and Y% without it".
- When the agent recommends a vault or a placement, it states how much that choice raises the privacy figure (for example "+Z
  points").
- The figure must come from a measure that is defined and published (for instance how many deposits of a similar amount, and how
  many notes in the same vault, an observer cannot tell apart), computed from what is on chain at that moment. No fixed or
  invented percentage: while the anonymity set is one (see below), the panel says so.

**Website on Vercel, three pages.**
1. Home: presentation of the project, with polished animations and the interesting metrics (same rule: measured and dated, or
   marked as an example).
2. Demo.
3. Downloads: links to install each app (Mac, other desktops, iPhone).

## Known limitations

- At launch the anonymity set is one, so ONA claims no unlinkability until a measured number of users is published.
- Deposits are public on chain and show that an account uses ONA.
- Every program trusts the NEAR RPC node it is given: no proof is checked, so a lying node can make the signer sign for a deposit
  that does not exist. Run your own node for the signer and the relay.
- The model enclave reads the pseudonymized prompt by design, under a TEE assumption. Pseudonyms replace declared terms only (see
  [what pseudonyms cover](#what-pseudonyms-cover)).
- **The relay can read what goes to the model and invent replies.** The client takes the model key from an attestation report that the
  relay delivers and does not verify the Intel and NVIDIA quotes yet. Every exposure report with a real call says so.
- The payment confirmation is a digest bound to the network, the contract, the mission, a random nonce, the recipient and the amount
  of the chosen offer; it proves the caller saw these fields, not that a human did, since it is not signed by a separate device.
- NEAR AI Cloud keeps one usage row per request.
- The computer must be on for a mission to progress.
- The same team would operate the relay, the signer and the anchoring.
- Anchoring proves that the checkpoints shown form an unbroken chain that existed at those dates. It rules out a second chain with
  the same key only if the aggregator is honest, kept its records and was not replaced during the mission, and the auditor knows
  from elsewhere when the mission was opened. It cannot rule out a second history built from the start with another key unless the
  mission's opening tag was recorded elsewhere, and it proves what the agent wrote, not that it is true.
- One owner of the registry can replace the other after 30 days unless the other vetoes, so a stolen key is a threat as long as
  nobody watches for such proposals.
- Chats are deleted after 24 hours only when the app runs: nothing purges while it is closed. Keys are in a local file outside the
  chat folder until the keychain is wired in, and overwriting deleted files does not erase them on an SSD or on APFS.
- Testnet only. The mint has no real-money deployment planned.
- **A dishonest relay may still be able to read replies.** With encryption version 2, the relay controls which client key the reply is encrypted to.
  The client now uses version 3, which binds the reply key, but this fixes the problem only if the NEAR AI gateway accepts version 3, which is **not verified**.
  Version 3 was tested only against a simulated enclave. A relay running in an attested enclave is not in place yet.
- The relay serves a fixed pool of 32 connections with per-request deadlines, so 32 slow clients are enough to keep it busy. Do not expose it
  to the internet yet; behind an onion service, rely on its denial-of-service protection.
- The signer and the relay read the chain through two RPC endpoints and stop when they disagree. Two endpoints that lie together still
  decide what gets signed.
- A stolen signer key can drain the reserve at the speed of the hourly redemption limit. There is no key rotation.
- An attacker holding tokens can keep a tier's redemption limit used up and slow exits for that tier (the relay has its own limit).

More in [SPEC.md](SPEC.md).

## Libraries and AI-generated code

Main libraries: `blst`, `near-sdk`, `near-sandbox`, `ed25519-dalek`, `sha2`, `chacha20poly1305`, `hkdf`, `serde_json`, `tokio`,
`unicode-normalization`.
The NEAR client, the deployment tool and the crowd simulator also use `ureq` (with `rustls`), `bs58`, `base64`, `anyhow`, `libc`,
`zeroize`, `rand` and `rand_chacha`. The relay and the signer use `ureq` 3.5.1 and `zeroize` 1.9.1, pinned exactly; the pool agent
(`ona-agent`) uses the same libraries, through the relay's HTTP front and two-endpoint reader. `Cargo.lock` fixes
every version, and `verify.sh` builds with `--locked`.

Client core (`crates/ona-core`), pinned exactly:

| Library | Version | Used by | Notes |
|---|---|---|---|
| `unicode-normalization` | 0.1.26 | `ona-core` (pseudonyms) | NFKD and combining marks, before protected terms are compared |

The code and tests in this repository were written with Claude (Anthropic), under human direction.

iOS side, pinned exactly (`Cargo.lock` pins the transitive ones):

| Library | Version | Used by | Notes |
|---|---|---|---|
| `arti-client` (Tor Project) | 0.48.0 | `ios/ArtiBridge` (the iOS app) | Features: tokio, native-tls, compression, onion-service-client, static-sqlite |
| `tor-rtcompat` (Tor Project) | 0.48.0 | `ios/ArtiBridge` | |
| `tokio` | 1.54.1 | `ios/ArtiBridge` | |
| `serde_json` | 1.0.154 | `ios/ArtiBridge` | |
| `tracing-subscriber` | 0.3.23 | `ios/ArtiBridge` | |
| `sysinfo` | 0.38.4, patched | `ios/ArtiBridge` (via `tor-memquota`) | Local copy with a one-function change so it builds for iOS: `ios/ArtiBridge/patches/sysinfo-0.38.4/ONA-PATCH.md` |

Desktop app for Windows and Linux (`desktop/tauri/src-tauri`), pinned exactly (`Cargo.lock` pins the transitive ones):

| Library | Version | Used for |
|---|---|---|
| `tauri` | 2.12.5 | window, web view, commands |
| `tauri-build` | 2.7.4 | build script |
| `p256` (RustCrypto) | 0.13.2 | checking the phone's ECDSA P-256 signatures, signing replies with the computer's key |
| `sha2` | 0.10.9 | pairing commitment, 6-digit code, digests of what the phone confirms |
| `base64` | 0.22.1 | protocol encoding |
| `rand` | 0.8.8 | pairing codes and ids |
| `qrcode` | 0.14.1 | pairing QR code (SVG) |
| `serde`, `serde_json` | 1.0.229, 1.0.154 | JSON |

Build tooling, not shipped: `.github/workflows/release.yml` builds the apps on GitHub's machines with Rust 1.99.1,
`tauri-cli` 2.12.4 (installed with `--locked`) and the GitHub actions `actions/checkout` v7.0.1,
`actions/upload-artifact` v7.0.2 and `actions/download-artifact` v8.0.2, each pinned to its commit
([docs/RELEASE.md](docs/RELEASE.md)).

Test tooling, not shipped: C Tor 0.4.9.16 (Homebrew) runs the test onion service on the developer's Mac.
The iOS app (`ios/ONA`) uses only Apple frameworks (SwiftUI, Foundation, CryptoKit, Security, VisionKit). The mock
computer (`ios/MockComputer`) uses only the Python standard library; its P-256 code (`p256.py`) is written for the mock
only and is not meant for real keys.

## Related project

To be named.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Hugo Thomas & Enzo Blain.
