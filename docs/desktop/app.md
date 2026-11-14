# macOS desktop app (SwiftUI)

Created on 2026-11-10 on the `desktop-app` branch. Phone protocol moved to version 1 on 2026-11-11 (security fixes, see
`docs/ios/protocol-draft.md`).

## What exists

| Path | Role |
|---|---|
| `desktop/OnaCoreBridge/` | Rust crate: C interface around `ona-core` (`ona_core_new`, `ona_core_dispatch(json)`, `ona_core_free`). Outside the root workspace; `Cargo.lock` copied from the root to get the same versions. `build.sh` produces `OnaCore.xcframework` (macOS, Apple silicon). |
| `desktop/ONADesktop/Core/` | The app's logic, tested by `swift test`: protocol bytes, pairing and signature checks (CryptoKit), HTTP server for the phone (Network.framework), conversation engine that drives `ona-core`, Tor service. |
| `desktop/ONADesktop/App/` | SwiftUI interface (macOS 26, Liquid Glass): conversations, pairing window, settings. |

## How it works

- **Agent**: each conversation has its own `ona-core` (`Core::dispatch`). The engine moves it one step forward every
  1.5 s (`open`, `propose_plan`, `search`, `read`, `compare`, `contact`, `prepare_payment`, `pay`, `close`,
  `exposure`) and stops at the three confirmations. Model, web and payments are `ona-core`'s fakes (`mode: mock`),
  hence the "Simulation" banner. The search uses the `lawyer` / `paris` search template of `ona-core`'s demo policy,
  whatever the request. Since 2026-11-13, a new conversation is a free research (see "Free research" below); the
  lawyer mission is only started by its tests.
- **Confirmations**: from the Mac (buttons in the conversation) or from the phone (signed). The payment is confirmed
  by `confirm_payment(digest)`: it is `ona-core`'s guardrail that compares the digest.
- **Pairing**: the Mac keeps its P-256 key and the paired phone (public key, token, last counter, identifiers of
  confirmations already carried out) in one item of the login keychain. The code asks for
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` on each write; the actual effect on a Mac's login keychain (file,
  unsigned app) is **not checked**. An unreadable item is never overwritten: the error is shown and pairing is
  disabled. "Pair a phone" window: single-use QR code valid for 10 minutes, commitment then reveal of the phone's key,
  6-digit code to compare within 5 minutes ("Reject" also if the phone shows no code). Nothing is saved before the
  comparison. A failure to save is shown.
- **Phone**: protocol v1 (`docs/ios/protocol-draft.md`): everything is `POST`, reads with the pairing token, writes
  signed by the phone with an increasing counter, replies signed by the Mac. `Host` header checked, browser requests
  refused.
- **Connection**: "Through Tor": server on 127.0.0.1, port chosen by the system at each start, published as a
  `.onion` service by the local `tor` daemon (Homebrew) once the server is listening; `__OwningControllerProcess`
  stops `tor` with the app. "Local network" (plain HTTP on all interfaces, port 8790): **Debug builds only**, absent
  from Release builds.
- **Server**: at most 16 simultaneous connections, 10 s to receive and handle a request.
- **Nothing on disk for conversations**: in memory only (`ona-core`'s vault is not wired in).

## Run

```bash
desktop/OnaCoreBridge/build.sh                 # once (~1 min)
open desktop/ONADesktop/ONADesktop.xcodeproj   # ONADesktop target
cd desktop/ONADesktop && swift test            # tests, with the real ona-core
```

The app is not sandboxed (it starts Homebrew's `tor`, which the sandbox forbids) and is signed "Sign to Run Locally".
"Hardened runtime" is enabled in Release (not checked: no Xcode here). The "Copy the code text" button (general
pasteboard) exists only in Debug.

## Checked on 2026-11-11 (protocol v1)

- `Core` tests (32, Testing framework) compiled with `swiftc` and run against the real `ona-core`: vectors shared with
  the Tauri app (including a signature made by `p256`), commitment and reveal, replay refused after a restart, token,
  `Host`, browser, signed content, v2 payment digest. `swift test` itself could not run (no Xcode in the test
  environment). The App target (SwiftUI) was not compiled.
- End to end with protocol v1 on 2026-11-11, local network: iPhone app (simulator) ↔ Mac app (Debug, branch
  `desktop-onion-ready`) ↔ `ona-core`, from pairing to the report (payment of 0.6 NEAR checked in v2).

## Checked on 2026-11-10 (protocol v0, before the fixes)

- `swift test`: 15 tests passed, including a full mission on the real `ona-core` (plan, choice of firm, a wrong digest
  refused by the guardrail, payment, report) and the router (pairing, refusal before the code is checked, signatures).
  Rust: 2 tests of the bridge.
- **End to end, local network**: iPhone app (simulator) ↔ Mac app ↔ `ona-core`. Pairing, creation of a signed
  conversation, plan, choice of cabinet-b, payment checked on the phone then confirmed, `ona-core`'s report
  (cabinet-b, 1 NEAR) received by the phone. Pairing kept after the Mac app restarted.
- The Mac's sidebar updated live (window capture).

## Not checked

- The Mac app's Tor mode (same torrc as `ios/MockComputer/run_onion.sh`, which worked).
- Showing a conversation in the Mac window and confirmations from the Mac: no automated click possible here; only the
  list and the "Paired phone" window were seen.
- Once, listening on the port did not start after a restart (cause unknown); the app now shows the error and retries
  on its own.
- NEAR wallet, deposits, real model: not in this app.
- Calls to `ona-core` are made on the main thread: with a real model (seconds per call), the window and the phone
  server would be blocked during each call. To be moved to a dedicated queue before the real model.
- The connection cap and the overall timeout of the Swift server have no automated test (those of the Tauri app do).

## Real model

Same settings and same rules as the Tauri app (docs/desktop/tauri.md, "Real model"), in
`~/Library/Application Support/ONA/model.json`. The bridge takes them with `ona_core_new_with`, and the core's traffic
goes through the app's tor, on a second SOCKS port. Tested with unit tests only, not against a relay yet.

The bridge's release profile does not strip build-time dylibs (proc macros): the `strip` of Xcode 27 (beta) leaves them
unloadable.

Each conversation's ona-core runs on a serial queue of its own (`CoreQueue`). The main actor, which also serves the
window and the phone, sends one command at a time and waits at most 50 ms per tick: a real model call goes on while
the app stays responsive, and its reply is taken at a later tick. Confirmations and the end of a mission wait for their
reply (they do not reach the model). Reading the pool for the phone still waits for its reply.

## Erasure and backups

Conversations are kept in memory only: they are gone when the app quits, and nothing about them is written to disk, so
no system task is needed to erase them. ona-core's vault (chats kept up to 24 hours) is not used by the app; if it is,
an erasure task running while the app is closed will be needed. The app's folder (`~/Library/Application Support/ONA`:
onion key, tor's state, `model.json`) is marked excluded from Time Machine at every launch; a failure is shown in the
window. A request tokens file elsewhere is not covered.

## Pool

The **Pool** toolbar button opens a sheet with the pool (docs/desktop/pool-commands.md): the total, the cash, one line
per vault (its value, "frozen" for a frozen vault, a clock while notes are spending or waiting for their signature), and the
operations: **Place cash** (enter), **Switch** and **Exit** on a vault (switch, exit), **Pay to an account**
(exit_cash), **Deposit** (deposit) and **Recover** (`pool_recover`). Each operation is prepared by ona-core
(`pool_prepare`), its summary shown (amount, vaults or account, what is received, what is left in the pool's cash and
lost, exit limit, fees, warnings, network, contract, expiry; not the share price), and executed only when the person
clicks **Confirm** in this sheet: never from the phone, which only reads the portfolio. An `outcome unknown` error is
shown as sent to the pool agent, result later through **Recover**. A deposit is prepared and its summary and wallet
call shown, without a confirm button: it is sent and signed by the person's own NEAR wallet, and connecting a wallet to
the app is not built. Amounts typed in NEAR ("1.5", "1,5", or "all" where the operation allows it) are turned into
yoctoNEAR exactly, without floating point.

Settings: `~/Library/Application Support/ONA/pool.json`, with the same keys as the Tauri app (docs/desktop/tauri.md,
"Pool"): `wallet_file`, `wallet_key_file`, `pool`, `rpc_url`, and optionally `rpc_url_2`, `recommended_near`,
`agent_url`. The bridge (`ona_core_new_with` with a `pool` object) refuses unknown keys and values that are not text.
Without the file the pool answers `no pool wallet configured`; an unreadable file is refused with its reason. With it,
the pool goes through the app's tor only, like the real model, and never has the real model itself.

The app has one pool core, on a serial queue of its own (`CoreQueue`). The sheet awaits its replies without holding
the main actor. When tor's port for the core changes (checked every 1.5 s), the core is released once the commands
already sent are answered, and the next pool command makes a new one: the wallet file is locked by the core that
opened it, so the new one is made only after the old one is gone. The phone's portfolio read still waits for its reply
on the main actor.

Tested with unit tests: the bridge's pool setup and refusals (`cargo test` in `desktop/OnaCoreBridge`), the settings
file handling, the engine's pool commands (only the four pool commands accepted, one core, a new core only after the
old one is released, the main actor not held) with a fake core, the NEAR amount conversions, and the reading of the
example replies of pool-commands.md. Not tested: the sheet itself (built, not run or looked at), and the pool against a
pool contract, an RPC node or a pool agent.

## Tor client authorization

Same as the Tauri app (docs/desktop/tauri.md, "Tor client authorization"): the onion service is published for the
paired phone's x25519 client key only, written to `tor/hs/authorized_clients/phone.auth` before `tor` starts; the QR
code gives the secret to the phone (`onion_auth`); the key is kept in the pairing record in the Keychain; forgetting the
phone makes a new key and starts `tor` again; a pairing made before this change is dropped once. The QR waits for the
self-check through `tor`, which answers "missing client authorization" (0xF4, `ExtendedErrors`) for a restricted
service it found.

## Relay published for named clients

Same as the Tauri app (docs/desktop/tauri.md, "A relay published for named clients only"): `tokens_file` is optional,
and for an `http://…onion` relay the app's tor presents a client key made once in
`~/Library/Application Support/ONA/tor/relay-client/`; the line to give the relay's operator is shown in the phone
sheet ("Key for the relay"). Tested with unit tests; the same file layout reached a restricted service with C tor.

**A local test node** (development builds only): same `"local_node": true` as the Tauri app; the Swift side passes it to the
bridge as `pool_direct` in Debug builds and refuses it in Release. Tested with unit tests only.

## Free research

A new conversation is now a free research (docs/research.md), not the lawyer mission; the lawyer mission's code is kept
and reached from its tests only (`ChatEngine(…, newChats: .mission)`). Each conversation's research has its own
ona-core on its `CoreQueue`, moved on at each tick without waiting: `research_open`, `research_propose`, then a
confirmation of the queries, then `research_step` until `done` (one activity item per event: `search`, `read`,
`think`), then `research_result` (one `answer` item, one `action` item per suggested action) and `research_exposure`
(the exposure item). Status: `working`, `waiting` on the queries, `idle` once answered.

- **Queries.** Shown in editable fields on the Mac (an emptied field drops that query); accepted as shown from the phone
  with the usual signed confirmation, whose content is `ProtocolBytes.queriesDigest` (`ona/queries/v1`, shared test
  vector with the Tauri and iPhone apps). ona-core checks the final list (1 to 3, 120 characters, protected terms); a
  refused list leaves the confirmation pending. Refusing stops the research before any search.
- **Answer.** The text, the notes with their quote and the site they come from, the sources with title, host and URL as
  selectable text (no link opens).
- **Actions, on the Mac only.** The person types the recipient (e-mail address or NEAR account), "Prepare" shows the
  exact action (`research_action_prepare`) with a warning when the recipient is written in a page read, then
  "Send from my mail app" or "Pay" confirms it by its digest and carries it out once
  (`research_action_confirm`, `research_action_do`). A message's `mailto:` URL is opened with `NSWorkspace`: the person
  sends it from their mail program. The item is then marked done (`state: "done"` for the phone) and the exposure item is
  updated in place. The phone has no route for actions.

Tested (`swift test`, against the real ona-core with its fake model and demo web): the queries digest vector; a new
chat waits on its queries and nothing is searched before; edited queries searched as edited, the activity texts, the
answer with notes and sources, two actions, the exposure counts and the phone's JSON view; a query list ona-core refuses
keeps the confirmation; refusing; a message (bad address refused, wrong digest refused, `mailto:` URL, not twice) and a
payment (mock transaction) with the exposure updated; the phone accepting the queries by a signed confirmation, and
refused when signed over other queries. The app builds (`xcodebuild`, Debug).

Not verified: the SwiftUI views were not looked at in the running app; opening the `mailto:` URL in a mail program; the
"seen in pages" warning (the demo pages hold no address; ona-core's own tests cover the flag); the real model and the
web through Tor (see docs/research.md, "Not tested"); the iPhone app's display of these items.
