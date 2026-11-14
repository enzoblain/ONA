# ONA iOS app: screens, pairing, signatures, Tor (steps 2 to 4)

Created on 2026-11-10.

## What exists

| Path | Role |
|---|---|
| `ios/ONA/` | SwiftUI app "ONA" (iOS 18+): pairing by QR code, mission tracking, three signed confirmations, exposure report, transport through Tor (embedded Arti) when the QR code gives a `.onion` address. |
| `ios/ONA/ONA/Tor/` | `ArtiTor` (Rust bridge `ios/ArtiBridge`) and `TorComputerLink`: the protocol over HTTP/1.0 to port 80 of the computer's onion service. In the app only, not in `Package.swift`. |
| `ios/ONA/ONATests/` | Unit tests (Swift Testing): payment, messages, pairing, signed bytes, signatures, simulated Keychain. |
| `ios/ONA/Package.swift` | Runs the part without a user interface (`Protocol/`, `Pairing/`, `Remote/`) and its tests on the Mac: `cd ios/ONA && swift test`. |
| `ios/MockComputer/mock_computer.py` | Mock computer (Python, standard library only), follows `protocol-draft.md`. Everything it returns carries `mode: mock`. |
| `ios/MockComputer/pairing.py`, `p256.py` | Pairing and signature checks of the mock computer. `p256.py`: P-256 in pure Python, **for the mock computer only** (not reviewed, not constant-time). |
| `ios/MockComputer/pairing_qr.swift` | Shows the pairing QR code as an image (`--qr`). |
| `ios/MockComputer/run_onion.sh` | Step 4: the mock computer reachable only through Tor (C Tor onion service, key outside the repository), QR code with the `.onion` address. |
| `ios/MockComputer/test_*.py` | Tests of the mock computer. |
| `docs/ios/protocol-draft.md` | The phone ↔ computer protocol. |

## Run

```bash
ios/ArtiBridge/build-xcframework.sh                         # once: Arti for the app (~5 min)
ios/MockComputer/run_onion.sh --qr                          # step 4: mock computer behind a .onion
python3 ios/MockComputer/mock_computer.py --qr              # without Tor, iOS simulator; also opens the QR code as an image
python3 ios/MockComputer/mock_computer.py --host 0.0.0.0 --qr   # iPhone on the same network
open ios/ONA/ONA.xcodeproj
```

The mock computer's terminal shows the text of the QR code (single use) and, after pairing, the 6-digit code.
On an iPhone: scan the QR code. In the simulator (no camera): the "Paste" button, or at launch
`xcrun simctl launch <simulator> org.ona.remote -ONAPairingText 'ona-pair:…'` (Debug + simulator only, absent from
builds for iPhone). A new QR code: `curl -X POST http://127.0.0.1:8790/v0/mock/unpair`.

## Interface

Tab bar at the bottom (Liquid Glass from iOS 26):

- **Home**: pairing (scan the QR code, or paste its text), then the **list of conversations** with the agent ("+"
  button at the top right, delete by swiping, long press or the "…" menu). A conversation looks like Claude or
  ChatGPT: messages, agent steps grouped and collapsible ("3 steps"), an "in progress" line, confirmation cards in
  Liquid Glass, exposure report at the end, floating input field (text only). A badge on the tab counts the
  conversations waiting for a confirmation. Target: iOS 26.
- **Tor**: Tor state (stopped, starting with progress, connected, error with "Details"), start / stop, Tor data kept
  on the phone and a button to erase it (replaces the "cold start" of the earlier test app), Arti version.
- **Settings**: paired computer and "Forget this computer", data kept on the phone, app version. The simulation
  buttons appear only with a simulated computer.

Error messages carry no technical detail; the detail of a Tor error is under "Details". Arti's logs are enabled only in
Debug.

## Behavior

- **Visible simulation**: a yellow "SIMULATION" banner appears as soon as a reply says `mode` ≠ `real`, and stays until
  the app is closed. The exposure report of a simulated mission says so too.
- **No push**: the app polls the computer every 3 s, only in the foreground.
- **Nothing on disk except the pairing**: ephemeral `URLSession` session (no cache, no cookies). The pairing (name,
  address, public key of the computer, identifier, reference to the phone's key) is a single Keychain item, "this
  device only", never synced. "Forget this computer" erases it.
- **Pairing**: QR code `ona-pair:…` → the phone creates its P-256 key (Secure Enclave, Face ID or passcode on each use),
  proves it holds it, then shows a 6-digit code to compare with the computer.
- **Signed confirmations**: plan, recipient, payment and refusal are signed (`protocol-draft.md`). The mock computer
  refuses a confirmation that is unsigned, wrongly signed or from another pairing.
- **Payment checked on the phone**: the app recomputes the digest (same bytes as `ona-core`) and the screen text from
  the amount and the recipient. If either does not match, the "Confirm" button is disabled. The digest sent is the one
  computed by the phone.
- **Refusal**: every confirmation can be refused, which stops the mission.

## Checked on 2026-11-10

- App tests on the Mac (`swift test`, Swift 6.4): 16 tests, 20 cases, all passed. Among them: the digest computed in
  Swift is the one from `ona-core`; another recipient, another amount or a different screen text are refused.
- The same tests in Xcode on an iOS 27 simulator: the test runner does not connect ("test runner hung", "unable to
  connect … service hub"), on two simulators. An Xcode 27 beta problem; the app itself runs.
- Mock computer tests: 6/6 (Python 3.14.7). The digest of the demo payment is identical to the one printed by
  `ona demo` (branch `main`): `a43ba249…fa31`. (This v0 digest no longer exists since protocol v1: see "Protocol v1"
  below.) The exposure report has the same values as the one from `ona demo` (`search` 1, `fetch` 2, `contact` 1,
  3 model calls, 1 payment).
- iPhone 17 simulator (iOS 27.0, Xcode 27.0 beta) against the mock computer: a full mission run by hand (plan approved
  → cabinet-b chosen → payment checked then confirmed → report shown).
- `localhost` did not work reliably from the simulator (requests timed out, server bound to IPv4): the default address
  is `127.0.0.1`.

### Step 3, checked on 2026-11-10

- `swift test`: 30 tests (14 of them new, on pairing and signatures), all passed. Python: 19 tests, all passed,
  including the RFC 6979 vector (P-256, SHA-256) for `p256.py`.
- Across languages: a signature made by CryptoKit is verified by `p256.py`, the signed bytes are identical in Swift and
  in Python, and so is the 6-digit code (vectors in `PairingTests.swift` and `test_pairing.py`).
- iPhone 17 simulator against the mock computer: pairing, same 6-digit code on both sides (871 519), signed
  confirmations accepted, unsigned confirmation refused, pairing kept after an app restart and a signature with the
  reloaded key accepted.
- **The simulator has no Secure Enclave**: it uses a software key (shown as such in the app). The Secure Enclave +
  Face ID path has not run yet.

### Step 4 (Tor), state on 2026-11-10

- Code: the QR code can give a `.onion` address instead of a local address; the app then sends the whole protocol
  (pairing, state, signed confirmations) through Arti 0.48.0. The Rust bridge gains a generic HTTP request (GET/POST,
  response ≤ 1 MiB) and a 120 s limit on Tor startup. Arti goes dormant when the app goes to the background.
- Tests: 3 Rust tests (reading the HTTP response, refusing header injection), 34 Swift tests (including the choice
  between `.onion` and local address, and a `.onion` pairing), 19 Python tests. All passed.
- **End to end through Tor: succeeded once on 2026-11-10 (evening)**, in the iPhone 17 simulator, against the mock
  computer reachable only by its `.onion` (`run_onion.sh`): pairing (code 537 645 on both sides), tracking shown as
  "Connected through Tor", signed confirmation of the plan accepted (`POST /v0/confirm -> 200`). The first two pairing
  attempts timed out (60 s) right after the Tor data was erased; the third succeeded. From the Mac, the same `.onion`
  answered in 9.3 s then 0.7 s. A single run, on a network that let Tor through that evening.
- Earlier the same day: **did not succeed.** On the school Wi-Fi (10.2.x.x), C Tor eventually started after many TLS
  cut-offs, but Arti got no circuit to the mock computer's `.onion` ("Failed to obtain hidden service circuit", 4
  attempts from the Mac). In the simulator, the app starts Arti (cache written) but does not get through on that
  network.
- Checked: on that network, with an empty Arti cache, Tor startup stops after 120 s and the app shows "bootstrap timed
  out after 120 s (is Tor blocked on this network?)" (simulator and Mac). A first version of this limit made the bridge
  panic (Tokio timer created outside the runtime); the panic was caught and shown; it is fixed.
- Not done yet at that point: Tor client authorization (restricted discovery) so that only the paired phone can reach
  the `.onion`; the real computer side in `ona-core`.

## Protocol v1, 2026-11-11

The app and the mock computer moved to protocol v1 (`docs/ios/protocol-draft.md`), after the security inspection of the
desktop apps (findings F-01 to F-17). What changes on the phone:

- **Signed replies (F-04).** All requests are `POST /v1/…` with a nonce; each reply is verified with the key of the
  computer from the QR code **before** it is read (`ComputerClient`). Otherwise: "Computer not authenticated".
- **Pairing with commitment (F-02).** Commitment to the key, then reveal; 6-digit code over the two nonces. QR code
  `v: 1` with `expires_at`. The pairing is saved only after "The codes match" (F-17); then the phone waits for the
  confirmation on the computer (403 `not paired` shown as waiting, not as an error).
- **Reads with a token (F-03), writes with a counter (F-01).** Token and counter in the Keychain; the counter is taken
  and saved before signing, never reused; writes one at a time. Signatures always low-s (F-16).
- **Sign what is shown (F-05).** The phone recomputes the digest of the plan, the offers or the payment from what it
  shows and signs it; it never takes `content` as given.
- **Payment v2 (F-01, F-14).** Digest `ona/pay/v2` (network, contract, mission, nonce, recipient, amount),
  `digest_version` 2 required; the recipient is shown only if it has the form of a NEAR account.
- **F-07.** An `http://` address in the QR code is accepted only in Debug; `NSAllowsLocalNetworking` only in the Debug
  `Info.plist` (`Config/Info-Release.plist` in Release, checked on the Release binary).
- **F-17.** Software key refused on an iPhone (simulator and tests only); Tor (Arti) state under Application Support,
  excluded from backups (the network cache stays in Library/Caches); a saved v0 pairing is forgotten (pair again).

Limits (F-15): a compromised computer does what it wants; the phone's signature is verified by the desktop app, not by
`ona-core` nor by the chain. A stolen, unlocked phone can read the conversations; each write still asks for Face ID or
the device passcode (not yet checked on a real iPhone).

Checked on 2026-11-11 (macOS, Xcode 27.0 beta, iPhone 17 simulator iOS 27.0):

- `swift test`: 47 tests passed, including all v1 vectors shared with the desktop apps, the reference Rust signature
  verified by CryptoKit, refusal of high-s signatures, refusal of a forged reply or of one signed for another request,
  and a v1 mock computer in Swift (commitment, token, counters, signatures).
- Mock computer: 24 Python tests passed (same vectors, full mission over HTTP with each reply verified, replay refused,
  confirmation on another plan refused).
- End to end, local network: iPhone app (simulator) ↔ Tauri app (branch `fix/inspection`) ↔ `ona-core`. v1 pairing,
  conversation, plan, cabinet-b, payment of 0.6 NEAR checked in v2 then confirmed, report received. A v0 pairing left in
  the simulator's Keychain was forgotten as intended.
- **Through Tor, on 2026-11-11** (same Mac, school network): iPhone app (simulator, Arti 0.48.0) ↔ `.onion` of the
  Tauri app in Tor mode (server on 127.0.0.1 only) ↔ `ona-core`. Full mission: v1 pairing, conversation, plan,
  cabinet-b, payment of 0.6 NEAR checked in v2 then confirmed, report received. A single run.
  - **Slow first connections.** Two pairings out of three timed out ("The computer did not answer in time", 60 s limit
    per request) before the third went through. Reproduced on the Mac with the Arti bridge alone: the first request to
    the `.onion` waited more than 60 s, the next answered in 2 s; another attempt, 11 s then 1 to 2 s. The request does
    not reach the computer during this wait: the pairing code is not used up, and it can be retried. Possible fix: a
    shorter limit for opening the circuit and an automatic retry (not done).
  - **Desktop app side.** On the first launch of the evening, the app showed its QR code while the service was not yet
    published on Tor: a Tor client on the Mac got "No more HSDir available" for at least 5 minutes. The app considers
    the address published as soon as the `hostname` file exists, and that file stays from one session to the next.
    After a restart, the service answered in under 20 s.
- **With the Mac app, on 2026-11-11** (local network): the same full mission, CryptoKit signatures on both sides.
- **New attempt through Tor (same day).** The Arti bridge gives each attempt to open the stream 20 s and starts another,
  within the 60 s limit; if the stream still has not opened (nothing was sent), the app sends the request again once.
  Measured on the Mac with the bridge alone, first request from a fresh Arti to the Tauri app's `.onion`: 19 successes
  out of 21 (two of them at about 32 s, saved by a new attempt), two failures after 60 s (one of them "stream not
  opened"). Without these attempts, the same day: 3 first requests out of 5 had timed out (2 in the app, 1 with the
  bridge alone). Few attempts, a single network. The resend on the app side was not observed for real.
- **Scan again.** When the computer no longer recognizes this phone (`not paired` after the delay, `unknown pairing`,
  `missing or wrong token`), Home offers "Scan the computer's code again". Tested by the unit tests, not on screen.
- **Limits (F-15)** in Settings: compromised computer, stolen unlocked phone.
- Not checked: on a real iPhone (Secure Enclave, Face ID).

## Pool tab (read only), 2026-11-12

A "Pool" tab next to Home, laid out like a wallet: the total value at the top, then one row for the cash and one per
vault, with its value (snowflake for a frozen vault, small clock while an operation is in progress). Data read through
`POST /v1/pool/portfolio` (signed reply, token). No action on the phone: pool operations are confirmed on the computer,
as `docs/desktop/pool-commands.md` specifies.

- Desktop apps: the route returns the `pool_portfolio` of an `ona-core` dedicated to the pool. As long as the bridge
  has no pool wallet (not done yet on the desktop side), it answers `no pool wallet configured`, which the app shows as
  "The pool is not set up on the computer yet".
- Mock computer: a made-up wallet (labeled `mock`) to try the screen.
- Checked: Swift tests (reading, decoding, amounts, refusals), Rust and Swift on the desktop side (token required,
  signed refusal without a wallet), Python; on screen in the simulator against the mock computer. Not checked with a
  real pool (none runs on a chain yet).

## Not done yet

- Real iPhone: app installed and launched on 2026-11-10 (step 2), but no request reached the mock computer. The Wi-Fi
  used (school network, 10.2.x.x) probably isolates devices from each other. Next try: the Mac on the iPhone's personal
  hotspot; it will also be the first test of the Secure Enclave and Face ID.

## Tor client authorization (2026-11-12)

A QR code with an onion address carries `onion_auth`, the 32-byte x25519 key of the phone's Tor client authorization
(docs/ios/protocol-draft.md). The app keeps it with the pairing in the Keychain and gives it to Arti
(`arti_bridge_set_onion_auth`, Arti's key store under its state folder) before the first request to that address.

Checked on a Mac, with the bridge built for the Mac and a desktop app's restricted onion service: with the key, Arti
reached the service (25 s to connect, a signed reply); without it, Arti refused with "Onion service required
authentication". Not confirmed in the app on the simulator: two pairing attempts there ended with "Could not reach the
computer through Tor" and the detail could not be read; the simulator's input then stopped responding. Not yet tried
again, nor on a real iPhone.

## Free research (2026-11-13)

The phone shows a research conversation (docs/research.md): the queries to confirm before anything leaves (accepted as
shown, signed over `SignedFields.queriesDigest`; editing them is done on the computer), the answer with its quoted notes
and its sources (as text: the phone never opens the pages), and the suggested actions, read only, with "To do on the
computer" (their recipient is given and confirmed there). Tested with Swift tests (decoding, the digest vector shared
with the desktop apps); not yet against a desktop app running a research.
