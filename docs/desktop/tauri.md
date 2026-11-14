# Windows and Linux desktop app (Tauri)

Created on 2026-11-10 on the `desktop-tauri` branch (part of `desktop-app`). Same role as the macOS app
([app.md](app.md)) for computers that are not Macs. Phone protocol v1 since 2026-11-11 (`docs/ios/protocol-draft.md`).

## What exists

| Path | Role |
|---|---|
| `desktop/tauri/src-tauri/` | Rust crate `ona-desktop` (Tauri 2), outside the root workspace. `Cargo.lock` starts from the root one: `ona-core` and its dependencies keep the same versions. |
| `src/protocol.rs` | Signed bytes (v1), commitment, 6-digit code, digests of the shown content and of the v2 payment, QR code text, ECDSA P-256 low-s signing and verification (`p256`). Same test vectors as the Mac app. |
| `src/pairing.rs` | Pairing: the computer's P-256 key, single-use QR code valid for 10 min, at most 5 wrong codes, commitment then reveal, code to compare, token, counter and identifiers already used. `pairing.json` file written atomically (temporary file, rename, folder synced), permissions 0600 on Linux at each write; nothing is written before the codes are compared (5 min to compare); a write failure is shown; an unreadable file is never overwritten (error shown, pairing disabled). |
| `src/engine.rs` | Conversations: one `ona-core` per conversation, one step every 1.5 s. A new conversation is a free research ("Free research" section); the lawyer mission (stopping at the three confirmations) is now reached only by the tests. Random identifiers (16 bytes). Same JSON as the Swift `ChatEngine`. |
| `src/http.rs`, `src/router.rs`, `src/server.rs` | Server for the phone: v1 routes of `docs/ios/protocol-draft.md`, signed replies, `Host` checked, browser requests refused; at most 16 connections, 10 s per request. Port chosen by the system in Tor mode. |
| `src/tor.rs` | Starts the installed `tor` program (first `/usr/bin/tor`, `/usr/sbin/tor`, `/usr/local/bin/tor`, `/opt/homebrew/bin/tor`, `C:\Program Files\Tor\tor.exe`, then the PATH) with a `.onion` service, only once the server is listening. `__OwningControllerProcess`: tor stops with the app, even after a crash. |
| `src/worker.rs` | A single thread owns everything (`ona-core` is not `Send`); the window and the server send it tasks. |
| `src/main.rs` | Tauri commands called by the window. |
| `desktop/tauri/ui/` | Window in HTML/CSS/JavaScript without a library: conversations, confirmations, report, "Phone" window. Light and dark themes. |
| `assets/make_icons.swift` | Draws the logo and all icons (iOS, macOS, Tauri): `swift assets/make_icons.swift`. |

## Run

Rust (tried with 1.97.1), then:

- **Linux** (Debian/Ubuntu): `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev`
  and the `tor` package.
- **Windows**: WebView2 (already present on an up-to-date Windows 10/11), MSVC build tools, and the "Tor Expert Bundle"
  with `tor.exe` in the PATH.

```bash
cd desktop/tauri/src-tauri
cargo test --locked     # 74 tests (13/11/2026), with the real ona-core
cargo run --locked      # the app (debug build)
```

The "Local network" mode (plain HTTP on all interfaces, port 8790) exists only in debug builds (`cargo run`); a release
build ignores it, even if it was chosen before.

For the installers (`.deb`, `.rpm`, AppImage, `.msi`, NSIS), the Tauri CLI is needed, pinned as well:
`cargo install tauri-cli --version <version> --locked`, then `cargo tauri build`. Never tried.

In debug only: the QR code text is written to the output (`ONA_PAIRING_PAYLOAD …`), for the iOS simulator, which has no
camera, and `ONA_AUTO_CONFIRM_PAIRING=1` confirms the code without a click. Whoever reads this text can pair before the
phone: for tests only. The window receives only the QR code image, not its text.

## Checked on 2026-11-11 (protocol v1), on macOS

- The `tauri` and `qrcode` crates are not in the offline cache: `cargo test` in `src-tauri` could not run. The modules
  (everything except `main.rs`) were compiled and tested offline in an external harness with the same pinned versions
  (`qrcode` replaced by a stub): 45 tests passed. `main.rs` and the window were not compiled. End to end with protocol
  v1 on 2026-11-11, on macOS, local network: iPhone app (simulator) ↔ Tauri app ↔ `ona-core`, from pairing (commitment
  then reveal) to the report, payment of 0.6 NEAR checked in v2 on the phone.

## Checked on 2026-11-10, on macOS (protocol v0, before the fixes)

- `cargo test`: 17 tests passed (protocol vectors, pairing, 0600 file, full mission on `ona-core` with a wrong digest
  refused, refusal, router with signatures, TCP server, pairing and conversation over HTTP).
  `cargo clippy --all-targets`: no warnings.
- **End to end, local network**: iPhone app (simulator) ↔ Tauri app ↔ `ona-core`. Pairing through the QR code text,
  signed conversation, plan approved, cabinet-b chosen, payment checked by the phone then confirmed, `ona-core`'s
  report (cabinet-b, 1 NEAR) received.
- Tauri window: list updated live and "Paired phone" (capture). The content of a conversation, the choice of firm and
  the `confirm` call were checked with the same interface in a browser, with a fake Tauri bridge and the real
  conversation data.
- **Tor mode**: server on 127.0.0.1 only, `tor` started, `.onion` address published. After `kill -9` of the app, `tor`
  stops too.

## Not checked

- **No build or run on Windows or Linux.** The Windows-specific code (`CREATE_NO_WINDOW`, `tor.exe` paths) has never
  been compiled.
- The phone reaching the app through Tor (only the publication of the address was seen).
- Clicks in the real Tauri window (no automated click possible here); the QR code shown in the window.
- The installers.
- Each conversation has its `ona-core` on a thread of its own. The thread that serves the window and the phone sends it
  one command at a time and waits no more than 200 ms: a call to the real model goes on while the window and the phone
  are served, and the reply is picked up at the next tick. Confirmations (plan, recipient, payment) and the end of a
  mission wait for the reply: they do not go through the model. Reading the pool for the phone still waits for its
  reply.
- The **computer's private key** (which signs the replies to the phone) and the phone's **token** (which opens reads)
  are in the system's credential store (`keyring` library: Keychain on Mac, Credential Manager on Windows, Secret
  Service on Linux), not in `pairing.json`, which keeps only the phone's public key, the counter and the identifiers
  already used. A `pairing.json` from an earlier version hands its secrets to the store at startup, then is rewritten
  without them. Without a usable store (Linux without a running Secret Service), the secrets stay in the file, readable
  by the user only, and the window says so. Tested with a fake store; the real store of each system has not been
  tried. Another program of the same user can usually read the store too: it mostly protects against a file being
  copied (backup, another machine).
- The store is read at startup on a separate thread: macOS may first ask for the person's consent (after an update not
  signed the same way, for example). Meanwhile the window responds and says "Reading the system keychain…"; the phone
  is not served and no QR code is shown until the pairing is loaded. A write to the store (new pairing) is still done
  on the main thread. The tests never use the system's store.
- On Windows, the pairing file and the onion service key (`tor/hs`) have no restricted permissions beyond the user's
  folder (no ACL set). On Linux, the onion key is a plain file in a 0700 folder: whoever copies it can publish the same
  address; the replies signed by the computer's key then limit impersonation.

## Real model

Without settings, ona-core keeps its fake model (`mode: mock`) and the app and the phone show the simulation banner. To
use the real one, write `model.json` in the app's data folder (next to `pairing.json`):

```json
{
  "relay_url": "https://relay.example.org",
  "model": "<a model the relay allows>",
  "max_tokens": 512,
  "token_budget": 20000,
  "tokens_file": "/path/to/request-tokens"
}
```

The names are those of `ona real` (docs/INSTALL.md, "Use the real model"); `token_budget` is for each conversation.
`tokens_file` holds one request token per line, readable by its owner only. It may be left out for a test relay that
asks for none (`ona-relay` refuses a chat without one).

**A relay published for named clients only** (docs/TOR.md, "onion client authorization"): when `relay_url` is an
`http://…onion` address, the app makes an x25519 key once (`tor/relay-client/key`, 0600), gives tor its secret half for
that address only (`ClientOnionAuthDir`), and shows the public half in the phone dialog, under "Relay": the relay's
operator adds that line to the service's `authorized_clients/`. Checked with two `tor` (0.4.9) on this Mac: a client set
up this way got HTTP 200 from a service restricted to its key. Not checked against the team's relay yet.

- Every connection ona-core opens goes through the app's own tor, on a second SOCKS port that is not onion-only
  (`ONA_REQUIRE_TOR`). The real model is used only in Tor mode, once the QR code is shown; before that, or in the
  local-network mode, a conversation is refused with the reason. Through Tor, the relay must be an `https` host name
  or an `http` onion address: an IP address is refused by ona-core.
- With an onion relay, once tor runs the app opens one connection to the relay in the background, so the first message
  does not wait for tor to find the service (about a minute on 13/11/2026, from `ona real`). Through Tor, ona-core
  allows 240 s to connect, then 120 s for each later step of a request (sending, waiting for the reply, reading it);
  the app's tor waits as long (`SocksTimeout 240`; its default, 120 s, would give up first).
- An unreadable `model.json`, or settings ona-core refuses, give a core that refuses every command with the reason: the
  app never falls back to the fake model in silence.
- The NEAR AI key is not in the app: the relay holds it (docs/INSTALL.md, "Run the relay").
- Only one conversation at a time can use the tokens file (ona-core locks it).

Tested with unit tests only (settings, refusals, a core set up through a SOCKS port). Not run against a relay yet.

## Allowed payment recipients

A free research pays only a NEAR account the person allowed (docs/research.md, "Money guardrails"). The list is
`payees.txt` in the app's data folder: one account per line, `#` starts a comment. It is read when the app starts and
sent with every `research_open`. Without the file, only the demo directory's accounts can be paid. An entry that is not
a NEAR account makes ona-core refuse the research, with the reason. Not tested in the window (13/11/2026): the change
is two lines in the engine and the worker; the core side is tested through `Core::dispatch`
(`crates/ona-core/tests/payees.rs`). The macOS app does not read the file yet.

## Erasure and backups

Conversations are kept in memory only and are gone when the app quits; nothing about them is written to disk. Nothing
marks the app's data folder (onion key, `pairing.json`, `model.json`) as excluded from backups on Windows or Linux:
there is no single mechanism every backup tool follows there.

## Free research

Since 13/11/2026 a new conversation, from this window or the phone, is a free research (docs/research.md), run by
ona-core's `research_*` commands on the conversation's own core thread:

1. `research_open`, then `research_propose`: the chat waits (`status: waiting`) on a confirmation of kind `queries`,
   whose content digest is `protocol::queries_digest` (SHA-256 of `fields("ona/queries/v1", id, query_1, …)`, no
   count). Test vector, shared with the Mac and iPhone tests: id `c-0123456789abcdef0123456789abcdef`, queries
   `plumber Lyon` and `plumber call-out fee in €` →
   `9d6f191e63db66db31141a4b0f27a2253f476ed9cc0329bbe829a174ed369abf`.
2. Accepted on the phone (signed confirmation over that digest, queries as shown) or in this window, where each query
   is an editable field (`confirm` with `queries`); `research_accept` gets the final list. Refusing closes the research:
   nothing was searched.
3. `research_step` until `done`, polled without waiting (a model call or a Tor fetch does not hold the window or the
   phone): one activity per event (`search`: `Search "…": N sources`, `read`: `Read <site>: N notes` or
   why the page was not read, `think` for the answer).
4. `research_result`: one `answer` item (answer, notes with their quote and source, sources with title and address,
   shown as text and never opened), one `action` item per suggested action (`state` `suggested`, then `done`), then
   `research_exposure`: the exposure item. The chat is then `idle`.
5. Actions, in this window only (the phone has no route for them): the person types the recipient (an e-mail address or
   a NEAR account) and clicks **Prepare** (`research_action_prepare`); the exact action is shown, with a warning when
   the recipient is also written in a page read; **Send from my mail app** or **Pay** sends
   `research_action_confirm` with the action's digest, then `research_action_do`. A message is opened as a `mailto:`
   address with the system's own command (the person sends it from their mail program; if nothing opened, the address
   is shown to copy); the exposure item is read again. A new message in the same conversation starts a new research,
   and the previous answer's actions are no longer available.

Tested (unit tests with the real ona-core on its demo web: fake model, `MockOpenWeb`): the whole flow, queries edited
here (exactly those are searched; one with a protected term is refused and the queries still wait), refusal, a slow
`research_step` not blocking the engine, actions (wrong digest refused, done once, flagged recipient, item `done`,
exposure counting the message), the phone accepting the queries over the router with its signature (and a signature
over other queries refused). The window was checked in a browser with a fake bridge and a view produced by the engine:
the queries card with edited fields (the `confirm` call carries them), the answer card, the action cards with the
warning, and the "not opened" fallback. Not tested: the clicks in the real Tauri window, opening a `mailto:` address
(on any system), a research through Tor or with the real model (docs/research.md, "Not tested"). Payments of a
research go through ona-core's mock payments (`MockPayments`): nothing is paid on a network.

## Pool

The **Pool** button opens the pool: the total, the cash, one line per vault, and the operations of
docs/desktop/pool-commands.md. Each operation is prepared by ona-core (`pool_prepare`), its summary shown (amount, what
is received, what is left in the pool's cash and lost, fees, network, contract, expiry), and executed only when the
person clicks **Confirm** in this window: never from the phone, which only reads the portfolio. Entries, exits and
payments are queued by the pool agent: the window says the result comes later, and **Recover** runs `pool_recover`.
A deposit is sent and signed by the person's own NEAR wallet, on the wallet page the app opens in the browser
(docs/desktop/wallet.md). Since 13/11/2026 the screen is laid out as below ("Pool screen").

Settings: `pool.json` in the app's data folder, with the names of `ona`'s variables (docs/INSTALL.md, "The pool
commands"):

```json
{
  "wallet_file": "/path/to/wallet",
  "wallet_key_file": "/path/to/wallet-key",
  "pool": "pool.<account>.testnet",
  "rpc_url": "https://…",
  "rpc_url_2": "https://… (optional, another operator)",
  "recommended_near": "100,500,2000",
  "agent_url": "https://… or http://….onion (optional)"
}
```

Without the file, the pool answers `no pool wallet configured`. With it, the pool goes through the app's tor only, like
the real model, and its core is made again when tor's port changes. Its core runs on its own thread: the window waits
for a pool reply there; the phone's portfolio read waits on the worker thread.

Tested: the settings and refusals (unit tests), and the window against a fake bridge returning the example values of
pool-commands.md (in a browser). Not run against a pool contract.

## Connected wallet, pool requests in the chat, Pool screen (13/11/2026)

**Connect wallet** (sidebar button, and the Pool screen's top line) opens the wallet page in the browser without a
deposit (`wallet_connect`): the person picks a wallet in NEAR Wallet Selector (Meteor, MyNearWallet, HERE, Intear) and
the page posts the account name to the app (`POST /wallet/<token>/connected`, same `Host`/`Origin` checks, a well-formed
NEAR account only, once per page). The app shows it, keeps the name in `wallet_account` in the data folder (no key), and
uses it as the depositing account of the chat's pool requests and as the only payout account. **Forget** removes it.
The wallet page's server first tries port 8797, so that the browser keeps the wallet connected across restarts (Wallet
Selector remembers it per address); another port is chosen by the system if 8797 is taken.

**Pool requests in the chat.** A message typed in this window (never one from the phone) is read with fixed patterns,
without the model (`src/pool_chat.rs`); anything else goes to the free research as before. It must start with its verb
and not be a question; the amount must carry its unit (`NEAR`); it is never guessed.

| Typed | Read as |
|---|---|
| `place 1 NEAR in vault 0`, `deposit 0.5 near into vault #1`, `put 1,5 NEAR in vault0` | deposit, then entry into that vault |
| `put 2 NEAR in the staking vault`, `invest 1 NEAR in staking` | deposit, then entry into the only open vault of that kind |
| `put 1 NEAR in a vault` | deposit, then entry into the only open vault (else the chat lists them and asks for a number) |
| `deposit 1 NEAR`, `stake 1near` | deposit only (cash notes) |
| `withdraw 0.5 NEAR`, `exit 1 NEAR to cash`, `cash out 1 NEAR`, `pay out 1 NEAR` | cash payout to the connected account |
| `show my portfolio`, `my portfolio`, `show me my pool holdings` | the portfolio, read only |

Without a connected wallet a deposit or payout is not started: the chat says to connect one. Otherwise the engine
reads `pool_info` (vault kind and target, cash tiers, cash hourly cap, recommended amounts), for a deposit
`pool_privacy` with the amount, then `pool_prepare`, and shows a card: amount, account, vault (kind and target), what
the wallet sends (amount plus storage margin), the cash notes, fees, "blends in with at most N notes" (`if_entered` of
the vault, or for cash the notes in circulation of the new notes' tiers plus one; the same upper bound as
docs/desktop/privacy.md), the recommended amounts or ona-core's warning, a warning when the amount is above the cash
hourly payout cap, and the steps Yes will take. **No** ends it (nothing sent). **Yes** prepares again (a preparation
lives 5 minutes) and opens the same wallet page as the Pool screen's deposit: the wallet asks to confirm the `deposit`
transaction, then to sign the pool agent's message (NEP-413); the two `pool_execute` run on the wallet page's path as
before, and each is reported in the chat ("Deposit reported sent by your wallet page", "Cash issued"; the app does not
read the transaction itself). With a vault, the engine then runs `pool_prepare` `enter` (vault, the same amount) and
`pool_execute`, and reports the summary and the outcome (normally queued by the agent: the share notes come with
**Recover**). A cash issue queued by the agent is followed with `pool_recover` about every 6 s for about 4 minutes before
the entry. A payout card shows what is received and the account's exit limit; Yes runs `pool_execute`. The card is
refused if another wallet was connected meanwhile. All pool commands of the chat are polled on the pool's thread: the
window and the phone are not held. The phone sees a `pool` item kind it does not know (decoded as `unknown` by
`ChatMessages.swift`; how the iOS app draws it was not checked) and cannot answer it; its protocol and digests are
unchanged.

**Safeguards added after review (14/11/2026).**
- No wallet page (connect or deposit) replaces a deposit in progress (still to be sent, or sent and waiting for the
  agent's message to be signed, and not expired): its last step would be refused and the cash never issued. The app
  answers "Finish or cancel the deposit in your wallet page first"; the sidebar shows the deposit in progress. Before
  it is sent, it can be cancelled (`wallet_cancel`, after a warning to cancel only if the wallet did not confirm the
  transaction); once sent, cancelling is refused: only the signature on that page finishes it.
- The first card shows the entry's storage fee (one `NOTE_STORAGE_FEE` per cash note). If the prepared entry would
  leave money in the pool's cash, or costs another fee, it is not run: the chat says why and shows a second card;
  **Yes** runs that very preparation (within its 5 minutes), **No** leaves the cash notes in the pool wallet.
- A queued cash issue counts as done only once `pool_recover` has brought back as many signatures as this deposit
  issued cash notes and none waits any more; if nothing waits but fewer came (the agent dropped it), the chat stops,
  says the cash issue was not completed (with the agent's error if any) and does not enter older cash. The signatures
  counted are all those `pool_recover` reports, not only this deposit's (it does not say which notes they were).
Run in the outside harness: 94 tests passed, no warning (four new: the second card, the dropped cash issue, a cancelled
wallet page, and the worker refusing to replace or cancel a deposit in progress).

**Pool screen.** Reads `pool_portfolio`, `pool_privacy` and `pool_info` together, each shown if it came, with its exact
error and a **Retry** button otherwise. Top: the connected wallet with Connect / Forget. Then the total value (as on the
phone), the simulation label in mock mode, the privacy summary, and the holdings: the cash (value; each tier's held
notes as "count × note value", notes in an operation; "operation in progress" with the moving value and the notes
awaiting the agent's signature; its privacy figure; what can be withdrawn: the held cash, to the depositing account, its
exit limit being checked when prepared) and one card per vault holding (kind and target, value, frozen, share notes per
tier with their share count, share price, operation in progress, privacy figure, "leave first, then pay out"). Then the
actions (deposit from the wallet with the account filled in and the recommended amounts as one-click chips, put cash in
a vault, pay cash out with the connected account filled in, recover), every vault the pool lists (kind, target, share
price, open or frozen, share note values, notes in circulation, exit cap, what an entry would blend in with), and the
deposit figures (recommended amounts, smallest deposit, cash note values, cash payouts per hour). Everything the
phone's Pool tab shows (total, cash value, one line per vault with its value, frozen, operation in progress, error and
retry) is on it. The operations go through the same prepare → summary → confirm → execute path as before.

`pool_info` is a new ona-core command (docs/desktop/pool-commands.md), allowed through the window's `pool` command.

**What was run (13/11/2026, on macOS, in a sandbox).** `cargo test --locked` in `src-tauri` could not run: unpacking the
crate `bit-vec` (a Tauri dependency) failed with "Operation not permitted". Every module except `main.rs` was compiled
and tested in an outside harness with the same pinned versions (`qrcode` replaced by a stand-in, as on 11/11): 90 tests
passed, no warning, among them the parser, the chat flow against a fake pool core (card, Yes, wallet page request,
the two wallet steps, entry, queued cash issue with recovery, refusal, payout, portfolio, unknown vault, a phone message
not read as a pool request, no wallet connected) and the connect page over HTTP. `cargo test -p ona-core`: the
`pool_info` test against the fake contract. The window's new code was run in Node with a stand-in DOM and a fake bridge
(cards and Pool screen render, no runtime error). **Not run:** `main.rs` and the real Tauri window, any click, the
wallet page in a browser, Meteor or any real wallet, the testnet pool. The wallet page's bundle (`dist/wallet.js`) could
not be rebuilt in the sandbox (it cannot read the wallet libraries' `*keystore*` files): the change of `src/main.js` was
applied to the bundle by exact text replacements; `npm ci && npm run build` regenerates it from the source.

## The chat pilots the pool; a simpler Pool screen (14/11/2026)

The same fixed patterns (`src/pool_chat.rs`, no model, messages typed in this window only) now also read the
operations on notes already in the pool, and questions about the person's pool. Amounts come only from the words
(`NEAR` required; no amount means all); vaults by number or kind.

| Typed | Read as | Core command |
|---|---|---|
| `put 2 NEAR of my cash in vault 0`, `move 1 NEAR from cash to the staking vault`, `put my cash in vault 0`, `put all my cash into vault 1`, `move my cash to vault 0` | cash into a vault | `pool_prepare` `enter` |
| `move vault 0 to vault 1`, `switch 1 NEAR from vault 0 to vault 1`, `move vault 1 to the staking vault` | switch | `pool_prepare` `switch` |
| `take my NEAR out of vault 0`, `take 0.5 NEAR out of vault 0`, `move vault 0 to cash`, `leave vault 0`, `withdraw 1 NEAR from vault 0`, `exit the staking vault`, `get my NEAR out of the staking vault` | leave to cash (kept in the pool) | `pool_prepare` `exit` |
| `withdraw 0.5 NEAR`, `exit 1 NEAR to cash`, `cash out 1 NEAR`, `pay out 0.6 NEAR` | payout to the connected account (unchanged) | `exit_cash` |
| `how much do I have?`, `what's my balance?`, `what do I have?` | total | reads |
| `what's in vault 0?`, `how much do I have in vault 1?` | one vault | reads |
| `how private is my position?`, `am I anonymous?` | privacy | reads |
| `how much can I withdraw?`, `what can I take out?` | what can be withdrawn | reads |
| `what vaults are there?`, `which vaults can I use` | the vaults | reads |
| `show my portfolio` (and the earlier forms) | the portfolio card (unchanged) | reads |

A question must be short (at most 10 words), start with a question word or end with "?", and, for the person's
figures, say "my" or "I"; "how much does a plumber cost?" still goes to the research. Since this round "withdraw 1
NEAR from vault 0" leaves the vault to cash (before, it went to the research).

**Cash entry, switch, leave.** No wallet account is needed (ONA signs with the notes' own keys). The engine reads
`pool_info`, checks the vaults (a destination must exist and be open; a source must exist, a frozen one can be left; the
same vault twice is refused), runs `pool_prepare`, and for an entry or a switch `pool_privacy` with the value the
preparation puts in the destination. The card shows that very preparation: amount (or all), from / into, shares
received or new shares or cash notes received (value), share price, left in the pool's cash, fees, "blends in with at
most N notes" in the destination (for a leave: the cash notes in circulation per value), the upper-bound caveat, a
warning when a leave exceeds the vault's hourly exit cap, and the steps. **Yes** runs that preparation's
`pool_execute` (within its 5 minutes; nothing is prepared again); **No** sends nothing (its notes stay reserved until the
preparation expires). The outcome is reported: queued by the agent (normally), done, or refused with the reason. A switch
stops after its leave, as ona-core does with the real agent: the chat says to ask "put my cash in vault N" once Recover
has the cash notes. Refusals read: "you have no notes as cash available for this…", "… cannot be made exactly from your
notes…", "there is no vault N…", "vault N is frozen…", "these shares are already in vault N…".

**Questions** are answered in the chat from `pool_info`, `pool_portfolio` and `pool_privacy`, computed in the app (no
model, no relay): figures in NEAR, the holdings by vault with kind and target, operations in progress, the payout
account and the cash payout cap, the vaults with their state and price, and the privacy line (least protected note,
"blends in with at most N", "without ONA … 1", upper bounds). A question from the phone stays a free research.

**Pool screen.** At the top: the wallet line, the total value, one line per holding (cash, each vault) with its value,
its privacy figure, an "operation in progress" marker and Switch / Leave for a vault, then **Deposit**, **Put cash in a
vault**, **Withdraw**, and a hint of chat phrases. Everything else is in **Details**, closed: the privacy summary, the
notes per tier, all vaults, the deposit figures, network and contract, **Recover pending operations**. The stray "null"
under the total value came from `replaceChildren` writing a `null` argument as text; null entries are now left out.

**What was run (14/11/2026, macOS sandbox).** The worktree could not move to the latest main (its git refs cannot be
written here); the changes are on the previous commit, and main's newer commit only rebuilt the wallet page's bundle.
`cargo test --locked` in `src-tauri` still cannot unpack `bit-vec`; every module except `main.rs` passed in the outside
harness: 100 tests, no compiler warning, no new clippy warning (new: the parser's moves and questions, cash entry with an
amount and with all, switch then leave with the cap warning and No, refusals, seven question answers checked against
their expected text, a phone question not answered). ona-core was not changed. The window's new code ran in Node with a stand-in
DOM and a fake bridge (move cards, the simpler Pool screen, no "null"). **Not run:** the real window, a click, the real
testnet pool for these operations, and the real agent's replies to a switch or a leave.

## Tor client authorization

In Tor mode the onion service is published for the paired phone's client key only (Tor "restricted discovery"): a Tor
client without the key cannot find it, so it cannot try a pairing code or a request. The app makes an x25519 key,
writes its public half to `tor/hs/authorized_clients/phone.auth` before starting `tor`, and gives the secret half to
the phone in the QR code (`onion_auth`, docs/ios/protocol-draft.md). The secret is kept with the pairing secrets (in
the system's credential store). Forgetting the phone makes a new key and starts `tor` again. A pairing made before
this change is dropped once: the phone pairs again.

Before showing the QR code, the app checks its own onion address through its own `tor` without the key: with
`ExtendedErrors` on that SOCKS port, `tor` answers "missing client authorization" (0xF4) once it found the descriptor,
which shows the service is published.

**A local test node** (development builds only): `"local_node": true` in `pool.json` makes the pool talk directly, without
Tor, to a node and an agent on this computer (`http://127.0.0.1:…`), for example a run of `ona-sandbox-pool`. A release build
refuses the setting. Run on 12/11/2026 against `ona-sandbox-pool --serve` (docs/INSTALL.md): through the engine's pool
thread, the portfolio (12 NEAR of cash), an entry of 10 NEAR into vault 0 queued by the agent, and `pool_recover`
collecting the share notes. The window itself was not driven against it (no automated clicks in the Tauri window).
