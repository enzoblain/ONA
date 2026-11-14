# Phone ↔ computer protocol, version 1

Version 1 of 2026-11-11: replaces version 0 (2026-11-10), after the security inspection (replay, 6-digit code without
commitment, open reads, computer not authenticated, incomplete signatures). Implemented by the desktop apps
(`desktop/tauri/src-tauri/src/{protocol,pairing,router}.rs`, `desktop/ONADesktop/Core/`), by the iPhone app
(`ios/ONA/ONA/Pairing/SignedFields.swift`, `Protocol/ComputerLink.swift`) and by the mock computer
(`ios/MockComputer`), on 2026-11-11.

It mirrors the three human confirmations of `ona-core`: `accept_plan`, `confirm_recipient`, `confirm_payment`.

## Principles

- The phone **polls** the computer (no push). It keeps nothing on disk outside the Keychain.
- The phone sees only what it must show: progress, the offers to choose between, the payment screen.
- Every reply carries `"mode"`: `"mock"` as long as the model and the payments are fake, `"real"` otherwise.
- Transport: HTTP/1.0 + JSON, **all requests are `POST`** with a JSON body (the app's Tor bridge can send neither
  headers nor `DELETE`). Through Tor (the computer's `.onion`). The "local network" mode (plain HTTP) exists only in
  development builds of the desktop apps.
- The computer refuses: a `Host` header that is missing, empty, repeated or other than its `.onion` address (or
  `127.0.0.1:port`, or its local address in local network mode); any request carrying `Origin`, `Sec-Fetch-Site`,
  `Sec-Fetch-Mode` or `Sec-Fetch-Dest`, even with an empty value (a browser); any method other than `POST`; the
  `/v0/…` routes.
- Limits on the computer side: 16 simultaneous connections, 10 s to send a request and receive its reply, headers and
  body of 16 KiB at most.

## `fields(…)` encoding

For each field: its length as a little-endian u32, then its bytes (text in UTF-8, keys as raw bytes, missing field =
length 0). Numbers (counter, HTTP status, price…) are written as ASCII decimal text. Nonces (`nonce`) are 16 random
bytes written as 32 lowercase hexadecimal characters. Digests are SHA-256 as 64 lowercase hexadecimal characters.

Signatures: ECDSA P-256 with SHA-256, DER encoding, in standard base64. **The "low-s" form is required** (s ≤ n/2): a
signature with s > n/2 is refused, on both sides. CryptoKit produces one half of the time: replace s with n − s before
sending. Public keys: uncompressed X9.63, 65 bytes starting with `04`.

## Replies signed by the computer

Each request carries a `"nonce"` field (32 hex, new for each request). Each reply from the computer has this body:

```json
{ "reply": "<the reply's JSON, as text>", "signature": "<base64, ECDSA DER>" }
```

`signature` covers `fields("ona/reply/v1", nonce, method, path, http_status, reply)` (method and path of the request,
for example `POST` and `/v1/chats/list`) and is verified with `computer_key` from the QR code. The phone verifies the
signature **over the exact value of `reply` obtained after decoding the JSON** (never re-encode: the Mac app escapes
`/` as `\/`), with its own `nonce`, method and path, **before** reading `reply`. It rejects any reply that is unsigned
or wrongly signed: a program that took over the computer's port, or a relay, can neither forge a reply, nor replay an
old one (the `nonce` changes), nor pass off the reply to one request as the reply to another.

The only replies **without a signature**: 400, 413 and 431 when the HTTP request itself is unreadable or too large
(before any JSON is read), and 503 (computer shutting down). An unsigned reply is always a failure; the phone does not
read its body and does not show it as coming from the computer. All other replies, errors included (including a 400
"body is not a JSON object"), are signed.

## Pairing

1. The computer shows a QR code: `ona-pair:` followed by the base64url (without `=`) of a JSON:

   ```json
   { "v": 1, "name": "My computer", "address": null, "onion": "<v3 address>.onion",
     "computer_key": "<base64, X9.63, 65 bytes>", "code": "<base64url, 16 random bytes>",
     "expires_at": 1762790600 }
   ```

   The code can be used only once and expires after 10 minutes (a new QR code is shown). After 5 wrong codes, it is
   replaced. The phone refuses a QR code whose `v` is not 1.

   With a `.onion` address, the QR code also carries `"onion_auth"`: the x25519 key (32 bytes, RFC 4648 base32 without
   `=`) of the phone's **Tor client authorization**. The computer publishes its onion service for this key only
   ("restricted discovery", `tor`'s `authorized_clients/phone.auth` file): a Tor client without the key does not even
   find the service, and so cannot attempt a pairing or a request. A new key for each new pairing (phone forgotten),
   and the computer republishes its service. The phone gives it to Arti before its first request and keeps it with the
   pairing. A QR code without `onion_auth` can still be read (computer running an earlier version).
2. The phone creates its P-256 key (Secure Enclave) and a nonce `phone_nonce`, then **commits**:

   ```json
   POST /v1/pair
   { "code": "<code from the QR code>", "commitment": "<hex>", "nonce": "<hex>" }
   ```

   `commitment = SHA-256(fields("ona/pair-commit/v1", phone_key, phone_nonce))`. The code is used up here, whatever
   happens next. Reply: `{"ok": true, "pairing_id": "p-<32 hex>", "computer_nonce": "<32 hex>", "mode": …}`.
3. The phone **reveals** its key:

   ```json
   POST /v1/pair/reveal
   { "pairing_id": "p-…", "phone_key": "<base64, X9.63>", "phone_nonce": "<hex>", "signature": "<base64>",
     "nonce": "<hex>" }
   ```

   `signature` (phone's key) covers
   `fields("ona/pair/v1", pairing_id, code, phone_key, computer_key, phone_nonce, computer_nonce)`. The computer
   checks the commitment and the signature: a single attempt; on failure, a new QR code. The commitment must arrive at
   most 2 minutes before the reveal. Reply: `{"ok": true, "pairing_id": "p-…", "token": "<base64url, 32 bytes>"}`.
4. Both sides show the 6-digit **verification code**:
   `SHA-256(fields("ona/sas/v1", computer_key, phone_key, code, phone_nonce, computer_nonce))`, first 4 bytes as a
   big-endian integer, modulo 1,000,000, on 6 digits. The phone's key is fixed (commitment) before `computer_nonce`
   exists: a party in the middle can no longer search for a key that gives the same code (one chance in a million per
   QR code). The computer saves the phone only after the person confirms, within 5 minutes (after that, a new QR
   code). Between the reveal and that click, every request gets 403 `not paired`: the phone shows the code and waits.
   The computer's screen says to refuse if the phone shows no code.
5. The phone keeps in the Keychain (this device only): `pairing_id`, `onion`, `computer_key`, `name`, `token`, its
   counter, the reference to its Secure Enclave key.

## Reads (token)

- `POST /v1/chats/list` `{"token", "nonce"}` → `{"mode", "chats": [{"id", "title", "updated_at", "preview",
  "status": "idle | working | waiting"}]}`, most recent first.
- `POST /v1/chats/{id}/view` `{"token", "nonce"}` → `{"mode", "chat": {"id", "title", "status",
  "working": {"tool", "text"} | null, "items": [...]}}`. Items: `user` / `agent` (`text`), `activity` (`tool`,
  `text`), `confirmation` (`pending`, `state`: `pending | accepted | rejected | expired`), `exposure`. An unknown
  `kind` is ignored.

Without the right token: 403 `missing or wrong token`. The token travels only inside the encrypted Tor stream.

## Pool (read only)

- `POST /v1/pool/portfolio` `{"token", "nonce"}` → `{"mode", "portfolio": {…}}`, where `portfolio` is the reply of
  `ona-core`'s `pool_portfolio` command without `ok` or `mode` (`cash`, `vaults`, `vault_count`, `total`; amounts in
  yoctoNEAR, see `docs/desktop/pool-commands.md`). Reply signed like the other reads.
- Without the right token: 403 `missing or wrong token`. If the computer has no pool configured, 409 with the error
  from `ona-core` (for example `no pool wallet configured`).
- Read only: deposits, placements, vault changes and exits are prepared and confirmed on the computer
  (`pool_prepare`, `pool_execute`), never on the phone.

## Writes (token + phone signature + counter)

Each write carries `token`, `pairing_id`, `counter` (a JSON integer with no decimal part, from 1 to 2^53 − 1 =
9007199254740991, strictly increasing for this pairing; `1.0`, `"1"` or `true` are refused) and `signature` (the
phone's key, hence Face ID or the device passcode). The computer saves the last accepted counter **before** running
the request, including across restarts: a replayed request, or a counter that does not increase, is refused
(`replayed request`). The phone sends its writes one at a time.

- `POST /v1/chats` `{"text", …}` → `{"ok", "chat_id": "chat-<32 hex>"}`.
  Signature: `fields("ona/message/v1", pairing_id, counter, "", text)`.
- `POST /v1/chats/{id}/messages` `{"text", …}`. Signature: `fields("ona/message/v1", pairing_id, counter, chat_id, text)`.
- `POST /v1/chats/{id}/delete` `{…}`. Signature: `fields("ona/delete/v1", pairing_id, counter, chat_id)`.
- Text: 1 to 2,000 characters. Conversation identifiers are random, never reused.

## Confirmations

`pending` (at most one per conversation) carries `id` (`c-<32 hex>`, random, issued by the computer, never reused) and
`content`, the digest of what is shown:

```json
{ "id": "c-…", "kind": "plan", "plan": ["search", "read", "…"], "content": "<hex>" }
{ "id": "c-…", "kind": "recipient", "content": "<hex>",
  "offers": [ { "firm_id": "cabinet-b", "price_cents": 60000, "delay_days": 10,
                "source_spans": ["Flat fee 600 euros, within 10 days"] } ] }
{ "id": "c-…", "kind": "payment", "content": "<hex>",
  "payment": { "to": "cabinet-b.testnet", "amount": "1000000000000000000000000",
               "screen": "Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet",
               "digest": "<hex>", "digest_version": 2, "network": "testnet", "contract": "…",
               "mission_id": "…", "nonce": "<32 hex>" } }
```

Digests, **recomputed by the phone from what it shows** (never taken from `content`):

- plan: `SHA-256(fields("ona/plan/v1", id, step_count, step_1, …, step_n))`;
- offers: `SHA-256(fields("ona/offers/v1", id, offer_count, then for each offer: firm_id, price_cents, delay_days,
  span_count, span_1, …))`;
- payment (v2, shared with `ona-core`):
  `digest = SHA-256(fields("ona/pay/v2", network, contract, mission_id, nonce, to, amount))`, and `content = digest`.
  These are the bytes of `ona-core`'s guardrail: the desktop app takes the six fields from the `prepare_payment`
  reply, checks the digest and passes them on unchanged with `screen`. `to` and `amount` must be those of `screen`.
  The amount is computed by `ona-core` (price of the chosen offer × the policy's rate), not by the app. The old digest
  (`to` and `amount` only, version 0) no longer exists: `digest_version` is always 2, and the phone refuses any other
  value. `to` must have the form of a NEAR account (2 to 64 characters `a-z 0-9 . _ -`).

```json
POST /v1/confirm
{ "id": "c-…", "decision": "accept | reject", "firm": "cabinet-b", "digest": "<hex>",
  "token": "…", "pairing_id": "p-…", "counter": 12, "signature": "<base64>", "nonce": "<hex>" }
```

- `firm`: required for an accepted `recipient`; `digest`: required for an accepted `payment`.
- `signature`: `fields("ona/confirm/v1", pairing_id, counter, id, decision, firm, digest, content)`, where `content` is
  the digest recomputed by the phone. The computer puts in its place the digest of what it asked for: if the phone
  showed something else (another plan, other prices), the signature does not verify.
- The computer refuses a confirmation whose `id` is no longer expected (`stale confirmation`), an `id` already carried
  out (`replayed request`, even after a restart) and a counter that does not increase. A reply refused by the agent
  (for example a wrong digest) does not block the confirmation: the phone can answer again, with a new counter.

**Correction of version 0**: the v0 draft claimed that a signature could not be replayed. That was wrong: the
`chat-N-c-M` identifiers restarted from 1 at each mission and each restart, no request had a counter, and the payment
digest depended only on the recipient and the amount. A whole mission, payment included, could be replayed.

## Known limitations

- A compromised computer does what it wants: the phone's signature is verified by the desktop app, not by `ona-core`
  nor by the chain. A stolen, unlocked phone can read everything; each write still asks for Face ID or the device
  passcode.
- In local network mode (development), the token and the requests travel in plain text.
- Whoever copies the onion service's key can publish the same address; they cannot sign the replies (the computer's
  key), but they see the phone's requests (encrypted by Tor up to them).
