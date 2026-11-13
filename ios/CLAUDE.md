# ONA iOS app — instructions (owner: Enzo)

Background: `docs/team/ios-brief.md` (brief received 2026-11-10) and `docs/team/ios-notes.md` (status, open questions).

## Scope

The iPhone is a **remote control of the user's computer over Tor**: mission progress and confirmations (recipient
choice, payment).

- It holds **no agent, no wallet, no tokens, no pseudonym table**. Nothing on disk except the pairing.
- **No push notifications** (an APNs token is a stable identifier). The app polls the computer; confirmations are
  discovered when the app is opened.
- No App Store in V1: development on a test iPhone, maybe TestFlight later.
- Accepted cost: without the computer switched on, nothing works.

## Order of work

1. **Tor spike on a real iPhone first.** Connect to a `.onion` with Arti (Rust) embedded. Measure startup time (cold
   and warm), binary size added, and stability in real use (network switch, background/foreground).
2. **Screens against a mock server**: mission progress and confirmations. The protocol spec and mock server come from
   the team. Everything coming from the mock must be shown as « simulation » in the app.
3. **QR pairing**: the QR holds the computer's onion address and public key. Confirmations are signed with a P-256 key
   in the Secure Enclave (CryptoKit).
4. **Real control over Tor.** Fallback if Tor on iPhone stays unstable: the iPhone only validates by QR, no network.

## Rules specific to this folder

- Swift package / Rust crate versions pinned exactly; log each adopted library in the README.
- Measurements go in `docs/ios/` with date, device, iOS version and library versions. No number in public text
  without a reproducible measurement.
- Research claims about Arti/Tor on iOS are unverified until checked (see `docs/team/ios-notes.md`).
