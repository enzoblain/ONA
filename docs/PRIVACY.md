# How ONA keeps you private: eight layers, and the pool

ONA is built so that **no single party receives both who you are and what you asked**. That property does not come from
one trick: it comes from eight layers, each closing one way a request could be tied back to you, plus a shared pool for
your savings. This page explains each one in plain terms, how ONA builds it, and what state it is in today.

**Prototype, not audited. Do not use real funds.** At launch the anonymity set is one, so ONA claims no unlinkability until
a measured number of users is published. The states below come from [STATUS.md](STATUS.md) and [SPEC.md](../SPEC.md)
(14/11/2026); the full list of limits is in [DESIGN.md](DESIGN.md#known-limitations). Anything simulated says `mode: mock`.

| # | Layer | What it stops | State today |
|---|---|---|---|
| 1 | [Your words don't give you away](#1-your-words-dont-give-you-away) | the model learning names and identifiers | built and tested |
| 2 | [Your address is hidden](#2-your-address-is-hidden) | the relay, the web and NEAR nodes seeing your IP | built in the core; one research ran through real Tor |
| 3 | [A relay stands between you and the AI](#3-a-relay-stands-between-you-and-the-ai) | the AI provider holding an account in your name | relay logic tested against fakes; real calls used a test relay |
| 4 | [Only the model can read your request](#4-only-the-model-can-read-your-request) | the relay reading your request or the reply | built; real encrypted calls passed |
| 5 | [Side signals are reduced](#5-side-signals-are-reduced) | tying you by headers, compression or timing | partly built |
| 6 | [You pay with blind tokens](#6-you-pay-with-blind-tokens) | linking a payment to a deposit | built; mint not on testnet |
| 7 | [Your other actions stay yours](#7-your-other-actions-stay-yours) | the agent acting without you, or paying the wrong party | built |
| 8 | [It reports without exposing you](#8-it-reports-without-exposing-you) | an unverifiable black box | built |
| + | [The pool](#the-pool-savings-that-dont-point-at-you) | your savings pointing at your account | test build on testnet; never used with a real wallet end to end |

## 1. Your words don't give you away

**The risk.** What betrays a person is mostly the content: a name, a case number, an employer.

**How ONA does it.** Before any text reaches the model, the core replaces every term you protect (names, case numbers,
company names) with a random 12-letter pseudonym, and puts the real words back locally in the reply. The table never leaves
your computer and is forgotten when the conversation ends. A text that still contains a protected term after replacement is
refused, not sent. Matching is robust to accents, case, HTML, invisible characters, hyphenation and look-alike dashes.

**Limits.** Only declared terms are replaced. A misspelling, a nickname or the context around a name (job, city, dates) can
still identify someone. Details: [what pseudonyms cover](DESIGN.md#what-pseudonyms-cover).

## 2. Your address is hidden

**The risk.** Your IP address alone ties every request to your home or office.

**How ONA does it.** With Tor enabled in the core, the relay, the pool agent, NEAR RPC reads, web searches and page reads
go through a local Tor daemon. Each model call gets its own circuit (its few requests share it), so two calls, or a cash
issue and a vault entry, do not share one. If Tor is down nothing is retried directly. Your phone reaches your own computer
through an onion service published for that phone only. Details: [TOR.md](TOR.md).

**Limits.** The separation of circuits is Tor's documented behaviour, not verified on the real Tor network. The desktop and
phone apps do not route their own model calls through Tor yet. Pool deposits are signed in your browser wallet, outside Tor.

**State.** One research ran end to end through real Tor with the real model on 13/11/2026; the iPhone paired with the
desktop app through Tor on a real device on 14/11/2026.

## 3. A relay stands between you and the AI

**The risk.** An AI account needs an API key, and an API key belongs to someone.

**How ONA does it.** The relay holds the NEAR AI key; you never need one. It is designed to be paid with anonymous tokens
(layer 6), not an account, and passes on only the encryption headers it needs.

**State and limits.** The relay logic is tested against a fake chain and a fake NEAR AI; the full relay program has not run
yet. The real calls of 12 and 13/11/2026 went through the team's test relay, on the team's own machine, reached as an onion
service, not inside an enclave: whoever runs it can see timing, sizes, the model name and token counts. It does not see the
content (layer 4).

## 4. Only the model can read your request

**The risk.** A relay in the middle could read your request, or replace the reply.

**How ONA does it.** The request is encrypted end to end for NEAR AI's enclave (encryption version 3, which also binds the
key the reply is encrypted to). Before using a model key, the client checks the enclave's Intel TDX quote: signed by Intel,
binding that key and this request, on the deployment observed. The reply is checked against the enclave's signature.

**State.** Real encrypted calls passed on 12 and 13/11/2026; the real NEAR AI quote passed Intel's check with live data on
13/11/2026. Not checked yet: the NVIDIA GPU evidence.

## 5. Side signals are reduced

**The risk.** Even with encrypted content, metadata can link requests: client headers, compression, sizes and timing.

**How ONA does it.** The relay forwards only a fixed list of encryption headers, sets the others itself, and always asks
NEAR AI for uncompressed replies; each model call has its own Tor circuit; web queries are shown to you and confirmed before
they leave.

**Limits.** Sizes and timing are not padded. This layer is the least complete.

## 6. You pay with blind tokens

**The risk.** A payment ties your wallet to what you bought.

**How ONA does it.** You deposit once into the `ona-mint` contract and receive blind BLS tokens. The mint signs them without
seeing them, so when a token is spent later it cannot link it to your deposit. Double spends and forged tokens are refused.

**State.** Contract built and tested on a mocked NEAR VM and a local NEAR node, gas measured. Not on testnet yet; payments
in the apps are simulated. Spec: [SPEC.md](../SPEC.md).

## 7. Your other actions stay yours

**The risk.** An agent that can pay or write for you can be tricked by a web page.

**How ONA does it.** Actions are only suggested: you type the recipient, see the exact action, and confirm it; a payment is
confirmed by a digest of its exact fields. Money can only go to recipients you allowed, and refusals are logged without
names. A block list for fraud addresses exists but is empty: no maintained public list was found. A message opens in your
own mail program. Conversations stay in memory and are gone when the app quits. Details: [research.md](research.md).

## 8. It reports without exposing you

**The risk.** "Trust us" is not a privacy property.

**How ONA does it.** After each conversation an exposure report lists every party that received something, with request and
byte counts, never the content. The journal is sealed, and its checkpoints can be anchored hourly on NEAR so an auditor can
check it was not rewritten. The contracts build reproducibly: `./verify.sh` prints their hashes.

**Limits.** Anchoring is built as a library; no program submits checkpoints yet.

## The pool: savings that don't point at you

**The risk.** Putting money into staking straight from your wallet ties that position to your account forever.

**How ONA does it.** You deposit into the `ona-pool` contract from your own NEAR wallet (ONA never holds its keys). The pool
agent turns the deposit into blind **cash notes**, tied to no vault. You can then enter a staking vault with share notes,
switch, and exit to cash or to an account that deposited; exits name no vault. Entries, leaves and cash exits are sent in
delayed batches, withdrawals on a fixed grid, and a 7-day escape lets you leave without the agent.

**How private, in numbers.** The app never shows a percentage. It shows how many identical notes yours blends in with,
counted on the chain at that moment ("blends in with at most N notes"), and how many more an entry would give you. These are
upper bounds; with few users the number is small, and the app says so. Details: [desktop/privacy.md](desktop/privacy.md),
[desktop/pool-commands.md](desktop/pool-commands.md).

**State and limits.** Run end to end on a local NEAR node (34 checks); a test build is deployed on testnet with a test staking
pool as its vault, never against a real staking pool. The deposit from a wallet is built in both desktop apps but has not
completed end to end with a real wallet. The agent itself sees every request, and it does not run in an enclave. Lending
is not built. Deposits are public on chain and show that an account uses ONA.

## Read more

- [README](../README.md): what ONA is and how to try it.
- [STATUS.md](STATUS.md): every component, and what it was tested on.
- [DESIGN.md](DESIGN.md): architecture and the full list of known limitations.
- [SPEC.md](../SPEC.md): contracts, tokens, measured gas.
- Website: https://ona-indol.vercel.app
