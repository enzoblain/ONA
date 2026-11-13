# ONA design notes

The design, the planned architecture and the known limitations, moved here from the README on 13/11/2026 without
changing their text. The README links here.

## What it is (details)

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
[what works today](STATUS.md) and the [known limitations](#known-limitations).

Example: find a labour lawyer and compare fees on a generic version of your case, without the firms you did not pick
learning who you are.

## The problem

A hosted AI chat links your identity, your conversations and your actions at one operator. Encrypted inference helps
with the content, but the account, the network address, the payment and the agent's actions still identify you.

## Planned architecture

| Component | Role | Language |
|---|---|---|
| `ona-core` | Runs on the user's computer: mission state machine, payment gate, pseudonyms, E2EE client for NEAR AI Cloud, wallet tokens, sealed state, journal, exposure report. Reaches the relay, the pool agent and the NEAR RPC nodes through a local `tor` over SOCKS5 when `ONA_TOR_SOCKS` is set, one circuit per request (per model call for the relay); otherwise directly, and says so at start | Rust |
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


## Next steps (product direction, not built yet)

**Privacy metrics in a side panel of the app.** A first version is built: `pool_privacy` counts, from the contract's public
views, how many notes of the same value at the same place a note hides among, and the desktop apps show it in the Pool window
and next to each vault offered for an entry (docs/desktop/privacy.md). The "with ONA / without ONA" comparison below is not built.
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
  The client now uses version 3, which binds the reply key. The NEAR AI gateway accepted version 3 in one real call on 12/11/2026 (model
  `z-ai/glm-5.3-flash`, through the test relay: decrypted reply, valid signature, 48 tokens). That the real gateway refuses a request whose
  reply key was replaced was tested only against a simulated enclave. A relay running in an attested enclave is not in place yet.
- The relay serves a fixed pool of 32 connections with per-request deadlines, so 32 slow clients are enough to keep it busy. Do not expose it
  to the internet yet; behind an onion service, rely on its denial-of-service protection.
- The signer and the relay read the chain through two RPC endpoints and stop when they disagree. Two endpoints that lie together still
  decide what gets signed.
- A stolen signer key can drain the reserve at the speed of the hourly redemption limit. There is no key rotation.
- An attacker holding tokens can keep a tier's redemption limit used up and slow exits for that tier (the relay has its own limit).

More in [SPEC.md](../SPEC.md).

