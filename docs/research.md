# Free research and actions

Next to the lawyer mission (unchanged), a conversation can be a **free research**: the agent searches the open web and
reads pages through Tor, answers with its sources, and may suggest a message or a payment that the person completes. The
core is `crates/ona-core/src/research.rs`; its module comment lists the guardrails.

## The flow

1. **Question.** The person writes; the app opens a research (`research_open`).
2. **Queries, confirmed before anything leaves.** The planner proposes up to 3 queries (`research_propose`). The person
   accepts them, on the computer or the phone, or edits them on the computer (`research_accept` with the final list). A
   query holding a protected term is refused.
3. **Search and reading, through Tor.** Step by step (`research_step`): each query searched (DuckDuckGo's onion
   service), the first 2 results of each read, at most 5 pages, one per site, https to a public host name or http to an
   onion address only. The model never chooses an address.
4. **Answer with sources** (`research_result`): written from notes whose quotes were found word for word in the pages,
   citing them.
5. **Actions** (at most 2, only if the question asks): a message or a NEAR payment. On the computer only: the person
   types the recipient (an e-mail address or a NEAR account; one also written in a page read is flagged), sees the exact
   action, confirms it (`research_action_prepare`, then `research_action_confirm` with its digest), and it is carried out
   once (`research_action_do`): a message opens in the person's own mail program (`mailto:`), the person sends it; a
   payment goes through `Payments` under the cap.
6. **What left** (`research_exposure`): every query, page, model call and action.

## Core commands

All through `Core::dispatch`, every reply with `ok` and `mode`.

| Command | Fields | Reply |
|---|---|---|
| `research_open` | `question`, optional `protected` (terms) | `opened`, `web` (`mock` on the demo web, `real` through Tor) |
| `research_propose` | | `queries` |
| `research_accept` | `queries` (1 to 3 strings, at most 120 characters each) | `accepted` |
| `research_step` | | `done`, `event` (`searched` with `query` and `sources` [`handle`, `title`, `site`]; `read` with `handle` and `notes`; `unreadable`, `unread` or `refused` with `handle` and `error`; `answered`) |
| `research_result` | | `answer`, `notes` [`source`, `claim`, `quote`], `sources` [`handle`, `title`, `url`], `actions` [`index`, `kind`, `purpose`, `text` or `amount` (yoctoNEAR), `done`] |
| `research_action_prepare` | `index`, `to` | `kind`, `to`, `content`, `digest`, `seen_in_pages` |
| `research_action_confirm` | `digest` | `confirmed` |
| `research_action_do` | | `done` (`message` with `mailto`, or `payment` with `tx`) |
| `research_close` | | `closed` |
| `research_exposure` | | the exposure report |

The action digest: SHA-256 of `fields("ona/action/v1", mission_id, index (decimal), kind, to, content)`, where `content`
is the message text or the amount in yoctoNEAR (decimal).

## The desktop apps' conversation views (phone protocol)

A research conversation uses the same `/v1/chats/…` views as a mission (docs/ios/protocol-draft.md, "Conversations"),
with these additions:

- **Activity** items (`kind: "activity"`): `tool` `think`, `search` (text « Recherche « <query> » : N sources ») or
  `read` (text « Lecture de <site> : N notes », or why it was not read).
- **Confirmation** of the queries (`kind: "confirmation"`): `pending` is
  `{"id": "c-…", "kind": "queries", "queries": ["…", "…"], "content": "<digest>"}`, like the plan's. Its content digest:
  SHA-256 of `fields("ona/queries/v1", id, query_1, query_2, …)` in hex (`protocol::queries_digest`, Swift
  `ProtocolBytes.queriesDigest`), recomputed by the phone from the queries it shows. The phone accepts or rejects it with the usual
  signed confirmation (`decision`, `content`); accepting accepts the queries as shown. Editing them is done on the computer.
- **Answer** item (`kind: "answer"`): `{"answer": "…", "notes": [{"source": "s1", "claim": "…", "quote": "…"}],
  "sources": [{"handle": "s1", "title": "…", "url": "…"}]}`.
- **Action** items (`kind: "action"`), one per suggested action: `{"action": {"index": 0, "kind": "message",
  "purpose": "…", "text": "…"}, "state": "suggested"}` (or `"kind": "payment"` with `"amount"` in yoctoNEAR), `state`
  `done` once carried out. Actions are completed on the computer only; the phone shows them.
- **Exposure** item at the end, as for a mission (`research_exposure`).

A chat's `status` is `working` while queries are searched and pages read, `waiting` while the queries await
confirmation, `idle` once answered (actions do not block it).

## Not tested

Through Tor end to end: the network used for development blocked Tor on 13/11/2026; the search engine and page reading
were checked directly (DuckDuckGo's HTML page and near.org). With the real model: not yet (the relay is not published).
