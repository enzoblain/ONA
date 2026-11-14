//! The agent's conversations: one ona-core per chat, driven step by step and stopped at each human confirmation.
//! Same JSON views as the macOS app's ChatEngine (desktop/ONADesktop/Core/Missions).
//!
//! A new conversation is a free research (docs/research.md): queries confirmed, then searched and read through ona-core,
//! an answer with its sources, and suggested actions completed on this computer only. The lawyer mission is kept
//! (`create_mission`, tests only).

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::pairing::ProtocolError;
use crate::pool_chat::{self, Amount, Intent, Question, VaultRef, near_text};
use crate::protocol::{self, parse_payment_screen};

/// Something that runs ona-core commands (`Core::dispatch`).
pub trait MissionCore {
    fn dispatch(&mut self, request: Value) -> Value;
}

impl MissionCore for ona_core::Core {
    fn dispatch(&mut self, request: Value) -> Value {
        let reply = ona_core::Core::dispatch(self, &request.to_string());
        serde_json::from_str(&reply).unwrap_or_else(|_| json!({"ok": false, "error": "unreadable reply from ona-core"}))
    }
}

/// A core whose panic is caught (the single worker thread survives) and which is never used again afterwards: its
/// state (gate, journal) may be half changed.
pub struct Guarded<C: MissionCore> {
    core: C,
    poisoned: bool,
}

impl<C: MissionCore> Guarded<C> {
    pub fn new(core: C) -> Self {
        Self { core, poisoned: false }
    }
}

impl<C: MissionCore> MissionCore for Guarded<C> {
    fn dispatch(&mut self, request: Value) -> Value {
        if self.poisoned {
            return json!({"ok": false, "error": "ona-core stopped after an internal error"});
        }
        let core = &mut self.core;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core.dispatch(request))) {
            Ok(reply) => reply,
            Err(_) => {
                self.poisoned = true;
                json!({"ok": false, "error": "panic inside ona-core"})
            }
        }
    }
}

/// Makes the cores, on the thread that will own each one.
pub type CoreFactory = Arc<dyn Fn() -> Box<dyn MissionCore> + Send + Sync>;

/// How long a tick waits for ona-core before going on: the fake model answers within it, a real call (the model
/// through Tor) does not, and the tick then leaves it running and looks again at the next one.
const QUICK_REPLY: Duration = Duration::from_millis(200);

/// One conversation's ona-core, on a thread of its own. The worker thread, which also serves the window and the phone,
/// sends one command at a time and never waits for a slow one (`poll`). The core is dropped with the thread, once its
/// last command is done (its request tokens file is then free again).
struct CoreThread {
    requests: Sender<(Value, Sender<Value>)>,
    /// The command sent and not answered yet.
    inflight: Option<(Value, Receiver<Value>)>,
}

impl CoreThread {
    fn spawn(factory: &CoreFactory) -> Self {
        let (requests, inbox) = mpsc::channel::<(Value, Sender<Value>)>();
        let factory = factory.clone();
        thread::spawn(move || {
            let mut core = factory();
            for (request, reply) in inbox {
                let _ = reply.send(core.dispatch(request));
            }
        });
        Self { requests, inflight: None }
    }

    /// ona-core's reply to `request` once it is there; None while ona-core works on it, and the same request is
    /// asked again at the next tick. A different request while one is in flight waits for the first one.
    fn poll(&mut self, request: Value) -> Option<Value> {
        if self.inflight.as_ref().is_some_and(|(sent, _)| *sent != request) {
            self.wait();
        }
        if self.inflight.is_none() {
            let (reply, answer) = mpsc::channel();
            if self.requests.send((request.clone(), reply)).is_err() {
                return Some(stopped());
            }
            self.inflight = Some((request, answer));
        }
        let (_, answer) = self.inflight.as_ref()?;
        match answer.recv_timeout(QUICK_REPLY) {
            Ok(reply) => {
                self.inflight = None;
                Some(reply)
            }
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                self.inflight = None;
                Some(stopped())
            }
        }
    }

    /// Waits for the reply: for the quick commands the person is waiting on (a confirmation, closing the mission).
    fn call(&mut self, request: Value) -> Value {
        self.wait();
        let (reply, answer) = mpsc::channel();
        if self.requests.send((request, reply)).is_err() {
            return stopped();
        }
        answer.recv().unwrap_or_else(|_| stopped())
    }

    fn wait(&mut self) {
        if let Some((_, answer)) = self.inflight.take() {
            let _ = answer.recv();
        }
    }
}

fn stopped() -> Value {
    json!({"ok": false, "error": "ona-core stopped"})
}

pub const MAX_TEXT: usize = 2000;
const CONTACT_MESSAGE: &str = "Hello, I would like a quote for an employment law consultation.";
const PLAN_MESSAGE: &str = "I have prepared a {}-step plan. It is fixed before anything is read on the web: I will contact no one and pay nothing without your approval. Approve it so I can start.";
const RECIPIENT_MESSAGE: &str = "I found {}. Which one should I contact?";
const PAYMENT_MESSAGE: &str = "The firm has been contacted. The consultation payment still needs your confirmation.";
const DONE_MESSAGE: &str = "Done. Here is what left your computer during this mission.";
const CANCELLED_MESSAGE: &str = "Mission stopped at your request. Nothing else will be sent.";
const BUSY_MESSAGE: &str = "I am still working on the current mission: I will keep you posted here.";
const QUERIES_MESSAGE: &str = "Here are the searches I suggest. Nothing leaves your computer before you approve: approve them here or on your phone (they can only be edited on the computer).";
const ANSWER_MESSAGE: &str = "Here is my answer, with its sources.";
const ACTIONS_MESSAGE: &str = "Here is my answer, with its sources. I also suggest {}, to complete on this computer with your approval.";
const QUERIES_CANCELLED_MESSAGE: &str = "Search stopped at your request: no query was sent.";

fn running_label(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "search" => "Searching…",
        "read" => "Reading a page…",
        "compare" => "Comparing the offers…",
        "contact" => "Getting in touch…",
        "prepare_payment" => "Preparing the payment…",
        "pay" => "Sending the payment…",
        _ => return None,
    })
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn ok(reply: &Value) -> bool {
    reply["ok"] == true
}

fn error_of(reply: &Value) -> String {
    reply["error"].as_str().unwrap_or("unknown error").to_owned()
}

/// What binds a payment confirmation to one mission, once (format v2, shared with ona-core).
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentBinding {
    pub network: String,
    pub contract: String,
    pub mission_id: String,
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    Plan(Vec<String>),
    Recipient(Vec<Value>),
    Payment { to: String, amount: String, screen: String, digest: String, binding: PaymentBinding },
    /// The search queries of a free research, before anything leaves.
    Queries(Vec<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    pub id: String,
    pub request: Request,
}

impl Pending {
    /// Digest of what the phone shows for this confirmation. The phone recomputes it from what it displays and signs
    /// it; a confirmation signed over anything else does not verify.
    pub fn content(&self) -> String {
        match &self.request {
            Request::Plan(steps) => protocol::plan_digest(&self.id, steps),
            Request::Recipient(offers) => protocol::offers_digest(&self.id, offers),
            Request::Payment { digest, .. } => digest.clone(),
            Request::Queries(queries) => protocol::queries_digest(&self.id, queries),
        }
    }

    fn json(&self) -> Value {
        let content = self.content();
        match &self.request {
            Request::Plan(steps) => json!({"id": self.id, "kind": "plan", "plan": steps, "content": content}),
            Request::Recipient(offers) => json!({"id": self.id, "kind": "recipient", "offers": offers, "content": content}),
            Request::Payment { to, amount, screen, digest, binding: b } => json!({
                "id": self.id, "kind": "payment", "content": content,
                "payment": {"to": to, "amount": amount, "screen": screen, "digest": digest, "digest_version": 2,
                            "network": b.network, "contract": b.contract, "mission_id": b.mission_id, "nonce": b.nonce},
            }),
            Request::Queries(queries) => json!({"id": self.id, "kind": "queries", "queries": queries, "content": content}),
        }
    }
}

/// Reads ona-core's `prepare_payment` reply: `screen`, `digest` and `payment` {`network`, `contract`, `mission_id`,
/// `nonce`, `to`, `amount`}. The digest must be `protocol::payment_digest_v2` of those six fields, and `to` and `amount`
/// must be the ones of the screen. Anything else is refused: the phone could not recompute what it signs.
pub fn read_prepared_payment(reply: &Value) -> Result<Request, String> {
    let screen = reply["screen"].as_str().unwrap_or_default().to_owned();
    let digest = reply["digest"].as_str().unwrap_or_default().to_owned();
    let (amount, to) = parse_payment_screen(&screen).ok_or("unreadable payment screen")?;
    if !protocol::is_hex(&digest, 64) {
        return Err("malformed payment digest".into());
    }
    let payment = &reply["payment"];
    let field = |key: &str| payment[key].as_str().map(String::from);
    let (Some(network), Some(contract), Some(mission_id), Some(nonce), Some(paid_to), Some(paid_amount)) =
        (field("network"), field("contract"), field("mission_id"), field("nonce"), field("to"), field("amount"))
    else {
        return Err("payment without its mission binding (digest v2 required)".into());
    };
    if paid_to != to || paid_amount != amount {
        return Err("payment fields differ from the payment screen".into());
    }
    if !protocol::is_hex(&nonce, 32) || mission_id.is_empty() {
        return Err("malformed payment binding".into());
    }
    if protocol::payment_digest_v2(&network, &contract, &mission_id, &nonce, &to, &amount) != digest {
        return Err("payment digest does not match its fields".into());
    }
    Ok(Request::Payment { to, amount, screen, digest, binding: PaymentBinding { network, contract, mission_id, nonce } })
}

enum Content {
    User(String),
    Agent(String),
    Activity { tool: String, text: String },
    Confirmation(Pending),
    Exposure(Value),
    /// A research's answer: `answer`, `notes`, `sources`.
    Answer(Value),
    /// A suggested action of the research run `run` (its number in the chat): ona-core's view of it.
    Action { run: u64, action: Value, done: bool },
    /// A pool request's card (`pool_chat`): what it would do, answered on this computer only. `state`: `pending`,
    /// `accepted`, `rejected`, `failed`, or `info` for a read-only card (the portfolio). Not a confirmation of the
    /// phone protocol: the phone sees an item kind it does not know, and cannot answer it.
    Pool { card: String, view: Value, state: &'static str },
}

struct Item {
    id: String,
    at: u64,
    content: Content,
}

enum Phase {
    Waiting(Pending),
    Running,
    Done,
    Stopped,
}

/// Where a free research is.
#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Open,
    Propose,
    Steps,
    Result,
    Exposure,
    Answered,
}

struct ResearchRun {
    question: String,
    /// The NEAR accounts the person allows to be paid (`payees.txt`), sent with `research_open`.
    payees: Vec<String>,
    stage: Stage,
    /// Accepted queries, searched ones, sources found (handle, site), pages read or skipped: for the working label.
    queries: usize,
    searched: usize,
    sources: Vec<(String, String)>,
    read: usize,
    /// The action index prepared in ona-core, waiting for its confirmation.
    prepared: Option<usize>,
}

/// What a conversation runs.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Research,
    /// The lawyer mission, reachable from the tests only.
    #[cfg_attr(not(test), allow(dead_code))]
    Mission,
}

/// Where a pool request of a chat is (`pool_chat`, docs/desktop/tauri.md "Pool requests in the chat").
#[derive(Clone, Copy, Debug, PartialEq)]
enum PoolStage {
    /// `pool_info`: the vaults (kind, target), the cash tiers and cap, the recommended deposits.
    Info,
    /// `pool_privacy` with the amount: how many notes the entry would blend in with.
    Privacy,
    /// `pool_prepare`, to show its summary on the card (and refuse at once what ona-core refuses).
    CardPrepare,
    /// The card waits for Yes or No.
    Card,
    /// After Yes: `pool_prepare` again, for a fresh 5 minutes.
    Prepare,
    /// The deposit is in the person's wallet, on the wallet page in the browser.
    Wallet,
    /// The cash issue was queued by the agent: `pool_recover` from time to time until the cash notes are signed.
    Recover,
    EnterPrepare,
    EnterExecute,
    /// A cash payout to the connected account, after Yes.
    Execute,
    /// A cash entry or a switch: `pool_privacy` with the value the card's preparation enters, before the card.
    MovePrivacy,
    Portfolio,
    PortfolioPrivacy,
    Done,
}

/// How many `pool_recover` a queued cash issue gets before the chat hands over to the Pool screen, and how many ticks
/// (1.5 s each) between two: about four minutes in all.
const RECOVER_TRIES: u32 = 40;
const RECOVER_PAUSE: u32 = 3;
/// The deposit's preparation lives 5 minutes (ona-core); a little more before the chat says the wallet step is over.
const WALLET_WAIT_SECS: u64 = 330;

struct PoolFlow {
    card: String,
    intent: Intent,
    stage: PoolStage,
    /// The connected wallet's account when the request was read: the depositing account, and the only payout account.
    account: Option<String>,
    amount: u128,
    vault: Option<u32>,
    mode: String,
    info: Value,
    privacy: Value,
    portfolio: Value,
    prepared_id: Option<String>,
    pause: u32,
    recover_left: u32,
    wallet_since: u64,
    /// The first `pool_execute` of the deposit ran (the wallet page reported the deposit sent).
    deposit_seen: bool,
    /// How many cash notes this deposit issues (its `cash_notes`): a queued cash issue counts as done only once
    /// `pool_recover` has brought back as many signatures.
    issue_count: u64,
    /// Signatures `pool_recover` brought back since the cash issue was queued.
    recovered: u64,
    /// The entry's storage fee the card showed (one `NOTE_STORAGE_FEE` per cash note): an entry prepared with another
    /// fee, or leaving money in the pool's cash, is not run without the person.
    entry_fee: Option<u128>,
    /// The card waiting is the second one, for an entry that differs from the first card (Yes runs `prepared_id`).
    entry_card: bool,
    /// An operation on notes already in the pool for everything there ("my cash"): `amount` is then 0.
    all: bool,
    /// The vault a switch or a leave starts from.
    from: Option<u32>,
    /// The `pool_prepare` summary a cash entry, switch or leave card shows (its `prepared_id` runs on Yes).
    summary: Value,
}

impl PoolFlow {
    /// A cash entry, a switch or a leave: notes already in the pool, signed by ONA with their own keys on Yes.
    fn moves_notes(&self) -> bool {
        matches!(self.intent, Intent::Enter { .. } | Intent::Switch { .. } | Intent::Leave { .. })
    }

    /// The amount sent to `pool_prepare`: yoctoNEAR, or "all".
    fn amount_arg(&self) -> String {
        if self.all { "all".into() } else { self.amount.to_string() }
    }
}

impl PoolFlow {
    /// Stages the engine's tick moves on (the card waits for the person; the wallet stage only watches the clock).
    fn ticking(&self) -> bool {
        !matches!(self.stage, PoolStage::Card | PoolStage::Done)
    }
}

/// A deposit the worker opens on the wallet page: (chat, card, `pool_prepare` reply).
pub type WalletRequest = (String, String, Value);

struct Run {
    core: CoreThread,
    /// The run's number in its chat: an action item belongs to one run.
    serial: u64,
    /// Some for a free research; None for the lawyer mission.
    research: Option<ResearchRun>,
    /// The person's request, sent to ona-core with `open`.
    mission: String,
    opened: bool,
    plan: Vec<String>,
    cursor: usize,
    phase: Phase,
    handles: Vec<String>,
    read_count: usize,
    ranked: Vec<Value>,
    chosen: Option<String>,
}

pub struct Chat {
    pub id: String,
    pub title: String,
    pub updated_at: u64,
    items: Vec<Item>,
    decisions: Vec<(String, &'static str)>,
    run: Option<Run>,
    /// The pool request of this chat, if one was typed here.
    pool: Option<PoolFlow>,
    kind: Kind,
    runs: u64,
    item_count: u32,
    /// Creation order, to sort chats updated in the same second.
    order: u64,
}

impl Chat {
    pub fn status(&self) -> &'static str {
        if let Some(flow) = self.pool.as_ref().filter(|f| f.stage != PoolStage::Done) {
            return if matches!(flow.stage, PoolStage::Card | PoolStage::Wallet) { "waiting" } else { "working" };
        }
        match self.run.as_ref().map(|r| &r.phase) {
            Some(Phase::Waiting(_)) => "waiting",
            Some(Phase::Running) => "working",
            _ => "idle",
        }
    }

    pub fn pending(&self) -> Option<&Pending> {
        match self.run.as_ref().map(|r| &r.phase) {
            Some(Phase::Waiting(p)) => Some(p),
            _ => None,
        }
    }

    fn state_of(&self, pending: &Pending) -> &'static str {
        if self.pending().is_some_and(|p| p.id == pending.id) {
            return "pending";
        }
        self.decisions.iter().find(|(id, _)| *id == pending.id).map(|(_, s)| *s).unwrap_or("expired")
    }

    fn working(&self) -> Option<(String, &'static str)> {
        if let Some(flow) = self.pool.as_ref().filter(|f| f.ticking() && f.stage != PoolStage::Wallet) {
            return Some(("pool".into(), match flow.stage {
                PoolStage::Prepare | PoolStage::CardPrepare | PoolStage::MovePrivacy => "Preparing with the pool…",
                PoolStage::Recover => "Waiting for the pool agent's cash notes…",
                PoolStage::EnterPrepare | PoolStage::EnterExecute => "Entering the vault…",
                PoolStage::Execute => "Sending the payout to the pool agent…",
                PoolStage::Portfolio | PoolStage::PortfolioPrivacy => "Reading your portfolio…",
                _ => "Reading the pool…",
            }));
        }
        let run = self.run.as_ref()?;
        if !matches!(run.phase, Phase::Running) {
            return None;
        }
        if let Some(r) = &run.research {
            return Some(match r.stage {
                Stage::Open | Stage::Propose => ("think".into(), "Choosing the searches…"),
                Stage::Steps if r.searched < r.queries => ("search".into(), "Searching…"),
                Stage::Steps if r.read < r.sources.len() => ("read".into(), "Reading a page…"),
                _ => ("think".into(), "Writing the answer…"),
            });
        }
        if run.plan.is_empty() {
            return Some(("think".into(), "Preparing a plan…"));
        }
        let tool = run.plan.get(run.cursor)?;
        running_label(tool).map(|text| (tool.clone(), text))
    }

    pub fn preview(&self) -> String {
        self.items.iter().rev().find_map(|item| match &item.content {
            Content::User(t) | Content::Agent(t) => Some(t.clone()),
            _ => None,
        }).unwrap_or_default()
    }

    fn add(&mut self, content: Content) {
        self.item_count += 1;
        self.updated_at = now();
        self.items.push(Item { id: format!("{}-i-{}", self.id, self.item_count), at: self.updated_at, content });
    }

    fn decide(&mut self, id: &str, state: &'static str) {
        self.decisions.push((id.to_owned(), state));
        self.updated_at = now();
    }
}

pub struct ChatEngine {
    chats: Vec<Chat>,
    /// Mode of the model behind ona-core: "mock" while the model is the fake.
    pub mode: String,
    make_core: CoreFactory,
    /// Makes the pool's core (`pool.json`).
    make_pool_core: CoreFactory,
    count: u64,
    /// One core for the pool, on its own thread, made on first use: it holds the wallet file's lock.
    pool: Option<CoreThread>,
    /// The NEAR accounts the person allows a research to pay (`payees.txt` in the data folder). Empty: only the
    /// demo directory's accounts can be paid.
    pub payees: Vec<String>,
    /// The account of the NEAR wallet the person connected on the wallet page: the depositing account of a pool
    /// request typed in the chat, and the only account its payouts go to. ONA never holds this wallet's keys.
    pub wallet_account: Option<String>,
    /// Deposits of chat pool requests, for the worker to open on the wallet page.
    wallet_requests: Vec<WalletRequest>,
}

impl ChatEngine {
    pub fn new(make_core: impl Fn() -> Box<dyn MissionCore> + Send + Sync + 'static) -> Self {
        let make_core: CoreFactory = Arc::new(make_core);
        Self {
            chats: Vec::new(), mode: "mock".into(), make_pool_core: make_core.clone(), make_core, count: 0, pool: None,
            payees: Vec::new(), wallet_account: None, wallet_requests: Vec::new(),
        }
    }

    /// ona-core cores, with the fake model or the real one as `setup` says when each core is made.
    pub fn with_ona_core(setup: crate::real::SharedSetup) -> Self {
        let pool_setup = setup.clone();
        let mut engine = Self::new(move || match setup.lock() {
            Ok(setup) => crate::real::make_core(&setup),
            Err(_) => crate::real::make_core(&crate::real::CoreSetup::default()),
        });
        engine.make_pool_core = Arc::new(move || match pool_setup.lock() {
            Ok(setup) => crate::real::make_pool_core(&setup),
            Err(_) => crate::real::make_pool_core(&crate::real::CoreSetup::default()),
        });
        engine
    }

    /// Drops the pool's core, so that the next pool command makes a new one: when tor becomes ready or stops.
    pub fn reset_pool(&mut self) {
        self.pool = None;
    }

    /// Where the window sends its pool commands, answered on the pool's own thread: the window waits for the reply
    /// there, not on the worker thread.
    pub fn pool_sender(&mut self) -> Sender<(Value, Sender<Value>)> {
        let factory = &self.make_pool_core;
        self.pool.get_or_insert_with(|| CoreThread::spawn(factory)).requests.clone()
    }

    fn sorted(&self) -> Vec<&Chat> {
        let mut chats: Vec<&Chat> = self.chats.iter().collect();
        chats.sort_by_key(|c| std::cmp::Reverse((c.updated_at, c.order)));
        chats
    }

    fn chat_mut(&mut self, id: &str) -> Option<&mut Chat> {
        self.chats.iter_mut().find(|c| c.id == id)
    }

    // Requests (from the phone or this computer)

    /// A new conversation from the phone: a free research on `text`.
    pub fn create(&mut self, text: &str) -> Result<String, ProtocolError> {
        self.open_chat(text, Kind::Research, false)
    }

    /// A new conversation typed in this window: a pool request (`pool_chat`) if it reads as one, else a free research.
    pub fn create_here(&mut self, text: &str) -> Result<String, ProtocolError> {
        self.open_chat(text, Kind::Research, true)
    }

    /// A new conversation running the lawyer mission (kept for its tests).
    #[cfg(test)]
    pub fn create_mission(&mut self, text: &str) -> Result<String, ProtocolError> {
        self.open_chat(text, Kind::Mission, false)
    }

    fn open_chat(&mut self, text: &str, kind: Kind, here: bool) -> Result<String, ProtocolError> {
        let text = clean(text).ok_or(ProtocolError::BadText)?;
        self.count += 1;
        // Random, never reused: an old signed request cannot target a new chat that took the same id.
        let id = format!("chat-{}", protocol::random_hex16());
        self.chats.push(Chat {
            id: id.clone(), title: title(&text), updated_at: now(), items: Vec::new(), decisions: Vec::new(),
            run: None, pool: None, kind, runs: 0, item_count: 0, order: self.count,
        });
        self.say(&text, &id, here);
        Ok(id)
    }

    /// A message from the phone: always a free research (pool operations are never asked or confirmed there).
    pub fn post(&mut self, text: &str, chat_id: &str) -> Result<(), ProtocolError> {
        self.post_from(text, chat_id, false)
    }

    /// A message typed in this window: a pool request if it reads as one, else a free research.
    pub fn post_here(&mut self, text: &str, chat_id: &str) -> Result<(), ProtocolError> {
        self.post_from(text, chat_id, true)
    }

    fn post_from(&mut self, text: &str, chat_id: &str, here: bool) -> Result<(), ProtocolError> {
        let text = clean(text).ok_or(ProtocolError::BadText)?;
        self.chat_mut(chat_id).ok_or(ProtocolError::UnknownChat)?;
        self.say(&text, chat_id, here);
        Ok(())
    }

    pub fn delete(&mut self, chat_id: &str) -> Result<(), ProtocolError> {
        let before = self.chats.len();
        self.chats.retain(|c| c.id != chat_id);
        if self.chats.len() == before { Err(ProtocolError::UnknownChat) } else { Ok(()) }
    }

    /// The content digest of a confirmation still pending (what the phone must have signed).
    pub fn pending_content(&self, id: &str) -> Option<String> {
        self.chats.iter().find_map(|c| c.pending().filter(|p| p.id == id)).map(Pending::content)
    }

    /// A decision on a pending confirmation. Returns an error code on refusal. Queries are accepted as shown.
    pub fn confirm(&mut self, id: Option<&str>, decision: Option<&str>, firm: Option<&str>, digest: Option<&str>)
                   -> Result<(), String> {
        self.decide_pending(id, decision, firm, digest, None)
    }

    /// The research queries accepted on this computer, possibly edited: they are what leaves, as written.
    pub fn accept_queries(&mut self, id: &str, queries: Vec<String>) -> Result<(), String> {
        self.decide_pending(Some(id), Some("accept"), None, None, Some(queries))
    }

    fn decide_pending(&mut self, id: Option<&str>, decision: Option<&str>, firm: Option<&str>, digest: Option<&str>,
                      edited: Option<Vec<String>>) -> Result<(), String> {
        let stale = || ProtocolError::Stale.code().to_owned();
        let bad = || ProtocolError::BadRequest.code().to_owned();
        let id = id.ok_or_else(stale)?;
        let chat = self.chats.iter_mut().find(|c| c.pending().is_some_and(|p| p.id == id)).ok_or_else(stale)?;
        let pending = chat.pending().cloned().ok_or_else(stale)?;
        match decision {
            Some("reject") => {
                chat.decide(id, "rejected");
                finish(chat, true);
                return Ok(());
            }
            Some("accept") => {}
            _ => return Err(bad()),
        }
        let run = chat.run.as_mut().ok_or_else(stale)?;
        let reply = match &pending.request {
            Request::Plan(_) => run.core.call(json!({"cmd": "accept_plan"})),
            Request::Recipient(_) => {
                let firm = firm.ok_or_else(bad)?;
                let reply = run.core.call(json!({"cmd": "confirm_recipient", "firm": firm}));
                if ok(&reply) {
                    run.chosen = Some(firm.to_owned());
                }
                reply
            }
            // ona-core's gate checks the digest against the payment it prepared.
            Request::Payment { .. } => {
                let digest = digest.ok_or_else(bad)?;
                run.core.call(json!({"cmd": "confirm_payment", "digest": digest}))
            }
            Request::Queries(shown) => {
                let queries = edited.unwrap_or_else(|| shown.clone());
                run.core.call(json!({"cmd": "research_accept", "queries": queries}))
            }
        };
        if !ok(&reply) {
            return Err(reply["error"].as_str().map(String::from).unwrap_or_else(bad));
        }
        if matches!(pending.request, Request::Recipient(_) | Request::Payment { .. }) {
            run.cursor += 1;
        }
        if let (Request::Queries(shown), Some(research)) = (&pending.request, run.research.as_mut()) {
            let accepted: Vec<String> = reply["accepted"].as_array()
                .map(|a| a.iter().filter_map(|q| q.as_str().map(String::from)).collect()).unwrap_or_default();
            research.queries = accepted.len();
            research.stage = Stage::Steps;
            run.phase = Phase::Running;
            if accepted != *shown {
                let list: Vec<String> = accepted.iter().map(|q| format!("“{q}”")).collect();
                chat.add(Content::Activity { tool: "think".into(),
                                             text: format!("Searches edited on the computer: {}", list.join(", ")) });
            }
            chat.decide(id, "accepted");
            return Ok(());
        }
        run.phase = Phase::Running;
        chat.decide(id, "accepted");
        Ok(())
    }

    // Progress

    /// Advances every working chat by one step. Called on a timer.
    pub fn tick(&mut self) {
        for chat in &mut self.chats {
            if chat.run.as_ref().is_some_and(|r| matches!(r.phase, Phase::Running)) {
                if let Some(mode) = step(chat) {
                    self.mode = mode;
                }
            }
        }
        self.tick_pool(None);
    }

    /// Moves the chats' pool requests on by one pool command each (all of them, or `only` this chat).
    fn tick_pool(&mut self, only: Option<&str>) {
        let Self { chats, pool, make_pool_core, wallet_requests, .. } = self;
        let ticking = |c: &Chat| only.is_none_or(|id| c.id == id) && c.pool.as_ref().is_some_and(PoolFlow::ticking);
        if !chats.iter().any(ticking) {
            return;
        }
        let core = pool.get_or_insert_with(|| CoreThread::spawn(make_pool_core));
        for chat in chats.iter_mut().filter(|c| ticking(c)) {
            step_pool(chat, core, wallet_requests);
        }
    }

    fn say(&mut self, text: &str, chat_id: &str, here: bool) {
        let make_core = &self.make_core;
        let payees = self.payees.clone();
        let account = self.wallet_account.clone();
        let Some(chat) = self.chats.iter_mut().find(|c| c.id == chat_id) else { return };
        chat.add(Content::User(text.to_owned()));
        if chat.run.as_ref().is_some_and(|r| matches!(r.phase, Phase::Running | Phase::Waiting(_)))
            || chat.pool.as_ref().is_some_and(|f| f.stage != PoolStage::Done)
        {
            chat.add(Content::Agent(BUSY_MESSAGE.into()));
            return;
        }
        // Typed here and read as a pool request: no model, no research (pool_chat).
        if let Some(intent) = here.then(|| pool_chat::parse(text)).flatten().filter(|_| chat.kind == Kind::Research) {
            if start_pool(chat, intent, account) {
                self.tick_pool(Some(chat_id));
            }
            return;
        }
        // A new core for every mission: the previous one (closed, or stopped by an error or a panic) is dropped.
        chat.runs += 1;
        let research = (chat.kind == Kind::Research).then(|| ResearchRun {
            question: text.to_owned(), payees, stage: Stage::Open, queries: 0, searched: 0, sources: Vec::new(), read: 0,
            prepared: None,
        });
        chat.run = Some(Run {
            core: CoreThread::spawn(make_core), serial: chat.runs, research, mission: text.to_owned(), opened: false,
            plan: Vec::new(), cursor: 0, phase: Phase::Running, handles: Vec::new(), read_count: 0, ranked: Vec::new(),
            chosen: None,
        });
        // The first step at once: with the fake model, the plan is there before this request returns.
        if let Some(mode) = step(chat) {
            self.mode = mode;
        }
        self.tick_chat(chat_id);
    }

    fn tick_chat(&mut self, chat_id: &str) {
        let Some(chat) = self.chats.iter_mut().find(|c| c.id == chat_id) else { return };
        if chat.run.as_ref().is_some_and(|r| matches!(r.phase, Phase::Running)) {
            if let Some(mode) = step(chat) {
                self.mode = mode;
            }
        }
    }

    // Actions of a free research: on this computer only, never from the phone (docs/research.md, step 5)

    /// The answered research of a chat, with its suggested action `index` still to do.
    fn action_run(&mut self, chat_id: &str, index: u64) -> Result<&mut Chat, String> {
        let chat = self.chat_mut(chat_id).ok_or_else(|| ProtocolError::UnknownChat.code().to_owned())?;
        let run = chat.run.as_ref().filter(|r| r.research.as_ref().is_some_and(|r| r.stage == Stage::Answered))
            .ok_or("this search is no longer running: the action is no longer available")?;
        let serial = run.serial;
        let suggested = chat.items.iter().any(|item| matches!(&item.content,
            Content::Action { run, action, done: false } if *run == serial && action["index"].as_u64() == Some(index)));
        if !suggested {
            return Err("this action is no longer available".into());
        }
        Ok(chat)
    }

    /// The person's recipient for a suggested action: ona-core returns the exact action (`kind`, `to`, `content`), its
    /// `digest`, and `seen_in_pages` when that recipient is also written in a page read.
    pub fn action_prepare(&mut self, chat_id: &str, index: u64, to: &str) -> Result<Value, String> {
        let chat = self.action_run(chat_id, index)?;
        let Some(run) = chat.run.as_mut() else { return Err("no research".into()) };
        let reply = run.core.call(json!({"cmd": "research_action_prepare", "index": index, "to": to}));
        if !ok(&reply) {
            return Err(error_of(&reply));
        }
        if let Some(research) = run.research.as_mut() {
            research.prepared = usize::try_from(index).ok();
        }
        let mut view = reply;
        if let Some(object) = view.as_object_mut() {
            object.remove("ok");
            object.remove("mode");
        }
        Ok(view)
    }

    /// Confirms the prepared action by its digest, then carries it out once. A message comes back with its `mailto`
    /// (the caller opens it in the person's mail program); a payment with its `tx`. The action item is then `done` and
    /// the exposure report is read again.
    pub fn action_do(&mut self, chat_id: &str, digest: &str) -> Result<Value, String> {
        let chat = self.chat_mut(chat_id).ok_or_else(|| ProtocolError::UnknownChat.code().to_owned())?;
        let index = chat.run.as_ref().and_then(|r| r.research.as_ref()).and_then(|r| r.prepared)
            .ok_or("no action prepared")? as u64;
        let chat = self.action_run(chat_id, index)?;
        let Some(run) = chat.run.as_mut() else { return Err("no research".into()) };
        let confirmed = run.core.call(json!({"cmd": "research_action_confirm", "digest": digest}));
        if !ok(&confirmed) {
            return Err(error_of(&confirmed));
        }
        let mut done = run.core.call(json!({"cmd": "research_action_do"}));
        if !ok(&done) {
            return Err(error_of(&done));
        }
        if let Some(research) = run.research.as_mut() {
            research.prepared = None;
        }
        let exposure = without_ok(run.core.call(json!({"cmd": "research_exposure"})));
        let serial = run.serial;
        for item in &mut chat.items {
            if let Content::Action { run, action, done } = &mut item.content {
                if *run == serial && action["index"].as_u64() == Some(index) {
                    *done = true;
                }
            }
        }
        // The report at the end of the chat now counts the action too.
        if let Some(item) = chat.items.iter_mut().rev().find(|i| matches!(i.content, Content::Exposure(_))) {
            item.content = Content::Exposure(exposure);
        }
        let text = match done["done"].as_str() {
            Some("payment") => format!("Payment sent: {}", done["tx"].as_str().unwrap_or("?")),
            _ => "Message opened in your mail app: it is up to you to send it".to_owned(),
        };
        chat.add(Content::Activity { tool: "action".into(), text });
        if let Some(object) = done.as_object_mut() {
            object.remove("ok");
        }
        Ok(done)
    }

    // JSON views for the phone (protocol-draft.md, "Conversations")

    /// The pool portfolio for the phone, read only: ona-core's `pool_portfolio` (cash, shares per vault, total). Err
    /// with ona-core's error, for instance `no pool wallet configured`. Pool operations are confirmed on the computer.
    pub fn pool_portfolio(&mut self) -> Result<Value, String> {
        let factory = &self.make_pool_core;
        let core = self.pool.get_or_insert_with(|| CoreThread::spawn(factory));
        let mut reply = core.call(json!({"cmd": "pool_portfolio"}));
        if reply["ok"] != true {
            return Err(reply["error"].as_str().unwrap_or("pool unavailable").to_owned());
        }
        let mode = reply["mode"].as_str().unwrap_or("mock").to_owned();
        if let Some(object) = reply.as_object_mut() {
            object.remove("ok");
            object.remove("mode");
        }
        Ok(json!({"mode": mode, "portfolio": reply}))
    }

    // Pool requests typed in the chat (pool_chat): decided on this computer only, never by the phone.

    /// Yes or No on a pool card. Yes prepares the operation again (a preparation lives 5 minutes): a deposit then goes
    /// to the person's wallet on the wallet page, a payout to the pool agent. Refused if the connected wallet changed
    /// since the card was made.
    pub fn pool_decide(&mut self, chat_id: &str, card: &str, accept: bool) -> Result<(), String> {
        let account = self.wallet_account.clone();
        let chat = self.chat_mut(chat_id).ok_or_else(|| ProtocolError::UnknownChat.code().to_owned())?;
        let flow = chat.pool.as_mut().filter(|f| f.card == card && f.stage == PoolStage::Card)
            .ok_or("this pool request is no longer waiting for an answer")?;
        if !accept {
            flow.stage = PoolStage::Done;
            let message = if flow.moves_notes() {
                "Not done: nothing was sent. The notes this card would have used stay reserved for up to 5 minutes by its \
                 preparation, then are free again."
            } else if flow.entry_card {
                "Not put into the vault. Your cash notes stay in your pool wallet (reserved for 5 minutes by the \
                 preparation, then free again in the Pool screen)."
            } else {
                "Cancelled: nothing was sent and nothing was signed."
            };
            set_card_state(chat, card, "rejected");
            chat.add(Content::Agent(message.into()));
            return Ok(());
        }
        if flow.account.is_some() && flow.account != account {
            return Err("the connected wallet changed since this card was made: ask again".into());
        }
        // A second entry card, or a cash entry, switch or leave: Yes runs the very preparation the card showed (within
        // its 5 minutes). A deposit or a payout is prepared again.
        flow.stage = if std::mem::take(&mut flow.entry_card) {
            PoolStage::EnterExecute
        } else if flow.moves_notes() {
            PoolStage::Execute
        } else {
            PoolStage::Prepare
        };
        set_card_state(chat, card, "accepted");
        self.tick_pool(Some(chat_id));
        Ok(())
    }

    /// The deposits of chat pool requests to open on the wallet page (the worker does, then calls `pool_wallet_opened`).
    pub fn take_wallet_requests(&mut self) -> Vec<WalletRequest> {
        std::mem::take(&mut self.wallet_requests)
    }

    /// The wallet page was opened (its address), or could not be.
    pub fn pool_wallet_opened(&mut self, chat_id: &str, card: &str, opened: Result<String, String>) {
        let Some(chat) = self.chat_mut(chat_id) else { return };
        let Some(flow) = chat.pool.as_mut().filter(|f| f.card == card && f.stage == PoolStage::Wallet) else { return };
        let account = flow.account.clone().unwrap_or_default();
        match opened {
            Ok(url) => chat.add(Content::Activity { tool: "pool".into(), text: format!(
                "Your wallet page is open in the browser. Connect your wallet as {account} if it asks, confirm the \
                 deposit transaction, then sign the pool agent's message. If no page opened: {url}") }),
            Err(error) => pool_fail(chat, &format!("the wallet page could not be opened: {error}")),
        }
    }

    /// The person cancelled the wallet page's deposit before it was sent.
    pub fn pool_wallet_cancelled(&mut self, chat_id: &str, card: &str) {
        let Some(chat) = self.chat_mut(chat_id) else { return };
        if chat.pool.as_ref().is_some_and(|f| f.card == card && f.stage == PoolStage::Wallet) {
            pool_fail(chat, "the deposit was cancelled before it was sent: nothing was taken");
        }
    }

    /// A step of the wallet page for a chat's deposit: `second` false for the first `pool_execute` (after the wallet
    /// sent the deposit), true for the second (after it signed the agent's message); `reply` is ona-core's reply.
    pub fn pool_wallet_step(&mut self, chat_id: &str, card: &str, second: bool, reply: &Value) {
        let Some(chat) = self.chat_mut(chat_id) else { return };
        let Some(flow) = chat.pool.as_mut().filter(|f| f.card == card && f.stage == PoolStage::Wallet) else { return };
        let label = mock_label(reply);
        let pool = |text: String| Content::Activity { tool: "pool".into(), text };
        if !second {
            if !ok(reply) {
                return pool_fail(chat, &format!("the first deposit step was refused: {}", error_of(reply)));
            }
            flow.deposit_seen = true;
            chat.add(pool(format!(
                "Deposit reported sent by your wallet page (the app does not read the transaction itself). Your cash \
                 notes are made and saved on this computer{label}. Next: sign the pool agent's message in your wallet.")));
            return;
        }
        let queued = !ok(reply) && error_of(reply).contains("outcome unknown");
        if !ok(reply) && !queued {
            return pool_fail(chat, &format!("the pool agent refused the cash issue: {}", error_of(reply)));
        }
        let into_vault = flow.vault.is_some();
        let amount = near_text(flow.amount);
        flow.stage = match (queued, into_vault) {
            (true, true) => PoolStage::Recover,
            (false, true) => PoolStage::EnterPrepare,
            (_, false) => PoolStage::Done,
        };
        flow.recover_left = RECOVER_TRIES;
        flow.pause = 0;
        if queued {
            chat.add(pool("Cash issue sent to the pool agent; its answer did not come back yet.".into()));
            if !into_vault {
                chat.add(Content::Agent("The cash notes will appear once the agent answers: use “Recover pending \
                                         operations” in the Pool screen.".into()));
            }
            return;
        }
        let issued = reply["steps"].as_array().and_then(|s| s.iter().find_map(|s| s["issued_cash"].as_u64()));
        let notes = issued.map(|n| plural(n as usize, "cash note")).unwrap_or_else(|| "the cash notes".into());
        chat.add(pool(format!("Cash issued: the pool agent signed {notes} worth {amount}{label}.")));
        if !into_vault {
            chat.add(Content::Agent(format!("Done: {amount} is now cash notes in your pool wallet.")));
        }
    }

    pub fn list_json(&self) -> Value {
        let chats: Vec<Value> = self.sorted().iter().map(|c| json!({
            "id": c.id, "title": c.title, "updated_at": c.updated_at, "preview": c.preview(), "status": c.status(),
        })).collect();
        json!({"mode": self.mode, "chats": chats})
    }

    pub fn chat_json(&self, id: &str) -> Option<Value> {
        let chat = self.chats.iter().find(|c| c.id == id)?;
        let items: Vec<Value> = chat.items.iter().map(|item| {
            let mut view = json!({"id": item.id, "at": item.at});
            let fields = match &item.content {
                Content::User(text) => json!({"kind": "user", "text": text}),
                Content::Agent(text) => json!({"kind": "agent", "text": text}),
                Content::Activity { tool, text } => json!({"kind": "activity", "tool": tool, "text": text}),
                Content::Confirmation(p) => json!({"kind": "confirmation", "pending": p.json(), "state": chat.state_of(p)}),
                Content::Exposure(exposure) => json!({"kind": "exposure", "exposure": exposure}),
                Content::Answer(answer) => {
                    let mut view = answer.clone();
                    view["kind"] = json!("answer");
                    view
                }
                Content::Action { action, done, .. } =>
                    json!({"kind": "action", "action": action, "state": if *done { "done" } else { "suggested" }}),
                Content::Pool { view, state, .. } => json!({"kind": "pool", "card": view, "state": state}),
            };
            if let (Some(view), Some(fields)) = (view.as_object_mut(), fields.as_object()) {
                view.extend(fields.clone());
            }
            view
        }).collect();
        let working = chat.working().map(|(tool, text)| json!({"tool": tool, "text": text})).unwrap_or(Value::Null);
        Some(json!({
            "mode": self.mode,
            "chat": {"id": chat.id, "title": chat.title, "status": chat.status(), "items": items, "working": working},
        }))
    }
}

/// Moves a working mission on by one command, when ona-core has answered the previous one. Returns ona-core's mode once
/// the mission is open.
fn step(chat: &mut Chat) -> Option<String> {
    let run = chat.run.as_mut()?;
    if run.research.is_some() {
        return step_research(chat);
    }
    if !run.opened {
        let opened = run.core.poll(json!({"cmd": "open", "mission": run.mission}))?;
        if !ok(&opened) {
            fail(chat, &error_of(&opened));
            return None;
        }
        run.opened = true;
        chat.add(Content::Activity { tool: "think".into(), text: "Reading your request and preparing a plan".into() });
        return opened["mode"].as_str().map(String::from);
    }
    if run.plan.is_empty() {
        let proposal = run.core.poll(json!({"cmd": "propose_plan"}))?;
        let plan: Option<Vec<String>> = proposal["plan"].as_array()
            .map(|steps| steps.iter().filter_map(|s| s.as_str().map(String::from)).collect());
        match plan {
            Some(plan) if ok(&proposal) && !plan.is_empty() => {
                run.plan = plan.clone();
                chat.add(Content::Agent(PLAN_MESSAGE.replace("{}", &plan.len().to_string())));
                wait(chat, Request::Plan(plan));
            }
            _ => fail(chat, &error_of(&proposal)),
        }
        return None;
    }
    advance(chat);
    None
}

fn advance(chat: &mut Chat) {
    let Some(run) = chat.run.as_mut() else { return };
    let Some(tool) = run.plan.get(run.cursor).cloned() else { return finish(chat, false) };
    let activity = |text: String| Content::Activity { tool: tool.clone(), text };
    let content = match tool.as_str() {
        "search" => {
            let Some(reply) = run.core.poll(json!({"cmd": "search", "template": "lawyer", "value": "paris"})) else { return };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            run.handles = reply["handles"].as_array().map(|h| h.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default();
            activity(format!("Search “employment lawyer paris”: {}", plural(run.handles.len(), "result")))
        }
        "read" => {
            let Some(handle) = run.handles.get(run.read_count).cloned() else { return fail(chat, "no page left to read") };
            let Some(reply) = run.core.poll(json!({"cmd": "read", "handle": handle})) else { return };
            run.read_count += 1;
            let offer = &reply["offer"];
            let (Some(firm), Some(price), Some(delay)) = (offer["firm_id"].as_str(), offer["price_cents"].as_i64(), offer["delay_days"].as_i64())
            else { return fail(chat, &error_of(&reply)) };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            activity(format!("Read a page: {firm}, €{}, within {}", price / 100, plural(delay as usize, "day")))
        }
        "compare" => {
            let Some(reply) = run.core.poll(json!({"cmd": "compare"})) else { return };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            run.ranked = reply["ranked"].as_array().cloned().unwrap_or_default();
            activity(format!("Comparison: {} ranked", plural(run.ranked.len(), "offer")))
        }
        "confirm_recipient" => {
            let ranked = run.ranked.clone();
            chat.add(Content::Agent(RECIPIENT_MESSAGE.replace("{}", &plural(ranked.len(), "offer"))));
            return wait(chat, Request::Recipient(ranked));
        }
        "contact" => {
            let Some(reply) = run.core.poll(json!({"cmd": "contact", "message": CONTACT_MESSAGE})) else { return };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            activity(format!("Generic message sent to {}", run.chosen.as_deref().unwrap_or("?")))
        }
        "prepare_payment" => {
            // No amount: ona-core computes it from the chosen offer's price and the policy's rate.
            let Some(reply) = run.core.poll(json!({"cmd": "prepare_payment"})) else { return };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            let request = match read_prepared_payment(&reply) {
                Ok(request) => request,
                Err(error) => return fail(chat, &error),
            };
            run.cursor += 1;
            let next_is_confirmation = run.plan.get(run.cursor).is_some_and(|t| t == "confirm_payment");
            chat.add(activity("Payment prepared from the directory".into()));
            if next_is_confirmation {
                chat.add(Content::Agent(PAYMENT_MESSAGE.into()));
                wait(chat, request);
            }
            return;
        }
        "confirm_payment" => return fail(chat, "payment confirmation without a prepared payment"),
        "pay" => {
            let Some(reply) = run.core.poll(json!({"cmd": "pay"})) else { return };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            activity(format!("Payment sent: {}", reply["tx"].as_str().unwrap_or("?")))
        }
        other => return fail(chat, &format!("unknown step {other}")),
    };
    run.cursor += 1;
    chat.add(content);
}

const CONNECT_FIRST: &str = "Connect your NEAR wallet first: click “Connect wallet” in the sidebar, choose your wallet \
    (Meteor, for example) on the page that opens in your browser, then ask again. ONA never holds your wallet's keys.";

/// Starts a pool request read by `pool_chat`. False when it cannot start (no wallet connected for a deposit or a
/// payout): the chat says why.
fn start_pool(chat: &mut Chat, intent: Intent, account: Option<String>) -> bool {
    let (amount, what) = match &intent {
        Intent::Deposit { amount, vault } => (*amount, format!("deposit {} from your wallet{}", near_text(*amount), match vault {
            Some(VaultRef::Index(i)) => format!(", then put it into vault {i}"),
            Some(VaultRef::Kind(kind)) => format!(", then put it into the {kind} vault"),
            Some(VaultRef::Any) => ", then put it into a vault".into(),
            None => " as cash notes".into(),
        })),
        Intent::Withdraw { amount } => (*amount, format!("pay {} of your pool cash out to your account", near_text(*amount))),
        Intent::Portfolio => (0, "show your pool portfolio".into()),
        Intent::Enter { amount, vault } => (near_of(amount), format!("put {} into {}", amount_words(amount, "your cash"), vault_words(vault))),
        Intent::Switch { from, to, amount } => (near_of(amount), format!("move {} from {} to {}",
            amount_words(amount, "your shares"), vault_words(from), vault_words(to))),
        Intent::Leave { from, amount } => (near_of(amount), format!("turn {} of {} into cash, kept in the pool",
            amount_words(amount, "your shares"), vault_words(from))),
        Intent::Ask(_) => (0, "answer from your pool's figures, read on this computer".into()),
    };
    let all = matches!(&intent, Intent::Enter { amount: Amount::All, .. } | Intent::Switch { amount: Amount::All, .. }
                                | Intent::Leave { amount: Amount::All, .. });
    // Only a deposit and a payout involve the person's wallet account.
    if matches!(intent, Intent::Deposit { .. } | Intent::Withdraw { .. }) && account.is_none() {
        chat.add(Content::Agent(CONNECT_FIRST.into()));
        return false;
    }
    chat.add(Content::Activity { tool: "pool".into(),
                                 text: format!("Pool request read on this computer, without the model: {what}.") });
    chat.pool = Some(PoolFlow {
        card: format!("p-{}", protocol::random_hex16()), intent, stage: PoolStage::Info, account, amount, vault: None,
        mode: "mock".into(), info: Value::Null, privacy: Value::Null, portfolio: Value::Null, prepared_id: None, pause: 0,
        recover_left: 0, wallet_since: 0, deposit_seen: false, issue_count: 0, recovered: 0, entry_fee: None,
        entry_card: false, all, from: None, summary: Value::Null,
    });
    true
}

fn near_of(amount: &Amount) -> u128 {
    match amount {
        Amount::Near(v) => *v,
        Amount::All => 0,
    }
}

fn amount_words(amount: &Amount, all: &str) -> String {
    match amount {
        Amount::Near(v) => near_text(*v),
        Amount::All => format!("all {all}"),
    }
}

fn vault_words(vault: &VaultRef) -> String {
    match vault {
        VaultRef::Index(i) => format!("vault {i}"),
        VaultRef::Kind(kind) => format!("the {kind} vault"),
        VaultRef::Any => "a vault".into(),
    }
}

/// Moves a chat's pool request on by one pool command, when the pool's core has answered the previous one.
fn step_pool(chat: &mut Chat, core: &mut CoreThread, wallet: &mut Vec<WalletRequest>) {
    let Some(flow) = chat.pool.as_mut() else { return };
    let pool = |text: String| Content::Activity { tool: "pool".into(), text };
    match flow.stage {
        PoolStage::Info => {
            let Some(reply) = core.poll(json!({"cmd": "pool_info"})) else { return };
            if !ok(&reply) {
                return pool_fail(chat, &format!("the pool could not be read: {}", error_of(&reply)));
            }
            flow.mode = reply["mode"].as_str().unwrap_or("mock").to_owned();
            // The vaults the person named, among those the pool lists: a destination must be open, a source must exist.
            let resolved: Result<(Option<u32>, Option<u32>), String> = match &flow.intent {
                Intent::Deposit { vault: Some(to), .. } | Intent::Enter { vault: to, .. } =>
                    resolve_vault(&reply, to).map(|to| (None, Some(to))),
                Intent::Switch { from, to, .. } => resolve_source(&reply, from).and_then(|from| {
                    let to = resolve_vault(&reply, to)?;
                    if from == to {
                        return Err(format!("these shares are already in vault {to}: name another vault"));
                    }
                    Ok((Some(from), Some(to)))
                }),
                Intent::Leave { from, .. } => resolve_source(&reply, from).map(|from| (Some(from), None)),
                _ => Ok((None, None)),
            };
            match resolved {
                Ok((from, to)) => {
                    flow.from = from;
                    flow.vault = to;
                }
                Err(error) => return pool_fail(chat, &error),
            }
            flow.stage = match flow.intent {
                Intent::Deposit { .. } => PoolStage::Privacy,
                Intent::Withdraw { .. } | Intent::Enter { .. } | Intent::Switch { .. } | Intent::Leave { .. } =>
                    PoolStage::CardPrepare,
                Intent::Portfolio | Intent::Ask(_) => PoolStage::Portfolio,
            };
            flow.info = reply;
        }
        PoolStage::Privacy => {
            let Some(reply) = core.poll(json!({"cmd": "pool_privacy", "amount": flow.amount.to_string()})) else { return };
            // Not needed to go on: the card then says the figure could not be read.
            flow.privacy = if ok(&reply) { reply } else { Value::Null };
            flow.stage = PoolStage::CardPrepare;
        }
        PoolStage::CardPrepare | PoolStage::Prepare => {
            let Some(reply) = core.poll(prepare_request(flow)) else { return };
            if !ok(&reply) {
                let error = refusal(flow, &error_of(&reply));
                return pool_fail(chat, &error);
            }
            if flow.moves_notes() {
                // The card shows this very preparation; Yes runs it.
                flow.prepared_id = reply["prepared_id"].as_str().map(String::from);
                flow.summary = reply["summary"].clone();
                if matches!(flow.intent, Intent::Leave { .. }) {
                    return show_move_card(chat);
                }
                flow.stage = PoolStage::MovePrivacy;
                return;
            }
            if matches!(flow.intent, Intent::Deposit { .. }) {
                flow.issue_count = cash_count(&reply["summary"]["cash_notes"]);
                if flow.stage == PoolStage::CardPrepare {
                    flow.entry_fee = flow.vault.map(|_| u128::from(flow.issue_count) * ona_core::pool::NOTE_STORAGE_FEE);
                }
            }
            if flow.stage == PoolStage::CardPrepare {
                let (message, view) = card(flow, &reply["summary"]);
                flow.stage = PoolStage::Card;
                let card = flow.card.clone();
                chat.add(Content::Agent(message));
                chat.add(Content::Pool { card, view, state: "pending" });
                return;
            }
            if matches!(flow.intent, Intent::Deposit { .. }) {
                flow.stage = PoolStage::Wallet;
                flow.wallet_since = now();
                wallet.push((chat.id.clone(), flow.card.clone(), reply));
            } else {
                flow.prepared_id = reply["prepared_id"].as_str().map(String::from);
                flow.stage = PoolStage::Execute;
            }
        }
        PoolStage::Card | PoolStage::Done => {}
        PoolStage::Wallet => {
            if now() < flow.wallet_since.saturating_add(WALLET_WAIT_SECS) {
                return;
            }
            let error = if flow.deposit_seen {
                "the pool agent's message was not signed within the 5 minutes of the preparation, so the app forgot \
                 these cash notes. The deposit stays in the pool contract: your account can ask for it back \
                 (request_refund, then refund_deposit after the contract's escape delay)"
            } else {
                "the deposit was not sent from your wallet within the 5 minutes of its preparation: nothing was taken. \
                 Ask again to start over"
            };
            pool_fail(chat, error);
        }
        PoolStage::Recover => {
            if flow.pause > 0 {
                flow.pause -= 1;
                return;
            }
            let Some(reply) = core.poll(json!({"cmd": "pool_recover"})) else { return };
            if ok(&reply) {
                flow.recovered = flow.recovered.saturating_add(reply["signatures_recovered"].as_u64().unwrap_or(0));
            }
            let cash_waiting = !ok(&reply)
                || reply["waiting"].as_array().is_some_and(|w| w.iter().any(|n| n["vault"].is_null()));
            let why = match (reply["agent_error"].as_str(), ok(&reply)) {
                (Some(e), _) => format!(" (pool agent: {e})"),
                (None, false) => format!(" ({})", error_of(&reply)),
                _ => String::new(),
            };
            // Only this deposit's own cash notes go into the vault: as many signatures as it issued notes, not older
            // cash that happens to be there.
            if !cash_waiting && flow.recovered >= flow.issue_count {
                flow.stage = PoolStage::EnterPrepare;
                let notes = plural(flow.issue_count as usize, "cash note");
                chat.add(pool(format!("This deposit's {notes} received from the pool agent (Recover).")));
                return;
            }
            if !cash_waiting {
                let (got, of) = (flow.recovered, flow.issue_count);
                return pool_fail(chat, &format!("the cash issue of this deposit was not completed: the pool agent signed \
                    {got} of its {of} cash notes and none is waiting any more{why}. Nothing was put into the vault. Check \
                    “Recover pending operations” in the Pool screen; if the cash never comes, the deposit stays in the pool \
                    contract and your account can ask for it back (request_refund, then refund_deposit after the \
                    contract's escape delay)"));
            }
            if flow.recover_left == 0 {
                return pool_fail(chat, &format!("the pool agent has not signed the cash notes yet{why}. Once “Recover \
                    pending operations” in the Pool screen brings them, put them into the vault from there"));
            }
            flow.recover_left -= 1;
            flow.pause = RECOVER_PAUSE;
        }
        PoolStage::EnterPrepare => {
            let Some(vault) = flow.vault else {
                flow.stage = PoolStage::Done;
                return;
            };
            let request = json!({"cmd": "pool_prepare", "op": "enter", "vault": vault, "amount": flow.amount.to_string()});
            let Some(reply) = core.poll(request) else { return };
            if !ok(&reply) {
                return pool_fail(chat, &format!("your cash notes are in your pool wallet, but the entry into vault {vault} \
                    could not be prepared ({}): put them in from the Pool screen", error_of(&reply)));
            }
            let s = &reply["summary"];
            let text = format!("Entry into vault {vault} prepared: shares worth {}, left in the pool's cash {} (lost), storage fee {}.",
                               yocto_text(&s["shares_value"]), yocto_text(&s["left_in_cash"]), yocto_text(&s["fees"]["storage"]));
            flow.prepared_id = reply["prepared_id"].as_str().map(String::from);
            let number = |v: &Value| v.as_str().and_then(|v| v.parse::<u128>().ok());
            let left = number(&s["left_in_cash"]);
            let fee = number(&s["fees"]["storage"]);
            // The card's Yes covers the entry it showed: no money left in the pool's cash, the fee it showed. Anything
            // else is asked again, on a second card.
            let mut reasons = Vec::new();
            if left != Some(0) {
                reasons.push(format!("it would leave {} in the pool's cash, owned by nobody", yocto_text(&s["left_in_cash"])));
            }
            if fee.is_none() || fee != flow.entry_fee {
                reasons.push(format!("its storage fee is {}, not the {} the card showed", yocto_text(&s["fees"]["storage"]),
                                     flow.entry_fee.map(near_text).unwrap_or_else(|| "?".into())));
            }
            if reasons.is_empty() {
                flow.stage = PoolStage::EnterExecute;
                chat.add(pool(text));
                return;
            }
            let card = format!("p-{}", protocol::random_hex16());
            let view = json!({
                "id": card, "op": "enter", "vault": flow.info["vaults"].get(vault as usize).cloned().unwrap_or(json!({"vault": vault})),
                "amount": flow.amount.to_string(), "shares_value": s["shares_value"], "left_in_cash": s["left_in_cash"],
                "fees": s["fees"], "reasons": reasons, "mode": flow.mode, "network": flow.info["network"],
                "contract": flow.info["contract"],
                "steps": ["ONA hands the entry to the pool agent, which sends entries in batches, after a random delay. \
                           This preparation lasts 5 minutes; until then its cash notes are reserved for it."],
            });
            flow.card = card.clone();
            flow.entry_card = true;
            flow.stage = PoolStage::Card;
            chat.add(pool(text));
            chat.add(Content::Agent(format!("I did not put the cash into vault {vault}: {}. Your cash notes are in your \
                pool wallet. Put them in anyway?", reasons.join("; and "))));
            chat.add(Content::Pool { card, view, state: "pending" });
        }
        PoolStage::MovePrivacy => {
            // The value the preparation puts into the destination vault: what its new notes would join.
            let value = if matches!(flow.intent, Intent::Switch { .. }) { &flow.summary["new_shares_value"] } else { &flow.summary["shares_value"] };
            let mut request = json!({"cmd": "pool_privacy"});
            if let Some(v) = value.as_str() {
                request["amount"] = json!(v);
            }
            let Some(reply) = core.poll(request) else { return };
            flow.privacy = if ok(&reply) { reply } else { Value::Null };
            show_move_card(chat);
        }
        PoolStage::EnterExecute | PoolStage::Execute => {
            let Some(id) = flow.prepared_id.clone() else { return pool_fail(chat, "nothing prepared") };
            let Some(reply) = core.poll(json!({"cmd": "pool_execute", "prepared_id": id})) else { return };
            let label = mock_label(&reply);
            let queued = !ok(&reply) && error_of(&reply).contains("outcome unknown");
            let amount = near_text(flow.amount);
            let account = flow.account.clone().unwrap_or_default();
            let vault = flow.vault.unwrap_or_default();
            let from = flow.from.unwrap_or_default();
            let what = match (&flow.intent, flow.stage) {
                (_, PoolStage::EnterExecute) => "deposit entry",
                (Intent::Enter { .. }, _) => "cash entry",
                (Intent::Switch { .. }, _) => "switch",
                (Intent::Leave { .. }, _) => "leave",
                _ => "payout",
            };
            if !ok(&reply) && !queued {
                let error = error_of(&reply);
                return pool_fail(chat, &match what {
                    "deposit entry" | "cash entry" => format!("the entry into vault {vault} was refused ({error}); your cash \
                                                              notes are still in your pool wallet"),
                    "switch" | "leave" => format!("the {what} was refused ({error}); your shares are still in vault {from}"),
                    _ => format!("the payout was refused ({error}); your cash notes are still in your pool wallet"),
                });
            }
            flow.stage = PoolStage::Done;
            let recover = "“Recover pending operations” in the Pool screen";
            let (activity, message) = match (what, queued, reply["complete"] == true) {
                ("deposit entry" | "cash entry", true, _) => (
                    format!("Entry into vault {vault} queued by the pool agent: it sends entries in batches, after a random delay{label}."),
                    format!("Your share notes will arrive with {recover} (minutes to hours).")),
                ("deposit entry", false, true) => (format!("Entered vault {vault}: the share notes are in your pool wallet{label}."),
                                                   format!("Done: {amount} deposited and placed into vault {vault}.")),
                ("cash entry", false, true) => (format!("Entered vault {vault}: the share notes are in your pool wallet{label}."),
                                                format!("Done: your cash is in vault {vault}.")),
                ("switch", true, _) => (
                    format!("Leave of vault {from} queued by the pool agent, the first half of the move: it sends leaves in \
                             batches, after a random delay{label}."),
                    format!("Once {recover} brings the cash notes, say “put my cash in vault {vault}” to finish the move.")),
                ("switch", false, true) => (format!("Moved from vault {from} to vault {vault}{label}."),
                                            format!("Done: your shares are in vault {vault}.")),
                ("leave", true, _) => (
                    format!("Leave of vault {from} queued by the pool agent: it sends leaves in batches, after a random delay{label}."),
                    format!("Your cash notes will arrive with {recover} (minutes to hours; longer if the vault's money is \
                             staked and must be brought back first).")),
                ("leave", false, true) => (format!("Left vault {from}: the cash notes are in your pool wallet{label}."),
                                           "Done: that part of your position is now cash, still in the pool.".to_owned()),
                ("payout", true, _) => (
                    format!("Payout queued by the pool agent: it pays in batches, after a random delay{label}."),
                    format!("{account} will receive the payout once the agent sends its batch; {recover} then shows the \
                             notes as spent.")),
                ("payout", false, true) => (format!("Paid out to {account}{label}."), format!("Done: {amount} of pool cash paid out.")),
                _ => (format!("Partly done: {}{label}.", error_of(&reply)), "See the Pool screen for what is left.".to_owned()),
            };
            chat.add(pool(activity));
            chat.add(Content::Agent(message));
        }
        PoolStage::Portfolio => {
            let Some(reply) = core.poll(json!({"cmd": "pool_portfolio"})) else { return };
            if !ok(&reply) {
                return pool_fail(chat, &format!("the portfolio could not be read: {}", error_of(&reply)));
            }
            flow.portfolio = reply;
            flow.stage = PoolStage::PortfolioPrivacy;
        }
        PoolStage::PortfolioPrivacy => {
            let Some(reply) = core.poll(json!({"cmd": "pool_privacy"})) else { return };
            flow.privacy = if ok(&reply) { reply } else { Value::Null };
            flow.stage = PoolStage::Done;
            if let Intent::Ask(question) = flow.intent {
                let text = answer(question, flow);
                chat.add(Content::Agent(text));
                return;
            }
            let mut portfolio = without_ok(flow.portfolio.clone());
            if let Some(object) = portfolio.as_object_mut() {
                object.remove("mode");
            }
            let view = json!({"id": flow.card, "op": "portfolio", "mode": flow.mode, "portfolio": portfolio,
                              "privacy": flow.privacy, "vaults_info": flow.info["vaults"], "recommended": flow.info["recommended"]});
            let card = flow.card.clone();
            chat.add(Content::Agent("Here is your pool portfolio: the notes on this computer, valued at the pool \
                                     contract's public prices.".into()));
            chat.add(Content::Pool { card, view, state: "info" });
        }
    }
}

/// The `pool_prepare` of a deposit or a payout: the account is the connected wallet's, the amount the person's words.
fn prepare_request(flow: &PoolFlow) -> Value {
    let account = flow.account.clone().unwrap_or_default();
    let (from, to, amount) = (flow.from.unwrap_or_default(), flow.vault.unwrap_or_default(), flow.amount_arg());
    match flow.intent {
        Intent::Withdraw { .. } => json!({"cmd": "pool_prepare", "op": "exit_cash", "to": account, "amount": amount}),
        Intent::Enter { .. } => json!({"cmd": "pool_prepare", "op": "enter", "vault": to, "amount": amount}),
        Intent::Switch { .. } => json!({"cmd": "pool_prepare", "op": "switch", "from": from, "to": to, "amount": amount}),
        Intent::Leave { .. } => json!({"cmd": "pool_prepare", "op": "exit", "from": from, "amount": amount}),
        _ => json!({"cmd": "pool_prepare", "op": "deposit", "account": account, "amount": amount}),
    }
}

/// A source vault the person named (a frozen vault can still be left).
fn resolve_source(info: &Value, wanted: &VaultRef) -> Result<u32, String> {
    let vaults = info["vaults"].as_array().cloned().unwrap_or_default();
    let listed = || format!("the pool lists {}", vaults.iter().map(describe_vault).collect::<Vec<_>>().join(", "));
    let found: Vec<&Value> = match wanted {
        VaultRef::Index(i) => vaults.get(*i as usize).into_iter().collect(),
        VaultRef::Kind(kind) => vaults.iter().filter(|v| v["adapter"].as_str() == Some(kind.as_str())).collect(),
        VaultRef::Any => vaults.iter().collect(),
    };
    match found.as_slice() {
        [one] => one["vault"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or_else(|| "a vault without its number".into()),
        [] => Err(format!("there is no {}: {}", vault_words(wanted).trim_start_matches("the "), listed())),
        _ => Err(format!("which vault? {}. Name it by its number, for example “vault 0”", listed())),
    }
}

/// What ona-core's refusal of a preparation means for the person.
fn refusal(flow: &PoolFlow, error: &str) -> String {
    let place = match (&flow.intent, flow.from) {
        (Intent::Switch { .. } | Intent::Leave { .. }, Some(from)) => format!("in vault {from}"),
        _ => "as cash".into(),
    };
    if error.contains("no held notes") {
        return format!("you have no notes {place} available for this (notes in an operation in progress are not); ask \
                        “how much do I have?” to see your holdings");
    }
    if error.contains("not a sum of whole notes") || error.contains("not a sum of cash notes") {
        return format!("{} cannot be made exactly from your notes {place} ({error}); try another amount, or all of them",
                       near_text(flow.amount));
    }
    format!("this cannot be done: {error}")
}

/// The card of a cash entry, a switch or a leave, from the preparation it will run on Yes.
fn show_move_card(chat: &mut Chat) {
    let Some(flow) = chat.pool.as_mut() else { return };
    let s = &flow.summary;
    let info = &flow.info;
    let number = |v: &Value| v.as_str().and_then(|v| v.parse::<u128>().ok());
    let vault_of = |id: Option<u32>| id.and_then(|id| info["vaults"].get(id as usize)).cloned().unwrap_or(Value::Null);
    let (from, to) = (flow.from.unwrap_or_default(), flow.vault.unwrap_or_default());
    let some = |all: &str, part: &str| match s["amount"].as_str() {
        Some("all") | None => all.to_owned(),
        Some(_) => format!("{} {part}", yocto_text(&s["amount"])),
    };
    let (op, title) = match &flow.intent {
        Intent::Enter { .. } => ("cash_enter", format!("Put {} into vault {to}", some("all your cash", "of your cash"))),
        Intent::Switch { .. } => ("switch", format!("Move {} to vault {to}",
                                                  some(&format!("all your shares of vault {from}"), &format!("of your shares of vault {from}")))),
        _ => ("leave", format!("Turn {} into cash", some(&format!("all your shares of vault {from}"),
                                                         &format!("of your shares of vault {from}")))),
    };
    let blends = flow.vault.and_then(|v| flow.privacy["vaults"].get(v as usize)).and_then(|p| p["if_entered"].as_u64());
    // A leave pays from the vault's liquid funds, within its hourly exit cap.
    let from_cap = flow.from.and_then(|f| number(&info["vaults"][f as usize]["hourly_cap"]));
    let spent = [&s["cash_value"], &s["left_in_cash"], &s["fees"]["storage"]].iter().filter_map(|v| number(v)).sum::<u128>();
    let mut steps = match &flow.intent {
        Intent::Enter { .. } => vec!["ONA signs the entry of your cash notes with their own keys and hands it to the \
            pool agent, which sends entries in batches, after a random delay. Your share notes come with “Recover \
            pending operations”."
            .to_owned()],
        Intent::Switch { .. } => vec![
            format!("ONA first turns these shares of vault {} into cash notes: the pool agent sends that in a batch, after a \
                     random delay.", flow.from.unwrap_or_default()),
            format!("Once “Recover pending operations” brings the cash notes, say “put my cash in vault {}” to finish the \
                     move (no exit, no account named).", flow.vault.unwrap_or_default()),
        ],
        _ => vec!["ONA signs the leave with the notes' own keys and hands it to the pool agent, which sends it in a batch, \
                   after a random delay. The cash notes come with “Recover pending operations” and stay in the pool \
                   (to pay them out to your account, ask “withdraw …”)."
            .to_owned()],
    };
    steps.push("This preparation lasts 5 minutes: after that, ask again. Until then its notes are reserved for it.".into());
    let view = json!({
        "id": flow.card, "op": op, "title": title, "amount": s["amount"], "from": vault_of(flow.from), "vault": vault_of(flow.vault),
        "shares_value": s["shares_value"], "new_shares_value": s["new_shares_value"], "cash_value": s["cash_value"],
        "share_price": s["share_price"], "left_in_cash": s["left_in_cash"], "fees": s["fees"], "blends_with": blends,
        "without_ona": 1, "cash_live": info["cash"]["tiers"], "hourly_cap": from_cap.map(|c| c.to_string()),
        "over_cap": matches!(flow.intent, Intent::Leave { .. }) && from_cap.is_some_and(|c| spent > c),
        "steps": steps, "mode": flow.mode, "network": info["network"], "contract": info["contract"],
    });
    flow.stage = PoolStage::Card;
    let card = flow.card.clone();
    chat.add(Content::Agent("Here is exactly what I would do. Nothing runs before you click Yes.".into()));
    chat.add(Content::Pool { card, view, state: "pending" });
}

/// The smallest set among the held notes of one place (`None`: the cash), from `pool_privacy`'s notes.
fn place_set(privacy: &Value, vault: Option<u64>) -> Option<u64> {
    privacy["wallet"]["notes"].as_array()?.iter()
        .filter(|n| n["vault"].as_u64() == vault && (vault.is_some() || n["vault"].is_null()))
        .filter_map(|n| n["set"].as_u64()).min()
}

const UPPER_BOUND: &str = "Without ONA, a direct staking deposit is tied to your account (a set of 1). These are upper \
    bounds counted on the chain: someone who cross-checks dates and amounts can rule some notes out.";

/// The privacy line of an answer: the least protected note, and the caveat.
fn privacy_line(privacy: &Value) -> String {
    if privacy.is_null() {
        return "Privacy figures are unavailable right now (the pool did not answer).".into();
    }
    match privacy["wallet"]["smallest_set"].as_u64() {
        None => "Privacy: you hold no notes yet, so there is nothing of yours to follow.".into(),
        Some(n) if n <= 1 => format!("Privacy: your least protected note is the only one of its value in its place, so \
                                     anyone watching the chain can follow it. {UPPER_BOUND}"),
        Some(n) => format!("Privacy: your least protected note blends in with at most {n} notes of the same value. {UPPER_BOUND}"),
    }
}

/// A question about the person's pool, answered from `pool_info`, `pool_portfolio` and `pool_privacy` (no model).
fn answer(question: Question, flow: &PoolFlow) -> String {
    let (info, portfolio, privacy) = (&flow.info, &flow.portfolio, &flow.privacy);
    let number = |v: &Value| v.as_str().and_then(|v| v.parse::<u128>().ok()).unwrap_or(0);
    let held: Vec<&Value> = portfolio["vaults"].as_array().map(|v| v.iter().collect()).unwrap_or_default();
    let info_vault = |id: u64| info["vaults"].as_array().and_then(|v| v.iter().find(|x| x["vault"].as_u64() == Some(id)));
    let name = |id: u64| info_vault(id).map(describe_vault).unwrap_or_else(|| format!("vault {id}"));
    let cash = number(&portfolio["cash"]["value"]);
    let in_vaults: u128 = held.iter().map(|v| number(&v["value"])).sum();
    let pending = portfolio["cash"]["spending_value"].as_str().is_some_and(|v| v != "0")
        || portfolio["cash"]["awaiting_signature"].as_u64().unwrap_or(0) > 0
        || held.iter().any(|v| v["spending_value"].as_str().is_some_and(|x| x != "0") || v["awaiting_signature"].as_u64().unwrap_or(0) > 0);
    let pending_note = if pending { " Some notes are in an operation in progress and are not counted until it completes." } else { "" };
    let simulation = if flow.mode == "mock" { " (Simulation: fake pool.)" } else { "" };
    let text = match question {
        Question::Total => {
            let total = number(&portfolio["total"]);
            if total == 0 && !pending {
                format!("You have nothing in the pool yet (0 NEAR). Say “deposit 1 NEAR” to start. {}", privacy_line(privacy))
            } else {
                let mut parts = vec![format!("{} as cash", near_text(cash))];
                parts.extend(held.iter().map(|v| format!("{} in {}", yocto_text(&v["value"]), name(v["vault"].as_u64().unwrap_or(0)))));
                format!("You have {} in the pool: {}.{pending_note} {}", near_text(total), parts.join(", "), privacy_line(privacy))
            }
        }
        Question::Vault(id) => match info_vault(u64::from(id)) {
            None => format!("The pool has no vault {id}: it lists {}.",
                            info["vaults"].as_array().map(|v| v.iter().map(describe_vault).collect::<Vec<_>>().join(", ")).unwrap_or_default()),
            Some(v) => {
                let state = if v["frozen"] == true { " It is frozen: it takes no new money." } else { "" };
                match held.iter().find(|h| h["vault"].as_u64() == Some(u64::from(id))) {
                    Some(h) => {
                        let notes: u64 = h["tiers"].as_array().map(|t| t.iter().filter_map(|t| t["held"].as_u64()).sum()).unwrap_or(0);
                        let set = place_set(privacy, Some(u64::from(id)))
                            .map(|n| format!(" These notes blend in with at most {n} notes of the same value. {UPPER_BOUND}"))
                            .unwrap_or_default();
                        format!("In {} you hold {}: {}, at {} per share.{state}{pending_note}{set}", describe_vault(v),
                                yocto_text(&h["value"]), plural(notes as usize, "share note"), yocto_text(&h["share_price"]))
                    }
                    None => {
                        let entry = privacy["vaults"].get(id as usize).and_then(|p| p["if_entered"].as_u64())
                            .map(|n| format!(" If you put your cash in, your notes would blend in with at most {n} notes. {UPPER_BOUND}"))
                            .unwrap_or_default();
                        format!("You hold nothing in {}.{state}{entry}", describe_vault(v))
                    }
                }
            }
        },
        Question::Privacy => {
            if privacy.is_null() {
                privacy_line(privacy)
            } else if privacy["wallet"]["smallest_set"].is_null() {
                "You hold no notes in the pool yet, so nothing of yours is there to follow. Once you deposit, each note \
                 hides among the notes of the same value at the same place."
                    .to_owned()
            } else {
                let mut lines = Vec::new();
                if let Some(n) = place_set(privacy, None) {
                    lines.push(format!("your cash blends in with at most {n} notes of the same value"));
                }
                for v in &held {
                    let id = v["vault"].as_u64().unwrap_or(0);
                    if let Some(n) = place_set(privacy, Some(id)) {
                        lines.push(format!("your notes in vault {id} blend in with at most {n}"));
                    }
                }
                let least = privacy["wallet"]["smallest_set"].as_u64().unwrap_or(0);
                format!("Your position: {}. Your least protected note blends in with at most {least}{}. {UPPER_BOUND}",
                        lines.join("; "), if least <= 1 { ", so anyone watching the chain can follow it" } else { "" })
            }
        }
        Question::Withdrawable => {
            let cap = info["cash"]["hourly_cap"].as_str().map(|c| format!(" The pool pays at most {} of cash per hour, all \
                accounts together.", yocto_text(&json!(c)))).unwrap_or_default();
            let to = flow.account.clone().map(|a| format!("to {a}")).unwrap_or_else(|| "to the account that deposited".into());
            let shares = if in_vaults > 0 {
                let first = held.first().and_then(|v| v["vault"].as_u64()).unwrap_or(0);
                format!(" {} in vaults must first become cash: say “take my NEAR out of vault {first}”.", near_text(in_vaults))
            } else {
                String::new()
            };
            if cash == 0 && in_vaults == 0 {
                format!("Nothing to withdraw: you hold nothing in the pool.{pending_note}")
            } else {
                format!("You can pay out {} of cash now, {to} (its exit limit is checked when the payout is prepared).{cap}\
                         {shares}{pending_note} A payout is public and names your account. {}", near_text(cash), privacy_line(privacy))
            }
        }
        Question::Vaults => {
            let vaults = info["vaults"].as_array().cloned().unwrap_or_default();
            if vaults.is_empty() {
                "The pool lists no vault yet.".into()
            } else {
                let lines: Vec<String> = vaults.iter().map(|v| {
                    let id = v["vault"].as_u64().unwrap_or(0);
                    let mine = held.iter().find(|h| h["vault"].as_u64() == Some(id))
                        .map(|h| format!(", you hold {}", yocto_text(&h["value"]))).unwrap_or_default();
                    format!("{}: {}, {} per share{mine}", describe_vault(v),
                            if v["frozen"] == true { "frozen" } else { "open" }, yocto_text(&v["share_price"]))
                }).collect();
                format!("The pool lists {}: {}.", plural(vaults.len(), "vault"), lines.join("; "))
            }
        }
    };
    format!("{text}{simulation}")
}

/// The card's message and view, from `pool_info`, `pool_privacy` and the summary of `pool_prepare`.
fn card(flow: &PoolFlow, summary: &Value) -> (String, Value) {
    let info = &flow.info;
    let cap = info["cash"]["hourly_cap"].as_str().and_then(|c| c.parse::<u128>().ok());
    let account = flow.account.clone().unwrap_or_default();
    let mut view = json!({
        "id": flow.card, "amount": flow.amount.to_string(), "account": account, "network": summary["network"],
        "contract": summary["contract"], "mode": flow.mode, "hourly_cap": cap.map(|c| c.to_string()),
        "over_cap": cap.is_some_and(|c| flow.amount > c), "fees": summary["fees"],
    });
    if matches!(flow.intent, Intent::Withdraw { .. }) {
        view["op"] = json!("withdraw");
        view["received"] = summary["received"].clone();
        view["exit_limit"] = summary["exit_limit"].clone();
        view["steps"] = json!([
            format!("ONA signs the payout of your cash notes with their own keys and hands it to the pool agent, which pays \
                     {account} in a batch, after a random delay."),
            "The payout is public on the chain and names your account.",
        ]);
        return ("Here is the payout I would ask for. Nothing is sent before you click Yes.".into(), view);
    }
    let vault = flow.vault.and_then(|v| info["vaults"].get(v as usize)).cloned();
    let blends = match flow.vault {
        Some(v) => flow.privacy["vaults"].get(v as usize).and_then(|p| p["if_entered"].as_u64()),
        None => cash_set(info, &summary["cash_notes"]),
    };
    let contract = summary["contract"].as_str().unwrap_or("the pool contract");
    let mut steps = vec![
        format!("Your wallet page opens in your browser; connect your wallet as {account} if it asks."),
        format!("Your wallet asks you to confirm the deposit transaction to {contract}: {} (the amount plus a refundable \
                 storage margin).", yocto_text(&summary["wallet_call"]["attached"])),
        "Your wallet asks you to sign a message for the pool agent (no transaction, no fee), so that it issues your cash \
         notes."
            .to_owned(),
    ];
    if let Some(v) = &vault {
        steps.push(format!("ONA then puts the cash notes into {} (storage fee {}). If that entry would leave money in \
                            the pool's cash, or cost another fee, ONA asks you again first. The pool agent sends entries \
                            in batches, after a random delay.", describe_vault(v),
                           flow.entry_fee.map(near_text).unwrap_or_else(|| "?".into())));
    }
    view["entry_fee"] = json!(flow.entry_fee.map(|f| f.to_string()));
    view["op"] = json!("deposit");
    view["vault"] = vault.map(|v| json!({"vault": v["vault"], "adapter": v["adapter"], "target": v["target"],
                                         "share_price": v["share_price"]})).unwrap_or(Value::Null);
    view["blends_with"] = json!(blends);
    view["without_ona"] = json!(1);
    view["recommended"] = if summary["recommended"].is_array() { summary["recommended"].clone() } else { info["recommended"].clone() };
    view["is_recommended"] = json!(summary["warning"].is_null());
    view["warning"] = summary["warning"].clone();
    view["cash_notes"] = summary["cash_notes"].clone();
    view["attached"] = summary["wallet_call"]["attached"].clone();
    view["steps"] = json!(steps);
    ("Here is what I would do. Nothing is sent before you click Yes, and your wallet asks you again before anything \
      leaves it."
        .into(), view)
}

/// How many notes a summary's `cash_notes` (`count` per tier) make.
fn cash_count(notes: &Value) -> u64 {
    notes.as_array().map(|n| n.iter().filter_map(|n| n["count"].as_u64()).sum()).unwrap_or(0)
}

/// The smallest set the new cash notes would join: notes in circulation of their tier, plus the new one (an upper
/// bound, as `pool_privacy`).
fn cash_set(info: &Value, notes: &Value) -> Option<u64> {
    notes.as_array()?.iter().filter_map(|n| {
        let tier = usize::try_from(n["tier"].as_u64()?).ok()?;
        info["cash"]["tiers"].get(tier)?["live"].as_u64().map(|live| live.saturating_add(1))
    }).min()
}

fn describe_vault(v: &Value) -> String {
    let id = v["vault"].as_u64().unwrap_or_default();
    match (v["adapter"].as_str(), v["target"].as_str()) {
        (Some(kind), Some(target)) => format!("vault {id} ({kind}, placed with {target})"),
        (Some(kind), None) => format!("vault {id} ({kind})"),
        _ => format!("vault {id}"),
    }
}

/// The vault the person named, among those `pool_info` lists: by number, by kind, or the only open one.
fn resolve_vault(info: &Value, wanted: &VaultRef) -> Result<u32, String> {
    let vaults = info["vaults"].as_array().cloned().unwrap_or_default();
    let listed = || if vaults.is_empty() {
        "the pool lists no vault".to_owned()
    } else {
        format!("the pool lists {}", vaults.iter().map(describe_vault).collect::<Vec<_>>().join(", "))
    };
    let open = || vaults.iter().filter(|v| v["frozen"] != true);
    let chosen: Vec<&Value> = match wanted {
        VaultRef::Index(i) => {
            let Some(v) = vaults.get(*i as usize) else { return Err(format!("there is no vault {i}: {}", listed())) };
            if v["frozen"] == true {
                return Err(format!("vault {i} is frozen: it takes no new money"));
            }
            vec![v]
        }
        VaultRef::Kind(kind) => open().filter(|v| v["adapter"].as_str() == Some(kind.as_str())).collect(),
        VaultRef::Any => open().collect(),
    };
    match chosen.as_slice() {
        [one] => one["vault"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or_else(|| "a vault without its number".into()),
        [] => Err(match wanted {
            VaultRef::Kind(kind) => format!("there is no open {kind} vault: {}", listed()),
            _ => format!("there is no open vault: {}", listed()),
        }),
        [first, ..] => Err(format!("which vault? {}. Name it by its number, for example “vault {}”", listed(),
                                   first["vault"].as_u64().unwrap_or_default())),
    }
}

/// A yoctoNEAR string as NEAR text, "?" when unreadable.
fn yocto_text(value: &Value) -> String {
    value.as_str().and_then(|v| v.parse::<u128>().ok()).map(near_text).unwrap_or_else(|| "?".into())
}

/// The honesty label of a figure from the fake pool (ona-core's `mode: mock`).
fn mock_label(reply: &Value) -> &'static str {
    // An error reply (a queued operation is one: "outcome unknown") carries the core's default mode, not the pool's:
    // only a successful pool reply says which pool answered.
    if ok(reply) && reply["mode"] == "mock" { " (simulation: fake pool)" } else { "" }
}

fn set_card_state(chat: &mut Chat, card: &str, state: &'static str) {
    for item in &mut chat.items {
        if let Content::Pool { card: c, state: s, .. } = &mut item.content {
            if *c == card {
                *s = state;
            }
        }
    }
    chat.updated_at = now();
}

/// Stops a chat's pool request with the reason; a card still pending or accepted is marked failed.
fn pool_fail(chat: &mut Chat, error: &str) {
    let card = chat.pool.as_mut().map(|flow| {
        flow.stage = PoolStage::Done;
        flow.card.clone()
    });
    if let Some(card) = card {
        let open = chat.items.iter().any(|i| matches!(&i.content,
            Content::Pool { card: c, state: "pending" | "accepted", .. } if *c == card));
        if open {
            set_card_state(chat, &card, "failed");
        }
    }
    chat.add(Content::Agent(format!("I could not finish this pool request: {error}.")));
}

fn plural(count: usize, word: &str) -> String {
    format!("{count} {word}{}", if count == 1 { "" } else { "s" })
}

/// Moves a free research on by one ona-core command (docs/research.md, "The flow"). The slow ones (the model, Tor)
/// are polled: a tick never waits for them.
fn step_research(chat: &mut Chat) -> Option<String> {
    let run = chat.run.as_mut()?;
    let r = run.research.as_mut()?;
    let think = |text: &str| Content::Activity { tool: "think".into(), text: text.into() };
    match r.stage {
        Stage::Open => {
            let opened = run.core.poll(json!({"cmd": "research_open", "question": r.question, "payees": r.payees}))?;
            if !ok(&opened) {
                fail(chat, &error_of(&opened));
                return None;
            }
            r.stage = Stage::Propose;
            chat.add(think("Reading your question and choosing the searches"));
            return opened["mode"].as_str().map(String::from);
        }
        Stage::Propose => {
            let proposal = run.core.poll(json!({"cmd": "research_propose"}))?;
            let queries: Vec<String> = proposal["queries"].as_array()
                .map(|q| q.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
            if !ok(&proposal) || queries.is_empty() {
                fail(chat, &error_of(&proposal));
                return None;
            }
            chat.add(Content::Agent(QUERIES_MESSAGE.into()));
            wait(chat, Request::Queries(queries));
        }
        Stage::Steps => {
            let reply = run.core.poll(json!({"cmd": "research_step"}))?;
            if !ok(&reply) {
                fail(chat, &error_of(&reply));
                return None;
            }
            let handle = reply["handle"].as_str().unwrap_or_default();
            let site = r.sources.iter().find(|(h, _)| h == handle).map(|(_, s)| s.clone()).unwrap_or_else(|| "?".into());
            let error = reply["error"].as_str().unwrap_or("unknown error");
            let activity = |tool: &str, text: String| Content::Activity { tool: tool.into(), text };
            let content = match reply["event"].as_str().unwrap_or_default() {
                "searched" => {
                    r.searched += 1;
                    let sources = reply["sources"].as_array().cloned().unwrap_or_default();
                    for s in &sources {
                        r.sources.push((s["handle"].as_str().unwrap_or_default().to_owned(),
                                        s["site"].as_str().unwrap_or("?").to_owned()));
                    }
                    let query = reply["query"].as_str().unwrap_or_default();
                    match reply["error"].as_str() {
                        // One query failed; the others go on (ona-core stops only when none gave a page).
                        Some(failure) => activity("search", format!("Search “{query}”: failed ({failure})")),
                        None => activity("search", format!("Search “{query}”: {}", plural(sources.len(), "source"))),
                    }
                }
                "read" => {
                    r.read += 1;
                    let notes = reply["notes"].as_u64().unwrap_or(0) as usize;
                    activity("read", format!("Read {site}: {}", plural(notes, "note")))
                }
                "unreadable" => {
                    r.read += 1;
                    activity("read", format!("Could not read {site}: {error}"))
                }
                "unread" => {
                    r.read += 1;
                    activity("read", format!("Page from {site} not read by the model: {error}"))
                }
                "refused" => {
                    r.read += 1;
                    activity("read", format!("Page from {site} not sent to the model: {error}"))
                }
                "answered" => think("Answer written from the checked notes"),
                other => {
                    let error = format!("unknown research event {other}");
                    fail(chat, &error);
                    return None;
                }
            };
            if reply["done"] == true {
                r.stage = Stage::Result;
            }
            chat.add(content);
        }
        Stage::Result => {
            let mut result = run.core.poll(json!({"cmd": "research_result"}))?;
            if !ok(&result) {
                fail(chat, &error_of(&result));
                return None;
            }
            r.stage = Stage::Exposure;
            let serial = run.serial;
            let actions = result["actions"].as_array().cloned().unwrap_or_default();
            chat.add(Content::Agent(if actions.is_empty() {
                ANSWER_MESSAGE.into()
            } else {
                ACTIONS_MESSAGE.replace("{}", &plural(actions.len(), "action"))
            }));
            let answer = json!({"answer": result["answer"].take(), "notes": result["notes"].take(),
                                "sources": result["sources"].take()});
            chat.add(Content::Answer(answer));
            for mut action in actions {
                let done = action["done"] == true;
                if let Some(object) = action.as_object_mut() {
                    object.remove("done");
                }
                chat.add(Content::Action { run: serial, action, done });
            }
        }
        Stage::Exposure => {
            let exposure = run.core.poll(json!({"cmd": "research_exposure"}))?;
            r.stage = Stage::Answered;
            run.phase = Phase::Done;
            chat.add(Content::Exposure(without_ok(exposure)));
        }
        Stage::Answered => {}
    }
    None
}

fn without_ok(mut reply: Value) -> Value {
    if let Some(object) = reply.as_object_mut() {
        object.remove("ok");
    }
    reply
}

fn wait(chat: &mut Chat, request: Request) {
    let Some(run) = chat.run.as_mut() else { return };
    // 16 random bytes: never the same id twice, across missions, chats and restarts.
    let pending = Pending { id: format!("c-{}", protocol::random_hex16()), request };
    run.phase = Phase::Waiting(pending.clone());
    chat.add(Content::Confirmation(pending));
}

fn finish(chat: &mut Chat, cancelled: bool) {
    let Some(run) = chat.run.as_mut() else { return };
    let research = run.research.is_some();
    let (close, report) = if research { ("research_close", "research_exposure") } else { ("close", "exposure") };
    run.core.call(json!({"cmd": close}));
    let exposure = without_ok(run.core.call(json!({"cmd": report})));
    run.phase = if cancelled { Phase::Stopped } else { Phase::Done };
    let message = match (cancelled, research) {
        (true, true) => QUERIES_CANCELLED_MESSAGE,
        (true, false) => CANCELLED_MESSAGE,
        (false, _) => DONE_MESSAGE,
    };
    chat.add(Content::Agent(message.into()));
    chat.add(Content::Exposure(exposure));
}

fn fail(chat: &mut Chat, error: &str) {
    if let Some(run) = chat.run.as_mut() {
        run.phase = Phase::Stopped;
    }
    chat.add(Content::Agent(format!("The agent stopped: {error}.")));
}

fn clean(text: &str) -> Option<String> {
    let trimmed = text.trim();
    (!trimmed.is_empty() && trimmed.chars().count() <= MAX_TEXT).then(|| trimmed.to_owned())
}

fn title(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() <= 48 {
        return line;
    }
    let cut: String = line.chars().take(47).collect();
    format!("{}…", cut.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_of(engine: &ChatEngine, chat: &str) -> Value {
        let view = engine.chat_json(chat).unwrap();
        let items = view["chat"]["items"].as_array().unwrap().clone();
        items.into_iter().rev().find(|i| i["kind"] == "confirmation").unwrap()["pending"].clone()
    }

    fn run_until_waiting(engine: &mut ChatEngine, chat: &str) {
        for _ in 0..20 {
            if engine.chat_json(chat).unwrap()["chat"]["status"] != "working" {
                return;
            }
            engine.tick();
        }
    }

    /// A slow model (the real one through Tor) does not hold the worker thread: the request returns at once, the chat
    /// says it is working, and the plan arrives at a later tick.
    #[test]
    fn a_slow_core_does_not_block_the_engine() {
        struct Slow(ona_core::Core);
        impl MissionCore for Slow {
            fn dispatch(&mut self, request: Value) -> Value {
                if request["cmd"] == "propose_plan" {
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                }
                MissionCore::dispatch(&mut self.0, request)
            }
        }
        let mut engine = ChatEngine::new(|| Box::new(Slow(ona_core::Core::new())));
        let started = std::time::Instant::now();
        let chat = engine.create_mission("Find me an employment lawyer in Paris").unwrap();
        engine.tick();
        assert!(started.elapsed() < std::time::Duration::from_millis(1200), "{:?}", started.elapsed());
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["status"], "working");
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["working"]["tool"], "think");
        let deadline = started + std::time::Duration::from_secs(10);
        while engine.chat_json(&chat).unwrap()["chat"]["status"] == "working" && std::time::Instant::now() < deadline {
            engine.tick();
        }
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["status"], "waiting");
    }

    #[test]
    fn runs_the_full_mission_with_ona_core() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let chat = engine.create_mission("  Find me an employment lawyer in Paris  ").unwrap();
        assert_eq!(engine.list_json()["chats"][0]["status"], "waiting");
        let plan = pending_of(&engine, &chat);
        assert_eq!(plan["kind"], "plan");
        engine.confirm(plan["id"].as_str(), Some("accept"), None, None).unwrap();
        // The same confirmation cannot be answered twice.
        assert_eq!(engine.confirm(plan["id"].as_str(), Some("accept"), None, None), Err("stale confirmation".into()));

        run_until_waiting(&mut engine, &chat);
        let recipient = pending_of(&engine, &chat);
        assert_eq!(recipient["kind"], "recipient");
        let firm = recipient["offers"][0]["firm_id"].as_str().unwrap().to_owned();
        engine.confirm(recipient["id"].as_str(), Some("accept"), Some(&firm), None).unwrap();

        run_until_waiting(&mut engine, &chat);
        let payment = pending_of(&engine, &chat);
        assert_eq!(payment["kind"], "payment");
        // The amount comes from ona-core (offer price × policy rate); the phone can recompute the v2 digest.
        let p = &payment["payment"];
        assert_eq!(p["digest_version"], 2);
        assert_eq!(p["screen"], format!("Pay {} yoctoNEAR to {}", p["amount"].as_str().unwrap(), p["to"].as_str().unwrap()));
        assert_eq!(p["digest"], protocol::payment_digest_v2(
            p["network"].as_str().unwrap(), p["contract"].as_str().unwrap(), p["mission_id"].as_str().unwrap(),
            p["nonce"].as_str().unwrap(), p["to"].as_str().unwrap(), p["amount"].as_str().unwrap()));
        assert_eq!(payment["content"], p["digest"]);
        // ona-core's gate refuses a digest that is not the one of the payment screen.
        assert!(engine.confirm(payment["id"].as_str(), Some("accept"), None, Some("00")).is_err());
        engine.confirm(payment["id"].as_str(), Some("accept"), None, payment["payment"]["digest"].as_str()).unwrap();

        run_until_waiting(&mut engine, &chat);
        let view = engine.chat_json(&chat).unwrap();
        assert_eq!(view["chat"]["status"], "idle");
        let items = view["chat"]["items"].as_array().unwrap();
        assert_eq!(items.last().unwrap()["kind"], "exposure");
        assert!(items.iter().any(|i| i["tool"] == "pay"));
        assert_eq!(view["mode"], "mock");
    }

    #[test]
    fn rejecting_stops_the_mission() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let chat = engine.create_mission("Find a lawyer").unwrap();
        let plan = pending_of(&engine, &chat);
        engine.confirm(plan["id"].as_str(), Some("reject"), None, None).unwrap();
        let view = engine.chat_json(&chat).unwrap();
        let items = view["chat"]["items"].as_array().unwrap();
        assert!(items.iter().any(|i| i["kind"] == "confirmation" && i["state"] == "rejected"));
        assert_eq!(items.last().unwrap()["kind"], "exposure");
        assert_eq!(view["chat"]["status"], "idle");
    }

    #[test]
    fn refuses_bad_text_and_unknown_chats() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        assert_eq!(engine.create("   "), Err(ProtocolError::BadText));
        assert_eq!(engine.create(&"a".repeat(MAX_TEXT + 1)), Err(ProtocolError::BadText));
        assert_eq!(engine.post("hello", "chat-9"), Err(ProtocolError::UnknownChat));
        assert_eq!(engine.delete("chat-1"), Err(ProtocolError::UnknownChat));
        assert_eq!(engine.delete("chat-9"), Err(ProtocolError::UnknownChat));
        let chat = engine.create("Find a lawyer").unwrap();
        engine.post("Et vite", &chat).unwrap();
        let view = engine.chat_json(&chat).unwrap();
        assert_eq!(view["chat"]["items"].as_array().unwrap().last().unwrap()["text"], BUSY_MESSAGE);
        engine.delete(&chat).unwrap();
        assert!(engine.chat_json(&chat).is_none());
    }

    /// Confirmation and chat ids never repeat (they used to restart at chat-1-c-1).
    #[test]
    fn ids_are_random_and_never_reused() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let chat = engine.create("Find a lawyer").unwrap();
        let other = engine.create("Find a lawyer").unwrap();
        assert_ne!(chat, other);
        assert!(chat.starts_with("chat-") && protocol::is_hex(&chat[5..], 32));
        let first = pending_of(&engine, &chat)["id"].as_str().unwrap().to_owned();
        assert!(first.starts_with("c-") && protocol::is_hex(&first[2..], 32));
        engine.confirm(Some(&first), Some("reject"), None, None).unwrap();
        engine.post("Recommence", &chat).unwrap();
        let second = pending_of(&engine, &chat)["id"].as_str().unwrap().to_owned();
        assert_ne!(first, second);
        assert_eq!(engine.confirm(Some(&first), Some("accept"), None, None), Err("stale confirmation".into()));
    }

    /// Each confirmation carries the digest of what it shows.
    #[test]
    fn confirmations_carry_the_digest_of_their_content() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let chat = engine.create_mission("Find a lawyer").unwrap();
        let plan = pending_of(&engine, &chat);
        let steps: Vec<String> = plan["plan"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_owned()).collect();
        let id = plan["id"].as_str().unwrap();
        assert_eq!(plan["content"], protocol::plan_digest(id, &steps));
        assert_eq!(engine.pending_content(id), Some(protocol::plan_digest(id, &steps)));
        assert_eq!(engine.pending_content("c-unknown"), None);
    }

    /// A core that panicked is caught, then never used again, and the chat's next mission gets a new core.
    #[test]
    fn a_core_that_panicked_is_not_reused() {
        struct Exploding;
        impl MissionCore for Exploding {
            fn dispatch(&mut self, request: Value) -> Value {
                if request["cmd"] == "propose_plan" {
                    panic!("inside the core");
                }
                json!({"ok": true, "mode": "mock"})
            }
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        let made = Arc::new(AtomicUsize::new(0));
        let counter = made.clone();
        let mut engine = ChatEngine::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::new(Guarded::new(Exploding)) as Box<dyn MissionCore>
        });
        let chat = engine.create_mission("Find a lawyer").unwrap();
        let view = engine.chat_json(&chat).unwrap();
        let last = view["chat"]["items"].as_array().unwrap().last().unwrap().clone();
        assert!(last["text"].as_str().unwrap().contains("panic inside ona-core"), "{last}");
        engine.post("Recommence", &chat).unwrap();
        assert_eq!(made.load(Ordering::SeqCst), 2);

        let mut guarded = Guarded::new(Exploding);
        assert_eq!(guarded.dispatch(json!({"cmd": "propose_plan"}))["error"], "panic inside ona-core");
        assert_eq!(guarded.dispatch(json!({"cmd": "open"}))["error"], "ona-core stopped after an internal error");
    }

    /// Payment v2: the digest binds network, contract, mission, nonce, account and amount.
    #[test]
    fn reads_a_v2_payment_and_refuses_unbound_or_mismatched_ones() {
        let nonce = "00112233445566778899aabbccddeeff";
        let screen = "Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet";
        let digest = protocol::payment_digest_v2("testnet", "pay.ona.testnet", "m-1", nonce, "cabinet-b.testnet",
                                                 "1000000000000000000000000");
        // Shape of ona-core's prepare_payment reply.
        let reply = json!({"ok": true, "screen": screen, "digest": digest, "amount_near": "1", "mode": "mock",
                           "payment": {"network": "testnet", "contract": "pay.ona.testnet", "mission_id": "m-1",
                                       "nonce": nonce, "to": "cabinet-b.testnet", "amount": "1000000000000000000000000"}});
        let Ok(request) = read_prepared_payment(&reply) else { panic!() };
        let pending = Pending { id: "c-1".into(), request };
        let view = pending.json();
        assert_eq!(view["payment"]["digest_version"], 2);
        assert_eq!(view["payment"]["mission_id"], "m-1");
        assert_eq!(view["payment"]["screen"], screen);
        assert_eq!(view["content"], digest);

        let mut other_mission = reply.clone();
        other_mission["payment"]["mission_id"] = json!("m-2");
        assert!(read_prepared_payment(&other_mission).is_err());
        let mut other_account = reply.clone();
        other_account["payment"]["to"] = json!("attacker.testnet");
        assert!(read_prepared_payment(&other_account).is_err());
        let mut other_amount = reply.clone();
        other_amount["payment"]["amount"] = json!("2");
        assert!(read_prepared_payment(&other_amount).is_err());
        // The old digest (account and amount only), even for a mock payment: refused.
        let unbound = json!({"ok": true, "screen": screen, "digest": digest, "mode": "mock"});
        assert!(read_prepared_payment(&unbound).is_err());
    }

    /// Answers `pool_portfolio` with a fixed portfolio, like ona-core with a pool wallet.
    struct FakePool;
    impl MissionCore for FakePool {
        fn dispatch(&mut self, request: Value) -> Value {
            assert_eq!(request["cmd"], "pool_portfolio");
            json!({"ok": true, "mode": "mock", "cash": {"tiers": [], "value": "0", "spending_value": "0",
                   "awaiting_signature": 0}, "vaults": [], "vault_count": 2, "total": "0"})
        }
    }

    #[test]
    fn serves_the_pool_portfolio_read_only() {
        let mut engine = ChatEngine::new(|| Box::new(FakePool));
        let view = engine.pool_portfolio().unwrap();
        assert_eq!(view["mode"], "mock");
        assert_eq!(view["portfolio"]["vault_count"], 2);
        assert!(view["portfolio"].get("ok").is_none());
        // ona-core without a pool wallet says so.
        let mut real = ChatEngine::with_ona_core(Default::default());
        assert_eq!(real.pool_portfolio(), Err("no pool wallet configured".to_owned()));
    }

    #[test]
    fn titles_are_one_short_line() {
        assert_eq!(title("a\n b"), "a b");
        assert_eq!(title(&"é".repeat(60)).chars().count(), 48);
    }

    // Free research (docs/research.md), with the real ona-core on its demo web (fake model, MockOpenWeb).

    fn items_of(engine: &ChatEngine, chat: &str) -> Vec<Value> {
        engine.chat_json(chat).unwrap()["chat"]["items"].as_array().unwrap().clone()
    }

    fn run_until_idle(engine: &mut ChatEngine, chat: &str) {
        for _ in 0..40 {
            if engine.chat_json(chat).unwrap()["chat"]["status"] != "working" {
                return;
            }
            engine.tick();
        }
        panic!("the research did not finish");
    }

    const QUESTION: &str = "How much does a plumber cost in Lyon? Write to them and pay a deposit";

    #[test]
    fn a_new_chat_runs_a_research_with_its_queries_confirmed_first() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let chat = engine.create(QUESTION).unwrap();
        let view = engine.chat_json(&chat).unwrap();
        assert_eq!(view["chat"]["status"], "waiting");
        let pending = pending_of(&engine, &chat);
        assert_eq!(pending["kind"], "queries");
        let id = pending["id"].as_str().unwrap();
        let queries: Vec<String> = pending["queries"].as_array().unwrap().iter().map(|q| q.as_str().unwrap().into()).collect();
        assert!(!queries.is_empty());
        assert_eq!(pending["content"], protocol::queries_digest(id, &queries));
        assert_eq!(engine.pending_content(id), Some(protocol::queries_digest(id, &queries)));
        assert!(items_of(&engine, &chat).iter().all(|i| i["tool"] != "search"), "nothing searched before the accord");

        // Accepted as shown (the phone's way).
        engine.confirm(Some(id), Some("accept"), None, None).unwrap();
        assert_eq!(engine.confirm(Some(id), Some("accept"), None, None), Err("stale confirmation".into()));
        run_until_idle(&mut engine, &chat);
        let view = engine.chat_json(&chat).unwrap();
        assert_eq!(view["chat"]["status"], "idle");
        assert!(view["chat"]["working"].is_null());
        let items = items_of(&engine, &chat);
        let search = items.iter().find(|i| i["tool"] == "search").unwrap();
        assert_eq!(search["text"], format!("Search “{}”: 2 sources", queries[0]));
        let reads: Vec<&Value> = items.iter().filter(|i| i["tool"] == "read").collect();
        assert_eq!(reads.len(), 2);
        assert!(reads[0]["text"].as_str().unwrap().starts_with("Read "), "{}", reads[0]);
        assert!(reads[0]["text"].as_str().unwrap().ends_with(" notes"), "{}", reads[0]);

        let answer = items.iter().find(|i| i["kind"] == "answer").unwrap();
        assert!(!answer["answer"].as_str().unwrap().is_empty());
        assert_eq!(answer["sources"].as_array().unwrap().len(), 2);
        assert!(answer["sources"][0]["url"].as_str().unwrap().starts_with("https://"));
        assert!(!answer["notes"].as_array().unwrap().is_empty());
        assert!(answer["notes"][0]["quote"].is_string() && answer["notes"][0]["source"].is_string());
        let actions: Vec<&Value> = items.iter().filter(|i| i["kind"] == "action").collect();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0]["state"], "suggested");
        assert_eq!(actions[0]["action"]["kind"], "message");
        assert_eq!(actions[0]["action"]["index"], 0);
        assert!(actions[0]["action"]["text"].is_string() && actions[0]["action"]["purpose"].is_string());
        assert_eq!(actions[1]["action"]["kind"], "payment");
        assert_eq!(actions[1]["action"]["amount"], "100000000000000000000000");
        let exposure = items.last().unwrap();
        assert_eq!(exposure["kind"], "exposure");
        assert_eq!(exposure["exposure"]["outputs"]["search"], 1);
        assert_eq!(view["mode"], "mock");
    }

    /// Edited on the computer: exactly the edited queries are searched; a protected term is refused and the queries
    /// still wait.
    #[test]
    fn queries_edited_on_the_computer_are_what_leaves() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let chat = engine.create(QUESTION).unwrap();
        let pending = pending_of(&engine, &chat);
        let id = pending["id"].as_str().unwrap().to_owned();
        assert!(engine.accept_queries(&id, vec!["Dupont plumber".into()]).unwrap_err().contains("protected"));
        assert!(engine.accept_queries(&id, vec![]).is_err());
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["status"], "waiting");
        engine.accept_queries(&id, vec!["plumber Lyon price".into(), "plumber Lyon reviews".into()]).unwrap();
        run_until_idle(&mut engine, &chat);
        let items = items_of(&engine, &chat);
        let searches: Vec<&str> = items.iter().filter(|i| i["tool"] == "search").map(|i| i["text"].as_str().unwrap()).collect();
        assert_eq!(searches, ["Search “plumber Lyon price”: 2 sources", "Search “plumber Lyon reviews”: 0 sources"]);
        assert!(items.iter().any(|i| i["text"] == "Searches edited on the computer: “plumber Lyon price”, “plumber Lyon reviews”"));
        let confirmation = items.iter().find(|i| i["kind"] == "confirmation").unwrap();
        assert_eq!(confirmation["state"], "accepted");
        assert_eq!(items.last().unwrap()["exposure"]["outputs"]["search"], 2);
    }

    #[test]
    fn refusing_the_queries_stops_the_research_before_anything_leaves() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let chat = engine.create(QUESTION).unwrap();
        let pending = pending_of(&engine, &chat);
        engine.confirm(pending["id"].as_str(), Some("reject"), None, None).unwrap();
        let view = engine.chat_json(&chat).unwrap();
        assert_eq!(view["chat"]["status"], "idle");
        let items = items_of(&engine, &chat);
        assert!(items.iter().any(|i| i["text"] == QUERIES_CANCELLED_MESSAGE));
        let exposure = &items.last().unwrap()["exposure"];
        assert!(exposure["outputs"].get("search").is_none(), "{exposure}");
    }

    /// Actions: the person's recipient, the exact action, its digest, done once, on this computer.
    #[test]
    fn actions_are_prepared_confirmed_and_done_once() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        // The person allows this recipient (payees.txt); without it the payment is refused (next test).
        engine.payees = vec!["lyon".into()];
        let chat = engine.create(QUESTION).unwrap();
        // Not before the answer.
        assert!(engine.action_prepare(&chat, 0, "quotes@plumbing.example").is_err());
        let pending = pending_of(&engine, &chat);
        engine.confirm(pending["id"].as_str(), Some("accept"), None, None).unwrap();
        run_until_idle(&mut engine, &chat);
        assert!(engine.action_do(&chat, "00").is_err(), "nothing prepared");
        assert!(engine.action_prepare(&chat, 5, "quotes@plumbing.example").is_err(), "no such action");
        assert!(engine.action_prepare(&chat, 0, "not an address").is_err());

        let message = engine.action_prepare(&chat, 0, "quotes@plumbing.example").unwrap();
        assert_eq!(message["kind"], "message");
        assert_eq!(message["to"], "quotes@plumbing.example");
        assert_eq!(message["seen_in_pages"], false);
        let action = items_of(&engine, &chat).into_iter().find(|i| i["kind"] == "action").unwrap();
        assert_eq!(message["content"], action["action"]["text"]);
        let digest = message["digest"].as_str().unwrap().to_owned();
        assert!(protocol::is_hex(&digest, 64));
        assert!(engine.action_do(&chat, &"0".repeat(64)).is_err(), "another digest");
        let done = engine.action_do(&chat, &digest).unwrap();
        assert_eq!(done["done"], "message");
        assert!(done["mailto"].as_str().unwrap().starts_with("mailto:quotes@plumbing.example?subject="));
        assert!(engine.action_do(&chat, &digest).is_err(), "once");
        assert!(engine.action_prepare(&chat, 0, "quotes@plumbing.example").is_err(), "already done");
        let items = items_of(&engine, &chat);
        let actions: Vec<&Value> = items.iter().filter(|i| i["kind"] == "action").collect();
        assert_eq!((actions[0]["state"].as_str(), actions[1]["state"].as_str()), (Some("done"), Some("suggested")));
        assert_eq!(items.last().unwrap()["kind"], "activity");
        let exposure = items.iter().rev().find(|i| i["kind"] == "exposure").unwrap();
        assert_eq!(exposure["exposure"]["outputs"]["message"], 1, "{exposure}");

        // A payment to an account also written in a page read ("Lyon directory") is flagged.
        let payment = engine.action_prepare(&chat, 1, "lyon").unwrap();
        assert_eq!((payment["kind"].as_str(), payment["seen_in_pages"].as_bool()), (Some("payment"), Some(true)));
        assert_eq!(payment["content"], "100000000000000000000000");
        let done = engine.action_do(&chat, payment["digest"].as_str().unwrap()).unwrap();
        assert_eq!(done["done"], "payment");
        assert!(items_of(&engine, &chat).iter().any(|i| i["tool"] == "action"
            && i["text"].as_str().unwrap().starts_with("Payment sent: ")));

        // A new question in the chat: the old answer's actions are no longer available.
        engine.post("And in Paris?", &chat).unwrap();
        assert!(engine.action_prepare(&chat, 1, "lyon").is_err());
    }

    #[test]
    fn a_payment_to_a_recipient_not_allowed_is_refused() {
        let mut engine = ChatEngine::with_ona_core(Default::default());
        let chat = engine.create(QUESTION).unwrap();
        let pending = pending_of(&engine, &chat);
        engine.confirm(pending["id"].as_str(), Some("accept"), None, None).unwrap();
        run_until_idle(&mut engine, &chat);
        let refused = engine.action_prepare(&chat, 1, "lyon").unwrap_err();
        assert!(refused.contains("not in the list"), "{refused}");
    }

    // Pool requests typed in the chat (pool_chat), against a fake pool core shaped like ona-core's replies
    // (docs/desktop/pool-commands.md): testnet tiers 0.1 and 0.5 NEAR, cash hourly cap 2 NEAR, vault 0 a staking pool.

    const N: u128 = pool_chat::NEAR;

    type Log = Arc<std::sync::Mutex<Vec<Value>>>;

    struct ChatPool {
        log: Log,
        /// The reply of the second deposit execute is "outcome unknown" (the agent queued the cash issue).
        queued_issue: bool,
        /// What `pool_recover` reports: signatures brought back (the agent dropped the issue when fewer than issued).
        recovered: u64,
        /// What a prepared entry leaves in the pool's cash, and an extra fee beyond one storage fee per note.
        left_in_cash: u128,
        extra_fee: u128,
        /// A second vault (1, staking, open) next to vault 0.
        second_vault: bool,
        /// The wallet holds 1 NEAR of cash and 2 NEAR in vault 0 (else 1 NEAR of cash only, and no note in privacy).
        holding: bool,
        /// No cash notes are held: a cash entry or payout is refused as ona-core does.
        no_cash: bool,
    }

    impl MissionCore for ChatPool {
        fn dispatch(&mut self, request: Value) -> Value {
            self.log.lock().unwrap().push(request.clone());
            // "all": the held cash (1 NEAR) or the vault holding (2 NEAR).
            let amount = |r: &Value| match r["amount"].as_str().unwrap_or("0") {
                "all" if r["op"] == "enter" => N,
                "all" => 2 * N,
                a => a.parse::<u128>().unwrap(),
            };
            let mut vaults = vec![json!({"vault": 0, "adapter": "staking", "target": "stake.testnet", "frozen": false,
                                         "share_price": "1000000000000000000", "hourly_cap": (N / 2).to_string(), "tiers": []})];
            if self.second_vault {
                vaults.push(json!({"vault": 1, "adapter": "staking", "target": "stake2.testnet", "frozen": false,
                                   "share_price": "1000000000000000000", "hourly_cap": null, "tiers": []}));
            }
            match request["cmd"].as_str().unwrap_or_default() {
                "pool_info" => json!({"ok": true, "mode": "real", "network": "testnet", "contract": "pool.testnet",
                    "cash": {"hourly_cap": (2 * N).to_string(), "tiers": [
                        {"tier": 0, "note_value": (N / 10).to_string(), "live": 3},
                        {"tier": 1, "note_value": (N / 2).to_string(), "live": 1}]},
                    "vaults": vaults,
                    "min_deposit": (N / 10).to_string(), "recommended": [N.to_string(), (2 * N).to_string()]}),
                "pool_privacy" if self.holding => json!({"ok": true, "mode": "real",
                    "wallet": {"smallest_set": 2, "notes": [{"vault": null, "tier": 1, "set": 2}, {"vault": 0, "tier": 0, "set": 11}]},
                    "vaults": [{"vault": 0, "frozen": false, "if_entered": 12}, {"vault": 1, "frozen": false, "if_entered": 3}],
                    "without_ona": 1}),
                "pool_privacy" => json!({"ok": true, "mode": "real", "wallet": {"smallest_set": null, "notes": []},
                    "vaults": [{"vault": 0, "frozen": false, "if_entered": 4}, {"vault": 1, "frozen": false, "if_entered": 3}],
                    "without_ona": 1}),
                "pool_prepare" if self.no_cash && (request["op"] == "enter" || request["op"] == "exit_cash") =>
                    json!({"ok": false, "mode": "real", "error": "no held notes for this"}),
                "pool_prepare" if request["op"] == "switch" => json!({"ok": true, "mode": "real", "prepared_id": "switch-1",
                    "summary": {"op": "switch", "from": request["from"], "to": request["to"], "amount": request["amount"],
                                "share_price": "1000000000000000000", "new_shares_value": (amount(&request) - N / 50).to_string(),
                                "left_in_cash": (N / 100).to_string(), "fees": {"storage": (N / 100).to_string()}}}),
                "pool_prepare" if request["op"] == "exit" => json!({"ok": true, "mode": "real", "prepared_id": "leave-1",
                    "summary": {"op": "exit", "from": request["from"], "amount": request["amount"],
                                "share_price": "1000000000000000000", "cash_value": (amount(&request) - N / 100).to_string(),
                                "left_in_cash": "0", "fees": {"storage": (N / 100).to_string()}}}),
                "pool_prepare" => match request["op"].as_str().unwrap_or_default() {
                    "deposit" => {
                        let a = amount(&request);
                        let mut summary = json!({"op": "deposit", "amount": a.to_string(), "account": request["account"],
                            "network": "testnet", "contract": "pool.testnet", "expires_at": 2_000_000_000_000_000_000u64,
                            "cash_notes": [{"tier": 1, "count": a / (N / 2), "note_value": (N / 2).to_string()}],
                            "recommended": [N.to_string(), (2 * N).to_string()],
                            "fees": {"storage_margin": (N / 100).to_string(), "refundable": "unused margin"},
                            "wallet_call": {"receiver": "pool.testnet", "method": "deposit", "args": {},
                                            "attached": (a + N / 100).to_string()}});
                        if a != N && a != 2 * N {
                            summary["warning"] = json!("this amount is not one of the recommended amounts");
                        }
                        json!({"ok": true, "mode": "real", "prepared_id": "dep-1", "summary": summary})
                    }
                    "enter" => {
                        let a = amount(&request);
                        let fee = (a / (N / 2)) * ona_core::pool::NOTE_STORAGE_FEE + self.extra_fee;
                        json!({"ok": true, "mode": "real", "prepared_id": "enter-1", "summary": {"op": "enter",
                            "vault": request["vault"], "amount": request["amount"],
                            "shares_value": (a - fee - self.left_in_cash).to_string(),
                            "left_in_cash": self.left_in_cash.to_string(), "fees": {"storage": fee.to_string()}}})
                    }
                    "exit_cash" => json!({"ok": true, "mode": "real", "prepared_id": "pay-1", "summary": {"op": "exit_cash",
                        "to": request["to"], "amount": request["amount"], "received": (amount(&request) - N / 100).to_string(),
                        "exit_limit": (3 * N).to_string(), "network": "testnet", "contract": "pool.testnet",
                        "fees": {"storage": (N / 100).to_string()}}}),
                    _ => json!({"ok": false, "error": "unknown operation"}),
                },
                "pool_execute" => match request["prepared_id"].as_str().unwrap_or_default() {
                    "enter-1" | "switch-1" | "leave-1" =>
                        json!({"ok": false, "mode": "real", "error": "outcome unknown, run pool_recover later: queued"}),
                    "pay-1" => json!({"ok": true, "mode": "real", "complete": true, "executed": "exit_cash", "steps": []}),
                    _ => json!({"ok": false, "error": "unknown, expired or already used prepared_id"}),
                },
                "pool_recover" => json!({"ok": true, "mode": "real", "spent": 0, "held_again": 0, "still_spending": 0,
                                         "signatures_recovered": self.recovered, "awaiting_signature": 0, "waiting": []}),
                "pool_portfolio" if self.holding => json!({"ok": true, "mode": "real", "total": (3 * N).to_string(), "vault_count": 1,
                    "cash": {"tiers": [{"tier": 1, "note_value": (N / 2).to_string(), "held": 2, "spending": 0}],
                             "value": N.to_string(), "spending_value": "0", "awaiting_signature": 0},
                    "vaults": [{"vault": 0, "share_price": "1000000000000000000", "frozen": false, "value": (2 * N).to_string(),
                                "spending_value": "0", "awaiting_signature": 0,
                                "tiers": [{"tier": 0, "note_value": (N / 10).to_string(), "held": 20, "spending": 0}]}]}),
                "pool_portfolio" => json!({"ok": true, "mode": "real", "total": N.to_string(), "vault_count": 1,
                    "cash": {"tiers": [{"tier": 1, "note_value": (N / 2).to_string(), "held": 2, "spending": 0}],
                             "value": N.to_string(), "spending_value": "0", "awaiting_signature": 0}, "vaults": []}),
                _ => json!({"ok": false, "error": "not a pool command"}),
            }
        }
    }

    impl ChatPool {
        /// What the wallet page's two `pool_execute` calls get back (they run on the wallet page's path, not here).
        fn issue(&self, second: bool) -> Value {
            match (second, self.queued_issue) {
                (false, _) => json!({"ok": true, "mode": "real", "complete": false, "executed": "deposit",
                    "sign_message": {"message": "ONA pool cash issue v1", "recipient": "pool.testnet", "nonce": "AA=="}}),
                (true, false) => json!({"ok": true, "mode": "real", "complete": true, "executed": "deposit",
                                        "steps": [{"issued_cash": 2}]}),
                (true, true) => json!({"ok": false, "mode": "real", "error": "outcome unknown, run pool_recover later"}),
            }
        }
    }

    fn fake_pool(log: &Log, queued_issue: bool) -> ChatPool {
        ChatPool { log: log.clone(), queued_issue, recovered: 2, left_in_cash: 0, extra_fee: 0, second_vault: false,
                   holding: false, no_cash: false }
    }

    fn pool_engine(queued_issue: bool) -> (ChatEngine, Log) {
        pool_engine_with(queued_issue, |_| {})
    }

    fn pool_engine_with(queued_issue: bool, adjust: impl Fn(&mut ChatPool) + Send + Sync + 'static) -> (ChatEngine, Log) {
        let log: Log = Default::default();
        let shared = log.clone();
        let mut engine = ChatEngine::new(move || {
            let mut fake = fake_pool(&shared, queued_issue);
            adjust(&mut fake);
            Box::new(fake)
        });
        engine.wallet_account = Some("alice.testnet".into());
        (engine, log)
    }

    /// "place 1 NEAR in vault 0", Yes, the wallet page opened, the deposit sent and the message signed.
    fn deposit_through_the_wallet(engine: &mut ChatEngine, log: &Log, queued: bool) -> String {
        let chat = engine.create_here("place 1 NEAR in vault 0").unwrap();
        ticks_until(engine, &chat, "waiting");
        let card = pool_card_of(engine, &chat)["card"]["id"].as_str().unwrap().to_owned();
        engine.pool_decide(&chat, &card, true).unwrap();
        ticks_until(engine, &chat, "waiting");
        assert_eq!(engine.take_wallet_requests().len(), 1);
        let fake = fake_pool(log, queued);
        engine.pool_wallet_step(&chat, &card, false, &fake.issue(false));
        engine.pool_wallet_step(&chat, &card, true, &fake.issue(true));
        chat
    }

    fn ticks_until(engine: &mut ChatEngine, chat: &str, status: &str) {
        for _ in 0..30 {
            if engine.chat_json(chat).unwrap()["chat"]["status"] == status {
                return;
            }
            engine.tick();
        }
        panic!("never {status}: {:?}", items_of(engine, chat));
    }

    fn pool_card_of(engine: &ChatEngine, chat: &str) -> Value {
        items_of(engine, chat).into_iter().rev().find(|i| i["kind"] == "pool").expect("a pool card")
    }

    fn sent(log: &Log, cmd: &str) -> Vec<Value> {
        log.lock().unwrap().iter().filter(|r| r["cmd"] == cmd).cloned().collect()
    }

    fn texts(engine: &ChatEngine, chat: &str) -> Vec<String> {
        items_of(engine, chat).iter().filter_map(|i| i["text"].as_str().map(String::from)).collect()
    }

    /// The flow the product owner asked for: the request, the card, Yes, the wallet page, the two wallet steps, the
    /// entry into the vault, each step reported in the chat.
    #[test]
    fn a_deposit_asked_in_the_chat_goes_through_the_wallet_then_into_the_vault() {
        for queued in [false, true] {
            let (mut engine, log) = pool_engine(queued);
            let chat = engine.create_here("place 1 NEAR in vault 0").unwrap();
            ticks_until(&mut engine, &chat, "waiting");
            let card = pool_card_of(&engine, &chat);
            assert_eq!(card["state"], "pending");
            let c = &card["card"];
            assert_eq!((c["op"].as_str(), c["amount"].as_str()), (Some("deposit"), Some(N.to_string().as_str())));
            assert_eq!(c["account"], "alice.testnet");
            assert_eq!((c["vault"]["vault"].as_u64(), c["vault"]["adapter"].as_str(), c["vault"]["target"].as_str()),
                       (Some(0), Some("staking"), Some("stake.testnet")));
            assert_eq!(c["blends_with"], 4, "pool_privacy's if_entered for vault 0");
            assert_eq!(c["recommended"], json!([N.to_string(), (2 * N).to_string()]));
            assert_eq!((c["is_recommended"].as_bool(), c["over_cap"].as_bool()), (Some(true), Some(false)));
            assert_eq!(c["hourly_cap"], (2 * N).to_string());
            assert_eq!(c["steps"].as_array().unwrap().len(), 4);
            assert_eq!(sent(&log, "pool_privacy")[0]["amount"], N.to_string());
            // Nothing leaves before Yes: one preparation (for the card), no wallet page.
            assert_eq!(sent(&log, "pool_prepare").len(), 1);
            assert!(engine.take_wallet_requests().is_empty());
            assert!(engine.pool_decide(&chat, "p-other", true).is_err());

            engine.pool_decide(&chat, c["id"].as_str().unwrap(), true).unwrap();
            assert!(engine.pool_decide(&chat, c["id"].as_str().unwrap(), true).is_err(), "answered once");
            ticks_until(&mut engine, &chat, "waiting");
            let requests = engine.take_wallet_requests();
            assert_eq!(requests.len(), 1, "{:?}", texts(&engine, &chat));
            let (chat_id, card_id, prepared) = &requests[0];
            assert_eq!((chat_id, card_id.as_str()), (&chat, c["id"].as_str().unwrap()));
            assert_eq!(prepared["summary"]["account"], "alice.testnet", "the connected wallet's account, not the model's");
            assert!(crate::wallet::Session::from_prepared(prepared).is_ok(), "the wallet page takes this preparation");
            let prepares = sent(&log, "pool_prepare");
            assert_eq!(prepares.len(), 2, "prepared again on Yes, for a fresh 5 minutes");
            assert_eq!((prepares[1]["account"].as_str(), prepares[1]["amount"].as_str()),
                       (Some("alice.testnet"), Some(N.to_string().as_str())));
            assert_eq!(pool_card_of(&engine, &chat)["state"], "accepted");

            engine.pool_wallet_opened(&chat, card_id, Ok("http://127.0.0.1:8797/wallet/x/".into()));
            let fake = fake_pool(&log, queued);
            engine.pool_wallet_step(&chat, card_id, false, &fake.issue(false));
            engine.pool_wallet_step(&chat, card_id, true, &fake.issue(true));
            ticks_until(&mut engine, &chat, "idle");
            let all = texts(&engine, &chat);
            assert!(all.iter().any(|t| t.starts_with("Your wallet page is open in the browser")), "{all:?}");
            assert!(all.iter().any(|t| t.starts_with("Deposit reported sent by your wallet page")), "{all:?}");
            if queued {
                assert!(all.iter().any(|t| t == "This deposit's 2 cash notes received from the pool agent (Recover)."), "{all:?}");
                assert!(!sent(&log, "pool_recover").is_empty());
            } else {
                assert!(all.iter().any(|t| t == "Cash issued: the pool agent signed 2 cash notes worth 1 NEAR."), "{all:?}");
            }
            let enter = sent(&log, "pool_prepare").into_iter().find(|r| r["op"] == "enter").expect("entry prepared");
            assert_eq!((enter["vault"].as_u64(), enter["amount"].as_str()), (Some(0), Some(N.to_string().as_str())));
            assert!(all.iter().any(|t| t.starts_with("Entry into vault 0 prepared: shares worth 0.996 NEAR, left in the \
                                                      pool's cash 0 NEAR (lost), storage fee 0.004 NEAR")), "{all:?}");
            assert!(all.iter().any(|t| t.starts_with("Entry into vault 0 queued by the pool agent")), "{all:?}");
            assert_eq!(sent(&log, "pool_execute").len(), 1, "only the entry: the deposit's executes are the wallet page's");
            assert_eq!(c["entry_fee"], (2 * ona_core::pool::NOTE_STORAGE_FEE).to_string(), "the card showed the entry fee");
        }
    }

    /// An entry that would leave money in the pool's cash, or cost a fee the card did not show, is not run on the
    /// first Yes: a second card asks, and runs that very preparation on Yes, or nothing on No.
    #[test]
    fn an_entry_that_differs_from_the_card_is_asked_again() {
        for (left, extra, accept) in [(N / 1000, 0, true), (0, N / 1000, false)] {
            let (mut engine, log) = pool_engine_with(false, move |f| {
                f.left_in_cash = left;
                f.extra_fee = extra;
            });
            let chat = deposit_through_the_wallet(&mut engine, &log, false);
            ticks_until(&mut engine, &chat, "waiting");
            assert!(sent(&log, "pool_execute").is_empty(), "not entered without the person");
            let card = pool_card_of(&engine, &chat);
            assert_eq!((card["card"]["op"].as_str(), card["state"].as_str()), (Some("enter"), Some("pending")));
            let reasons = card["card"]["reasons"].as_array().unwrap();
            assert_eq!(reasons.len(), 1);
            let reason = reasons[0].as_str().unwrap();
            if left > 0 {
                assert!(reason.contains("leave 0.001 NEAR in the pool's cash"), "{reason}");
            } else {
                assert!(reason.contains("its storage fee is 0.005 NEAR, not the 0.004 NEAR the card showed"), "{reason}");
            }
            let last_agent = texts(&engine, &chat).into_iter().rev().find(|t| t.starts_with("I did not put")).unwrap();
            assert!(last_agent.contains("Put them in anyway?"), "{last_agent}");
            engine.pool_decide(&chat, card["card"]["id"].as_str().unwrap(), accept).unwrap();
            ticks_until(&mut engine, &chat, "idle");
            let executes = sent(&log, "pool_execute");
            if accept {
                assert_eq!(executes.len(), 1);
                assert_eq!(executes[0]["prepared_id"], "enter-1", "the preparation the second card showed");
                assert_eq!(sent(&log, "pool_prepare").iter().filter(|r| r["op"] == "enter").count(), 1);
            } else {
                assert!(executes.is_empty());
                assert!(texts(&engine, &chat).last().unwrap().starts_with("Not put into the vault."));
            }
        }
    }

    /// A queued cash issue the agent finally drops: nothing waits any more, but this deposit's notes never came. The
    /// chat stops there; older cash is not entered in their place.
    #[test]
    fn a_dropped_cash_issue_stops_before_the_entry() {
        let (mut engine, log) = pool_engine_with(true, |f| f.recovered = 0);
        let chat = deposit_through_the_wallet(&mut engine, &log, true);
        ticks_until(&mut engine, &chat, "idle");
        assert!(!sent(&log, "pool_recover").is_empty());
        assert!(sent(&log, "pool_prepare").iter().all(|r| r["op"] != "enter"), "no entry with older notes");
        let last = texts(&engine, &chat).last().unwrap().clone();
        assert!(last.contains("the cash issue of this deposit was not completed: the pool agent signed 0 of its 2 cash \
                               notes and none is waiting any more"), "{last}");
        assert!(!texts(&engine, &chat).iter().any(|t| t.contains("received from the pool agent")));
    }

    /// "put my cash in vault 0": a card from the very preparation, which Yes runs (no second preparation); no wallet
    /// account is needed (ONA signs with the notes' own keys).
    #[test]
    fn cash_already_in_the_pool_goes_into_a_vault_on_yes() {
        for (text, amount) in [("put my cash in vault 0", "all".to_owned()), ("put 1 NEAR of my cash in vault 0", N.to_string())] {
            let (mut engine, log) = pool_engine(false);
            engine.wallet_account = None;
            let chat = engine.create_here(text).unwrap();
            ticks_until(&mut engine, &chat, "waiting");
            let card = pool_card_of(&engine, &chat);
            let c = &card["card"];
            assert_eq!((c["op"].as_str(), c["amount"].as_str()), (Some("cash_enter"), Some(amount.as_str())));
            assert_eq!(c["vault"]["adapter"], "staking");
            assert_eq!(c["title"], if amount == "all" { "Put all your cash into vault 0" } else { "Put 1 NEAR of your cash into vault 0" });
            let fee = 2 * ona_core::pool::NOTE_STORAGE_FEE;
            assert_eq!(c["shares_value"], (N - fee).to_string());
            assert_eq!((c["left_in_cash"].as_str(), c["fees"]["storage"].as_str()), (Some("0"), Some(fee.to_string().as_str())));
            assert_eq!(c["blends_with"], 4);
            assert_eq!(sent(&log, "pool_privacy")[0]["amount"], (N - fee).to_string(), "what the entry puts in");
            assert_eq!(sent(&log, "pool_prepare")[0]["amount"], amount);
            assert!(sent(&log, "pool_execute").is_empty(), "nothing runs before Yes");
            engine.pool_decide(&chat, c["id"].as_str().unwrap(), true).unwrap();
            ticks_until(&mut engine, &chat, "idle");
            assert_eq!(sent(&log, "pool_prepare").len(), 1, "Yes runs the card's preparation");
            assert_eq!(sent(&log, "pool_execute")[0]["prepared_id"], "enter-1");
            let all = texts(&engine, &chat);
            assert!(all.iter().any(|t| t.starts_with("Entry into vault 0 queued by the pool agent")), "{all:?}");
        }
    }

    #[test]
    fn shares_move_between_vaults_and_to_cash_on_yes_only() {
        let (mut engine, log) = pool_engine_with(false, |f| f.second_vault = true);
        let chat = engine.create_here("move vault 0 to vault 1").unwrap();
        ticks_until(&mut engine, &chat, "waiting");
        let c = pool_card_of(&engine, &chat)["card"].clone();
        assert_eq!((c["op"].as_str(), c["from"]["vault"].as_u64(), c["vault"]["vault"].as_u64()), (Some("switch"), Some(0), Some(1)));
        assert_eq!(c["title"], "Move all your shares of vault 0 to vault 1");
        assert_eq!((c["new_shares_value"].as_str(), c["left_in_cash"].as_str()),
                   (Some((2 * N - N / 50).to_string().as_str()), Some((N / 100).to_string().as_str())));
        assert_eq!(c["blends_with"], 3, "vault 1's figure");
        assert!(c["steps"][1].as_str().unwrap().contains("put my cash in vault 1"));
        let prepare = &sent(&log, "pool_prepare")[0];
        assert_eq!((prepare["op"].as_str(), prepare["from"].as_u64(), prepare["to"].as_u64(), prepare["amount"].as_str()),
                   (Some("switch"), Some(0), Some(1), Some("all")));
        engine.pool_decide(&chat, c["id"].as_str().unwrap(), true).unwrap();
        ticks_until(&mut engine, &chat, "idle");
        assert_eq!(sent(&log, "pool_execute")[0]["prepared_id"], "switch-1");
        assert!(texts(&engine, &chat).last().unwrap().contains("say “put my cash in vault 1” to finish the move"));

        // Leave: the vault's hourly exit cap (0.5 NEAR) is below what leaves: said on the card. No: nothing runs.
        let chat = engine.create_here("take my NEAR out of vault 0").unwrap();
        ticks_until(&mut engine, &chat, "waiting");
        let c = pool_card_of(&engine, &chat)["card"].clone();
        assert_eq!((c["op"].as_str(), c["from"]["vault"].as_u64()), (Some("leave"), Some(0)));
        assert_eq!(c["cash_value"], (2 * N - N / 100).to_string());
        assert_eq!((c["over_cap"].as_bool(), c["hourly_cap"].as_str()), (Some(true), Some((N / 2).to_string().as_str())));
        assert_eq!(c["cash_live"][1]["live"], 1);
        engine.pool_decide(&chat, c["id"].as_str().unwrap(), false).unwrap();
        assert_eq!(sent(&log, "pool_execute").len(), 1, "only the switch ran");

        let chat = engine.create_here("move vault 1 to vault 1").unwrap();
        ticks_until(&mut engine, &chat, "idle");
        assert!(texts(&engine, &chat).last().unwrap().contains("already in vault 1"));
    }

    #[test]
    fn what_cannot_be_done_is_refused_clearly() {
        let (mut engine, _) = pool_engine_with(false, |f| f.no_cash = true);
        let chat = engine.create_here("put my cash in vault 0").unwrap();
        ticks_until(&mut engine, &chat, "idle");
        let last = texts(&engine, &chat).last().unwrap().clone();
        assert!(last.contains("you have no notes as cash available for this"), "{last}");
        let chat = engine.create_here("move vault 0 to vault 1").unwrap();
        ticks_until(&mut engine, &chat, "idle");
        assert!(texts(&engine, &chat).last().unwrap().contains("there is no vault 1"));
        // A frozen vault takes no new money.
        let info = json!({"vaults": [{"vault": 0, "adapter": "staking", "frozen": true}]});
        assert!(resolve_vault(&info, &VaultRef::Index(0)).unwrap_err().contains("frozen"));
        assert_eq!(resolve_source(&info, &VaultRef::Index(0)), Ok(0), "but can still be left");
    }

    /// Questions about the person's pool are answered here, from the pool's reads, without the model.
    #[test]
    fn questions_about_the_pool_are_answered_locally() {
        let (mut engine, log) = pool_engine_with(false, |f| {
            f.holding = true;
            f.second_vault = true;
        });
        let mut ask = |text: &str| -> String {
            let chat = engine.create_here(text).unwrap();
            ticks_until(&mut engine, &chat, "idle");
            texts(&engine, &chat).last().unwrap().clone()
        };
        let caveat = "These are upper bounds counted on the chain";
        let total = ask("how much do I have?");
        assert!(total.starts_with("You have 3 NEAR in the pool: 1 NEAR as cash, 2 NEAR in vault 0 (staking, placed with \
                                   stake.testnet). Privacy: your least protected note blends in with at most 2 notes"), "{total}");
        assert!(total.contains(caveat));
        let vault = ask("what's in vault 0?");
        assert!(vault.starts_with("In vault 0 (staking, placed with stake.testnet) you hold 2 NEAR: 20 share notes, at \
                                   0.000001 NEAR per share. These notes blend in with at most 11 notes"), "{vault}");
        let empty = ask("what's in vault 1?");
        assert!(empty.starts_with("You hold nothing in vault 1 (staking, placed with stake2.testnet). If you put your cash \
                                   in, your notes would blend in with at most 3 notes."), "{empty}");
        assert!(ask("what's in vault 5?").starts_with("The pool has no vault 5"));
        let privacy = ask("how private is my position?");
        assert!(privacy.starts_with("Your position: your cash blends in with at most 2 notes of the same value; your notes \
                                     in vault 0 blend in with at most 11. Your least protected note blends in with at most 2."),
                "{privacy}");
        assert!(privacy.contains(caveat));
        let withdraw = ask("how much can I withdraw?");
        assert!(withdraw.starts_with("You can pay out 1 NEAR of cash now, to alice.testnet"), "{withdraw}");
        assert!(withdraw.contains("2 NEAR in vaults must first become cash: say “take my NEAR out of vault 0”"), "{withdraw}");
        let vaults = ask("what vaults are there?");
        assert_eq!(vaults, "The pool lists 2 vaults: vault 0 (staking, placed with stake.testnet): open, 0.000001 NEAR per \
                            share, you hold 2 NEAR; vault 1 (staking, placed with stake2.testnet): open, 0.000001 NEAR per share.");
        assert!(log.lock().unwrap().iter().all(|r| ["pool_info", "pool_portfolio", "pool_privacy"].contains(&r["cmd"].as_str().unwrap())),
                "only reads");
        // From the phone, the same question is a free research.
        let chat = engine.create("how much do I have?").unwrap();
        assert!(!texts(&engine, &chat).iter().any(|t| t.starts_with("You have")));
    }

    #[test]
    fn a_cancelled_wallet_page_stops_the_chat_deposit() {
        let (mut engine, _) = pool_engine(false);
        let chat = engine.create_here("deposit 1 NEAR").unwrap();
        ticks_until(&mut engine, &chat, "waiting");
        let card = pool_card_of(&engine, &chat)["card"]["id"].as_str().unwrap().to_owned();
        engine.pool_decide(&chat, &card, true).unwrap();
        ticks_until(&mut engine, &chat, "waiting");
        engine.pool_wallet_cancelled(&chat, &card);
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["status"], "idle");
        assert!(texts(&engine, &chat).last().unwrap().contains("cancelled before it was sent: nothing was taken"));
        assert_eq!(pool_card_of(&engine, &chat)["state"], "failed");
    }

    #[test]
    fn without_a_connected_wallet_nothing_is_asked_of_the_pool() {
        let (mut engine, log) = pool_engine(false);
        engine.wallet_account = None;
        let chat = engine.create_here("deposit 1 NEAR").unwrap();
        assert_eq!(texts(&engine, &chat).last().unwrap(), CONNECT_FIRST);
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["status"], "idle");
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn no_on_the_card_sends_nothing() {
        let (mut engine, log) = pool_engine(false);
        let chat = engine.create_here("put 2 NEAR in the staking vault").unwrap();
        ticks_until(&mut engine, &chat, "waiting");
        let card = pool_card_of(&engine, &chat);
        assert_eq!(card["card"]["vault"]["vault"], 0, "the only staking vault");
        engine.pool_decide(&chat, card["card"]["id"].as_str().unwrap(), false).unwrap();
        assert_eq!(pool_card_of(&engine, &chat)["state"], "rejected");
        for _ in 0..3 {
            engine.tick();
        }
        assert_eq!(sent(&log, "pool_prepare").len(), 1);
        assert!(engine.take_wallet_requests().is_empty());
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["status"], "idle");
    }

    #[test]
    fn the_card_says_when_the_amount_is_unusual_or_above_the_hourly_cap() {
        let (mut engine, _) = pool_engine(false);
        let chat = engine.create_here("deposit 2.5 NEAR").unwrap();
        ticks_until(&mut engine, &chat, "waiting");
        let c = pool_card_of(&engine, &chat)["card"].clone();
        assert_eq!((c["over_cap"].as_bool(), c["is_recommended"].as_bool()), (Some(true), Some(false)));
        assert!(c["warning"].as_str().unwrap().contains("recommended"));
        assert!(c["vault"].is_null(), "no vault named: cash only");
        assert_eq!(c["blends_with"], 2, "0.5-NEAR cash notes: 1 in circulation, plus the new one");
        assert_eq!(c["steps"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn a_vault_the_pool_does_not_list_is_refused_with_the_list() {
        let (mut engine, log) = pool_engine(false);
        let chat = engine.create_here("place 1 NEAR in vault 7").unwrap();
        ticks_until(&mut engine, &chat, "idle");
        let last = texts(&engine, &chat).last().unwrap().clone();
        assert!(last.contains("there is no vault 7: the pool lists vault 0 (staking, placed with stake.testnet)"), "{last}");
        assert!(sent(&log, "pool_prepare").is_empty());
        let chat = engine.create_here("place 1 NEAR in the lending vault").unwrap();
        ticks_until(&mut engine, &chat, "idle");
        assert!(texts(&engine, &chat).last().unwrap().contains("there is no open lending vault"));
    }

    #[test]
    fn a_payout_goes_to_the_connected_account_only() {
        let (mut engine, log) = pool_engine(false);
        let chat = engine.create_here("withdraw 0.5 NEAR").unwrap();
        ticks_until(&mut engine, &chat, "waiting");
        let c = pool_card_of(&engine, &chat)["card"].clone();
        assert_eq!((c["op"].as_str(), c["account"].as_str()), (Some("withdraw"), Some("alice.testnet")));
        assert_eq!(c["received"], (N / 2 - N / 100).to_string());
        assert_eq!(c["exit_limit"], (3 * N).to_string());
        // Another wallet connected meanwhile: the card no longer holds.
        engine.wallet_account = Some("bob.testnet".into());
        assert!(engine.pool_decide(&chat, c["id"].as_str().unwrap(), true).unwrap_err().contains("wallet changed"));
        engine.wallet_account = Some("alice.testnet".into());
        engine.pool_decide(&chat, c["id"].as_str().unwrap(), true).unwrap();
        ticks_until(&mut engine, &chat, "idle");
        assert!(sent(&log, "pool_prepare").iter().all(|r| r["to"] == "alice.testnet"));
        assert_eq!(sent(&log, "pool_execute")[0]["prepared_id"], "pay-1");
        assert!(texts(&engine, &chat).iter().any(|t| t == "Paid out to alice.testnet."));
    }

    #[test]
    fn the_portfolio_is_a_read_only_card() {
        let (mut engine, log) = pool_engine(false);
        engine.wallet_account = None;
        let chat = engine.create_here("show my portfolio").unwrap();
        ticks_until(&mut engine, &chat, "idle");
        let card = pool_card_of(&engine, &chat);
        assert_eq!((card["state"].as_str(), card["card"]["op"].as_str()), (Some("info"), Some("portfolio")));
        assert_eq!(card["card"]["portfolio"]["total"], N.to_string());
        assert_eq!(card["card"]["vaults_info"][0]["adapter"], "staking");
        assert!(sent(&log, "pool_prepare").is_empty());
    }

    /// The phone's messages stay free research: a pool request is read only when typed on this computer.
    #[test]
    fn a_pool_request_from_the_phone_is_not_read_as_one() {
        let (mut engine, log) = pool_engine(false);
        let chat = engine.create("place 1 NEAR in vault 0").unwrap();
        engine.post("place 1 NEAR in vault 0", &chat).unwrap();
        assert!(items_of(&engine, &chat).iter().all(|i| i["kind"] != "pool"));
        assert!(log.lock().unwrap().iter().all(|r| !r["cmd"].as_str().unwrap_or_default().starts_with("pool_")));
    }

    /// A slow research step (the model or Tor) does not hold the worker thread.
    #[test]
    fn a_slow_research_step_does_not_block_the_engine() {
        struct Slow(ona_core::Core);
        impl MissionCore for Slow {
            fn dispatch(&mut self, request: Value) -> Value {
                if request["cmd"] == "research_step" {
                    std::thread::sleep(std::time::Duration::from_millis(700));
                }
                MissionCore::dispatch(&mut self.0, request)
            }
        }
        let mut engine = ChatEngine::new(|| Box::new(Slow(ona_core::Core::new())));
        let chat = engine.create(QUESTION).unwrap();
        let pending = pending_of(&engine, &chat);
        engine.confirm(pending["id"].as_str(), Some("accept"), None, None).unwrap();
        let started = std::time::Instant::now();
        engine.tick();
        assert!(started.elapsed() < std::time::Duration::from_millis(600), "{:?}", started.elapsed());
        let view = engine.chat_json(&chat).unwrap();
        assert_eq!(view["chat"]["status"], "working");
        assert_eq!(view["chat"]["working"]["tool"], "search");
        let deadline = started + std::time::Duration::from_secs(20);
        while engine.chat_json(&chat).unwrap()["chat"]["status"] == "working" && std::time::Instant::now() < deadline {
            engine.tick();
        }
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["status"], "idle");
        assert!(items_of(&engine, &chat).iter().any(|i| i["kind"] == "answer"));
    }
}
