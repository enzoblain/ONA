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
const CONTACT_MESSAGE: &str = "Bonjour, je souhaite un devis pour une consultation en droit du travail.";
const PLAN_MESSAGE: &str = "J'ai préparé un plan en {} étapes. Il est figé avant toute lecture du web : je ne contacterai personne et ne paierai rien sans votre accord. Validez-le pour que je commence.";
const RECIPIENT_MESSAGE: &str = "J'ai trouvé {} offres. Laquelle dois-je contacter ?";
const PAYMENT_MESSAGE: &str = "Le cabinet est contacté. Il reste à confirmer le paiement de la consultation.";
const DONE_MESSAGE: &str = "C'est fait. Voici ce qui est sorti de votre ordinateur pendant cette mission.";
const CANCELLED_MESSAGE: &str = "Mission arrêtée à votre demande. Rien d'autre ne sera envoyé.";
const BUSY_MESSAGE: &str = "Je suis encore sur la mission en cours : je vous tiens au courant ici.";
const QUERIES_MESSAGE: &str = "Voici les recherches que je propose. Rien ne quitte votre ordinateur avant votre accord : validez-les ici ou sur votre téléphone (on ne peut les modifier que sur l'ordinateur).";
const ANSWER_MESSAGE: &str = "Voici ma réponse, avec ses sources.";
const ACTIONS_MESSAGE: &str = "Voici ma réponse, avec ses sources. Je vous propose aussi {} action(s) : vous les complétez sur l'ordinateur, avec votre accord.";
const QUERIES_CANCELLED_MESSAGE: &str = "Recherche arrêtée à votre demande : aucune requête n'est partie.";

fn running_label(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "search" => "Recherche en cours…",
        "read" => "Lecture d'une page…",
        "compare" => "Comparaison des offres…",
        "contact" => "Prise de contact…",
        "prepare_payment" => "Préparation du paiement…",
        "pay" => "Envoi du paiement…",
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
    reply["error"].as_str().unwrap_or("erreur inconnue").to_owned()
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
    kind: Kind,
    runs: u64,
    item_count: u32,
    /// Creation order, to sort chats updated in the same second.
    order: u64,
}

impl Chat {
    pub fn status(&self) -> &'static str {
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
        let run = self.run.as_ref()?;
        if !matches!(run.phase, Phase::Running) {
            return None;
        }
        if let Some(r) = &run.research {
            return Some(match r.stage {
                Stage::Open | Stage::Propose => ("think".into(), "Choix des recherches…"),
                Stage::Steps if r.searched < r.queries => ("search".into(), "Recherche en cours…"),
                Stage::Steps if r.read < r.sources.len() => ("read".into(), "Lecture d'une page…"),
                _ => ("think".into(), "Rédaction de la réponse…"),
            });
        }
        if run.plan.is_empty() {
            return Some(("think".into(), "Préparation d'un plan…"));
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
}

impl ChatEngine {
    pub fn new(make_core: impl Fn() -> Box<dyn MissionCore> + Send + Sync + 'static) -> Self {
        let make_core: CoreFactory = Arc::new(make_core);
        Self {
            chats: Vec::new(), mode: "mock".into(), make_pool_core: make_core.clone(), make_core, count: 0, pool: None,
            payees: Vec::new(),
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

    /// A new conversation: a free research on `text`.
    pub fn create(&mut self, text: &str) -> Result<String, ProtocolError> {
        self.open_chat(text, Kind::Research)
    }

    /// A new conversation running the lawyer mission (kept for its tests).
    #[cfg(test)]
    pub fn create_mission(&mut self, text: &str) -> Result<String, ProtocolError> {
        self.open_chat(text, Kind::Mission)
    }

    fn open_chat(&mut self, text: &str, kind: Kind) -> Result<String, ProtocolError> {
        let text = clean(text).ok_or(ProtocolError::BadText)?;
        self.count += 1;
        // Random, never reused: an old signed request cannot target a new chat that took the same id.
        let id = format!("chat-{}", protocol::random_hex16());
        self.chats.push(Chat {
            id: id.clone(), title: title(&text), updated_at: now(), items: Vec::new(), decisions: Vec::new(),
            run: None, kind, runs: 0, item_count: 0, order: self.count,
        });
        self.say(&text, &id);
        Ok(id)
    }

    pub fn post(&mut self, text: &str, chat_id: &str) -> Result<(), ProtocolError> {
        let text = clean(text).ok_or(ProtocolError::BadText)?;
        self.chat_mut(chat_id).ok_or(ProtocolError::UnknownChat)?;
        self.say(&text, chat_id);
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
                let list: Vec<String> = accepted.iter().map(|q| format!("« {q} »")).collect();
                chat.add(Content::Activity { tool: "think".into(),
                                             text: format!("Recherches modifiées sur l'ordinateur : {}", list.join(", ")) });
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
    }

    fn say(&mut self, text: &str, chat_id: &str) {
        let make_core = &self.make_core;
        let payees = self.payees.clone();
        let Some(chat) = self.chats.iter_mut().find(|c| c.id == chat_id) else { return };
        chat.add(Content::User(text.to_owned()));
        if chat.run.as_ref().is_some_and(|r| matches!(r.phase, Phase::Running | Phase::Waiting(_))) {
            chat.add(Content::Agent(BUSY_MESSAGE.into()));
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
            .ok_or("cette recherche n'est plus en cours : l'action n'est plus disponible")?;
        let serial = run.serial;
        let suggested = chat.items.iter().any(|item| matches!(&item.content,
            Content::Action { run, action, done: false } if *run == serial && action["index"].as_u64() == Some(index)));
        if !suggested {
            return Err("cette action n'est plus disponible".into());
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
            .ok_or("aucune action préparée")? as u64;
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
            Some("payment") => format!("Paiement envoyé : {}", done["tx"].as_str().unwrap_or("?")),
            _ => "Message ouvert dans votre messagerie : à vous de l'envoyer".to_owned(),
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
        chat.add(Content::Activity { tool: "think".into(), text: "Lecture de votre demande et préparation d'un plan".into() });
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
            activity(format!("Recherche « avocat droit du travail paris » : {} résultats", run.handles.len()))
        }
        "read" => {
            let Some(handle) = run.handles.get(run.read_count).cloned() else { return fail(chat, "no page left to read") };
            let Some(reply) = run.core.poll(json!({"cmd": "read", "handle": handle})) else { return };
            run.read_count += 1;
            let offer = &reply["offer"];
            let (Some(firm), Some(price), Some(delay)) = (offer["firm_id"].as_str(), offer["price_cents"].as_i64(), offer["delay_days"].as_i64())
            else { return fail(chat, &error_of(&reply)) };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            activity(format!("Lecture d'une page : {firm}, {} €, sous {delay} jours", price / 100))
        }
        "compare" => {
            let Some(reply) = run.core.poll(json!({"cmd": "compare"})) else { return };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            run.ranked = reply["ranked"].as_array().cloned().unwrap_or_default();
            activity(format!("Comparaison : {} offres classées", run.ranked.len()))
        }
        "confirm_recipient" => {
            let ranked = run.ranked.clone();
            chat.add(Content::Agent(RECIPIENT_MESSAGE.replace("{}", &ranked.len().to_string())));
            return wait(chat, Request::Recipient(ranked));
        }
        "contact" => {
            let Some(reply) = run.core.poll(json!({"cmd": "contact", "message": CONTACT_MESSAGE})) else { return };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            activity(format!("Message générique envoyé à {}", run.chosen.as_deref().unwrap_or("?")))
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
            chat.add(activity("Paiement préparé à partir de l'annuaire".into()));
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
            activity(format!("Paiement envoyé : {}", reply["tx"].as_str().unwrap_or("?")))
        }
        other => return fail(chat, &format!("unknown step {other}")),
    };
    run.cursor += 1;
    chat.add(content);
}

fn plural(count: usize, word: &str) -> String {
    format!("{count} {word}{}", if count > 1 { "s" } else { "" })
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
            chat.add(think("Lecture de votre question et choix des recherches"));
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
            let error = reply["error"].as_str().unwrap_or("erreur inconnue");
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
                        Some(failure) => activity("search", format!("Recherche « {query} » : échec ({failure})")),
                        None => activity("search", format!("Recherche « {query} » : {}", plural(sources.len(), "source"))),
                    }
                }
                "read" => {
                    r.read += 1;
                    let notes = reply["notes"].as_u64().unwrap_or(0) as usize;
                    activity("read", format!("Lecture de {site} : {}", plural(notes, "note")))
                }
                "unreadable" => {
                    r.read += 1;
                    activity("read", format!("Lecture de {site} impossible : {error}"))
                }
                "unread" => {
                    r.read += 1;
                    activity("read", format!("Page de {site} non lue par le modèle : {error}"))
                }
                "refused" => {
                    r.read += 1;
                    activity("read", format!("Page de {site} non envoyée au modèle : {error}"))
                }
                "answered" => think("Réponse rédigée à partir des notes vérifiées"),
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
                ACTIONS_MESSAGE.replace("{}", &actions.len().to_string())
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
    chat.add(Content::Agent(format!("L'agent s'est arrêté : {error}.")));
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
        let chat = engine.create_mission("Trouve-moi un avocat en droit du travail à Paris").unwrap();
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
        let chat = engine.create_mission("  Trouve-moi un avocat en droit du travail à Paris  ").unwrap();
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
        let chat = engine.create_mission("Trouve un avocat").unwrap();
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
        assert_eq!(engine.post("bonjour", "chat-9"), Err(ProtocolError::UnknownChat));
        assert_eq!(engine.delete("chat-1"), Err(ProtocolError::UnknownChat));
        assert_eq!(engine.delete("chat-9"), Err(ProtocolError::UnknownChat));
        let chat = engine.create("Trouve un avocat").unwrap();
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
        let chat = engine.create("Trouve un avocat").unwrap();
        let other = engine.create("Trouve un avocat").unwrap();
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
        let chat = engine.create_mission("Trouve un avocat").unwrap();
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
        let chat = engine.create_mission("Trouve un avocat").unwrap();
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

    const QUESTION: &str = "Combien coûte un plombier à Lyon ? Écris-leur et paie un acompte";

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
        assert_eq!(search["text"], format!("Recherche « {} » : 2 sources", queries[0]));
        let reads: Vec<&Value> = items.iter().filter(|i| i["tool"] == "read").collect();
        assert_eq!(reads.len(), 2);
        assert!(reads[0]["text"].as_str().unwrap().starts_with("Lecture de "), "{}", reads[0]);
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
        assert!(engine.accept_queries(&id, vec!["Dupont plombier".into()]).unwrap_err().contains("protected"));
        assert!(engine.accept_queries(&id, vec![]).is_err());
        assert_eq!(engine.chat_json(&chat).unwrap()["chat"]["status"], "waiting");
        engine.accept_queries(&id, vec!["plombier Lyon tarif".into(), "plombier Lyon avis".into()]).unwrap();
        run_until_idle(&mut engine, &chat);
        let items = items_of(&engine, &chat);
        let searches: Vec<&str> = items.iter().filter(|i| i["tool"] == "search").map(|i| i["text"].as_str().unwrap()).collect();
        assert_eq!(searches, ["Recherche « plombier Lyon tarif » : 2 sources", "Recherche « plombier Lyon avis » : 0 source"]);
        assert!(items.iter().any(|i| i["text"] == "Recherches modifiées sur l'ordinateur : « plombier Lyon tarif », « plombier Lyon avis »"));
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
        let chat = engine.create(QUESTION).unwrap();
        // Not before the answer.
        assert!(engine.action_prepare(&chat, 0, "devis@plomberie.example").is_err());
        let pending = pending_of(&engine, &chat);
        engine.confirm(pending["id"].as_str(), Some("accept"), None, None).unwrap();
        run_until_idle(&mut engine, &chat);
        assert!(engine.action_do(&chat, "00").is_err(), "nothing prepared");
        assert!(engine.action_prepare(&chat, 5, "devis@plomberie.example").is_err(), "no such action");
        assert!(engine.action_prepare(&chat, 0, "pas une adresse").is_err());

        let message = engine.action_prepare(&chat, 0, "devis@plomberie.example").unwrap();
        assert_eq!(message["kind"], "message");
        assert_eq!(message["to"], "devis@plomberie.example");
        assert_eq!(message["seen_in_pages"], false);
        let action = items_of(&engine, &chat).into_iter().find(|i| i["kind"] == "action").unwrap();
        assert_eq!(message["content"], action["action"]["text"]);
        let digest = message["digest"].as_str().unwrap().to_owned();
        assert!(protocol::is_hex(&digest, 64));
        assert!(engine.action_do(&chat, &"0".repeat(64)).is_err(), "another digest");
        let done = engine.action_do(&chat, &digest).unwrap();
        assert_eq!(done["done"], "message");
        assert!(done["mailto"].as_str().unwrap().starts_with("mailto:devis@plomberie.example?subject="));
        assert!(engine.action_do(&chat, &digest).is_err(), "once");
        assert!(engine.action_prepare(&chat, 0, "devis@plomberie.example").is_err(), "already done");
        let items = items_of(&engine, &chat);
        let actions: Vec<&Value> = items.iter().filter(|i| i["kind"] == "action").collect();
        assert_eq!((actions[0]["state"].as_str(), actions[1]["state"].as_str()), (Some("done"), Some("suggested")));
        assert_eq!(items.last().unwrap()["kind"], "activity");
        let exposure = items.iter().rev().find(|i| i["kind"] == "exposure").unwrap();
        assert_eq!(exposure["exposure"]["outputs"]["message"], 1, "{exposure}");

        // A payment to an account also written in a page read ("Annuaire de Lyon") is flagged.
        let payment = engine.action_prepare(&chat, 1, "lyon").unwrap();
        assert_eq!((payment["kind"].as_str(), payment["seen_in_pages"].as_bool()), (Some("payment"), Some(true)));
        assert_eq!(payment["content"], "100000000000000000000000");
        let done = engine.action_do(&chat, payment["digest"].as_str().unwrap()).unwrap();
        assert_eq!(done["done"], "payment");
        assert!(items_of(&engine, &chat).iter().any(|i| i["tool"] == "action"
            && i["text"].as_str().unwrap().starts_with("Paiement envoyé")));

        // A new question in the chat: the old answer's actions are no longer available.
        engine.post("Et à Paris ?", &chat).unwrap();
        assert!(engine.action_prepare(&chat, 1, "lyon").is_err());
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
