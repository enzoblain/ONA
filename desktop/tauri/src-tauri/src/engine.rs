//! The agent's conversations: one ona-core per chat, driven step by step and stopped at each human confirmation.
//! Same behaviour and same JSON views as the macOS app's ChatEngine (desktop/ONADesktop/Core/Missions).

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::pairing::ProtocolError;
use crate::protocol::parse_payment_screen;

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

pub const MAX_TEXT: usize = 2000;
/// Amount of the demo payment, in yoctoNEAR (1 NEAR), as in ona-core's demo.
const DEMO_AMOUNT: &str = "1000000000000000000000000";
const CONTACT_MESSAGE: &str = "Bonjour, je souhaite un devis pour une consultation en droit du travail.";
const PLAN_MESSAGE: &str = "J'ai préparé un plan en {} étapes. Il est figé avant toute lecture du web : je ne contacterai personne et ne paierai rien sans votre accord. Validez-le pour que je commence.";
const RECIPIENT_MESSAGE: &str = "J'ai trouvé {} offres. Laquelle dois-je contacter ?";
const PAYMENT_MESSAGE: &str = "Le cabinet est contacté. Il reste à confirmer le paiement de la consultation.";
const DONE_MESSAGE: &str = "C'est fait. Voici ce qui est sorti de votre ordinateur pendant cette mission.";
const CANCELLED_MESSAGE: &str = "Mission arrêtée à votre demande. Rien d'autre ne sera envoyé.";
const BUSY_MESSAGE: &str = "Je suis encore sur la mission en cours : je vous tiens au courant ici.";

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

#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    Plan(Vec<String>),
    Recipient(Vec<Value>),
    Payment { to: String, amount: String, screen: String, digest: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    pub id: String,
    pub request: Request,
}

impl Pending {
    fn json(&self) -> Value {
        match &self.request {
            Request::Plan(steps) => json!({"id": self.id, "kind": "plan", "plan": steps}),
            Request::Recipient(offers) => json!({"id": self.id, "kind": "recipient", "offers": offers}),
            Request::Payment { to, amount, screen, digest } => json!({
                "id": self.id, "kind": "payment",
                "payment": {"to": to, "amount": amount, "screen": screen, "digest": digest},
            }),
        }
    }
}

enum Content {
    User(String),
    Agent(String),
    Activity { tool: String, text: String },
    Confirmation(Pending),
    Exposure(Value),
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

struct Run {
    core: Box<dyn MissionCore>,
    plan: Vec<String>,
    cursor: usize,
    phase: Phase,
    handles: Vec<String>,
    read_count: usize,
    ranked: Vec<Value>,
    chosen: Option<String>,
    confirmations: u32,
}

pub struct Chat {
    pub id: String,
    pub title: String,
    pub updated_at: u64,
    items: Vec<Item>,
    decisions: Vec<(String, &'static str)>,
    run: Option<Run>,
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
    make_core: Box<dyn Fn() -> Box<dyn MissionCore>>,
    count: u64,
}

impl ChatEngine {
    pub fn new(make_core: impl Fn() -> Box<dyn MissionCore> + 'static) -> Self {
        Self { chats: Vec::new(), mode: "mock".into(), make_core: Box::new(make_core), count: 0 }
    }

    pub fn with_ona_core() -> Self {
        Self::new(|| Box::new(ona_core::Core::new()))
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

    pub fn create(&mut self, text: &str) -> Result<String, ProtocolError> {
        let text = clean(text).ok_or(ProtocolError::BadText)?;
        self.count += 1;
        let id = format!("chat-{}", self.count);
        self.chats.push(Chat {
            id: id.clone(), title: title(&text), updated_at: now(), items: Vec::new(), decisions: Vec::new(),
            run: None, item_count: 0, order: self.count,
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

    /// A decision on a pending confirmation. Returns an error code on refusal.
    pub fn confirm(&mut self, id: Option<&str>, decision: Option<&str>, firm: Option<&str>, digest: Option<&str>)
                   -> Result<(), String> {
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
            Request::Plan(_) => run.core.dispatch(json!({"cmd": "accept_plan"})),
            Request::Recipient(_) => {
                let firm = firm.ok_or_else(bad)?;
                let reply = run.core.dispatch(json!({"cmd": "confirm_recipient", "firm": firm}));
                if ok(&reply) {
                    run.chosen = Some(firm.to_owned());
                }
                reply
            }
            // ona-core's gate checks the digest against the payment it prepared.
            Request::Payment { .. } => {
                let digest = digest.ok_or_else(bad)?;
                run.core.dispatch(json!({"cmd": "confirm_payment", "digest": digest}))
            }
        };
        if !ok(&reply) {
            return Err(reply["error"].as_str().map(String::from).unwrap_or_else(bad));
        }
        if !matches!(pending.request, Request::Plan(_)) {
            run.cursor += 1;
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
                step(chat);
            }
        }
    }

    fn say(&mut self, text: &str, chat_id: &str) {
        let make_core = &self.make_core;
        let Some(chat) = self.chats.iter_mut().find(|c| c.id == chat_id) else { return };
        chat.add(Content::User(text.to_owned()));
        if chat.run.as_ref().is_some_and(|r| matches!(r.phase, Phase::Running | Phase::Waiting(_))) {
            chat.add(Content::Agent(BUSY_MESSAGE.into()));
            return;
        }
        let core = chat.run.take().map(|r| r.core).unwrap_or_else(|| make_core());
        if let Some(mode) = start(chat, core, text) {
            self.mode = mode;
        }
    }

    // JSON views for the phone (protocol-draft.md, "Conversations")

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

/// Opens the mission and waits for the plan's approval. Returns ona-core's mode.
fn start(chat: &mut Chat, core: Box<dyn MissionCore>, text: &str) -> Option<String> {
    chat.run = Some(Run {
        core, plan: Vec::new(), cursor: 0, phase: Phase::Running, handles: Vec::new(), read_count: 0,
        ranked: Vec::new(), chosen: None, confirmations: 0,
    });
    let run = chat.run.as_mut()?;
    let opened = run.core.dispatch(json!({"cmd": "open", "mission": text}));
    if !ok(&opened) {
        fail(chat, &error_of(&opened));
        return None;
    }
    let mode = opened["mode"].as_str().map(String::from);
    chat.add(Content::Activity { tool: "think".into(), text: "Lecture de votre demande et préparation d'un plan".into() });
    let run = chat.run.as_mut()?;
    let proposal = run.core.dispatch(json!({"cmd": "propose_plan"}));
    let plan: Option<Vec<String>> = proposal["plan"].as_array()
        .map(|steps| steps.iter().filter_map(|s| s.as_str().map(String::from)).collect());
    match plan {
        Some(plan) if ok(&proposal) => {
            run.plan = plan.clone();
            chat.add(Content::Agent(PLAN_MESSAGE.replace("{}", &plan.len().to_string())));
            wait(chat, Request::Plan(plan));
        }
        _ => fail(chat, &error_of(&proposal)),
    }
    mode
}

fn step(chat: &mut Chat) {
    let Some(run) = chat.run.as_mut() else { return };
    let Some(tool) = run.plan.get(run.cursor).cloned() else { return finish(chat, false) };
    let activity = |text: String| Content::Activity { tool: tool.clone(), text };
    let content = match tool.as_str() {
        "search" => {
            let reply = run.core.dispatch(json!({"cmd": "search", "template": "lawyer", "value": "paris"}));
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            run.handles = reply["handles"].as_array().map(|h| h.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default();
            activity(format!("Recherche « avocat droit du travail paris » : {} résultats", run.handles.len()))
        }
        "read" => {
            let Some(handle) = run.handles.get(run.read_count).cloned() else { return fail(chat, "no page left to read") };
            let reply = run.core.dispatch(json!({"cmd": "read", "handle": handle}));
            run.read_count += 1;
            let offer = &reply["offer"];
            let (Some(firm), Some(price), Some(delay)) = (offer["firm_id"].as_str(), offer["price_cents"].as_i64(), offer["delay_days"].as_i64())
            else { return fail(chat, &error_of(&reply)) };
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            activity(format!("Lecture d'une page : {firm}, {} €, sous {delay} jours", price / 100))
        }
        "compare" => {
            let reply = run.core.dispatch(json!({"cmd": "compare"}));
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
            let reply = run.core.dispatch(json!({"cmd": "contact", "message": CONTACT_MESSAGE}));
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            activity(format!("Message générique envoyé à {}", run.chosen.as_deref().unwrap_or("?")))
        }
        "prepare_payment" => {
            let reply = run.core.dispatch(json!({"cmd": "prepare_payment", "amount": DEMO_AMOUNT}));
            let screen = reply["screen"].as_str().unwrap_or_default().to_owned();
            let digest = reply["digest"].as_str().unwrap_or_default().to_owned();
            let Some((amount, to)) = parse_payment_screen(&screen).filter(|_| ok(&reply) && !digest.is_empty())
            else { return fail(chat, &error_of(&reply)) };
            run.cursor += 1;
            let next_is_confirmation = run.plan.get(run.cursor).is_some_and(|t| t == "confirm_payment");
            chat.add(activity("Paiement préparé à partir de l'annuaire".into()));
            if next_is_confirmation {
                chat.add(Content::Agent(PAYMENT_MESSAGE.into()));
                wait(chat, Request::Payment { to, amount, screen, digest });
            }
            return;
        }
        "confirm_payment" => return fail(chat, "payment confirmation without a prepared payment"),
        "pay" => {
            let reply = run.core.dispatch(json!({"cmd": "pay"}));
            if !ok(&reply) { return fail(chat, &error_of(&reply)) }
            activity(format!("Paiement envoyé : {}", reply["tx"].as_str().unwrap_or("?")))
        }
        other => return fail(chat, &format!("unknown step {other}")),
    };
    run.cursor += 1;
    chat.add(content);
}

fn wait(chat: &mut Chat, request: Request) {
    let Some(run) = chat.run.as_mut() else { return };
    run.confirmations += 1;
    let pending = Pending { id: format!("{}-c-{}", chat.id, run.confirmations), request };
    run.phase = Phase::Waiting(pending.clone());
    chat.add(Content::Confirmation(pending));
}

fn finish(chat: &mut Chat, cancelled: bool) {
    let Some(run) = chat.run.as_mut() else { return };
    run.core.dispatch(json!({"cmd": "close"}));
    let mut exposure = run.core.dispatch(json!({"cmd": "exposure"}));
    if let Some(object) = exposure.as_object_mut() {
        object.remove("ok");
    }
    run.phase = if cancelled { Phase::Stopped } else { Phase::Done };
    chat.add(Content::Agent(if cancelled { CANCELLED_MESSAGE } else { DONE_MESSAGE }.into()));
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

    #[test]
    fn runs_the_full_mission_with_ona_core() {
        let mut engine = ChatEngine::with_ona_core();
        let chat = engine.create("  Trouve-moi un avocat en droit du travail à Paris  ").unwrap();
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
        assert_eq!(payment["payment"]["amount"], DEMO_AMOUNT);
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
        let mut engine = ChatEngine::with_ona_core();
        let chat = engine.create("Trouve un avocat").unwrap();
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
        let mut engine = ChatEngine::with_ona_core();
        assert_eq!(engine.create("   "), Err(ProtocolError::BadText));
        assert_eq!(engine.create(&"a".repeat(MAX_TEXT + 1)), Err(ProtocolError::BadText));
        assert_eq!(engine.post("bonjour", "chat-9"), Err(ProtocolError::UnknownChat));
        assert_eq!(engine.delete("chat-9"), Err(ProtocolError::UnknownChat));
        let chat = engine.create("Trouve un avocat").unwrap();
        engine.post("Et vite", &chat).unwrap();
        let view = engine.chat_json(&chat).unwrap();
        assert_eq!(view["chat"]["items"].as_array().unwrap().last().unwrap()["text"], BUSY_MESSAGE);
        engine.delete(&chat).unwrap();
        assert!(engine.chat_json(&chat).is_none());
    }

    #[test]
    fn titles_are_one_short_line() {
        assert_eq!(title("a\n b"), "a b");
        assert_eq!(title(&"é".repeat(60)).chars().count(), 48);
    }
}
