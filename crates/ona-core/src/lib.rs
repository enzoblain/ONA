//! `ona-core`: local mission logic. The model, the web and the chain are behind traits and are
//! faked in this version. Every reply is labelled `mode: mock` so a fake can't pass for a result.

pub mod gate;
pub mod journal;
pub mod reader;
pub mod vault;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use gate::{PaymentIntent, Policy};
use journal::{Journal, Kind};
use reader::Offer;

pub const MODE: &str = "mock";
pub const MAX_PLAN_STEPS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    Search,
    Read,
    Compare,
    ConfirmRecipient,
    Contact,
    PreparePayment,
    ConfirmPayment,
    Pay,
}

/// Checks a plan against the catalogue. The plan comes from a model, so nothing about it is taken
/// on trust: order and counts are enforced here.
pub fn validate_plan(plan: &[Step]) -> Result<(), &'static str> {
    if plan.is_empty() || plan.len() > MAX_PLAN_STEPS {
        return Err("plan length out of range");
    }
    let position = |step| plan.iter().position(|s| *s == step);
    let count = |step| plan.iter().filter(|s| **s == step).count();
    for once in [Step::Search, Step::Compare, Step::ConfirmRecipient, Step::Contact, Step::PreparePayment, Step::ConfirmPayment, Step::Pay] {
        if count(once) > 1 {
            return Err("a step appears too many times");
        }
    }
    let before = |a, b| match (position(a), position(b)) {
        (Some(x), Some(y)) => x < y,
        (_, None) => true,
        (None, Some(_)) => false,
    };
    let order = [
        (Step::Search, Step::Read),
        (Step::Read, Step::Compare),
        (Step::Compare, Step::ConfirmRecipient),
        (Step::ConfirmRecipient, Step::Contact),
        (Step::ConfirmRecipient, Step::PreparePayment),
        (Step::PreparePayment, Step::ConfirmPayment),
        (Step::ConfirmPayment, Step::Pay),
    ];
    if !order.iter().all(|(a, b)| before(*a, *b)) {
        return Err("steps are out of order");
    }
    if let (Some(confirm), Some(pay)) = (position(Step::ConfirmPayment), position(Step::Pay)) {
        if pay != confirm + 1 {
            return Err("the payment must directly follow its confirmation");
        }
    }
    Ok(())
}

/// A model reply, always carrying how it was produced.
#[derive(Debug, Clone)]
pub struct ModelReply {
    pub text: String,
    pub mode: &'static str,
}

/// The planner sees only the mission, the reader sees only one page. Separate calls, no shared
/// context, and neither one has tools.
pub trait Model {
    fn plan(&mut self, mission: &str) -> ModelReply;
    fn read_page(&mut self, page: &str) -> ModelReply;
}

pub trait Web {
    /// Returns opaque handles, never URLs chosen by a model.
    fn search(&mut self, query: &str) -> Vec<String>;
    fn fetch(&mut self, handle: &str) -> Option<String>;
    fn contact(&mut self, firm: &str, message: &str);
}

pub trait Payments {
    /// Submits the payment. Returns a transaction reference.
    fn pay(&mut self, intent: &PaymentIntent) -> String;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Phase {
    Open,
    PlanProposed,
    Running,
    Closed,
}

pub struct Mission<M, W, P> {
    pub model: M,
    pub web: W,
    pub payments: P,
    pub policy: Policy,
    pub journal: Journal,
    phase: Phase,
    mission_text: String,
    proposed: Vec<Step>,
    plan: Vec<Step>,
    cursor: usize,
    handles: BTreeSet<String>,
    offers: Vec<Offer>,
    ranked: Vec<Offer>,
    chosen: Option<String>,
    payment: Option<PaymentIntent>,
    confirmed: Option<String>,
    outputs: BTreeMap<&'static str, u32>,
}

type Reply = Result<Value, String>;

impl<M: Model, W: Web, P: Payments> Mission<M, W, P> {
    pub fn open(model: M, web: W, payments: P, policy: Policy, salt: [u8; 32], text: &str) -> Self {
        let mut journal = Journal::new(salt);
        let fingerprint = journal.fingerprint(text.as_bytes());
        journal.append(Kind::MissionOpen, json!({"mission": fingerprint, "mode": MODE}));
        Self {
            model,
            web,
            payments,
            policy,
            journal,
            phase: Phase::Open,
            mission_text: text.to_string(),
            proposed: Vec::new(),
            plan: Vec::new(),
            cursor: 0,
            handles: BTreeSet::new(),
            offers: Vec::new(),
            ranked: Vec::new(),
            chosen: None,
            payment: None,
            confirmed: None,
            outputs: BTreeMap::new(),
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn plan(&self) -> &[Step] {
        &self.plan
    }

    pub fn ranked(&self) -> &[Offer] {
        &self.ranked
    }

    /// Asks the planner once. Nothing from the web exists yet at this point.
    pub fn propose_plan(&mut self) -> Reply {
        if self.phase != Phase::Open {
            return Err("a plan was already proposed".into());
        }
        let reply = self.model.plan(&self.mission_text);
        self.commit_llm("plan", &reply);
        let plan: Vec<Step> =
            serde_json::from_str(&reply.text).map_err(|_| "plan does not match the catalogue".to_string())?;
        validate_plan(&plan).map_err(String::from)?;
        self.proposed = plan;
        self.phase = Phase::PlanProposed;
        Ok(json!({"plan": self.proposed, "mode": reply.mode}))
    }

    /// The human accepts the plan. From here on the list of steps cannot change.
    pub fn accept_plan(&mut self) -> Reply {
        if self.phase != Phase::PlanProposed {
            return Err("no plan to accept".into());
        }
        self.plan = std::mem::take(&mut self.proposed);
        let encoded = serde_json::to_vec(&self.plan).map_err(|e| e.to_string())?;
        let fingerprint = self.journal.fingerprint(&encoded);
        self.journal.append(Kind::PlanAccepted, json!({"plan": fingerprint, "steps": self.plan.len()}));
        self.phase = Phase::Running;
        Ok(json!({"accepted": true, "mode": MODE}))
    }

    fn at_step(&self, step: Step) -> Result<(), String> {
        if self.phase != Phase::Running {
            return Err("mission is not running".into());
        }
        match self.plan.get(self.cursor) {
            Some(current) if *current == step => Ok(()),
            current => Err(format!("step {step:?} is not next in the plan (next is {current:?})")),
        }
    }

    fn advance(&mut self) {
        self.cursor += 1;
    }

    fn commit_llm(&mut self, role: &str, reply: &ModelReply) {
        let response = self.journal.fingerprint(reply.text.as_bytes());
        self.journal.append(Kind::LlmCommit, json!({"role": role, "response": response, "mode": reply.mode}));
    }

    fn gate_log(&mut self, output: &str, verdict: Result<(), &gate::GateError>) {
        let result = match verdict {
            Ok(()) => "allow".to_string(),
            Err(e) => e.as_str().to_string(),
        };
        self.journal.append(Kind::GateDecision, json!({"output": output, "result": result}));
    }

    fn count_output(&mut self, name: &'static str) {
        *self.outputs.entry(name).or_insert(0) += 1;
    }

    pub fn search(&mut self, template: &str, value: &str) -> Reply {
        self.at_step(Step::Search)?;
        let query = self.policy.build_search(template, value);
        self.gate_log("search", query.as_ref().map(|_| ()));
        let query = query.map_err(|e| e.as_str().to_string())?;
        let handles = self.web.search(&query);
        self.count_output("search");
        self.handles.extend(handles.iter().cloned());
        let fingerprint = self.journal.fingerprint(query.as_bytes());
        self.journal.append(Kind::ToolCommit, json!({"tool": "search", "query": fingerprint, "results": handles.len()}));
        self.advance();
        Ok(json!({"handles": handles, "mode": MODE}))
    }

    /// Reads one page through the isolated reader. A page that fails the schema is dropped.
    pub fn read(&mut self, handle: &str) -> Reply {
        self.at_step(Step::Read)?;
        let checked = self.policy.check_fetch(handle, &self.handles);
        self.gate_log("fetch", checked.as_ref().map(|_| *&()));
        checked.map_err(|e| e.as_str().to_string())?;
        let page = self.web.fetch(handle).ok_or("page not available")?;
        self.count_output("fetch");
        let reply = self.model.read_page(&page);
        self.commit_llm("reader", &reply);
        let offer = reader::parse_offer(&reply.text, &page);
        let page_fingerprint = self.journal.fingerprint(page.as_bytes());
        let accepted = offer.is_ok();
        self.journal.append(Kind::ToolCommit, json!({"tool": "fetch", "page": page_fingerprint, "accepted": accepted}));
        // Consecutive Read steps are one per page, so a refused page still consumes its step.
        self.advance();
        let offer = offer.map_err(|e| e.as_str().to_string())?;
        self.offers.push(offer.clone());
        Ok(json!({"offer": offer, "mode": reply.mode}))
    }

    pub fn compare(&mut self) -> Reply {
        self.at_step(Step::Compare)?;
        let directory = &self.policy.directory;
        self.ranked = reader::rank(&self.offers, |firm| directory.contains_key(firm));
        self.advance();
        Ok(json!({"ranked": self.ranked, "mode": MODE}))
    }

    /// First human confirmation: the choice of the firm among the ranked offers.
    pub fn confirm_recipient(&mut self, firm: &str) -> Reply {
        self.at_step(Step::ConfirmRecipient)?;
        if !self.ranked.iter().any(|o| o.firm_id == firm) {
            return Err("firm is not among the compared offers".into());
        }
        self.chosen = Some(firm.to_string());
        self.journal.append(Kind::HumanConfirm, json!({"what": "recipient", "firm": firm}));
        self.advance();
        Ok(json!({"firm": firm, "mode": MODE}))
    }

    fn chosen_firm(&self) -> Result<String, String> {
        self.chosen.clone().ok_or_else(|| "no firm chosen".to_string())
    }

    pub fn contact(&mut self, message: &str) -> Reply {
        self.at_step(Step::Contact)?;
        let firm = self.chosen_firm()?;
        let checked = self.policy.check_contact(&firm, message);
        self.gate_log("contact", checked.as_ref().map(|_| *&()));
        checked.map_err(|e| e.as_str().to_string())?;
        self.web.contact(&firm, message);
        self.count_output("contact");
        let fingerprint = self.journal.fingerprint(message.as_bytes());
        self.journal.append(Kind::ToolCommit, json!({"tool": "contact", "firm": firm, "message": fingerprint}));
        self.advance();
        Ok(json!({"sent": true, "mode": MODE}))
    }

    /// Builds the payment. The recipient comes from the directory, the screen from these bytes.
    pub fn prepare_payment(&mut self, amount: u128) -> Reply {
        self.at_step(Step::PreparePayment)?;
        let firm = self.chosen_firm()?;
        let intent = self.policy.build_payment(&firm, amount);
        self.gate_log("prepare_payment", intent.as_ref().map(|_| ()));
        let intent = intent.map_err(|e| e.as_str().to_string())?;
        let reply = json!({"screen": intent.screen(), "digest": intent.digest(), "mode": MODE});
        self.payment = Some(intent);
        self.advance();
        Ok(reply)
    }

    /// Second human confirmation, bound to the digest shown on the payment screen.
    pub fn confirm_payment(&mut self, digest: &str) -> Reply {
        self.at_step(Step::ConfirmPayment)?;
        let intent = self.payment.clone().ok_or("no payment prepared")?;
        let checked = self.policy.check_payment(&intent, digest);
        self.gate_log("confirm_payment", checked.as_ref().map(|_| *&()));
        checked.map_err(|e| e.as_str().to_string())?;
        self.confirmed = Some(digest.to_string());
        self.journal.append(Kind::HumanConfirm, json!({"what": "payment", "digest": digest}));
        self.advance();
        Ok(json!({"confirmed": true, "mode": MODE}))
    }

    pub fn pay(&mut self) -> Reply {
        self.at_step(Step::Pay)?;
        let intent = self.payment.clone().ok_or("no payment prepared")?;
        let confirmed = self.confirmed.clone().ok_or("payment not confirmed")?;
        let checked = self.policy.check_payment(&intent, &confirmed);
        self.gate_log("pay", checked.as_ref().map(|_| *&()));
        checked.map_err(|e| e.as_str().to_string())?;
        let tx = self.payments.pay(&intent);
        self.count_output("pay");
        self.journal.append(
            Kind::TxSubmitted,
            json!({"to": intent.to, "amount": intent.amount.to_string(), "tx": tx, "mode": MODE}),
        );
        self.advance();
        Ok(json!({"tx": tx, "mode": MODE}))
    }

    /// Ends the mission and forgets the mission text and the offers.
    pub fn close(&mut self) -> Reply {
        if self.phase == Phase::Closed {
            return Err("mission already closed".into());
        }
        self.journal.append(Kind::MissionClose, json!({"steps_done": self.cursor, "mode": MODE}));
        self.phase = Phase::Closed;
        self.mission_text.clear();
        self.offers.clear();
        self.ranked.clear();
        let head: String = self.journal.head().iter().map(|b| format!("{b:02x}")).collect();
        Ok(json!({"head": head, "entries": self.journal.len(), "mode": MODE}))
    }

    pub fn exposure(&self) -> Value {
        exposure_report(&self.journal)
    }
}

/// What left the machine, rebuilt from the journal alone, not from the running mission's memory.
pub fn exposure_report(journal: &Journal) -> Value {
    let mut outputs: BTreeMap<String, u64> = BTreeMap::new();
    let mut refused: BTreeMap<String, u64> = BTreeMap::new();
    let mut payments = Vec::new();
    let mut firms = BTreeSet::new();
    let mut model_calls = 0u64;
    let mut any_mock = false;
    for entry in journal.entries() {
        let data = &entry["data"];
        if data["mode"] == MODE {
            any_mock = true;
        }
        match entry["kind"].as_str().unwrap_or_default() {
            "tool_commit" => {
                let tool = data["tool"].as_str().unwrap_or("unknown").to_string();
                *outputs.entry(tool).or_insert(0) += 1;
                if let Some(firm) = data["firm"].as_str() {
                    firms.insert(firm.to_string());
                }
            }
            "llm_commit" => model_calls += 1,
            "gate_decision" if data["result"] != "allow" => {
                let key = format!("{}: {}", data["output"].as_str().unwrap_or("?"), data["result"].as_str().unwrap_or("?"));
                *refused.entry(key).or_insert(0) += 1;
            }
            "tx_submitted" => payments.push(json!({"to": data["to"], "amount": data["amount"]})),
            _ => {}
        }
    }
    json!({
        "outputs": outputs,
        "refused_by_gate": refused,
        "firms_contacted": firms,
        "payments": payments,
        "model_calls": model_calls,
        "mode": if any_mock { MODE } else { "real" },
    })
}

// ---------- fakes, used by the CLI and the tests ----------

/// Deterministic stand-in for the model. It is honest: it follows the page's visible data.
pub struct MockModel {
    pub plan_reply: String,
}

impl Default for MockModel {
    fn default() -> Self {
        Self { plan_reply: DEMO_PLAN.to_string() }
    }
}

pub const DEMO_PLAN: &str = r#"["search","read","read","compare","confirm_recipient","contact","prepare_payment","confirm_payment","pay"]"#;

impl Model for MockModel {
    fn plan(&mut self, _mission: &str) -> ModelReply {
        ModelReply { text: self.plan_reply.clone(), mode: MODE }
    }

    fn read_page(&mut self, page: &str) -> ModelReply {
        // Pages in the demo carry the offer as a line starting with "OFFER ".
        let text = page
            .lines()
            .find_map(|l| l.strip_prefix("OFFER "))
            .unwrap_or("{}")
            .to_string();
        ModelReply { text, mode: MODE }
    }
}

pub struct MockWeb {
    pub pages: BTreeMap<String, String>,
    pub sent: Vec<(String, String)>,
    pub queries: Vec<String>,
}

impl MockWeb {
    pub fn demo() -> Self {
        let offer = |id: &str, price: u32, days: u16, span: &str| {
            format!(
                "{span}\nOFFER {}",
                json!({"firm_id":id,"specialties":["labour"],"price_cents":price,"delay_days":days,"source_spans":[span]})
            )
        };
        let mut pages = BTreeMap::new();
        pages.insert("h1".to_string(), offer("cabinet-a", 90_000, 7, "Consultation 900 euros, sous 7 jours"));
        pages.insert("h2".to_string(), offer("cabinet-b", 60_000, 10, "Forfait 600 euros, sous 10 jours"));
        Self { pages, sent: Vec::new(), queries: Vec::new() }
    }
}

impl Web for MockWeb {
    fn search(&mut self, query: &str) -> Vec<String> {
        self.queries.push(query.to_string());
        self.pages.keys().cloned().collect()
    }

    fn fetch(&mut self, handle: &str) -> Option<String> {
        self.pages.get(handle).cloned()
    }

    fn contact(&mut self, firm: &str, message: &str) {
        self.sent.push((firm.to_string(), message.to_string()));
    }
}

#[derive(Default)]
pub struct MockPayments {
    pub paid: Vec<PaymentIntent>,
}

impl Payments for MockPayments {
    fn pay(&mut self, intent: &PaymentIntent) -> String {
        self.paid.push(intent.clone());
        let hash: String = Sha256::digest(intent.bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect();
        format!("mock-tx-{hash}")
    }
}

pub fn demo_policy() -> Policy {
    let mut templates = BTreeMap::new();
    templates.insert(
        "lawyer".to_string(),
        gate::SearchTemplate {
            text: "avocat droit du travail {}".to_string(),
            allowed_values: ["paris", "lyon"].iter().map(|s| s.to_string()).collect(),
        },
    );
    let mut directory = BTreeMap::new();
    directory.insert("cabinet-a".to_string(), "cabinet-a.testnet".to_string());
    directory.insert("cabinet-b".to_string(), "cabinet-b.testnet".to_string());
    Policy {
        templates,
        protected_terms: vec!["Dupont".to_string()],
        directory,
        amount_cap: 5_000_000_000_000_000_000_000_000,
        max_message_len: 500,
    }
}

pub type DemoMission = Mission<MockModel, MockWeb, MockPayments>;

/// One JSON request, one JSON reply. Both front ends go through this single entry point.
pub struct Core {
    mission: Option<DemoMission>,
    vault: Option<vault::Vault>,
}

fn unix_now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "system clock is before 1970".to_string())
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

impl Core {
    pub fn new() -> Self {
        Self { mission: None, vault: None }
    }

    pub fn with_vault(vault: vault::Vault) -> Self {
        Self { mission: None, vault: Some(vault) }
    }

    fn run(&mut self, request: &Value) -> Reply {
        let text = |key: &str| -> Result<String, String> {
            request[key].as_str().map(String::from).ok_or_else(|| format!("missing field {key}"))
        };
        let cmd = text("cmd")?;
        if matches!(cmd.as_str(), "chat_save" | "chat_read" | "chat_keep" | "chat_forget") {
            let vault = self.vault.as_mut().ok_or("no vault configured")?;
            let now = unix_now()?;
            let id = text("id")?;
            return match cmd.as_str() {
                "chat_save" => {
                    vault.put(&id, &text("text")?, now)?;
                    Ok(json!({"saved": true, "expires_in_secs": vault::MAX_TTL_SECS, "mode": MODE}))
                }
                "chat_read" => Ok(json!({"text": vault.get(&id, now)?, "mode": MODE})),
                "chat_keep" => {
                    vault.keep(&id, now)?;
                    Ok(json!({"kept": true, "mode": MODE}))
                }
                _ => Ok(json!({"forgotten": vault.forget(&id)?, "mode": MODE})),
            };
        }
        if cmd == "open" {
            let mission = text("mission")?;
            let salt: [u8; 32] = Sha256::digest(mission.as_bytes()).into();
            self.mission = Some(Mission::open(
                MockModel::default(),
                MockWeb::demo(),
                MockPayments::default(),
                demo_policy(),
                salt,
                &mission,
            ));
            return Ok(json!({"opened": true, "mode": MODE}));
        }
        let m = self.mission.as_mut().ok_or("no open mission")?;
        match cmd.as_str() {
            "propose_plan" => m.propose_plan(),
            "accept_plan" => m.accept_plan(),
            "search" => m.search(&text("template")?, &text("value")?),
            "read" => m.read(&text("handle")?),
            "compare" => m.compare(),
            "confirm_recipient" => m.confirm_recipient(&text("firm")?),
            "contact" => m.contact(&text("message")?),
            "prepare_payment" => {
                let amount = text("amount")?.parse::<u128>().map_err(|_| "bad amount".to_string())?;
                m.prepare_payment(amount)
            }
            "confirm_payment" => m.confirm_payment(&text("digest")?),
            "pay" => m.pay(),
            "close" => m.close(),
            "exposure" => Ok(m.exposure()),
            other => Err(format!("unknown command {other}")),
        }
    }

    pub fn dispatch(&mut self, request: &str) -> String {
        let reply = match serde_json::from_str::<Value>(request) {
            Ok(v) => self.run(&v),
            Err(_) => Err("request is not valid JSON".to_string()),
        };
        match reply {
            Ok(mut v) => {
                v["ok"] = json!(true);
                v.to_string()
            }
            Err(e) => json!({"ok": false, "error": e, "mode": MODE}).to_string(),
        }
    }
}
