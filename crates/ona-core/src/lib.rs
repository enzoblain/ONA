//! `ona-core`: local mission logic. The model, the web and the chain are behind traits. The web and
//! the chain are faked in this version, and the model is faked unless a real one is configured.
//! Every reply is labelled with its `mode` so a fake can't pass for a result.

pub mod auditor;
pub mod checkpoint;
pub mod e2ee;
pub mod gate;
pub mod journal;
pub mod quote;
pub mod reader;
pub mod remote;
pub mod vault;

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::OsRng;
use rand::RngCore;
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

/// What the journal records about a real call. Never any content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealCall {
    pub model: String,
    /// Known only for a reply whose signature was verified.
    pub response_id: Option<String>,
    pub tokens_used: u64,
}

/// A model reply, always carrying how it was produced.
#[derive(Debug, Clone)]
pub struct ModelReply {
    pub text: String,
    pub mode: &'static str,
    /// `None` for a fake.
    pub call: Option<RealCall>,
}

/// A call that gave no usable reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelFailure {
    /// Fixed wording, safe for the journal.
    pub reason: &'static str,
    /// For the caller only. Not journaled.
    pub detail: String,
    /// `Some` if the request left the machine.
    pub call: Option<RealCall>,
    /// The input itself is unacceptable, so trying it again cannot help.
    pub refused_input: bool,
}

/// The planner sees only the mission, the reader sees only one page. Separate calls, no shared
/// context, and neither one has tools.
pub trait Model {
    fn plan(&mut self, mission: &str) -> Result<ModelReply, ModelFailure>;
    fn read_page(&mut self, page: &str) -> Result<ModelReply, ModelFailure>;

    /// Says whether a call could be made now, so a page is not fetched for nothing.
    fn ready(&self) -> Result<(), ModelFailure> {
        Ok(())
    }

    fn mode(&self) -> &'static str {
        MODE
    }
}

impl Model for Box<dyn Model> {
    fn plan(&mut self, mission: &str) -> Result<ModelReply, ModelFailure> {
        (**self).plan(mission)
    }

    fn read_page(&mut self, page: &str) -> Result<ModelReply, ModelFailure> {
        (**self).read_page(page)
    }

    fn ready(&self) -> Result<(), ModelFailure> {
        (**self).ready()
    }

    fn mode(&self) -> &'static str {
        (**self).mode()
    }
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
    error_mode: Option<&'static str>,
}

type Reply = Result<Value, String>;

impl<M: Model, W: Web, P: Payments> Mission<M, W, P> {
    pub fn open(model: M, web: W, payments: P, policy: Policy, salt: [u8; 32], text: &str) -> Self {
        let mut journal = Journal::new(salt);
        let fingerprint = journal.fingerprint(text.as_bytes());
        journal.append(Kind::MissionOpen, json!({"mission": fingerprint, "mode": model.mode()}));
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
            error_mode: None,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The mode of the model call just made, if any: an error only carries it when it came from one.
    pub fn take_error_mode(&mut self) -> Option<&'static str> {
        self.error_mode.take()
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
        let input = self.journal.fingerprint(self.mission_text.as_bytes());
        let reply = match self.model.plan(&self.mission_text) {
            Ok(reply) => reply,
            Err(failure) => return Err(self.model_failed("plan", &input, failure)),
        };
        self.commit_llm("plan", &input, &reply);
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

    fn commit_llm(&mut self, role: &str, input: &str, reply: &ModelReply) {
        self.error_mode = Some(reply.mode);
        let response = self.journal.fingerprint(reply.text.as_bytes());
        let mut data = json!({"role": role, "response": response, "mode": reply.mode});
        if let Some(call) = &reply.call {
            data["input"] = json!(input);
            data["model"] = json!(call.model);
            data["response_id"] = json!(call.response_id);
            data["tokens_used"] = json!(call.tokens_used);
            data["outcome"] = json!("ok");
        }
        self.journal.append(Kind::LlmCommit, data);
    }

    /// A request that left the machine is exposure even without a reply. One that never left is
    /// a refusal.
    fn model_failed(&mut self, role: &str, input: &str, failure: ModelFailure) -> String {
        self.error_mode = Some(self.model.mode());
        match &failure.call {
            Some(call) => self.journal.append(
                Kind::LlmCommit,
                json!({
                    "role": role,
                    "input": input,
                    "mode": remote::REAL_MODE,
                    "model": call.model,
                    "response_id": call.response_id,
                    "tokens_used": call.tokens_used,
                    "outcome": "failed",
                }),
            ),
            None => self.journal.append(Kind::GateDecision, json!({"output": "model", "result": failure.reason})),
        }
        failure.detail
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
        self.journal.append(Kind::ToolCommit, json!({"tool": "search", "query": fingerprint, "results": handles.len(), "mode": MODE}));
        self.advance();
        Ok(json!({"handles": handles, "mode": MODE}))
    }

    /// Reads one page through the isolated reader. A page that fails the schema is dropped.
    pub fn read(&mut self, handle: &str) -> Reply {
        self.at_step(Step::Read)?;
        let checked = self.policy.check_fetch(handle, &self.handles);
        self.gate_log("fetch", checked.as_ref().map(|_| *&()));
        checked.map_err(|e| e.as_str().to_string())?;
        if let Err(failure) = self.model.ready() {
            return Err(self.model_failed("reader", "", failure));
        }
        let page = self.web.fetch(handle).ok_or("page not available")?;
        self.count_output("fetch");
        let page_fingerprint = self.journal.fingerprint(page.as_bytes());
        let reply = match self.model.read_page(&page) {
            Ok(reply) => reply,
            Err(failure) => {
                // The page was fetched, so it counts. A page refused for its size uses up its step.
                // Otherwise the step stays: the budget limits retries of a call that was sent, and
                // the model stops after repeated failures that sent nothing.
                self.journal.append(Kind::ToolCommit, json!({"tool": "fetch", "page": page_fingerprint, "accepted": false, "mode": MODE}));
                if failure.refused_input {
                    self.advance();
                }
                return Err(self.model_failed("reader", &page_fingerprint, failure));
            }
        };
        self.commit_llm("reader", &page_fingerprint, &reply);
        let offer = reader::parse_offer(&reply.text, &page);
        let accepted = offer.is_ok();
        self.journal.append(Kind::ToolCommit, json!({"tool": "fetch", "page": page_fingerprint, "accepted": accepted, "mode": MODE}));
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
        self.journal.append(Kind::ToolCommit, json!({"tool": "contact", "firm": firm, "message": fingerprint, "mode": MODE}));
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
        let mode = self.model.mode();
        self.journal.append(Kind::MissionClose, json!({"steps_done": self.cursor, "mode": mode}));
        self.phase = Phase::Closed;
        self.mission_text.clear();
        self.offers.clear();
        self.ranked.clear();
        let head: String = self.journal.head().iter().map(|b| format!("{b:02x}")).collect();
        Ok(json!({"head": head, "entries": self.journal.len(), "mode": mode}))
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
    let mut mock_calls = 0u64;
    let mut real_calls = Vec::new();
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
            "llm_commit" => {
                model_calls += 1;
                if data["mode"] == remote::REAL_MODE {
                    real_calls.push(json!({
                        "role": data["role"],
                        "model": data["model"],
                        "response_id": data["response_id"],
                        "tokens_used": data["tokens_used"],
                        "outcome": data["outcome"],
                    }));
                } else {
                    mock_calls += 1;
                }
            }
            "gate_decision" if data["result"] != "allow" => {
                let key = format!("{}: {}", data["output"].as_str().unwrap_or("?"), data["result"].as_str().unwrap_or("?"));
                *refused.entry(key).or_insert(0) += 1;
            }
            "tx_submitted" => payments.push(json!({"to": data["to"], "amount": data["amount"]})),
            _ => {}
        }
    }
    let mode = match (!real_calls.is_empty(), any_mock) {
        (true, true) => "mixed",
        (false, true) => MODE,
        (_, false) => remote::REAL_MODE,
    };
    json!({
        "outputs": outputs,
        "refused_by_gate": refused,
        "firms_contacted": firms,
        "payments": payments,
        "model_calls": model_calls,
        "model_calls_mock": mock_calls,
        "model_calls_real": real_calls.len(),
        "real_calls": real_calls,
        "mode": mode,
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
    fn plan(&mut self, _mission: &str) -> Result<ModelReply, ModelFailure> {
        Ok(ModelReply { text: self.plan_reply.clone(), mode: MODE, call: None })
    }

    fn read_page(&mut self, page: &str) -> Result<ModelReply, ModelFailure> {
        // Pages in the demo carry the offer as a line starting with "OFFER ".
        let text = page
            .lines()
            .find_map(|l| l.strip_prefix("OFFER "))
            .unwrap_or("{}")
            .to_string();
        Ok(ModelReply { text, mode: MODE, call: None })
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
///
/// The model is the fake unless `use_real_model` is called. It moves from one mission to the next,
/// so its token budget covers all of them.
pub struct Core {
    mission: Option<CoreMission>,
    vault: Option<vault::Vault>,
    model: Option<Box<dyn Model>>,
    model_mode: &'static str,
}

type CoreMission = Mission<Box<dyn Model>, MockWeb, MockPayments>;

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
        Self { mission: None, vault: None, model: Some(Box::new(MockModel::default())), model_mode: MODE }
    }

    pub fn with_vault(vault: vault::Vault) -> Self {
        Self { vault: Some(vault), ..Self::new() }
    }

    /// Replaces the model. Refused during a mission, whose plan was made with the previous one.
    pub fn set_model(&mut self, model: Box<dyn Model>) -> Result<(), String> {
        if self.mission.is_some() {
            return Err("cannot change the model after a mission was opened".into());
        }
        self.model_mode = model.mode();
        self.model = Some(model);
        Ok(())
    }

    /// Switches to the real model. Only an explicit call with a full configuration does this.
    pub fn use_real_model(&mut self, config: remote::RemoteConfig) -> Result<(), String> {
        self.set_model(Box::new(remote::http_model(config)?))
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
            if self.mission.as_ref().is_some_and(|m| m.phase() != Phase::Closed) {
                return Err("close the current mission first".into());
            }
            let mission = text("mission")?;
            // Random, so that someone holding the journal cannot test a guessed mission against it.
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);
            let model = match self.mission.take() {
                Some(previous) => previous.model,
                None => self.model.take().ok_or("no model configured")?,
            };
            self.mission = Some(Mission::open(
                model,
                MockWeb::demo(),
                MockPayments::default(),
                demo_policy(),
                salt,
                &mission,
            ));
            return Ok(json!({"opened": true, "mode": self.model_mode}));
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
        let error_mode = self.mission.as_mut().and_then(|m| m.take_error_mode()).unwrap_or(MODE);
        match reply {
            Ok(mut v) => {
                v["ok"] = json!(true);
                v.to_string()
            }
            Err(e) => json!({"ok": false, "error": e, "mode": error_mode}).to_string(),
        }
    }
}
