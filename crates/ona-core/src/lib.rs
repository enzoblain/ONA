//! `ona-core`: local mission logic. The model, the web and the chain are behind traits. The web and
//! the chain are faked in this version, and the model is faked unless a real one is configured.
//! Every reply is labelled with its `mode` so a fake can't pass for a result.

pub mod attestation;
pub mod auditor;
pub mod checkpoint;
pub mod e2ee;
pub mod gate;
pub mod journal;
pub mod pool;
pub mod pool_agent;
mod private_fs;
pub mod pseudonym;
pub mod quote;
pub mod reader;
pub mod remote;
pub mod research;
pub mod tor;
pub mod vault;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read, Write};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use gate::{GateError, PaymentIntent, Policy};
use journal::{Journal, Kind};
use pseudonym::{Pseudonyms, MAX_TERMS, MAX_TERM_CHARS, MIN_TERM_CHARS};
use reader::{Offer, ReadError};

pub const MODE: &str = "mock";
pub const MAX_PLAN_STEPS: usize = 12;
/// Longest request line `serve` accepts.
pub const MAX_REQUEST_BYTES: usize = 65_536;
/// Said in every exposure report with a real model call: what the model key check (`attestation`) covers, and what
/// it does not.
pub const ENCLAVE_TRUST_WARNING: &str =
    "a model key is used only if an Intel-signed TDX quote binds it to this request and shows the NEAR AI system and deployment observed on 10/11/2026; not checked: the NVIDIA GPU evidence, which is not bound to that quote, and what the code of that deployment does with the prompt";

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
/// on trust: order and counts are enforced here. Every `read` sits in one block between `search`
/// and `compare`, so nothing is read from the web once offers are compared.
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
    let reads: Vec<usize> = plan.iter().enumerate().filter(|(_, s)| **s == Step::Read).map(|(i, _)| i).collect();
    if let (Some(first), Some(last)) = (reads.first(), reads.last()) {
        if last - first + 1 != reads.len() {
            return Err("every read must come in one block, between search and compare");
        }
        if position(Step::Compare).is_some_and(|compare| *last > compare) {
            return Err("every read must come in one block, between search and compare");
        }
    }
    if let (Some(confirm), Some(pay)) = (position(Step::ConfirmPayment), position(Step::Pay)) {
        if pay != confirm + 1 {
            return Err("the payment must directly follow its confirmation");
        }
    }
    Ok(())
}

/// What the journal records about a real call. Never any content.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealCall {
    pub model: String,
    /// Known only for a reply whose signature was verified.
    pub response_id: Option<String>,
    pub tokens_used: u64,
    /// The relay every request of this call went to.
    pub relay: String,
    /// HTTP requests that left for the relay: attestation, chat and signature requests.
    pub requests: u32,
    /// Bytes handed to the transport: paths, header names and values, and bodies. HTTP framing
    /// and TLS overhead are not counted.
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// False when only the attestation request left and the prompt never did.
    pub prompt_sent: bool,
    /// Size of the encrypted chat body, which the relay passes on to NEAR AI.
    pub prompt_bytes: u64,
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
    /// `Some` if any request left the machine, even one without the prompt.
    pub call: Option<RealCall>,
    /// The input itself is unacceptable, so trying it again cannot help.
    pub refused_input: bool,
}

/// The planner sees only the mission, the reader sees only one page. Separate calls, no shared
/// context, and neither one has tools. Both receive their text after pseudonymisation.
pub trait Model {
    fn plan(&mut self, mission: &str) -> Result<ModelReply, ModelFailure>;
    fn read_page(&mut self, page: &str) -> Result<ModelReply, ModelFailure>;

    /// Free research (`research`): proposes search queries for a question. Each role is its own call, with no shared
    /// context; a model that does not do research refuses.
    fn research_queries(&mut self, _question: &str) -> Result<ModelReply, ModelFailure> {
        Err(research::unsupported())
    }

    /// Free research: notes from one page, each with a quote copied from it. `input` holds the question and the page.
    fn research_read(&mut self, _input: &str) -> Result<ModelReply, ModelFailure> {
        Err(research::unsupported())
    }

    /// Free research: the answer, from the checked notes only (never a page), and up to two suggested actions.
    fn research_answer(&mut self, _input: &str) -> Result<ModelReply, ModelFailure> {
        Err(research::unsupported())
    }

    /// Says whether a call could be made now, so a page is not fetched for nothing.
    fn ready(&self) -> Result<(), ModelFailure> {
        Ok(())
    }

    fn mode(&self) -> &'static str {
        MODE
    }
}

impl Model for Box<dyn Model> {
    fn research_queries(&mut self, question: &str) -> Result<ModelReply, ModelFailure> {
        (**self).research_queries(question)
    }

    fn research_read(&mut self, input: &str) -> Result<ModelReply, ModelFailure> {
        (**self).research_read(input)
    }

    fn research_answer(&mut self, input: &str) -> Result<ModelReply, ModelFailure> {
        (**self).research_answer(input)
    }

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
    /// The directory firm a handle's page belongs to, decided by the search and never by the
    /// page. An offer read from that page counts only for this firm.
    fn source(&self, handle: &str) -> Option<String>;
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
    mission_id: String,
    mission_text: String,
    pseudonyms: Pseudonyms,
    planner_asked: bool,
    proposed: Vec<Step>,
    plan: Vec<Step>,
    cursor: usize,
    handles: BTreeSet<String>,
    read_handles: BTreeSet<String>,
    offers: Vec<Offer>,
    ranked: Vec<Offer>,
    chosen: Option<String>,
    payment: Option<PaymentIntent>,
    confirmed: Option<String>,
    outputs: BTreeMap<&'static str, u32>,
    error_mode: Option<&'static str>,
}

type Reply = Result<Value, String>;

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl<M: Model, W: Web, P: Payments> Mission<M, W, P> {
    pub fn open(model: M, web: W, payments: P, policy: Policy, salt: [u8; 32], text: &str) -> Self {
        let mut journal = Journal::new(salt);
        let fingerprint = journal.fingerprint(text.as_bytes());
        journal.append(Kind::MissionOpen, json!({"mission": fingerprint, "mode": model.mode()}));
        let pseudonyms = Pseudonyms::new(&policy.protected_terms);
        Self {
            model,
            web,
            payments,
            policy,
            journal,
            phase: Phase::Open,
            mission_id: random_hex(16),
            mission_text: text.to_string(),
            pseudonyms,
            planner_asked: false,
            proposed: Vec::new(),
            plan: Vec::new(),
            cursor: 0,
            handles: BTreeSet::new(),
            read_handles: BTreeSet::new(),
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

    /// Random per mission. Part of the payment confirmation digest.
    pub fn mission_id(&self) -> &str {
        &self.mission_id
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

    /// Declares more protected terms for this mission (names, identifiers). Allowed only before
    /// the planner is asked. A term matches as a whole word; write it `*between asterisks*` to match
    /// it inside words too. They are replaced by pseudonyms before anything goes to the model, and
    /// the gate refuses them in searches, messages and model input.
    pub fn protect(&mut self, terms: &[String]) -> Reply {
        if self.phase != Phase::Open || self.planner_asked {
            return Err("protected terms must be declared before the plan is asked".into());
        }
        let terms: Vec<String> = terms.iter().map(|t| t.trim().to_string()).collect();
        if terms.iter().any(|t| !(MIN_TERM_CHARS..=MAX_TERM_CHARS).contains(&pseudonym::term_len(t))) {
            return Err(format!("a protected term must have {MIN_TERM_CHARS} to {MAX_TERM_CHARS} characters"));
        }
        if self.policy.protected_terms.len() + terms.len() > MAX_TERMS {
            return Err(format!("at most {MAX_TERMS} protected terms"));
        }
        self.policy.protected_terms.extend(terms.iter().cloned());
        self.pseudonyms = Pseudonyms::new(&self.policy.protected_terms);
        self.journal.append(Kind::HumanConfirm, json!({"what": "protected_terms", "count": terms.len()}));
        Ok(json!({"protected_terms": self.policy.protected_terms.len(), "pseudonyms": self.pseudonyms.len(), "mode": MODE}))
    }

    /// Pseudonymises a text for the model, then refuses it if a protected term is still in it.
    fn outgoing(&mut self, text: &str) -> Result<(String, usize), String> {
        let (sent, replaced) = self.pseudonyms.apply(text);
        if let Err(e) = self.policy.check_terms(&sent) {
            self.gate_log("model", Err(&e));
            return Err(e.as_str().to_string());
        }
        Ok((sent, replaced))
    }

    /// Asks the planner once. Nothing from the web exists yet at this point.
    pub fn propose_plan(&mut self) -> Reply {
        if self.phase != Phase::Open {
            return Err("a plan was already proposed".into());
        }
        let mission = self.mission_text.clone();
        let (sent, replaced) = self.outgoing(&mission)?;
        self.planner_asked = true;
        let input = self.journal.fingerprint(sent.as_bytes());
        let reply = match self.model.plan(&sent) {
            Ok(reply) => reply,
            Err(failure) => return Err(self.model_failed("plan", &input, replaced, failure)),
        };
        self.commit_llm("plan", &input, replaced, &reply);
        let text = self.pseudonyms.restore(&reply.text);
        let plan: Vec<Step> = serde_json::from_str(&text).map_err(|_| "plan does not match the catalogue".to_string())?;
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

    fn call_data(data: &mut Value, call: &RealCall) {
        call_data(data, call)
    }
}

/// The journal fields of a real call: never any content.
pub(crate) fn call_data(data: &mut Value, call: &RealCall) {
    data["model"] = json!(call.model);
    data["response_id"] = json!(call.response_id);
    data["tokens_used"] = json!(call.tokens_used);
    data["relay"] = json!(call.relay);
    data["requests"] = json!(call.requests);
    data["bytes_sent"] = json!(call.bytes_sent);
    data["bytes_received"] = json!(call.bytes_received);
    data["prompt_sent"] = json!(call.prompt_sent);
    data["prompt_bytes"] = json!(call.prompt_bytes);
}

impl<M: Model, W: Web, P: Payments> Mission<M, W, P> {
    fn commit_llm(&mut self, role: &str, input: &str, replaced: usize, reply: &ModelReply) {
        self.error_mode = Some(reply.mode);
        let response = self.journal.fingerprint(reply.text.as_bytes());
        let mut data = json!({"role": role, "response": response, "mode": reply.mode, "pseudonyms": replaced});
        if let Some(call) = &reply.call {
            data["input"] = json!(input);
            Self::call_data(&mut data, call);
            data["outcome"] = json!("ok");
        }
        self.journal.append(Kind::LlmCommit, data);
    }

    /// Any request that left the machine is exposure, even without a reply and even when only the
    /// attestation request left. One that never left is a refusal.
    fn model_failed(&mut self, role: &str, input: &str, replaced: usize, failure: ModelFailure) -> String {
        self.error_mode = Some(self.model.mode());
        match &failure.call {
            Some(call) => {
                let mut data = json!({
                    "role": role,
                    "input": input,
                    "mode": remote::REAL_MODE,
                    "pseudonyms": replaced,
                    "outcome": if call.prompt_sent { "failed" } else { "prompt_not_sent" },
                });
                Self::call_data(&mut data, call);
                self.journal.append(Kind::LlmCommit, data);
            }
            None => self.journal.append(Kind::GateDecision, json!({"output": "model", "result": failure.reason})),
        }
        failure.detail
    }

    fn gate_log(&mut self, output: &str, verdict: Result<(), &GateError>) {
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
        self.journal.append(
            Kind::ToolCommit,
            json!({"tool": "search", "party": "search engine", "bytes_sent": query.len(), "query": fingerprint, "results": handles.len(), "mode": MODE}),
        );
        self.advance();
        Ok(json!({"handles": handles, "mode": MODE}))
    }

    /// Reads one page through the isolated reader. A page that fails the schema is dropped.
    pub fn read(&mut self, handle: &str) -> Reply {
        self.at_step(Step::Read)?;
        let checked = self.policy.check_fetch(handle, &self.handles);
        self.gate_log("fetch", checked.as_ref().map(|_| ()));
        checked.map_err(|e| e.as_str().to_string())?;
        if self.read_handles.contains(handle) {
            return Err("this page was already read".into());
        }
        if let Err(failure) = self.model.ready() {
            return Err(self.model_failed("reader", "", 0, failure));
        }
        let party = format!("site {handle}");
        // Recorded before the answer is known: a request that left counts even without a page.
        let page = match self.web.fetch(handle) {
            Some(page) => page,
            None => {
                self.count_output("fetch");
                self.journal.append(
                    Kind::ToolCommit,
                    json!({"tool": "fetch", "party": party, "bytes_sent": handle.len(), "available": false, "mode": MODE}),
                );
                return Err("page not available".into());
            }
        };
        self.count_output("fetch");
        self.read_handles.insert(handle.to_string());
        let page_fingerprint = self.journal.fingerprint(page.as_bytes());
        let fetched = |accepted: bool| {
            json!({"tool": "fetch", "party": party, "bytes_sent": handle.len(), "page": page_fingerprint, "accepted": accepted, "mode": MODE})
        };
        let (sent, replaced) = match self.outgoing(&page) {
            Ok(outgoing) => outgoing,
            Err(e) => {
                self.journal.append(Kind::ToolCommit, fetched(false));
                self.advance();
                return Err(e);
            }
        };
        let reply = match self.model.read_page(&sent) {
            Ok(reply) => reply,
            Err(failure) => {
                // The page was fetched, so it counts. A page refused for its size uses up its step.
                // Otherwise the step stays: the budget limits retries of a call that was sent, and
                // the model stops after repeated failures that sent nothing.
                self.journal.append(Kind::ToolCommit, fetched(false));
                if failure.refused_input {
                    self.advance();
                } else {
                    self.read_handles.remove(handle);
                }
                return Err(self.model_failed("reader", &page_fingerprint, replaced, failure));
            }
        };
        self.commit_llm("reader", &page_fingerprint, replaced, &reply);
        // Excerpts are checked against the text the reader was given (pseudonyms in place), then
        // the pseudonyms are put back for display.
        let pseudonyms = &self.pseudonyms;
        let offer = match self.web.source(handle) {
            Some(source) => reader::parse_offer(&reply.text, &sent, &source).map_err(|e| e.as_str().to_string()),
            None => Err(ReadError::NotTheSource.as_str().to_string()),
        }
        .map(|mut offer| {
            offer.source_spans = offer.source_spans.iter().map(|s| pseudonyms.restore(s)).collect();
            offer
        })
        .and_then(|offer| {
            if self.offers.iter().any(|o| o.firm_id == offer.firm_id) {
                Err("this firm already has an offer".to_string())
            } else {
                Ok(offer)
            }
        });
        self.journal.append(Kind::ToolCommit, fetched(offer.is_ok()));
        // Consecutive Read steps are one per page, so a refused page still consumes its step.
        self.advance();
        let offer = offer?;
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
        self.gate_log("contact", checked.as_ref().map(|_| ()));
        checked.map_err(|e| e.as_str().to_string())?;
        self.web.contact(&firm, message);
        self.count_output("contact");
        let fingerprint = self.journal.fingerprint(message.as_bytes());
        self.journal.append(
            Kind::ToolCommit,
            json!({"tool": "contact", "firm": firm, "party": format!("firm {firm}"), "bytes_sent": message.len(), "message": fingerprint, "mode": MODE}),
        );
        self.advance();
        Ok(json!({"sent": true, "mode": MODE}))
    }

    fn chosen_offer_amount(&self) -> Result<u128, GateError> {
        let firm = self.chosen.as_deref().ok_or(GateError::RecipientNotAllowed)?;
        let offer = self.ranked.iter().find(|o| o.firm_id == firm).ok_or(GateError::RecipientNotAllowed)?;
        self.policy.amount_for_offer(offer.price_cents)
    }

    /// The amount in yoctoNEAR that the chosen offer's price stands for, with the policy's rate.
    pub fn offer_amount(&self) -> Result<u128, String> {
        self.chosen_offer_amount().map_err(|e| e.as_str().to_string())
    }

    /// Builds the payment. The recipient comes from the directory, the amount from the chosen
    /// offer: `amount` must be exactly `offer_amount()`. A new random nonce is drawn, so the
    /// confirmation digest is new for every payment.
    pub fn prepare_payment(&mut self, amount: u128) -> Reply {
        self.at_step(Step::PreparePayment)?;
        let firm = self.chosen_firm()?;
        let intent = match self.chosen_offer_amount() {
            Ok(expected) if expected == amount => self.policy.build_payment(&firm, amount, &self.mission_id),
            Ok(_) => Err(GateError::AmountNotOffered),
            Err(e) => Err(e),
        };
        self.gate_log("prepare_payment", intent.as_ref().map(|_| ()));
        let intent = intent.map_err(|e| e.as_str().to_string())?;
        let reply = json!({
            "screen": intent.screen(),
            "amount_near": intent.amount_near(),
            "digest": intent.digest(),
            "payment": {
                "network": intent.network,
                "contract": intent.contract,
                "mission_id": intent.mission_id,
                "nonce": intent.nonce_hex(),
                "to": intent.to,
                "amount": intent.amount.to_string(),
            },
            "mode": MODE,
        });
        self.payment = Some(intent);
        self.advance();
        Ok(reply)
    }

    /// Second confirmation, bound to the digest of this payment of this mission.
    pub fn confirm_payment(&mut self, digest: &str) -> Reply {
        self.at_step(Step::ConfirmPayment)?;
        let intent = self.payment.clone().ok_or("no payment prepared")?;
        let checked = self.policy.check_payment(&intent, digest, &self.mission_id);
        self.gate_log("confirm_payment", checked.as_ref().map(|_| ()));
        checked.map_err(|e| e.as_str().to_string())?;
        self.confirmed = Some(digest.to_string());
        let fingerprint = self.journal.fingerprint(digest.as_bytes());
        self.journal.append(Kind::HumanConfirm, json!({"what": "payment", "digest": fingerprint}));
        self.advance();
        Ok(json!({"confirmed": true, "mode": MODE}))
    }

    /// Pays once: the prepared payment and its confirmation are used up here.
    pub fn pay(&mut self) -> Reply {
        self.at_step(Step::Pay)?;
        let intent = self.payment.clone().ok_or("no payment prepared")?;
        let confirmed = self.confirmed.clone().ok_or("payment not confirmed")?;
        let checked = self.policy.check_payment(&intent, &confirmed, &self.mission_id);
        self.gate_log("pay", checked.as_ref().map(|_| ()));
        checked.map_err(|e| e.as_str().to_string())?;
        self.payment = None;
        self.confirmed = None;
        let tx = self.payments.pay(&intent);
        self.count_output("pay");
        self.journal.append(
            Kind::TxSubmitted,
            json!({
                "to": intent.to,
                "amount": intent.amount.to_string(),
                "tx": tx,
                "party": format!("chain {}, contract {}", intent.network, intent.contract),
                "bytes_sent": intent.bytes().len(),
                "mode": MODE,
            }),
        );
        self.advance();
        Ok(json!({"tx": tx, "mode": MODE}))
    }

    /// Ends the mission and forgets the mission text, the pseudonym table and the offers.
    pub fn close(&mut self) -> Reply {
        if self.phase == Phase::Closed {
            return Err("mission already closed".into());
        }
        let mode = self.model.mode();
        self.journal.append(Kind::MissionClose, json!({"steps_done": self.cursor, "mode": mode}));
        self.phase = Phase::Closed;
        self.mission_text.clear();
        self.pseudonyms = Pseudonyms::default();
        self.offers.clear();
        self.ranked.clear();
        let head: String = self.journal.head().iter().map(|b| format!("{b:02x}")).collect();
        Ok(json!({"head": head, "entries": self.journal.len(), "mode": mode}))
    }

    pub fn exposure(&self) -> Value {
        exposure_report(&self.journal)
    }
}

#[derive(Default)]
struct PartyCount {
    kind: &'static str,
    mode: String,
    requests: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

/// What left the machine, rebuilt from the journal alone, not from the running mission's memory.
/// `parties` names every party that received something and counts the requests and bytes it got.
pub fn exposure_report(journal: &Journal) -> Value {
    let mut outputs: BTreeMap<String, u64> = BTreeMap::new();
    let mut refused: BTreeMap<String, u64> = BTreeMap::new();
    let mut parties: BTreeMap<String, PartyCount> = BTreeMap::new();
    let mut payments = Vec::new();
    let mut firms = BTreeSet::new();
    let mut model_calls = 0u64;
    let mut mock_calls = 0u64;
    let mut pseudonyms = 0u64;
    let mut real_calls = Vec::new();
    let mut any_mock = false;
    let mut any_real_request = false;
    let num = |v: &Value| v.as_u64().unwrap_or(0);
    let mut count = |name: String, kind: &'static str, mode: &str, requests: u64, sent: u64, received: u64| {
        let p = parties.entry(name).or_default();
        p.kind = kind;
        p.mode = mode.to_string();
        p.requests += requests;
        p.bytes_sent += sent;
        p.bytes_received += received;
    };
    for entry in journal.entries() {
        let data = &entry["data"];
        if data["mode"] == MODE {
            any_mock = true;
        }
        let party = data["party"].as_str().map(String::from);
        let mode = data["mode"].as_str().unwrap_or("?");
        match entry["kind"].as_str().unwrap_or_default() {
            "tool_commit" => {
                let tool = data["tool"].as_str().unwrap_or("unknown").to_string();
                if let Some(party) = party {
                    let kind = match tool.as_str() {
                        "search" => "search engine",
                        "fetch" => "website",
                        "contact" => "contacted firm",
                        _ => "other",
                    };
                    // One entry per request: a fetch is journaled once, with or without a page.
                    count(party, kind, mode, 1, num(&data["bytes_sent"]), 0);
                }
                *outputs.entry(tool).or_insert(0) += 1;
                if let Some(firm) = data["firm"].as_str() {
                    firms.insert(firm.to_string());
                }
            }
            "llm_commit" => {
                pseudonyms += num(&data["pseudonyms"]);
                if data["mode"] == remote::REAL_MODE {
                    any_real_request = true;
                    let relay = data["relay"].as_str().unwrap_or("?");
                    count(
                        format!("relay {relay}"),
                        "relay",
                        remote::REAL_MODE,
                        num(&data["requests"]),
                        num(&data["bytes_sent"]),
                        num(&data["bytes_received"]),
                    );
                    if data["prompt_sent"] == false {
                        continue;
                    }
                    let model = data["model"].as_str().unwrap_or("?");
                    count(format!("NEAR AI model {model}, through the relay"), "model", remote::REAL_MODE, 1, num(&data["prompt_bytes"]), 0);
                    model_calls += 1;
                    real_calls.push(json!({
                        "role": data["role"],
                        "model": data["model"],
                        "response_id": data["response_id"],
                        "tokens_used": data["tokens_used"],
                        "outcome": data["outcome"],
                    }));
                } else {
                    model_calls += 1;
                    mock_calls += 1;
                }
            }
            "gate_decision" if data["result"] != "allow" => {
                let key = format!("{}: {}", data["output"].as_str().unwrap_or("?"), data["result"].as_str().unwrap_or("?"));
                *refused.entry(key).or_insert(0) += 1;
            }
            "tx_submitted" => {
                payments.push(json!({"to": data["to"], "amount": data["amount"]}));
                if let Some(party) = party {
                    count(party, "chain", mode, 1, num(&data["bytes_sent"]), 0);
                }
            }
            _ => {}
        }
    }
    let mode = match (!real_calls.is_empty() || any_real_request, any_mock) {
        (true, true) => "mixed",
        (false, true) => MODE,
        (_, false) => remote::REAL_MODE,
    };
    let parties: Vec<Value> = parties
        .into_iter()
        .map(|(name, p)| {
            json!({
                "party": name,
                "kind": p.kind,
                "mode": p.mode,
                "requests": p.requests,
                "bytes_sent": p.bytes_sent,
                "bytes_received": p.bytes_received,
            })
        })
        .collect();
    let warnings: Vec<&str> = if any_real_request { vec![ENCLAVE_TRUST_WARNING] } else { vec![] };
    json!({
        "parties": parties,
        "outputs": outputs,
        "refused_by_gate": refused,
        "firms_contacted": firms,
        "payments": payments,
        "model_calls": model_calls,
        "model_calls_mock": mock_calls,
        "model_calls_real": real_calls.len(),
        "real_calls": real_calls,
        "pseudonyms_replaced": pseudonyms,
        "content_readable_by_relay": any_real_request,
        "warnings": warnings,
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

    /// The demo's research: the question itself as the one query.
    fn research_queries(&mut self, question: &str) -> Result<ModelReply, ModelFailure> {
        let query: String = question.chars().take(research::MAX_QUERY_CHARS).collect();
        Ok(ModelReply { text: json!({"queries": [query.trim()]}).to_string(), mode: MODE, call: None })
    }

    /// The demo's reader: up to two sentences of the page, those with figures first (prices, delays), quoted as they are.
    fn research_read(&mut self, input: &str) -> Result<ModelReply, ModelFailure> {
        let page = input.split_once("\n\nPage:\n").map_or("", |(_, p)| p);
        let mut sentences: Vec<&str> = page
            .split_inclusive(['.', '!', '?'])
            .map(str::trim)
            .filter(|s| (research::MIN_QUOTE_CHARS..=research::MAX_NOTE_CHARS).contains(&s.chars().count()))
            .collect();
        sentences.sort_by_key(|s| !s.chars().any(|c| c.is_ascii_digit()));
        let notes: Vec<Value> = sentences.into_iter().take(2).map(|s| json!({"claim": s, "quote": s})).collect();
        Ok(ModelReply { text: json!({"notes": notes}).to_string(), mode: MODE, call: None })
    }

    /// The demo's answer: the notes put together; a message when the question asks to write, a payment of 0.1 NEAR
    /// when it asks to pay.
    fn research_answer(&mut self, input: &str) -> Result<ModelReply, ModelFailure> {
        let (question, notes) = input.split_once("\n\nNotes:\n").unwrap_or((input, "[]"));
        let notes: Vec<Value> = serde_json::from_str(notes).unwrap_or_default();
        let claims: Vec<&str> = notes.iter().filter_map(|n| n["claim"].as_str()).collect();
        let answer = if claims.is_empty() { "Aucune source lue ne répond à la question.".to_string() } else { claims.join(" ") };
        let lower = question.to_lowercase();
        let mut actions = Vec::new();
        if ["écri", "ecri", "contact", "message"].iter().any(|w| lower.contains(w)) {
            actions.push(json!({"kind": "message", "purpose": "Demande de devis",
                "text": "Bonjour, je souhaite un devis. Pouvez-vous me dire vos disponibilités et votre tarif ? Merci."}));
        }
        if ["paie", "payer", "paye", "acompte"].iter().any(|w| lower.contains(w)) {
            actions.push(json!({"kind": "payment", "purpose": "Acompte", "amount_near": "0.1"}));
        }
        let cites: Vec<usize> = (1..=notes.len()).collect();
        Ok(ModelReply { text: json!({"answer": answer, "cites": cites, "actions": actions}).to_string(), mode: MODE, call: None })
    }
}

pub struct MockWeb {
    pub pages: BTreeMap<String, String>,
    /// Handle to the directory firm whose page it is.
    pub sources: BTreeMap<String, String>,
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
        let mut sources = BTreeMap::new();
        sources.insert("h1".to_string(), "cabinet-a".to_string());
        sources.insert("h2".to_string(), "cabinet-b".to_string());
        Self { pages, sources, sent: Vec::new(), queries: Vec::new() }
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

    fn source(&self, handle: &str) -> Option<String> {
        self.sources.get(handle).cloned()
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

/// yoctoNEAR per cent of offer price in the demo: 10^19, so 600 euros pay 0.6 NEAR. A fixed demo
/// value, not a market rate.
pub const DEMO_YOCTO_PER_CENT: u128 = 10_000_000_000_000_000_000;

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
        network: "sandbox".to_string(),
        payment_contract: "mint.test".to_string(),
        yocto_per_cent: DEMO_YOCTO_PER_CENT,
    }
}

pub type DemoMission = Mission<MockModel, MockWeb, MockPayments>;

/// One JSON request, one JSON reply. Both front ends go through this single entry point.
///
/// The model is the fake unless `use_real_model` is called. It moves from one mission to the next,
/// so its token budget covers all of them.
pub struct Core {
    mission: Option<CoreMission>,
    /// A free research (`research_*` commands, `research`), which uses the same model.
    research: Option<CoreResearch>,
    /// How the real model reaches the network: the research's web goes the same way. None: the demo web.
    web: Option<tor::Network>,
    vault: Option<vault::Vault>,
    pool: Option<pool::PoolClient>,
    model: Option<Box<dyn Model>>,
    model_mode: &'static str,
}

type CoreMission = Mission<Box<dyn Model>, MockWeb, MockPayments>;
type CoreResearch = research::Research<Box<dyn Model>, Box<dyn research::OpenWeb>, MockPayments>;

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
        Self {
            mission: None,
            research: None,
            web: None,
            vault: None,
            pool: None,
            model: Some(Box::new(MockModel::default())),
            model_mode: MODE,
        }
    }

    pub fn with_vault(vault: vault::Vault) -> Self {
        Self { vault: Some(vault), ..Self::new() }
    }

    /// Adds the pool client, which answers `pool::COMMANDS`.
    pub fn set_pool(&mut self, pool: pool::PoolClient) {
        self.pool = Some(pool);
    }

    /// Replaces the model. Refused during a mission, whose plan was made with the previous one.
    pub fn set_model(&mut self, model: Box<dyn Model>) -> Result<(), String> {
        if self.mission.is_some() || self.research.is_some() {
            return Err("cannot change the model after a mission was opened".into());
        }
        self.model_mode = model.mode();
        self.model = Some(model);
        Ok(())
    }

    /// Switches to the real model. Only an explicit call with a full configuration does this.
    pub fn use_real_model(&mut self, config: remote::RemoteConfig, network: &tor::Network) -> Result<(), String> {
        self.set_model(Box::new(remote::http_model(config, network)?))?;
        self.web = Some(network.clone());
        Ok(())
    }

    /// The model, freed from a closed mission or research: it moves from one to the next, so its token budget covers
    /// all of them. Refused while one is still open.
    fn free_model(&mut self) -> Result<Box<dyn Model>, String> {
        if self.mission.as_ref().is_some_and(|m| m.phase() != Phase::Closed)
            || self.research.as_ref().is_some_and(|r| r.phase() != research::ResearchPhase::Closed)
        {
            return Err("close the current mission first".into());
        }
        if let Some(previous) = self.mission.take() {
            return Ok(previous.model);
        }
        if let Some(previous) = self.research.take() {
            return Ok(previous.model);
        }
        self.model.take().ok_or_else(|| "no model configured".to_string())
    }

    fn research_command(&mut self, cmd: &str, request: &Value) -> Reply {
        let text = |key: &str| -> Result<String, String> {
            request[key].as_str().map(String::from).ok_or_else(|| format!("missing field {key}"))
        };
        if cmd == "research_open" {
            let question = text("question")?;
            // Checked before the model is freed: a refused question keeps it where it was.
            if question.trim().is_empty() || question.trim().len() > research::MAX_QUESTION_BYTES {
                return Err(format!("the question must have 1 to {} bytes", research::MAX_QUESTION_BYTES));
            }
            let mut policy = demo_policy();
            if let Some(items) = request["protected"].as_array() {
                let terms: Vec<String> = items.iter().filter_map(|v| v.as_str()).map(|t| t.trim().to_string()).collect();
                if terms.len() != items.len() || terms.iter().any(|t| !(MIN_TERM_CHARS..=MAX_TERM_CHARS).contains(&pseudonym::term_len(t))) {
                    return Err(format!("protected terms must be strings of {MIN_TERM_CHARS} to {MAX_TERM_CHARS} characters"));
                }
                if policy.protected_terms.len() + terms.len() > MAX_TERMS {
                    return Err(format!("at most {MAX_TERMS} protected terms"));
                }
                policy.protected_terms.extend(terms);
            }
            let model = self.free_model()?;
            let web: Box<dyn research::OpenWeb> = match &self.web {
                Some(network) => Box::new(research::TorWeb::new(network.clone())),
                None => Box::new(research::MockOpenWeb::demo()),
            };
            let web_mode = web.mode();
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);
            self.research = Some(research::Research::open(model, web, MockPayments::default(), policy, salt, &question)?);
            return Ok(json!({"opened": true, "mode": self.model_mode, "web": web_mode}));
        }
        let r = self.research.as_mut().ok_or("no open research")?;
        match cmd {
            "research_propose" => r.propose(),
            "research_accept" => {
                let queries: Vec<String> = request["queries"]
                    .as_array()
                    .ok_or("missing field queries")?
                    .iter()
                    .map(|q| q.as_str().map(String::from).ok_or_else(|| "queries must be strings".to_string()))
                    .collect::<Result<_, _>>()?;
                r.accept(&queries)
            }
            "research_step" => r.step(),
            "research_result" => r.result(),
            "research_action_prepare" => {
                let index = request["index"].as_u64().and_then(|i| usize::try_from(i).ok()).ok_or("missing field index")?;
                r.prepare_action(index, &text("to")?)
            }
            "research_action_confirm" => r.confirm_action(&text("digest")?),
            "research_action_do" => r.do_action(),
            "research_close" => r.close(),
            "research_exposure" => Ok(r.exposure()),
            other => Err(format!("unknown command {other}")),
        }
    }

    fn run(&mut self, request: &Value) -> Reply {
        let text = |key: &str| -> Result<String, String> {
            request[key].as_str().map(String::from).ok_or_else(|| format!("missing field {key}"))
        };
        let cmd = text("cmd")?;
        if pool::COMMANDS.contains(&cmd.as_str()) {
            return self.pool.as_mut().ok_or("no pool wallet configured")?.run(&cmd, request);
        }
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
        if cmd.starts_with("research_") {
            return self.research_command(&cmd, request);
        }
        if cmd == "open" {
            if self.mission.as_ref().is_some_and(|m| m.phase() != Phase::Closed)
                || self.research.as_ref().is_some_and(|r| r.phase() != research::ResearchPhase::Closed)
            {
                return Err("close the current mission first".into());
            }
            let mission = text("mission")?;
            let protected: Vec<String> = match &request["protected"] {
                Value::Null => Vec::new(),
                Value::Array(items) => items
                    .iter()
                    .map(|v| v.as_str().map(String::from).ok_or_else(|| "protected terms must be strings".to_string()))
                    .collect::<Result<_, _>>()?,
                _ => return Err("protected must be a list of strings".into()),
            };
            // Random, so that someone holding the journal cannot test a guessed mission against it.
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);
            let model = self.free_model()?;
            let mut opened = Mission::open(model, MockWeb::demo(), MockPayments::default(), demo_policy(), salt, &mission);
            let declared = if protected.is_empty() { Ok(Value::Null) } else { opened.protect(&protected) };
            self.mission = Some(opened);
            if let Err(e) = declared {
                // The mission stays open so its model is kept, but it cannot be used for a plan.
                if let Some(m) = self.mission.as_mut() {
                    let _ = m.close();
                }
                return Err(e);
            }
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
                // Without an amount, the chosen offer's amount is used; with one, it must match.
                let amount = match &request["amount"] {
                    Value::Null => m.offer_amount()?,
                    _ => text("amount")?.parse::<u128>().map_err(|_| "bad amount".to_string())?,
                };
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

    /// As `dispatch`, for raw bytes: a request that is not UTF-8 gets an error reply.
    pub fn dispatch_bytes(&mut self, request: &[u8]) -> String {
        match std::str::from_utf8(request) {
            Ok(text) => self.dispatch(text),
            Err(_) => json!({"ok": false, "error": "request is not valid UTF-8", "mode": MODE}).to_string(),
        }
    }
}

/// Reads one request per line and writes one reply per line, until the input ends. A line that is
/// not UTF-8 or longer than `MAX_REQUEST_BYTES` gets an error reply instead of stopping the loop,
/// so a bad line cannot end the open mission.
pub fn serve(core: &mut Core, mut input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
    let limit = MAX_REQUEST_BYTES as u64 + 1;
    let mut line = Vec::new();
    loop {
        line.clear();
        if (&mut input).take(limit).read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        let complete = line.last() == Some(&b'\n');
        if complete {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        let reply = if !complete && line.len() > MAX_REQUEST_BYTES {
            // Skip the rest of the line without keeping it.
            let mut rest = Vec::new();
            loop {
                rest.clear();
                let n = (&mut input).take(limit).read_until(b'\n', &mut rest)?;
                if n == 0 || rest.last() == Some(&b'\n') {
                    break;
                }
            }
            json!({"ok": false, "error": "request too long", "mode": MODE}).to_string()
        } else {
            core.dispatch_bytes(&line)
        };
        writeln!(output, "{reply}")?;
        output.flush()?;
    }
}
