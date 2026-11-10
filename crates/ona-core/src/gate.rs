//! The deterministic gate in front of every network output and payment. Code, not a model.
//!
//! Limits, stated plainly: the gate blocks exact pseudonym terms only, so a secret rephrased or
//! encoded by a compromised writer can pass `contact`. It cannot tell whether a quote is honest.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    UnknownTemplate,
    BadTemplateValue,
    ForbiddenTerm,
    UnknownHandle,
    UnknownFirm,
    MessageTooLong,
    RecipientNotAllowed,
    AmountOverCap,
    ZeroAmount,
    ConfirmationMismatch,
}

impl GateError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnknownTemplate => "unknown search template",
            Self::BadTemplateValue => "template value not in the allowed list",
            Self::ForbiddenTerm => "text contains a protected term",
            Self::UnknownHandle => "handle was not produced by a search",
            Self::UnknownFirm => "firm is not in the directory",
            Self::MessageTooLong => "message too long",
            Self::RecipientNotAllowed => "recipient is not in the list chosen by the user",
            Self::AmountOverCap => "amount over the cap",
            Self::ZeroAmount => "amount must be positive",
            Self::ConfirmationMismatch => "confirmation does not match this payment",
        }
    }
}

/// A search query with one fixed slot, filled only from an allowlist.
#[derive(Debug, Clone)]
pub struct SearchTemplate {
    pub text: String,
    pub allowed_values: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub templates: BTreeMap<String, SearchTemplate>,
    /// Terms from the private file that must never leave, even in a search.
    pub protected_terms: Vec<String>,
    /// Firm id to payment account. Chosen outside the web, never read from a page.
    pub directory: BTreeMap<String, String>,
    pub amount_cap: u128,
    pub max_message_len: usize,
}

impl Policy {
    fn check_terms(&self, text: &str) -> Result<(), GateError> {
        let lower = text.to_lowercase();
        if self.protected_terms.iter().any(|t| lower.contains(&t.to_lowercase())) {
            return Err(GateError::ForbiddenTerm);
        }
        Ok(())
    }

    pub fn build_search(&self, template: &str, value: &str) -> Result<String, GateError> {
        let t = self.templates.get(template).ok_or(GateError::UnknownTemplate)?;
        if !t.allowed_values.contains(value) {
            return Err(GateError::BadTemplateValue);
        }
        let query = t.text.replace("{}", value);
        self.check_terms(&query)?;
        Ok(query)
    }

    pub fn check_fetch(&self, handle: &str, known: &BTreeSet<String>) -> Result<(), GateError> {
        if known.contains(handle) {
            Ok(())
        } else {
            Err(GateError::UnknownHandle)
        }
    }

    pub fn check_contact(&self, firm: &str, message: &str) -> Result<(), GateError> {
        if !self.directory.contains_key(firm) {
            return Err(GateError::UnknownFirm);
        }
        if message.chars().count() > self.max_message_len {
            return Err(GateError::MessageTooLong);
        }
        self.check_terms(message)
    }

    /// The recipient comes from the directory, so nothing on a page can supply it.
    pub fn build_payment(&self, firm: &str, amount: u128) -> Result<PaymentIntent, GateError> {
        let to = self.directory.get(firm).ok_or(GateError::RecipientNotAllowed)?;
        if amount == 0 {
            return Err(GateError::ZeroAmount);
        }
        if amount > self.amount_cap {
            return Err(GateError::AmountOverCap);
        }
        Ok(PaymentIntent { to: to.clone(), amount })
    }

    /// Final check right before submission: the human approved exactly these bytes.
    pub fn check_payment(&self, intent: &PaymentIntent, confirmed: &str) -> Result<(), GateError> {
        if !self.directory.values().any(|account| account == &intent.to) {
            return Err(GateError::RecipientNotAllowed);
        }
        if intent.amount == 0 {
            return Err(GateError::ZeroAmount);
        }
        if intent.amount > self.amount_cap {
            return Err(GateError::AmountOverCap);
        }
        if intent.digest() != confirmed {
            return Err(GateError::ConfirmationMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentIntent {
    pub to: String,
    pub amount: u128,
}

impl PaymentIntent {
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.to.len() + 24);
        out.extend_from_slice(&(self.to.len() as u32).to_le_bytes());
        out.extend_from_slice(self.to.as_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out
    }

    pub fn digest(&self) -> String {
        Sha256::digest(self.bytes()).iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The confirmation text, derived from the payment itself and never from model output.
    pub fn screen(&self) -> String {
        format!("Pay {} yoctoNEAR to {}", self.amount, self.to)
    }
}
