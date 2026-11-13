//! The deterministic gate in front of every network output and payment. Code, not a model.
//!
//! Limits, stated plainly: the gate blocks the protected terms only (after normalization, see
//! `crate::pseudonym`), so a secret rephrased or encoded by a compromised writer can pass `contact`. It
//! cannot tell whether a quote is honest. The payment confirmation is a digest the caller sends
//! back: it binds the payment to one mission and one random nonce, but it is not a signature, so
//! it proves that the caller saw this payment's fields, not that a human did.

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Domain label of the payment confirmation digest.
pub const PAY_DOMAIN: &str = "ona/pay/v2";
/// Length of the random nonce drawn for each prepared payment.
pub const PAY_NONCE_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    UnknownTemplate,
    BadTemplateValue,
    ForbiddenTerm,
    UnknownHandle,
    UnknownFirm,
    MessageTooLong,
    RecipientNotAllowed,
    RecipientBlocked,
    AmountOverCap,
    ZeroAmount,
    ConfirmationMismatch,
    AmountNotOffered,
    NoConversionRate,
    WrongPaymentContext,
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
            Self::RecipientBlocked => "recipient is on the list of fraudulent accounts",
            Self::AmountOverCap => "amount over the cap",
            Self::ZeroAmount => "amount must be positive",
            Self::ConfirmationMismatch => "confirmation does not match this payment",
            Self::AmountNotOffered => "amount is not the price of the chosen offer",
            Self::NoConversionRate => "no conversion rate from offer prices to yoctoNEAR is configured",
            Self::WrongPaymentContext => "payment belongs to another network, contract or mission",
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
    /// Terms from the private file that must never leave, even in a search. Before anything is
    /// sent to the model they are replaced by pseudonyms (`crate::pseudonym`).
    pub protected_terms: Vec<String>,
    /// Firm id to payment account. Chosen outside the web, never read from a page.
    pub directory: BTreeMap<String, String>,
    pub amount_cap: u128,
    pub max_message_len: usize,
    /// Network the payment is made on, part of the confirmation digest.
    pub network: String,
    /// Account of the contract that carries the payment, part of the confirmation digest.
    pub payment_contract: String,
    /// yoctoNEAR per cent of offer price. Set by the user, never read from a page. Zero refuses
    /// every payment, since then no amount can be tied to an offer.
    pub yocto_per_cent: u128,
    /// Accounts the person allows as payment recipients, besides the directory's. A free research pays only these.
    pub allowed_payees: BTreeSet<String>,
    /// Accounts known to be fraudulent: never paid, even when allowed. See `blocked_accounts`.
    pub blocked_accounts: BTreeSet<String>,
}

/// Why a payment recipient was refused. Written to the journal as is, without the recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayeeRefusal {
    Blocked,
    NotAllowed,
}

impl PayeeRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::NotAllowed => "not_allowed",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Blocked => "recipient is on the list of fraudulent accounts",
            Self::NotAllowed => "recipient is not in the list chosen by the user",
        }
    }
}

/// The built-in list of fraudulent NEAR accounts: one account per line, `#` starts a comment. Empty on
/// 13/11/2026: no maintained public list of NEAR account ids was found (lists found cover phishing web domains).
const BLOCKED_ACCOUNTS: &str = include_str!("../data/blocked-accounts.txt");

/// Parses a list of accounts, one per line; blank lines and `#` comments are skipped, names are lowercased.
pub fn parse_account_list(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_lowercase())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The built-in list of fraudulent accounts.
pub fn blocked_accounts() -> BTreeSet<String> {
    parse_account_list(BLOCKED_ACCOUNTS)
}

/// The encoding used for signed and hashed messages (same as the phone protocol): for each
/// field, its length as a little-endian u32, then its bytes.
pub fn fields(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

impl Policy {
    /// Refuses a text that contains a protected term, compared as the pseudonym table compares
    /// (decoded escapes, invisible characters removed, NFKC, lowercase, whole words unless the term
    /// is written `*between asterisks*`): see `crate::pseudonym`.
    pub fn check_terms(&self, text: &str) -> Result<(), GateError> {
        if crate::pseudonym::contains_protected(text, &self.protected_terms) {
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

    /// A payment recipient must not be on the fraud list, and must be one the person allowed (directory or
    /// `allowed_payees`). Account names are compared lowercased.
    pub fn check_payee(&self, to: &str) -> Result<(), PayeeRefusal> {
        let to = to.trim().to_lowercase();
        if self.blocked_accounts.contains(&to) {
            return Err(PayeeRefusal::Blocked);
        }
        let allowed = self.allowed_payees.contains(&to) || self.directory.values().any(|a| a.to_lowercase() == to);
        if !allowed {
            return Err(PayeeRefusal::NotAllowed);
        }
        Ok(())
    }

    /// The amount an offer price stands for, with the user's conversion rate.
    pub fn amount_for_offer(&self, price_cents: u32) -> Result<u128, GateError> {
        if self.yocto_per_cent == 0 {
            return Err(GateError::NoConversionRate);
        }
        u128::from(price_cents).checked_mul(self.yocto_per_cent).ok_or(GateError::AmountOverCap)
    }

    /// The recipient comes from the directory, so nothing on a page can supply it. A new random
    /// nonce is drawn for each payment, so its digest cannot be computed in advance or reused.
    pub fn build_payment(&self, firm: &str, amount: u128, mission_id: &str) -> Result<PaymentIntent, GateError> {
        let to = self.directory.get(firm).ok_or(GateError::RecipientNotAllowed)?;
        if self.blocked_accounts.contains(&to.to_lowercase()) {
            return Err(GateError::RecipientBlocked);
        }
        if amount == 0 {
            return Err(GateError::ZeroAmount);
        }
        if amount > self.amount_cap {
            return Err(GateError::AmountOverCap);
        }
        let mut nonce = [0u8; PAY_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        Ok(PaymentIntent {
            network: self.network.clone(),
            contract: self.payment_contract.clone(),
            mission_id: mission_id.to_string(),
            nonce,
            to: to.clone(),
            amount,
        })
    }

    /// Final check right before submission: the caller confirmed exactly this payment, of this
    /// mission, on this network and contract.
    pub fn check_payment(&self, intent: &PaymentIntent, confirmed: &str, mission_id: &str) -> Result<(), GateError> {
        if intent.network != self.network || intent.contract != self.payment_contract || intent.mission_id != mission_id {
            return Err(GateError::WrongPaymentContext);
        }
        if self.blocked_accounts.contains(&intent.to.to_lowercase()) {
            return Err(GateError::RecipientBlocked);
        }
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
    pub network: String,
    pub contract: String,
    pub mission_id: String,
    pub nonce: [u8; PAY_NONCE_LEN],
    pub to: String,
    pub amount: u128,
}

impl PaymentIntent {
    pub fn nonce_hex(&self) -> String {
        self.nonce.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `fields("ona/pay/v2", network, contract, mission_id, nonce_hex, to, amount_decimal)`.
    pub fn bytes(&self) -> Vec<u8> {
        let nonce = self.nonce_hex();
        let amount = self.amount.to_string();
        fields(&[
            PAY_DOMAIN.as_bytes(),
            self.network.as_bytes(),
            self.contract.as_bytes(),
            self.mission_id.as_bytes(),
            nonce.as_bytes(),
            self.to.as_bytes(),
            amount.as_bytes(),
        ])
    }

    /// SHA-256 of `bytes()`, in lowercase hex.
    pub fn digest(&self) -> String {
        Sha256::digest(self.bytes()).iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The confirmation text, derived from the payment itself and never from model output.
    pub fn screen(&self) -> String {
        format!("Pay {} yoctoNEAR to {}", self.amount, self.to)
    }

    /// The amount in NEAR, written out in full (24 decimals, trailing zeros removed).
    pub fn amount_near(&self) -> String {
        const YOCTO: u128 = 1_000_000_000_000_000_000_000_000;
        let whole = self.amount / YOCTO;
        let fraction = format!("{:024}", self.amount % YOCTO);
        let fraction = fraction.trim_end_matches('0');
        if fraction.is_empty() {
            whole.to_string()
        } else {
            format!("{whole}.{fraction}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_lists_skip_comments_and_blank_lines() {
        let list = parse_account_list("# fraud list\n\nArnaque.testnet  # source, date\n  vol.near\n");
        assert_eq!(list, ["arnaque.testnet", "vol.near"].iter().map(|s| s.to_string()).collect());
        assert!(blocked_accounts().is_empty(), "no public list of NEAR accounts was found on 13/11/2026");
    }

    #[test]
    fn a_payee_must_be_allowed_and_not_blocked() {
        let mut policy = Policy::default();
        policy.directory.insert("cabinet".into(), "cabinet.testnet".into());
        assert_eq!(policy.check_payee("cabinet.testnet"), Ok(()), "the directory counts as allowed");
        assert_eq!(policy.check_payee("autre.testnet"), Err(PayeeRefusal::NotAllowed));
        policy.allowed_payees.insert("autre.testnet".into());
        assert_eq!(policy.check_payee(" autre.testnet "), Ok(()));
        policy.blocked_accounts.insert("cabinet.testnet".into());
        assert_eq!(policy.check_payee("cabinet.testnet"), Err(PayeeRefusal::Blocked), "the fraud list wins");
        assert_eq!(policy.build_payment("cabinet", 1, "m").unwrap_err(), GateError::RecipientBlocked);
    }
}
