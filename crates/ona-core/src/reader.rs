//! Closed-schema reading of an untrusted page. Only typed values reach the rest of the agent.
//!
//! A value must cite an exact excerpt of the page. That stops an invented value, not a false one
//! that the page itself states.

use serde::{Deserialize, Serialize};

pub const MAX_SPANS: usize = 8;
pub const MAX_SPAN_LEN: usize = 200;
pub const MAX_FIRM_ID_LEN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Specialty {
    Labour,
    Family,
    Tax,
    Criminal,
    Commercial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub firm_id: String,
    pub specialties: Vec<Specialty>,
    pub price_cents: u32,
    pub delay_days: u16,
    pub source_spans: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    Schema,
    BadFirmId,
    MissingSpan,
    SpanNotOnPage,
    TooManySpans,
    SpanTooLong,
}

impl ReadError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Schema => "reader output does not match the schema",
            Self::BadFirmId => "bad firm id",
            Self::MissingSpan => "a value must cite the page",
            Self::SpanNotOnPage => "cited excerpt is not on the page",
            Self::TooManySpans => "too many excerpts",
            Self::SpanTooLong => "excerpt too long",
        }
    }
}

/// Parses and checks reader output. Anything outside the schema is refused, not cleaned up.
pub fn parse_offer(reader_output: &str, page: &str) -> Result<Offer, ReadError> {
    let offer: Offer = serde_json::from_str(reader_output).map_err(|_| ReadError::Schema)?;
    let id_ok = !offer.firm_id.is_empty()
        && offer.firm_id.len() <= MAX_FIRM_ID_LEN
        && offer.firm_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !id_ok {
        return Err(ReadError::BadFirmId);
    }
    if offer.source_spans.is_empty() {
        return Err(ReadError::MissingSpan);
    }
    if offer.source_spans.len() > MAX_SPANS {
        return Err(ReadError::TooManySpans);
    }
    for span in &offer.source_spans {
        if span.is_empty() || span.chars().count() > MAX_SPAN_LEN {
            return Err(ReadError::SpanTooLong);
        }
        if !page.contains(span.as_str()) {
            return Err(ReadError::SpanNotOnPage);
        }
    }
    Ok(offer)
}

/// Ranks offers by code on typed fields: price first, then delay, then id for a stable order.
/// Only firms in the directory count. No model takes part in this.
pub fn rank(offers: &[Offer], is_listed: impl Fn(&str) -> bool) -> Vec<Offer> {
    let mut listed: Vec<Offer> = offers.iter().filter(|o| is_listed(&o.firm_id)).cloned().collect();
    listed.sort_by(|a, b| {
        (a.price_cents, a.delay_days, &a.firm_id).cmp(&(b.price_cents, b.delay_days, &b.firm_id))
    });
    listed
}
