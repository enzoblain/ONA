//! Closed-schema reading of an untrusted page. Only typed values reach the rest of the agent.
//!
//! An offer belongs to the firm the search tied the page to (`Web::source`), never to a firm the
//! page names: the reader need not give `firm_id`, and one that differs is refused. Each excerpt
//! must appear word for word on the text the reader was given and be at least `MIN_SPAN_LEN`
//! characters long. The excerpts must write the price and the delay as numbers that are exactly the
//! offer's values (see `cited_numbers`). That stops an invented value, not a false one that the
//! page itself states.

use serde::{Deserialize, Serialize};

pub const MAX_SPANS: usize = 8;
pub const MAX_SPAN_LEN: usize = 200;
/// Shortest excerpt accepted, in characters, spaces at both ends not counted.
pub const MIN_SPAN_LEN: usize = 12;
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
    /// Optional in the reader's output: filled from the page's source.
    #[serde(default)]
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
    SpanTooShort,
    NotTheSource,
    ValueNotCited,
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
            Self::SpanTooShort => "excerpt too short",
            Self::NotTheSource => "offer names another firm than the one whose page was read",
            Self::ValueNotCited => "price or delay is not written in the cited excerpts",
        }
    }
}

/// One number written in an excerpt: its whole part and, if written, its decimals as digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitedNumber {
    pub whole: u64,
    pub decimals: Option<String>,
}

impl CitedNumber {
    /// The amount in cents: whole units plus one or two decimals ("12,5" is 1250, "600,05" is
    /// 60005). More decimals give no amount. One reading only.
    pub fn as_cents(&self) -> Option<u64> {
        let cents = match self.decimals.as_deref() {
            None => 0,
            Some(d) if d.len() == 1 => d.parse::<u64>().ok()? * 10,
            Some(d) if d.len() == 2 => d.parse::<u64>().ok()?,
            Some(_) => return None,
        };
        self.whole.checked_mul(100)?.checked_add(cents)
    }

    /// A whole number, written without decimals.
    pub fn as_whole(&self) -> Option<u64> {
        self.decimals.is_none().then_some(self.whole)
    }
}

fn is_group_separator(c: char) -> bool {
    matches!(c, ' ' | '\u{00A0}' | '\u{202F}' | '.' | ',' | '\'')
}

/// The numbers written in a text, each read one way only. Digits may be grouped by three with a
/// space, a no-break space, `.`, `,` or `'` ("1 200", "1.200", "1'200"). After `.` or `,`, a group of
/// any other length that ends the number is its decimals ("12,5", "600.05", "3,14159"): never a
/// second number. "12" is never read as "1", "12,5" never as 12 and 5.
pub fn cited_numbers(text: &str) -> Vec<CitedNumber> {
    let chars: Vec<char> = text.chars().collect();
    let digits_at = |i: usize| chars[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() || (i > 0 && chars[i - 1].is_ascii_digit()) {
            i += 1;
            continue;
        }
        let first = digits_at(i);
        let mut whole: String = chars[i..i + first].iter().collect();
        let mut decimals = None;
        let mut j = i + first;
        while j + 1 < chars.len() && is_group_separator(chars[j]) && chars[j + 1].is_ascii_digit() {
            let group = digits_at(j + 1);
            let next = j + 1 + group;
            if group == 3 && first <= 3 {
                whole.extend(&chars[j + 1..next]);
                j = next;
            } else if matches!(chars[j], '.' | ',') {
                decimals = Some(chars[j + 1..next].iter().collect::<String>());
                j = next;
                break;
            } else {
                break;
            }
        }
        if let Ok(whole) = whole.parse() {
            out.push(CitedNumber { whole, decimals });
        }
        i = j.max(i + 1);
    }
    out
}

/// True if one excerpt number is exactly the price (whole units, or units and two-digit cents) and
/// one whole number is exactly the delay.
fn values_are_cited(offer: &Offer) -> bool {
    let numbers: Vec<CitedNumber> = offer.source_spans.iter().flat_map(|s| cited_numbers(s)).collect();
    let price_ok = numbers.iter().any(|n| n.as_cents() == Some(u64::from(offer.price_cents)));
    let delay_ok = numbers.iter().any(|n| n.as_whole() == Some(u64::from(offer.delay_days)));
    price_ok && delay_ok
}

/// Parses and checks reader output for a page whose firm is `source` (decided by the search).
/// `page` is the text the reader was given. Anything outside the schema is refused, not cleaned up.
pub fn parse_offer(reader_output: &str, page: &str, source: &str) -> Result<Offer, ReadError> {
    let mut offer: Offer = serde_json::from_str(reader_output).map_err(|_| ReadError::Schema)?;
    if offer.firm_id.is_empty() {
        offer.firm_id = source.to_string();
    }
    let id_ok = offer.firm_id.len() <= MAX_FIRM_ID_LEN
        && offer.firm_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !id_ok {
        return Err(ReadError::BadFirmId);
    }
    if offer.firm_id != source {
        return Err(ReadError::NotTheSource);
    }
    if offer.source_spans.is_empty() {
        return Err(ReadError::MissingSpan);
    }
    if offer.source_spans.len() > MAX_SPANS {
        return Err(ReadError::TooManySpans);
    }
    for span in &offer.source_spans {
        if span.chars().count() > MAX_SPAN_LEN {
            return Err(ReadError::SpanTooLong);
        }
        if span.trim().chars().count() < MIN_SPAN_LEN {
            return Err(ReadError::SpanTooShort);
        }
        if !page.contains(span.as_str()) {
            return Err(ReadError::SpanNotOnPage);
        }
    }
    if !values_are_cited(&offer) {
        return Err(ReadError::ValueNotCited);
    }
    Ok(offer)
}

/// Ranks offers by code on typed fields: price first, then delay, then id for a stable order.
/// Only firms in the directory count, and only the first offer of each firm. No model takes part.
pub fn rank(offers: &[Offer], is_listed: impl Fn(&str) -> bool) -> Vec<Offer> {
    let mut seen = std::collections::BTreeSet::new();
    let mut listed: Vec<Offer> = offers
        .iter()
        .filter(|o| is_listed(&o.firm_id) && seen.insert(o.firm_id.clone()))
        .cloned()
        .collect();
    listed.sort_by(|a, b| {
        (a.price_cents, a.delay_days, &a.firm_id).cmp(&(b.price_cents, b.delay_days, &b.firm_id))
    });
    listed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbers(text: &str) -> Vec<(u64, Option<&'static str>)> {
        cited_numbers(text)
            .into_iter()
            .map(|n| (n.whole, n.decimals.map(|d| &*Box::leak(d.into_boxed_str()))))
            .collect()
    }

    #[test]
    fn numbers_are_read_one_way_only() {
        assert_eq!(numbers("Flat fee 600 euros, within 10 days"), [(600, None), (10, None)]);
        assert_eq!(numbers("600,00 € in 12 days"), [(600, Some("00")), (12, None)]);
        assert_eq!(numbers("1 200 € or 1.200 € or 1'200,50 €"), [(1200, None), (1200, None), (1200, Some("50"))]);
        assert_eq!(numbers("v2.5, 3,14159"), [(2, Some("5")), (3, Some("14159"))]);
    }

    #[test]
    fn a_lone_decimal_is_never_a_second_number() {
        for (text, cents) in [("12,5 €", 1250), ("600.5 €", 60050)] {
            let found = cited_numbers(text);
            assert_eq!(found.len(), 1, "{text}");
            assert_eq!(found[0].as_cents(), Some(cents), "{text}");
            assert_eq!(found[0].as_whole(), None, "a decimal number is no delay: {text}");
        }
        let offer = |price_cents, delay_days, span: &str| Offer {
            firm_id: "a".into(),
            specialties: vec![],
            price_cents,
            delay_days,
            source_spans: vec![span.into()],
        };
        assert!(!values_are_cited(&offer(500, 12, "Price 12,5 euros, 12 days")), "5 is not a number of this text");
        assert!(!values_are_cited(&offer(1250, 5, "Price 12,5 euros, 12 days")), "nor a delay");
        assert!(!values_are_cited(&offer(500, 600, "Price 600.5 euros, 600 days")));
        assert!(values_are_cited(&offer(1250, 12, "Price 12,5 euros, 12 days")));
    }
}
