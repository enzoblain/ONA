//! Pool requests and questions typed in a conversation on this computer ("place 1 NEAR in vault 0", "how much do I
//! have?"): read here with fixed patterns, never by the model. The amount and the vault come from the person's words
//! only; the account is the wallet the person connected (docs/desktop/tauri.md, "Pool requests in the chat"). A text
//! that does not match falls through to the free research.

/// 1 NEAR in yoctoNEAR.
pub const NEAR: u128 = 1_000_000_000_000_000_000_000_000;

#[derive(Clone, Debug, PartialEq)]
pub enum VaultRef {
    /// "vault 0", "vault #1".
    Index(u32),
    /// "the staking vault", "in staking": a vault whose kind (`adapter`) is this word.
    Kind(String),
    /// "a vault", "the vault": the pool's only open vault, if it has one only.
    Any,
}

/// An amount of an operation on notes already in the pool: written in NEAR, or everything there ("my cash").
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Amount {
    Near(u128),
    All,
}

/// A question about the person's own pool, answered on this computer from the pool's reads.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Question {
    /// "how much do I have?"
    Total,
    /// "what's in vault 0?"
    Vault(u32),
    /// "how private is my position?"
    Privacy,
    /// "how much can I withdraw?"
    Withdrawable,
    /// "what vaults are there?"
    Vaults,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Intent {
    /// A deposit from the person's wallet, then (with a vault) an entry of the cash notes into that vault.
    Deposit { amount: u128, vault: Option<VaultRef> },
    /// Cash paid out to the connected (depositing) account.
    Withdraw { amount: u128 },
    /// The portfolio, read only.
    Portfolio,
    /// Cash already in the pool put into a vault.
    Enter { amount: Amount, vault: VaultRef },
    /// Shares of one vault moved to another (through cash, without any exit).
    Switch { from: VaultRef, to: VaultRef, amount: Amount },
    /// Shares of a vault turned into cash notes, kept in the pool.
    Leave { from: VaultRef, amount: Amount },
    /// A question answered from the pool's reads.
    Ask(Question),
}

const DEPOSIT_VERBS: [&str; 7] = ["place", "put", "deposit", "invest", "stake", "add", "enter"];
const MOVE_VERBS: [&str; 4] = ["move", "switch", "transfer", "shift"];
const POLITE: [&str; 6] = ["please", "ona", "ok", "okay", "now", "can"];
const QUESTION_WORDS: [&str; 12] = ["how", "what", "whats", "which", "where", "am", "is", "are", "show", "list", "tell", "give"];

/// The words of `text`, lower case, punctuation other than `.`/`,` inside numbers and `#` dropped.
fn words(text: &str) -> Vec<String> {
    let cleaned: String = text
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == ',' || c == '#' || c == '-' || c == '_' { c } else { ' ' })
        .collect();
    cleaned
        .split_whitespace()
        .map(|w| {
            // A sentence's final dot or comma is not part of a number or a word.
            w.trim_end_matches(['.', ',']).trim_start_matches(['.', ',']).to_owned()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

/// "1", "1.5", "0,5" as yoctoNEAR, exact (at most 24 decimals); None for anything else.
pub fn parse_near(text: &str) -> Option<u128> {
    let text = text.replace(',', ".");
    let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
    if whole.is_empty() && fraction.is_empty() {
        return None;
    }
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    if !digits(whole) || !digits(fraction) || fraction.len() > 24 || whole.len() > 12 {
        return None;
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let fraction: u128 = if fraction.is_empty() { 0 } else { format!("{fraction:0<24}").parse().ok()? };
    whole.checked_mul(NEAR)?.checked_add(fraction).filter(|v| *v > 0)
}

/// yoctoNEAR as "1.5 NEAR", exact.
pub fn near_text(yocto: u128) -> String {
    let whole = yocto / NEAR;
    let fraction = format!("{:024}", yocto % NEAR);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() { format!("{whole} NEAR") } else { format!("{whole}.{fraction} NEAR") }
}

/// The amounts written with their unit ("1 NEAR", "1.5near"), and whether a number with that unit was unreadable.
fn amounts(words: &[String]) -> (Vec<u128>, bool) {
    let (mut found, mut bad) = (Vec::new(), false);
    for (i, w) in words.iter().enumerate() {
        let number = match w.strip_suffix("near").filter(|n| !n.is_empty()) {
            Some(n) if n.starts_with(|c: char| c.is_ascii_digit() || c == '.') => Some(n),
            Some(_) => None,
            None if words.get(i + 1).is_some_and(|next| next == "near")
                && w.starts_with(|c: char| c.is_ascii_digit() || c == '.' || c == ',') => Some(w.as_str()),
            None => None,
        };
        if let Some(n) = number {
            match parse_near(n) {
                Some(v) => found.push(v),
                None => bad = true,
            }
        }
    }
    (found, bad)
}

/// The one amount written with its unit. Two amounts, or an unreadable one: None.
fn amount(words: &[String]) -> Option<u128> {
    match amounts(words) {
        (found, false) if found.len() == 1 => Some(found[0]),
        _ => None,
    }
}

/// The amount of an operation on notes in the pool: the one written, or all when none is. None when two are written or
/// one is unreadable.
fn amount_or_all(words: &[String]) -> Option<Amount> {
    match amounts(words) {
        (found, false) if found.is_empty() => Some(Amount::All),
        (found, false) if found.len() == 1 => Some(Amount::Near(found[0])),
        _ => None,
    }
}

/// Every vault named, with the position of its word: "vault 0", "vault0", "vault #1", "staking", "lending".
fn vault_refs(words: &[String]) -> Vec<(usize, VaultRef)> {
    let mut refs = Vec::new();
    for (i, w) in words.iter().enumerate() {
        let number = if w == "vault" {
            words.get(i + 1).map(|n| n.trim_start_matches('#').to_owned())
        } else {
            w.strip_prefix("vault").map(|n| n.trim_start_matches('#').to_owned())
        };
        if let Some(index) = number.filter(|n| !n.is_empty()).and_then(|n| n.parse::<u32>().ok()) {
            refs.push((i, VaultRef::Index(index)));
        } else if w == "staking" || w == "lending" {
            refs.push((i, VaultRef::Kind(w.clone())));
        }
    }
    refs
}

fn vault(words: &[String]) -> Option<VaultRef> {
    let refs = vault_refs(words);
    if let Some((_, first)) = refs.into_iter().next() {
        return Some(first);
    }
    words.iter().any(|w| w == "vault" || w == "vaults").then_some(VaultRef::Any)
}

fn has(words: &[String], word: &str) -> bool {
    words.iter().any(|w| w == word)
}

/// Where a move starts and ends: a vault, or the cash.
#[derive(Debug, PartialEq)]
enum Place {
    Vault(VaultRef),
    Cash,
}

/// "from X to Y" / "X to Y" / "Y" after "into", "in": the places before and after the destination word.
fn places(words: &[String]) -> (Option<Place>, Option<Place>) {
    let split = words.iter().position(|w| w == "to" || w == "into" || w == "in").unwrap_or(words.len());
    let refs = vault_refs(words);
    let place = |range: std::ops::Range<usize>| -> Option<Place> {
        if let Some((_, r)) = refs.iter().find(|(i, _)| range.contains(i)) {
            return Some(Place::Vault(r.clone()));
        }
        if words[range.clone()].iter().any(|w| w == "cash") {
            return Some(Place::Cash);
        }
        words[range].iter().any(|w| w == "vault").then_some(Place::Vault(VaultRef::Any))
    };
    (place(0..split), place(split..words.len()))
}

/// A question about the person's pool, or None. Short (at most 10 words), starting with a question word or ending
/// with "?", and about "my"/"I" for the person's figures.
fn question(words: &[String], asked: bool) -> Option<Question> {
    let first = words.first()?.as_str();
    if words.len() > 10 || !(asked || QUESTION_WORDS.contains(&first)) {
        return None;
    }
    let w = |word: &str| has(words, word);
    let me = w("my") || w("i") || w("me") || w("mine");
    let index = vault_refs(words).into_iter().find_map(|(_, r)| match r {
        VaultRef::Index(i) => Some(i),
        _ => None,
    });
    if ["private", "privacy", "anonymous", "anonymity", "traceable", "linkable", "hidden"].iter().any(|x| w(x))
        && (me || w("position"))
    {
        return Some(Question::Privacy);
    }
    if (w("withdraw") || w("withdrawable") || (w("take") && w("out")) || w("cash-out")) && me && (w("can") || w("much")) {
        return Some(Question::Withdrawable);
    }
    if let Some(i) = index {
        if ["what", "whats", "how", "show", "tell"].contains(&first) && !w("vaults") {
            return Some(Question::Vault(i));
        }
    }
    if w("vaults") || (w("vault") && index.is_none() && (w("which") || w("what") || w("whats") || w("list"))) {
        return Some(Question::Vaults);
    }
    let holding = w("have") || w("hold") || w("own") || w("got");
    if me && ((w("much") && holding) || (w("what") && holding) || w("balance") || w("total") || w("worth")) {
        return Some(Question::Total);
    }
    None
}

/// Reads a pool request or a question about the person's pool; None when `text` is neither (it then goes to the free
/// research). An order starts with its verb (after "please", "ona"…) and is not a question.
pub fn parse(text: &str) -> Option<Intent> {
    if text.chars().count() > 200 {
        return None;
    }
    let asked = text.trim_end().ends_with('?');
    let all = words(text);
    let start = all.iter().position(|w| !POLITE.contains(&w.as_str()) && w != "you" && w != "i" && w != "want" && w != "to"
        && w != "would" && w != "like" && w != "could")?;
    let words = &all[start..];
    let verb = words.first()?.as_str();

    let portfolio_words = ["portfolio", "holdings", "positions"];
    if (["show", "see", "display", "view", "open", "my"].contains(&verb) || portfolio_words.contains(&verb))
        && words.len() <= 8
        && words.iter().any(|w| portfolio_words.contains(&w.as_str()))
        && (has(words, "my") || portfolio_words.contains(&verb))
    {
        return Some(Intent::Portfolio);
    }
    // Questions are read from the whole text ("can I withdraw…?" starts with a polite word).
    if let Some(q) = question(&all, asked) {
        return Some(Intent::Ask(q));
    }
    if asked || words.len() > 16 {
        return None;
    }
    let (from, to) = places(words);
    let source_vault = |p: &Option<Place>| match p {
        Some(Place::Vault(r)) if *r != VaultRef::Any => Some(r.clone()),
        _ => None,
    };
    match verb {
        // "move vault 0 to vault 1", "move vault 0 to cash", "move 1 NEAR from cash to the staking vault".
        v if MOVE_VERBS.contains(&v) => {
            let amount = amount_or_all(words)?;
            match (from, to) {
                (Some(Place::Vault(a)), Some(Place::Vault(b))) if a != VaultRef::Any =>
                    Some(Intent::Switch { from: a, to: b, amount }),
                (Some(Place::Vault(a)), Some(Place::Cash)) if a != VaultRef::Any => Some(Intent::Leave { from: a, amount }),
                (Some(Place::Cash), Some(Place::Vault(b))) => Some(Intent::Enter { amount, vault: b }),
                _ => None,
            }
        }
        // "take my NEAR out of vault 0", "get 1 NEAR out of the staking vault".
        "take" | "get" if has(words, "out") => {
            let from = source_vault(&from).or_else(|| source_vault(&to))?;
            Some(Intent::Leave { from, amount: amount_or_all(words)? })
        }
        "leave" => Some(Intent::Leave { from: source_vault(&from).or_else(|| source_vault(&to))?, amount: amount_or_all(words)? }),
        // "withdraw 1 NEAR from vault 0" leaves the vault (to cash); "withdraw 0.5 NEAR" pays cash out.
        "withdraw" | "exit" => match source_vault(&from).or_else(|| source_vault(&to)) {
            Some(from) => Some(Intent::Leave { from, amount: amount_or_all(words)? }),
            None if verb == "withdraw" || words.iter().any(|w| w == "cash" || w == "wallet" || w == "account") =>
                Some(Intent::Withdraw { amount: amount(words)? }),
            None => None,
        },
        "cash" | "pay" if words.get(1).is_some_and(|w| w == "out") && vault(words).is_none() =>
            Some(Intent::Withdraw { amount: amount(words)? }),
        // "put my cash in vault 0", "put 2 NEAR of my cash in vault 0": cash already in the pool.
        v if DEPOSIT_VERBS.contains(&v) && v != "deposit" && has(words, "cash") => {
            let Some(Place::Vault(vault)) = to.or(from) else { return None };
            Some(Intent::Enter { amount: amount_or_all(words)?, vault })
        }
        v if DEPOSIT_VERBS.contains(&v) => Some(Intent::Deposit { amount: amount(words)?, vault: vault(words) }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deposit(amount: u128, vault: Option<VaultRef>) -> Option<Intent> {
        Some(Intent::Deposit { amount, vault })
    }

    fn kind(k: &str) -> VaultRef {
        VaultRef::Kind(k.into())
    }

    #[test]
    fn reads_deposits_with_their_vault() {
        assert_eq!(parse("place 1 NEAR in vault 0"), deposit(NEAR, Some(VaultRef::Index(0))));
        assert_eq!(parse("Place 1 NEAR in vault 0."), deposit(NEAR, Some(VaultRef::Index(0))));
        assert_eq!(parse("put 2 NEAR in the staking vault"), deposit(2 * NEAR, Some(kind("staking"))));
        assert_eq!(parse("deposit 1 NEAR"), deposit(NEAR, None));
        assert_eq!(parse("please deposit 0.5 near into vault #1"), deposit(NEAR / 2, Some(VaultRef::Index(1))));
        assert_eq!(parse("I want to put 1,5 NEAR in a vault"), deposit(3 * NEAR / 2, Some(VaultRef::Any)));
        assert_eq!(parse("stake 1near"), deposit(NEAR, None));
        assert_eq!(parse("invest 0.1 NEAR in staking"), deposit(NEAR / 10, Some(kind("staking"))));
        assert_eq!(parse("place 1 NEAR in vault0"), deposit(NEAR, Some(VaultRef::Index(0))));
    }

    #[test]
    fn reads_withdrawals_and_the_portfolio() {
        assert_eq!(parse("withdraw 0.5 NEAR"), Some(Intent::Withdraw { amount: NEAR / 2 }));
        assert_eq!(parse("exit 1 NEAR to cash"), Some(Intent::Withdraw { amount: NEAR }));
        assert_eq!(parse("cash out 1 NEAR"), Some(Intent::Withdraw { amount: NEAR }));
        assert_eq!(parse("pay out 0.6 NEAR"), Some(Intent::Withdraw { amount: 6 * NEAR / 10 }));
        assert_eq!(parse("show my portfolio"), Some(Intent::Portfolio));
        assert_eq!(parse("Show me my pool holdings"), Some(Intent::Portfolio));
        assert_eq!(parse("my portfolio"), Some(Intent::Portfolio));
        assert_eq!(parse("portfolio"), Some(Intent::Portfolio));
        assert_eq!(parse("show my portfolio?"), Some(Intent::Portfolio));
    }

    #[test]
    fn reads_moves_of_notes_already_in_the_pool() {
        let enter = |amount, vault| Some(Intent::Enter { amount, vault });
        assert_eq!(parse("put 2 NEAR of my cash in vault 0"), enter(Amount::Near(2 * NEAR), VaultRef::Index(0)));
        assert_eq!(parse("move 1 NEAR from cash to the staking vault"), enter(Amount::Near(NEAR), kind("staking")));
        assert_eq!(parse("put my cash in vault 0"), enter(Amount::All, VaultRef::Index(0)));
        assert_eq!(parse("put all my cash into vault 1"), enter(Amount::All, VaultRef::Index(1)));
        assert_eq!(parse("move my cash to vault 0"), enter(Amount::All, VaultRef::Index(0)));

        let switch = |from, to, amount| Some(Intent::Switch { from, to, amount });
        assert_eq!(parse("move vault 0 to vault 1"), switch(VaultRef::Index(0), VaultRef::Index(1), Amount::All));
        assert_eq!(parse("switch 1 NEAR from vault 0 to vault 1"),
                   switch(VaultRef::Index(0), VaultRef::Index(1), Amount::Near(NEAR)));
        assert_eq!(parse("move vault 1 to the staking vault"), switch(VaultRef::Index(1), kind("staking"), Amount::All));

        let leave = |from, amount| Some(Intent::Leave { from, amount });
        assert_eq!(parse("take my NEAR out of vault 0"), leave(VaultRef::Index(0), Amount::All));
        assert_eq!(parse("take 0.5 NEAR out of vault 0"), leave(VaultRef::Index(0), Amount::Near(NEAR / 2)));
        assert_eq!(parse("move vault 0 to cash"), leave(VaultRef::Index(0), Amount::All));
        assert_eq!(parse("leave vault 0"), leave(VaultRef::Index(0), Amount::All));
        assert_eq!(parse("withdraw 1 NEAR from vault 0"), leave(VaultRef::Index(0), Amount::Near(NEAR)));
        assert_eq!(parse("exit the staking vault"), leave(kind("staking"), Amount::All));
        assert_eq!(parse("get my NEAR out of the staking vault"), leave(kind("staking"), Amount::All));
    }

    #[test]
    fn reads_questions_about_the_pool() {
        let ask = |q| Some(Intent::Ask(q));
        assert_eq!(parse("how much do I have?"), ask(Question::Total));
        assert_eq!(parse("How much do I have in the pool"), ask(Question::Total));
        assert_eq!(parse("what's my balance?"), ask(Question::Total));
        assert_eq!(parse("what do I have?"), ask(Question::Total));
        assert_eq!(parse("what's in vault 0?"), ask(Question::Vault(0)));
        assert_eq!(parse("how much do I have in vault 1?"), ask(Question::Vault(1)));
        assert_eq!(parse("how private is my position?"), ask(Question::Privacy));
        assert_eq!(parse("Am I anonymous?"), ask(Question::Privacy));
        assert_eq!(parse("how much can I withdraw?"), ask(Question::Withdrawable));
        assert_eq!(parse("what can I take out?"), ask(Question::Withdrawable));
        assert_eq!(parse("what vaults are there?"), ask(Question::Vaults));
        assert_eq!(parse("which vaults can I use"), ask(Question::Vaults));
    }

    #[test]
    fn anything_else_goes_to_the_research() {
        for text in [
            "How much does it cost to deposit 1 NEAR in a staking pool?",
            "Combien coûte un plombier à Lyon ? Écris-leur et paie un acompte",
            "How much does a plumber cost in Lyon?",
            "What is the privacy policy of the city of Lyon?",
            "how much do I have to pay a plumber for a leak in Lyon?", // more than 10 words
            "deposit some NEAR",                       // no amount
            "place 1 NEAR and 2 NEAR in vault 0",      // two amounts
            "deposit 1 in vault 0",                    // no unit: never guessed
            "place 0 NEAR in vault 0",                 // nothing to deposit
            "place 0.0000000000000000000000001 NEAR",  // more than 24 decimals
            "find me a lawyer to put 1 NEAR in vault 0", // not an order to ONA's pool
            "pay 1 NEAR to bob.testnet",               // a payment, not a pool exit
            "move 1 NEAR to bob.testnet",              // nowhere in the pool
            "move vault 0",                            // no destination
            "put my cash in my pocket",                // no vault
            "take 0 NEAR out of vault 0",              // nothing
            "show me the news",
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    #[test]
    fn amounts_are_exact() {
        assert_eq!(parse_near("1"), Some(NEAR));
        assert_eq!(parse_near("0.1"), Some(NEAR / 10));
        assert_eq!(parse_near(".5"), Some(NEAR / 2));
        assert_eq!(parse_near("2,25"), Some(9 * NEAR / 4));
        assert_eq!(parse_near("1e3"), None);
        assert_eq!(parse_near("-1"), None);
        assert_eq!(near_text(15 * NEAR / 10), "1.5 NEAR");
        assert_eq!(near_text(2 * NEAR), "2 NEAR");
        assert_eq!(near_text(1), "0.000000000000000000000001 NEAR");
    }
}
