//! Pool requests typed in a conversation on this computer ("place 1 NEAR in vault 0"): read here with fixed patterns,
//! never by the model. The amount and the vault come from the person's words only; the account is the wallet the
//! person connected (docs/desktop/tauri.md, "Pool requests in the chat"). A text that does not match falls through to
//! the free research.

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

#[derive(Clone, Debug, PartialEq)]
pub enum Intent {
    /// A deposit from the person's wallet, then (with a vault) an entry of the cash notes into that vault.
    Deposit { amount: u128, vault: Option<VaultRef> },
    /// Cash paid out to the connected (depositing) account.
    Withdraw { amount: u128 },
    /// The portfolio, read only.
    Portfolio,
}

const DEPOSIT_VERBS: [&str; 7] = ["place", "put", "deposit", "invest", "stake", "add", "enter"];
const WITHDRAW_VERBS: [&str; 4] = ["withdraw", "exit", "cash", "pay"];
const POLITE: [&str; 6] = ["please", "ona", "ok", "okay", "now", "can"];

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

/// The one amount written with its unit: "1 NEAR", "1.5near", "0,5 Ⓝ" is not read. Two amounts: None.
fn amount(words: &[String]) -> Option<u128> {
    let mut found = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if let Some(number) = w.strip_suffix("near").filter(|n| !n.is_empty()) {
            found.extend(parse_near(number));
        } else if words.get(i + 1).is_some_and(|next| next == "near") {
            if let Some(value) = parse_near(w) {
                found.push(value);
            }
        }
    }
    (found.len() == 1).then(|| found[0])
}

fn vault(words: &[String]) -> Option<VaultRef> {
    for (i, w) in words.iter().enumerate() {
        let number = if w == "vault" {
            words.get(i + 1).map(|n| n.trim_start_matches('#').to_owned())
        } else {
            w.strip_prefix("vault").map(|n| n.trim_start_matches('#').to_owned())
        };
        if let Some(index) = number.filter(|n| !n.is_empty()).and_then(|n| n.parse::<u32>().ok()) {
            return Some(VaultRef::Index(index));
        }
    }
    for kind in ["staking", "lending"] {
        if words.iter().any(|w| w == kind) {
            return Some(VaultRef::Kind(kind.into()));
        }
    }
    words.iter().any(|w| w == "vault" || w == "vaults").then_some(VaultRef::Any)
}

/// Reads a pool request; None when `text` is not one (it then goes to the free research). Only an order counts: it
/// starts with its verb (after "please", "ona"…) and is not a question.
pub fn parse(text: &str) -> Option<Intent> {
    if text.trim_end().ends_with('?') || text.chars().count() > 200 {
        return None;
    }
    let all = words(text);
    let start = all.iter().position(|w| !POLITE.contains(&w.as_str()) && w != "you" && w != "i" && w != "want" && w != "to"
        && w != "would" && w != "like" && w != "could")?;
    let words = &all[start..];
    let verb = words.first()?.as_str();

    let portfolio_words = ["portfolio", "holdings", "positions", "balance", "balances"];
    if ["show", "see", "display", "view", "open", "my", "what"].contains(&verb) || portfolio_words.contains(&verb) {
        if words.len() <= 8 && words.iter().any(|w| portfolio_words.contains(&w.as_str()))
            && (words.iter().any(|w| w == "my") || portfolio_words.contains(&verb))
        {
            return Some(Intent::Portfolio);
        }
        return None;
    }
    if words.len() > 16 {
        return None;
    }
    if DEPOSIT_VERBS.contains(&verb) {
        let amount = amount(words)?;
        return Some(Intent::Deposit { amount, vault: vault(words) });
    }
    if WITHDRAW_VERBS.contains(&verb) {
        // "exit 1 NEAR to cash", "cash out 1 NEAR", "pay out 1 NEAR", "withdraw 1 NEAR".
        let ok = match verb {
            "withdraw" => true,
            "exit" => words.iter().any(|w| w == "cash" || w == "wallet" || w == "account"),
            _ => words.get(1).is_some_and(|w| w == "out"),
        };
        if !ok || vault(words).is_some() {
            return None;
        }
        return Some(Intent::Withdraw { amount: amount(words)? });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deposit(amount: u128, vault: Option<VaultRef>) -> Option<Intent> {
        Some(Intent::Deposit { amount, vault })
    }

    #[test]
    fn reads_deposits_with_their_vault() {
        assert_eq!(parse("place 1 NEAR in vault 0"), deposit(NEAR, Some(VaultRef::Index(0))));
        assert_eq!(parse("Place 1 NEAR in vault 0."), deposit(NEAR, Some(VaultRef::Index(0))));
        assert_eq!(parse("put 2 NEAR in the staking vault"), deposit(2 * NEAR, Some(VaultRef::Kind("staking".into()))));
        assert_eq!(parse("deposit 1 NEAR"), deposit(NEAR, None));
        assert_eq!(parse("please deposit 0.5 near into vault #1"), deposit(NEAR / 2, Some(VaultRef::Index(1))));
        assert_eq!(parse("I want to put 1,5 NEAR in a vault"), deposit(3 * NEAR / 2, Some(VaultRef::Any)));
        assert_eq!(parse("stake 1near"), deposit(NEAR, None));
        assert_eq!(parse("invest 0.1 NEAR in staking"), deposit(NEAR / 10, Some(VaultRef::Kind("staking".into()))));
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
    }

    #[test]
    fn anything_else_goes_to_the_research() {
        for text in [
            "How much does it cost to deposit 1 NEAR in a staking pool?",
            "Combien coûte un plombier à Lyon ? Écris-leur et paie un acompte",
            "deposit some NEAR",                       // no amount
            "place 1 NEAR and 2 NEAR in vault 0",      // two amounts
            "deposit 1 in vault 0",                    // no unit: never guessed
            "place 0 NEAR in vault 0",                 // nothing to deposit
            "place 0.0000000000000000000000001 NEAR",  // more than 24 decimals
            "find me a lawyer to put 1 NEAR in vault 0", // not an order to ONA's pool
            "pay 1 NEAR to bob.testnet",               // a payment, not a pool exit
            "withdraw 1 NEAR from vault 0",            // a vault leave is done in the Pool screen
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
