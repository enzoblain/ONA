//! Local pseudonym table. Each protected term (names, identifiers, words the user declares for a
//! mission) is replaced by a random pseudonym before any text goes to the model, and replies are
//! put back locally. The table never leaves this machine.
//!
//! Texts and terms are compared on a normalized view, built in this order:
//! 1. one level of decoding: HTML tags and comments removed (`<br>`, `<p>`, `<div>`, `<li>`, `<tr>`
//!    count as a line break); numeric character references, with or without `;` and with any number
//!    of leading zeros, `&#128;` to `&#159;` read as Windows-1252 like browsers do; named references
//!    of Latin-1 (also without `;`, longest name first), Latin Extended-A, common punctuation and the
//!    invisible ones (`&ZeroWidthSpace;`, `&NoBreak;`, `&it;`...); `%XX` runs, bytes that are not
//!    valid UTF-8 dropped;
//! 2. Unicode default-ignorable characters removed, and U+2028, U+2029, U+0085;
//! 3. a dash or a soft hyphen that ends a line between letters kept as optional: a term matches with
//!    or without it (`Du-` / `pont` matches "Dupont", `Jean-` / `Luc` matches "Jean-Luc");
//! 4. apostrophe-like and dash-like characters folded (the exact lists are `APOSTROPHES` and `DASHES`);
//! 5. Unicode NFKD, every combining mark removed (so accents never matter: "Elodie" and "ELODIE" match
//!    "Élodie", and stray underline or strike-through marks are ignored), Unicode lowercasing, `ß` as
//!    `ss`;
//! 6. every run of Unicode white space collapsed to one space.
//!
//! A term matches as a whole word: "Ali" is not replaced inside "alibi". A term written between two
//! asterisks (`*ali*`) matches anywhere, also inside words. The gate (`gate::Policy::check_terms`)
//! uses the same comparison and refuses any text that still holds a term.
//!
//! Not covered: a term that was not declared; a term written another way (misspelled, abbreviated,
//! inflected, initials, transliterated, split by a line break without a hyphen); look-alike letters of
//! other scripts (Cyrillic `у` for `u`) and small capitals, which NFKD does not fold; escapes nested
//! twice or more (`%2570`, `&amp;#112;`); `+` used for a space in URLs; HTML named references outside
//! the sets above; and the context around a name (job, place, dates, a rare situation).

use rand::rngs::OsRng;
use rand::RngCore;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

/// A term shorter than this, after normalization, gets no pseudonym; the gate still refuses it.
pub const MIN_TERM_CHARS: usize = 2;
pub const MAX_TERMS: usize = 64;
pub const MAX_TERM_CHARS: usize = 200;
/// Pseudonyms are this many letters from `ALPHABET`: no vowel, so they spell no word, and no digit,
/// so they can never be read as a price or a delay.
pub const PSEUDONYM_LEN: usize = 12;
const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
const ATTEMPTS: usize = 64;

/// One character of the comparison view, with the byte range of the original text it comes from.
/// An `optional` unit is a hyphen that ended a line: a term may match with or without it.
#[derive(Debug, Clone, Copy)]
struct Unit {
    c: char,
    start: usize,
    end: usize,
    optional: bool,
}

/// Unicode Default_Ignorable_Code_Point (as of Unicode 15), plus the line and paragraph separators
/// and NEL.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{0085}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{FFF0}'..='\u{FFF8}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}')
}

fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}' | '\u{0085}' | '\u{000B}' | '\u{000C}')
}

/// Folded to `-`: General_Category Pd and the Dash property (Unicode 15), plus U+02D7 and U+2796.
pub const DASHES: &[char] = &[
    '-', '\u{058A}', '\u{05BE}', '\u{1400}', '\u{1806}', '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}',
    '\u{2015}', '\u{2043}', '\u{2053}', '\u{207B}', '\u{208B}', '\u{2212}', '\u{2E17}', '\u{2E1A}', '\u{2E3A}', '\u{2E3B}',
    '\u{2E40}', '\u{2E5D}', '\u{301C}', '\u{3030}', '\u{30A0}', '\u{FE31}', '\u{FE32}', '\u{FE58}', '\u{FE63}', '\u{FF0D}',
    '\u{10EAD}', '\u{02D7}', '\u{2796}',
];

/// Folded to `'`.
pub const APOSTROPHES: &[char] = &[
    '\'', '`', '\u{00B4}', '\u{02B9}', '\u{02BB}', '\u{02BC}', '\u{02BD}', '\u{02BE}', '\u{0384}', '\u{055A}', '\u{05F3}',
    '\u{1FBD}', '\u{1FBF}', '\u{1FEF}', '\u{1FFD}', '\u{2018}', '\u{2019}', '\u{201B}', '\u{2032}', '\u{2035}', '\u{A78B}',
    '\u{A78C}', '\u{FF07}', '\u{FF40}',
];

fn is_dash(c: char) -> bool {
    DASHES.contains(&c)
}

fn fold(c: char) -> char {
    if is_dash(c) {
        '-'
    } else if APOSTROPHES.contains(&c) {
        '\''
    } else {
        c
    }
}

/// `&#128;` to `&#159;`, read as Windows-1252 by browsers.
const WINDOWS_1252: [u32; 32] = [
    0x20AC, 0x81, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8D, 0x017D, 0x8F,
    0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x9D, 0x017E, 0x0178,
];

/// Latin-1 names, U+00A0 to U+00FF in order.
const LATIN1: [&str; 96] = [
    "nbsp", "iexcl", "cent", "pound", "curren", "yen", "brvbar", "sect", "uml", "copy", "ordf", "laquo", "not", "shy", "reg", "macr",
    "deg", "plusmn", "sup2", "sup3", "acute", "micro", "para", "middot", "cedil", "sup1", "ordm", "raquo", "frac14", "frac12", "frac34", "iquest",
    "Agrave", "Aacute", "Acirc", "Atilde", "Auml", "Aring", "AElig", "Ccedil", "Egrave", "Eacute", "Ecirc", "Euml", "Igrave", "Iacute", "Icirc", "Iuml",
    "ETH", "Ntilde", "Ograve", "Oacute", "Ocirc", "Otilde", "Ouml", "times", "Oslash", "Ugrave", "Uacute", "Ucirc", "Uuml", "Yacute", "THORN", "szlig",
    "agrave", "aacute", "acirc", "atilde", "auml", "aring", "aelig", "ccedil", "egrave", "eacute", "ecirc", "euml", "igrave", "iacute", "icirc", "iuml",
    "eth", "ntilde", "ograve", "oacute", "ocirc", "otilde", "ouml", "divide", "oslash", "ugrave", "uacute", "ucirc", "uuml", "yacute", "thorn", "yuml",
];

/// Latin Extended-A (U+0100 to U+017F) and punctuation names of HTML5.
const OTHER_NAMES: &[(&str, u32)] = &[
    ("Amacr", 0x100), ("amacr", 0x101), ("Abreve", 0x102), ("abreve", 0x103), ("Aogon", 0x104), ("aogon", 0x105),
    ("Cacute", 0x106), ("cacute", 0x107), ("Ccirc", 0x108), ("ccirc", 0x109), ("Cdot", 0x10A), ("cdot", 0x10B),
    ("Ccaron", 0x10C), ("ccaron", 0x10D), ("Dcaron", 0x10E), ("dcaron", 0x10F), ("Dstrok", 0x110), ("dstrok", 0x111),
    ("Emacr", 0x112), ("emacr", 0x113), ("Edot", 0x116), ("edot", 0x117), ("Eogon", 0x118), ("eogon", 0x119),
    ("Ecaron", 0x11A), ("ecaron", 0x11B), ("Gcirc", 0x11C), ("gcirc", 0x11D), ("Gbreve", 0x11E), ("gbreve", 0x11F),
    ("Gdot", 0x120), ("gdot", 0x121), ("Gcedil", 0x122), ("Hcirc", 0x124), ("hcirc", 0x125), ("Hstrok", 0x126),
    ("hstrok", 0x127), ("Itilde", 0x128), ("itilde", 0x129), ("Imacr", 0x12A), ("imacr", 0x12B), ("Iogon", 0x12E),
    ("iogon", 0x12F), ("Idot", 0x130), ("imath", 0x131), ("inodot", 0x131), ("IJlig", 0x132), ("ijlig", 0x133),
    ("Jcirc", 0x134), ("jcirc", 0x135), ("Kcedil", 0x136), ("kcedil", 0x137), ("kgreen", 0x138), ("Lacute", 0x139),
    ("lacute", 0x13A), ("Lcedil", 0x13B), ("lcedil", 0x13C), ("Lcaron", 0x13D), ("lcaron", 0x13E), ("Lmidot", 0x13F),
    ("lmidot", 0x140), ("Lstrok", 0x141), ("lstrok", 0x142), ("Nacute", 0x143), ("nacute", 0x144), ("Ncedil", 0x145),
    ("ncedil", 0x146), ("Ncaron", 0x147), ("ncaron", 0x148), ("napos", 0x149), ("ENG", 0x14A), ("eng", 0x14B),
    ("Omacr", 0x14C), ("omacr", 0x14D), ("Odblac", 0x150), ("odblac", 0x151), ("OElig", 0x152), ("oelig", 0x153),
    ("Racute", 0x154), ("racute", 0x155), ("Rcedil", 0x156), ("rcedil", 0x157), ("Rcaron", 0x158), ("rcaron", 0x159),
    ("Sacute", 0x15A), ("sacute", 0x15B), ("Scirc", 0x15C), ("scirc", 0x15D), ("Scedil", 0x15E), ("scedil", 0x15F),
    ("Scaron", 0x160), ("scaron", 0x161), ("Tcedil", 0x162), ("tcedil", 0x163), ("Tcaron", 0x164), ("tcaron", 0x165),
    ("Tstrok", 0x166), ("tstrok", 0x167), ("Utilde", 0x168), ("utilde", 0x169), ("Umacr", 0x16A), ("umacr", 0x16B),
    ("Ubreve", 0x16C), ("ubreve", 0x16D), ("Uring", 0x16E), ("uring", 0x16F), ("Udblac", 0x170), ("udblac", 0x171),
    ("Uogon", 0x172), ("uogon", 0x173), ("Wcirc", 0x174), ("wcirc", 0x175), ("Ycirc", 0x176), ("ycirc", 0x177),
    ("Yuml", 0x178), ("Zacute", 0x179), ("zacute", 0x17A), ("Zdot", 0x17B), ("zdot", 0x17C), ("Zcaron", 0x17D),
    ("zcaron", 0x17E), ("fnof", 0x192), ("circ", 0x2C6), ("tilde", 0x2DC), ("ensp", 0x2002), ("emsp", 0x2003),
    ("thinsp", 0x2009), ("zwnj", 0x200C), ("zwj", 0x200D), ("lrm", 0x200E), ("rlm", 0x200F), ("hyphen", 0x2010),
    ("dash", 0x2010), ("ndash", 0x2013), ("mdash", 0x2014), ("lsquo", 0x2018), ("rsquo", 0x2019), ("rsquor", 0x2019),
    ("sbquo", 0x201A), ("ldquo", 0x201C), ("rdquo", 0x201D), ("bdquo", 0x201E), ("minus", 0x2212), ("apos", 0x27),
    ("quot", 0x22), ("amp", 0x26), ("lt", 0x3C), ("gt", 0x3E),
    ("ZeroWidthSpace", 0x200B), ("NegativeVeryThinSpace", 0x200B), ("NegativeThinSpace", 0x200B),
    ("NegativeMediumSpace", 0x200B), ("NegativeThickSpace", 0x200B), ("NoBreak", 0x2060), ("af", 0x2061),
    ("ApplyFunction", 0x2061), ("it", 0x2062), ("InvisibleTimes", 0x2062), ("ic", 0x2063), ("InvisibleComma", 0x2063),
    ("NonBreakingSpace", 0xA0), ("hairsp", 0x200A), ("VeryThinSpace", 0x200A), ("ThinSpace", 0x2009), ("puncsp", 0x2008),
    ("numsp", 0x2007), ("MediumSpace", 0x205F), ("emsp13", 0x2004), ("emsp14", 0x2005), ("NewLine", 0x0A), ("Tab", 0x09),
    ("DownBreve", 0x311), ("tdot", 0x20DB), ("TripleDot", 0x20DB), ("DotDot", 0x20DC),
];

fn named(name: &str) -> Option<char> {
    if let Some(i) = LATIN1.iter().position(|n| *n == name) {
        return char::from_u32(0xA0 + i as u32);
    }
    OTHER_NAMES.iter().find(|(n, _)| *n == name).and_then(|(_, c)| char::from_u32(*c))
}

/// Decodes one HTML character reference at the start of `s` (which starts with `&`): the character
/// and the number of bytes it takes.
fn html_entity(s: &str) -> Option<(char, usize)> {
    let b = s.as_bytes();
    if b.get(1) == Some(&b'#') {
        let hex = matches!(b.get(2), Some(b'x' | b'X'));
        let start = if hex { 3 } else { 2 };
        let digits = b[start..].iter().take_while(|c| if hex { c.is_ascii_hexdigit() } else { c.is_ascii_digit() }).count();
        if digits == 0 {
            return None;
        }
        let written = s[start..start + digits].trim_start_matches('0');
        let value = if written.is_empty() {
            Some(0)
        } else if written.len() > 8 {
            None
        } else {
            u32::from_str_radix(written, if hex { 16 } else { 10 }).ok()
        };
        let value = match value {
            Some(v @ 0x80..=0x9F) => WINDOWS_1252[(v - 0x80) as usize],
            Some(v) => v,
            None => 0xFFFD,
        };
        let c = char::from_u32(value).filter(|c| *c != '\0').unwrap_or('\u{FFFD}');
        let end = start + digits;
        return Some((c, if b.get(end) == Some(&b';') { end + 1 } else { end }));
    }
    let letters = b[1..].iter().take(32).take_while(|c| c.is_ascii_alphanumeric()).count();
    if b.get(1 + letters) == Some(&b';') {
        if let Some(c) = named(&s[1..1 + letters]) {
            return Some((c, letters + 2));
        }
    }
    // Otherwise browsers still decode the longest Latin-1 name, and `amp`, `lt`, `gt`, `quot`, at
    // the start of the letters, even if a `;` comes later ("Fran&ccedilois;").
    (2..=letters).rev().find_map(|len| {
        let name = &s[1..1 + len];
        let c = if LATIN1.contains(&name) {
            named(name)
        } else {
            match name {
                "amp" | "AMP" => Some('&'),
                "lt" | "LT" => Some('<'),
                "gt" | "GT" => Some('>'),
                "quot" | "QUOT" => Some('"'),
                _ => None,
            }
        };
        c.map(|c| (c, len + 1))
    })
}

/// An HTML tag or comment at the start of `s` (which starts with `<`): its length, and whether it
/// stands for a line break.
fn html_tag(s: &str) -> Option<(usize, bool)> {
    if let Some(rest) = s.strip_prefix("<!--") {
        // Bounded like tags, so a page full of unclosed comments costs linear time.
        let window = &rest.as_bytes()[..rest.len().min(2048)];
        return window.windows(3).position(|w| w == b"-->").map(|end| (4 + end + 3, false));
    }
    let b = s.as_bytes();
    let first = *b.get(1)?;
    if !(first.is_ascii_alphabetic() || matches!(first, b'/' | b'!' | b'?')) {
        return None;
    }
    let end = b.iter().take(2048).position(|c| *c == b'>')?;
    if b[1..end].contains(&b'<') {
        return None;
    }
    let name: String = s[1..end].trim_start_matches('/').chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
    let breaks = matches!(name.to_ascii_lowercase().as_str(), "br" | "p" | "div" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6");
    Some((end + 1, breaks))
}

/// Decodes a run of `%XX` escapes at the start of `s`. Bytes that are not valid UTF-8 are dropped,
/// and the run goes on.
fn percent_run(s: &str) -> Option<(Vec<(char, usize, usize)>, usize)> {
    let b = s.as_bytes();
    let mut bytes = Vec::new();
    let mut i = 0;
    while i + 2 < b.len() && b[i] == b'%' && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
        bytes.push(u8::from_str_radix(&s[i + 1..i + 3], 16).ok()?);
        i += 3;
    }
    if bytes.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let mut offset = 0;
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            let len = c.len_utf8();
            out.push((c, offset * 3, (offset + len) * 3));
            offset += len;
        }
        // Bytes that are not valid UTF-8 are dropped, so they cannot split a term.
        offset += chunk.invalid().len();
    }
    Some((out, i))
}

/// Decoding, invisible characters, hyphens at line ends: one unit per decoded character.
fn decode(text: &str) -> Vec<Unit> {
    let unit = |c, start, end| Unit { c, start, end, optional: false };
    let mut units = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        let c = rest.chars().next().expect("not at the end");
        if c == '<' {
            if let Some((len, breaks)) = html_tag(rest) {
                if breaks {
                    units.push(unit('\n', i, i + len));
                }
                i += len;
                continue;
            }
        }
        if c == '&' {
            if let Some((d, len)) = html_entity(rest) {
                units.push(unit(d, i, i + len));
                i += len;
                continue;
            }
        }
        if c == '%' {
            if let Some((chars, len)) = percent_run(rest) {
                units.extend(chars.into_iter().map(|(d, s, e)| unit(d, i + s, i + e)));
                i += len;
                continue;
            }
        }
        units.push(unit(c, i, i + c.len_utf8()));
        i += c.len_utf8();
    }
    // Invisible characters go, except the line breaks and soft hyphens the rule below still needs.
    units.retain(|u| is_line_break(u.c) || u.c == '\u{00AD}' || !is_invisible(u.c));
    let mut joined: Vec<Unit> = Vec::with_capacity(units.len());
    let mut k = 0;
    while k < units.len() {
        let u = units[k];
        if (is_dash(u.c) || u.c == '\u{00AD}') && joined.last().is_some_and(|p| p.c.is_alphabetic()) {
            let mut j = k + 1;
            let mut broken = false;
            while j < units.len() && (units[j].c.is_whitespace() || is_line_break(units[j].c) || units[j].c == '\u{00AD}') {
                broken |= is_line_break(units[j].c);
                j += 1;
            }
            if broken && j < units.len() && units[j].c.is_alphabetic() {
                // The hyphen stays, marked optional; the break and the spaces go.
                joined.push(Unit { c: '-', optional: true, ..u });
                k = j;
                continue;
            }
        }
        joined.push(u);
        k += 1;
    }
    joined.retain(|u| !is_invisible(u.c));
    joined
}

/// The comparison view: apostrophes and dashes folded, NFKD by base character and its combining
/// marks with every mark removed, lowercase, `ß` as `ss`, folded again, and white space collapsed.
fn normalize(text: &str) -> Vec<Unit> {
    let units = decode(text);
    let mut out: Vec<Unit> = Vec::with_capacity(units.len());
    let mut k = 0;
    while k < units.len() {
        let mut j = k + 1;
        while j < units.len() && is_combining_mark(units[j].c) {
            j += 1;
        }
        let cluster: String = units[k..j].iter().map(|u| fold(u.c)).collect();
        let (start, end, optional) = (units[k].start, units[j - 1].end, units[k].optional);
        let chars = cluster.nfkd().filter(|c| !is_combining_mark(*c)).flat_map(char::to_lowercase).filter(|c| !is_combining_mark(*c));
        for c in chars {
            for c in if c == '\u{00DF}' { vec!['s', 's'] } else { vec![fold(c)] } {
                if c.is_whitespace() {
                    if let Some(last) = out.last_mut().filter(|l| l.c == ' ' && !l.optional) {
                        last.end = end;
                        continue;
                    }
                    out.push(Unit { c: ' ', start, end, optional: false });
                } else {
                    out.push(Unit { c, start, end, optional });
                }
            }
        }
        k = j;
    }
    out
}

/// The normalized characters of a text (optional hyphens included), for tests and comparisons.
pub fn normalized(text: &str) -> String {
    normalize(text).iter().map(|u| u.c).collect()
}

#[derive(Debug, Clone)]
struct Term {
    /// As declared, without the asterisks: what replies get back.
    display: String,
    chars: Vec<char>,
    substring: bool,
}

fn parse_term(term: &str) -> Option<Term> {
    let trimmed = term.trim();
    let (display, substring) = match trimmed.strip_prefix('*').and_then(|t| t.strip_suffix('*')) {
        Some(inner) => (inner.trim(), true),
        None => (trimmed, false),
    };
    let chars: Vec<char> = normalize(display).iter().map(|u| u.c).collect();
    (!chars.is_empty()).then(|| Term { display: display.to_string(), chars, substring })
}

/// Number of normalized characters of a term as declared, for length limits.
pub fn term_len(term: &str) -> usize {
    parse_term(term).map_or(0, |t| t.chars.len())
}

/// Where a match of `term` starting at `i` ends (exclusive), if there is one. An optional hyphen in
/// the text is skipped when the term has no hyphen there.
fn matches_at(view: &[Unit], i: usize, term: &Term) -> Option<usize> {
    let mut j = i;
    for (n, tc) in term.chars.iter().enumerate() {
        if j < view.len() && view[j].optional && *tc != '-' && n > 0 {
            j += 1;
        }
        if j >= view.len() || view[j].c != *tc {
            return None;
        }
        j += 1;
    }
    if term.substring {
        return Some(j);
    }
    let before = i == 0 || !view[i - 1].c.is_alphanumeric();
    let after = j == view.len() || !view[j].c.is_alphanumeric();
    (before && after).then_some(j)
}

/// True if `text` holds one of `terms` under the comparison of this module. Used by the gate.
pub fn contains_protected(text: &str, terms: &[String]) -> bool {
    let terms: Vec<Term> = terms.iter().filter_map(|t| parse_term(t)).collect();
    if terms.is_empty() {
        return false;
    }
    let view = normalize(text);
    (0..view.len()).any(|i| terms.iter().any(|t| matches_at(&view, i, t).is_some()))
}

#[derive(Debug, Clone, Default)]
pub struct Pseudonyms {
    /// (term, pseudonym), longest term first.
    entries: Vec<(Term, String)>,
}

fn new_pseudonym() -> String {
    let mut bytes = [0u8; PSEUDONYM_LEN];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char).collect()
}

impl Pseudonyms {
    /// Builds a table with a new random pseudonym for each usable term. Empty, too short or too
    /// long terms get no pseudonym (the gate still blocks them).
    pub fn new(terms: &[String]) -> Self {
        let mut usable: Vec<Term> = terms
            .iter()
            .filter_map(|t| parse_term(t))
            .filter(|t| (MIN_TERM_CHARS..=MAX_TERM_CHARS).contains(&t.chars.len()))
            .collect();
        usable.sort_by(|a, b| b.chars.len().cmp(&a.chars.len()).then(a.chars.cmp(&b.chars)));
        usable.dedup_by(|a, b| a.chars == b.chars && a.substring == b.substring);
        usable.truncate(MAX_TERMS);
        let all: Vec<String> = usable
            .iter()
            .map(|t| if t.substring { format!("*{}*", t.display) } else { t.display.clone() })
            .collect();
        let mut entries: Vec<(Term, String)> = Vec::new();
        for term in usable {
            // A pseudonym must not hold a term, or the gate would refuse every text using it.
            let pseudonym = (0..ATTEMPTS)
                .map(|_| new_pseudonym())
                .find(|p| !contains_protected(p, &all) && !entries.iter().any(|(_, q)| q == p));
            if let Some(pseudonym) = pseudonym {
                entries.push((term, pseudonym));
            }
        }
        Self { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The text to send, and how many occurrences were replaced.
    pub fn apply(&self, text: &str) -> (String, usize) {
        let view = normalize(text);
        let mut out = String::with_capacity(text.len());
        let mut copied = 0;
        let mut replaced = 0;
        let mut i = 0;
        while i < view.len() {
            let found = self.entries.iter().find_map(|(t, p)| matches_at(&view, i, t).map(|end| (end, p)));
            match found {
                Some((end, pseudonym)) if view[i].start >= copied => {
                    out.push_str(&text[copied..view[i].start]);
                    out.push_str(pseudonym);
                    copied = view[end - 1].end;
                    replaced += 1;
                    i = end;
                }
                _ => i += 1,
            }
        }
        out.push_str(&text[copied..]);
        (out, replaced)
    }

    /// Puts the declared terms back in a reply. Pseudonyms are recognised whatever their case.
    pub fn restore(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (term, pseudonym) in &self.entries {
            let lower_pseudonym = pseudonym.to_ascii_lowercase();
            let mut result = String::with_capacity(out.len());
            let lower = out.to_ascii_lowercase();
            let mut last = 0;
            for (at, _) in lower.match_indices(&lower_pseudonym) {
                result.push_str(&out[last..at]);
                result.push_str(&term.display);
                last = at + pseudonym.len();
            }
            result.push_str(&out[last..]);
            out = result;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(terms: &[&str]) -> Pseudonyms {
        Pseudonyms::new(&terms.iter().map(|t| t.to_string()).collect::<Vec<_>>())
    }

    fn strings(terms: &[&str]) -> Vec<String> {
        terms.iter().map(|t| t.to_string()).collect()
    }

    /// Seen by the gate, replaced once, and the gate finds nothing left.
    fn hidden(term: &str, text: &str) {
        assert!(contains_protected(text, &strings(&[term])), "the gate sees {term:?} in {text:?}");
        let t = table(&[term]);
        let (sent, n) = t.apply(text);
        assert_eq!(n, 1, "{text:?} -> {sent:?}");
        assert!(!contains_protected(&sent, &strings(&[term])), "{text:?} -> {sent:?}");
    }

    #[test]
    fn every_occurrence_is_replaced_whatever_the_case_and_comes_back() {
        let t = table(&["Dupont", "ACME"]);
        let (sent, n) = t.apply("Mr Dupont, dismissed by acme. DUPONT disputes it.");
        assert_eq!(n, 3);
        assert!(!sent.to_lowercase().contains("dupont") && !sent.to_lowercase().contains("acme"), "{sent}");
        assert_eq!(t.restore(&sent), "Mr Dupont, dismissed by ACME. Dupont disputes it.");
    }

    #[test]
    fn a_decomposed_accent_is_still_the_term() {
        hidden("Élodie", "For E\u{301}lodie.");
    }

    #[test]
    fn a_soft_hyphen_inside_the_term_does_not_hide_it() {
        hidden("Dupont", "Mr Du\u{AD}pont");
    }

    #[test]
    fn a_zero_width_space_inside_the_term_does_not_hide_it() {
        hidden("Dupont", "Mr Du\u{200B}pont");
        hidden("Dupont", "Mr Du\u{200D}pont");
    }

    #[test]
    fn full_width_letters_are_the_term() {
        hidden("Dupont", "Mr \u{FF24}\u{FF55}\u{FF50}\u{FF4F}\u{FF4E}\u{FF54}");
    }

    #[test]
    fn a_word_cut_at_the_end_of_a_line_is_joined() {
        hidden("Dupont", "Mr Du-\npont");
        hidden("Dupont", "Mr Du-\r\n   pont");
    }

    #[test]
    fn a_hyphenated_term_cut_at_its_hyphen_still_matches() {
        hidden("Jean-Luc", "Mr Jean-\nLuc");
        hidden("Jean-Luc", "Mr Jean-Luc");
    }

    #[test]
    fn every_dash_is_a_hyphen() {
        for dash in ['\u{2011}', '\u{2013}', '\u{2212}', '\u{2010}', '\u{2014}'] {
            hidden("Jean-Luc", &format!("Mr Jean{dash}Luc"));
        }
        hidden("Dupont", "Mr Du\u{2011}\npont");
    }

    #[test]
    fn an_html_character_reference_is_decoded() {
        hidden("Dupont", "Mr Du&#112;ont");
        hidden("Dupont", "Mr Du&#x70;ont");
    }

    #[test]
    fn a_numeric_reference_without_semicolon_is_decoded() {
        hidden("Dupont", "Mr Du&#112ont");
    }

    #[test]
    fn named_references_of_letters_are_decoded() {
        hidden("François", "Mr Fran&ccedil;ois");
        hidden("Élodie", "Ms &Eacute;lodie");
        hidden("Łukasz", "Mr &Lstrok;ukasz");
        hidden("François", "Mr Fran&ccedilois");
    }

    #[test]
    fn a_url_escape_is_decoded() {
        hidden("Dupont", "/lawyer?name=Du%70ont");
    }

    #[test]
    fn an_invalid_byte_does_not_stop_url_decoding() {
        hidden("Dupont", "/lawyer?name=%44%75%70%6F%6E%74%FF");
        hidden("Dupont", "/lawyer?name=%FF%44%75%70%6F%6E%74");
    }

    #[test]
    fn typographic_apostrophes_are_the_apostrophe() {
        for text in ["Mr O\u{2019}Brien", "Mr O&#8217;Brien", "Mr O&rsquo;Brien", "Mr O\u{2018}Brien", "Mr O\u{02BC}Brien", "Mr O\u{FF07}Brien"] {
            hidden("O'Brien", text);
        }
    }

    #[test]
    fn line_separators_and_musical_format_characters_are_invisible() {
        hidden("Dupont", "Mr Du\u{2028}pont");
        hidden("Dupont", "Mr Du\u{2029}pont");
        hidden("Dupont", "Mr Du\u{1D173}pont");
        hidden("Dupont", "Mr Du\u{1D17A}pont");
    }

    #[test]
    fn any_run_of_white_space_is_one_space() {
        for text in ["Jean\nDupont", "Jean  Dupont", "Jean\tDupont", "Jean&nbsp;Dupont", "Jean%20Dupont", "Jean\u{2003}\r\n Dupont"] {
            hidden("Jean Dupont", text);
        }
    }

    #[test]
    fn accents_and_stray_combining_marks_never_matter() {
        hidden("Élodie", "ELODIE");
        hidden("Élodie", "Elodie");
        hidden("Elodie", "Élodie");
        hidden("Dupont", "Dupo\u{0332}nt");
        hidden("Dupont", "D\u{0336}u\u{0336}p\u{0336}o\u{0336}n\u{0336}t\u{0336}");
        hidden("Dupont", "Dupont\u{0301}");
        hidden("Dupont", "Du\u{200B}\u{0301}pont");
        hidden("Strauß", "Strauss");
    }

    #[test]
    fn numeric_references_with_leading_zeros_and_windows_1252_are_decoded() {
        hidden("Dupont", "Du&#0000000112;ont");
        hidden("Dupont", "Du&#x000000070;ont");
        hidden("O'Brien", "O&#146;Brien");
        hidden("Jean-Luc", "Jean&#150;Luc");
    }

    #[test]
    fn the_longest_latin1_name_is_decoded_even_before_a_later_semicolon() {
        hidden("François", "Fran&ccedilois;");
        hidden("Élodie", "&Eacutelodie;");
        hidden("Élodie", "For &Eacutelodie");
        hidden("Šimon", "&Scaron;imon");
        hidden("Œdipe", "&OElig;dipe");
        hidden("Đoković", "&Dstrok;okovi&cacute;");
    }

    #[test]
    fn invisible_named_references_are_removed() {
        for text in ["Du&ZeroWidthSpace;pont", "Du&NoBreak;pont", "Du&InvisibleTimes;pont", "Du&it;pont", "Du&shy;pont"] {
            hidden("Dupont", text);
        }
    }

    #[test]
    fn a_soft_hyphen_or_dash_at_a_line_end_joins_the_word() {
        for text in ["Du\u{AD}\npont", "Du-\n\npont", "Du-\rpont", "Du-<br>pont", "Du-&#10;pont", "Du\u{0085}pont", "Du&shy;\npont"] {
            hidden("Dupont", text);
        }
        hidden("Jean-Luc", "Jean\u{2010}\nLuc");
    }

    #[test]
    fn html_tags_and_comments_do_not_split_a_term() {
        hidden("Dupont", "Du<b></b>pont");
        hidden("Dupont", "Du<!-- -->pont");
        hidden("Dupont", "<p>Me <span class=\"x\">Du</span>pont</p>");
    }

    #[test]
    fn unclosed_comments_are_scanned_in_bounded_time() {
        let page = "<!--x".repeat(20_000) + " Dupont";
        let started = std::time::Instant::now();
        assert!(contains_protected(&page, &strings(&["Dupont"])));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn invalid_bytes_in_a_url_escape_are_dropped() {
        hidden("Dupont", "Du%C3%70ont");
    }

    #[test]
    fn every_listed_dash_and_apostrophe_is_folded() {
        for d in ['\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}', '\u{2015}', '\u{2212}', '\u{FE58}', '\u{FE63}', '\u{FF0D}', '\u{2043}', '\u{2053}', '\u{2E17}', '\u{2E1A}', '\u{2E40}', '\u{301C}', '\u{30A0}', '\u{FE31}', '\u{02D7}', '\u{2796}', '\u{207B}'] {
            hidden("Jean-Luc", &format!("Jean{d}Luc"));
        }
        for a in ['\u{2032}', '\u{0060}', '\u{00B4}', '\u{02BB}', '\u{02B9}', '\u{A78C}', '\u{055A}'] {
            hidden("O'Brien", &format!("O{a}Brien"));
        }
        hidden("Dupont", "\u{1D403}\u{1D42E}\u{1D429}\u{1D428}\u{1D427}\u{1D42D}");
    }

    #[test]
    fn only_whole_words_unless_declared_as_a_substring() {
        let t = table(&["Ali"]);
        assert_eq!(t.apply("An alibi for Ali.").1, 1);
        assert!(t.apply("An alibi for Ali.").0.starts_with("An alibi for "));
        assert!(!contains_protected("An alibi", &strings(&["Ali"])));
        let t = table(&["*ali*"]);
        assert_eq!(t.apply("An alibi for Ali.").1, 2);
        assert!(contains_protected("An alibi", &strings(&["*ali*"])));
    }

    #[test]
    fn pseudonyms_have_a_fixed_shape_no_rank_and_no_digit() {
        let t = table(&["Jean", "Dupont"]);
        for (_, p) in &t.entries {
            assert_eq!(p.len(), PSEUDONYM_LEN);
            assert!(p.bytes().all(|b| ALPHABET.contains(&b)), "{p}");
            assert!(!p.bytes().any(|b| b.is_ascii_digit()), "{p}");
            assert!(crate::reader::cited_numbers(p).is_empty(), "{p} would read as a number");
        }
        let (a, _) = table(&["Dupont"]).apply("Dupont");
        let (b, _) = table(&["Dupont"]).apply("Dupont");
        assert_ne!(a, b, "random per table");
    }

    #[test]
    fn a_pseudonym_is_restored_whatever_its_case() {
        let t = table(&["Dupont"]);
        let (sent, _) = t.apply("Dupont");
        assert_eq!(t.restore(&sent.to_lowercase()), "Dupont");
    }

    #[test]
    fn the_longest_term_wins() {
        let t = table(&["Jean", "Jean Dupont"]);
        let (sent, n) = t.apply("Jean Dupont, puis Jean.");
        assert_eq!(n, 2);
        assert_eq!(t.restore(&sent), "Jean Dupont, puis Jean.");
    }

    #[test]
    fn short_or_empty_terms_get_no_pseudonym() {
        assert!(table(&["", " ", "x", "**"]).is_empty());
    }
}
