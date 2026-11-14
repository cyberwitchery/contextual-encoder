//! exhaustive property / invariant test suite.
//!
//! the conformance suite pins behaviour with hand-picked example vectors. this
//! suite instead sweeps the entire unicode scalar range
//! (`0..=0x10FFFF`, ~1.1M values) and asserts machine-checked invariants that
//! must hold for *every* input:
//!
//! - **round-trip** or **safety**, whichever property the entry in
//!   `src/encoders.rs` names: a hand-written decoder (std only, defined below)
//!   recovers the original string from the encoded form, or no
//!   context-breaking sequence survives in the output for that context.
//! - **boundary**: for js_template, the css encoders, xml_comment and cdata,
//!   two `write_*` calls into one sink concatenate to output that is still
//!   safe and still decodes to both inputs.
//! - **universal**: ascii-alphanumeric input is identity, and the `for_*`,
//!   `write_*`, and `display_*` variants agree.
//!
//! the decoders and safety predicates are modelled directly on each encoder's
//! documented mapping, so a passing sweep means the invariant genuinely holds
//! rather than that the predicate is vacuous. the CSS contexts go further and
//! run a tokenizer transcribed from CSS Syntax Level 3 §4.3 over the encoded
//! output.

use std::fmt;

use contextual_encoder::*;

/// signature shared by every `for_*` encoder and the `display_*` wrappers.
type ForFn = fn(&str) -> String;
/// signature shared by every `write_*` encoder (monomorphised to `String`).
type WriteFn = fn(&mut String, &str) -> fmt::Result;

/// every unicode scalar value (surrogates excluded — they are not `char`s).
fn scalars() -> impl Iterator<Item = char> {
    (0..=0x10FFFF).filter_map(char::from_u32)
}

/// renders a single scalar as a `&str` without allocating.
fn one(c: char, buf: &mut [u8; 4]) -> &str {
    c.encode_utf8(buf)
}

// ===========================================================================
// shared predicates (mirrors of the private engine helpers)
// ===========================================================================

fn is_noncharacter(cp: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE == 0xFFFE)
}

/// characters invalid in xml 1.0 output (replaced with space/dash by the
/// html/xml encoders). mirrors `engine::is_invalid_for_xml`.
fn is_invalid_for_xml(c: char) -> bool {
    let cp = c as u32;
    cp <= 0x08
        || cp == 0x0B
        || cp == 0x0C
        || (0x0E..=0x1F).contains(&cp)
        || cp == 0x7F
        || (0x80..=0x9F).contains(&cp)
        || is_noncharacter(cp)
}

/// characters that cannot appear literally in xml 1.1 output (encoded as
/// `&#xHH;` or, for nul / noncharacters, replaced with space). mirrors
/// `engine::is_xml11_restricted_or_invalid`.
fn is_xml11_restricted(c: char) -> bool {
    let cp = c as u32;
    cp == 0
        || (0x01..=0x08).contains(&cp)
        || cp == 0x0B
        || cp == 0x0C
        || (0x0E..=0x1F).contains(&cp)
        || (0x7F..=0x9F).contains(&cp)
        || cp == 0x2028
        || is_noncharacter(cp)
}

// ===========================================================================
// decoders for the lossless encoders (std only, no external crates)
// ===========================================================================

/// percent-decodes `%HH` escapes; when `plus_as_space`, also maps `+` to space
/// (form-urlencoded). the percent-encoders emit only ascii, so byte-level
/// slicing of the hex digits is always on char boundaries.
fn percent_decode(s: &str, plus_as_space: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let byte = u8::from_str_radix(&s[i + 1..i + 3], 16).expect("valid percent escape");
                out.push(byte);
                i += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).expect("percent-decode yields valid utf-8")
}

/// reads `n` following hex digits and returns their value.
fn take_hex(chars: &mut impl Iterator<Item = char>, n: usize) -> u32 {
    let mut v = 0;
    for _ in 0..n {
        let d = chars
            .next()
            .expect("hex digit")
            .to_digit(16)
            .expect("hex digit");
        v = v * 16 + d;
    }
    v
}

/// unescapes a JSON string body (the escapes `for_json` can emit).
fn json_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next().expect("escape body") {
            'b' => out.push('\u{8}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'f' => out.push('\u{c}'),
            'r' => out.push('\r'),
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'u' => {
                let cp = take_hex(&mut chars, 4);
                out.push(char::from_u32(cp).expect("valid scalar"));
            }
            other => panic!("unexpected json escape \\{other}"),
        }
    }
    out
}

/// unescapes a JavaScript string / template body. handles both hex-quote
/// (`\x22`) and backslash-quote (`\"`) forms plus `\uHHHH`, so it decodes the
/// output of every javascript encoder.
fn js_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next().expect("escape body") {
            'b' => out.push('\u{8}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'f' => out.push('\u{c}'),
            'r' => out.push('\r'),
            'x' => out.push(char::from_u32(take_hex(&mut chars, 2)).expect("byte scalar")),
            'u' => out.push(char::from_u32(take_hex(&mut chars, 4)).expect("valid scalar")),
            // \\, \", \', \/, \`, \$ all decode to the literal following char
            other => out.push(other),
        }
    }
    out
}

/// decodes a rust byte-string body to bytes, then reassembles the utf-8 text.
/// non-ascii input is emitted as one `\xHH` per utf-8 byte, so decoding must
/// happen at the byte level.
fn rust_byte_string_unescape(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            // every passthrough char is ascii (non-ascii is always escaped)
            bytes.push(c as u8);
            continue;
        }
        match chars.next().expect("escape body") {
            '0' => bytes.push(0),
            't' => bytes.push(b'\t'),
            'n' => bytes.push(b'\n'),
            'r' => bytes.push(b'\r'),
            '\\' => bytes.push(b'\\'),
            '"' => bytes.push(b'"'),
            'x' => bytes.push(take_hex(&mut chars, 2) as u8),
            other => panic!("unexpected byte-string escape \\{other}"),
        }
    }
    String::from_utf8(bytes).expect("byte-string decode yields valid utf-8")
}

/// the codepoints `rustc` denies raw in a literal.
fn is_text_direction_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// unescapes a `quote`-delimited rust string or char literal body per the Rust
/// Reference's grammar, panicking where `rustc` would reject it.
fn rust_literal_unescape(s: &str, quote: char) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let rejected = c == quote
                || c == '\r'
                || is_text_direction_control(c)
                || (quote == '\'' && matches!(c, '\n' | '\t'));
            assert!(!rejected, "raw {c:?} in rust literal body {s:?}");
            out.push(c);
            continue;
        }
        match chars.next().expect("escape body") {
            q @ ('\'' | '"' | '\\') => out.push(q),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            'x' => {
                let hi = chars
                    .next()
                    .and_then(|d| d.to_digit(8))
                    .expect("ascii hex escape");
                let lo = chars
                    .next()
                    .and_then(|d| d.to_digit(16))
                    .expect("hex digit");
                out.push(char::from((hi * 16 + lo) as u8));
            }
            'u' => {
                assert_eq!(chars.next(), Some('{'), "`\\u` without `{{` in {s:?}");
                let (mut cp, mut digits) = (0u32, 0);
                loop {
                    match chars.next().expect("closing `}`") {
                        '}' => break,
                        '_' if digits > 0 => {}
                        d => {
                            assert!(digits < 6, "over-long unicode escape in {s:?}");
                            cp = cp * 16 + d.to_digit(16).expect("hex digit");
                            digits += 1;
                        }
                    }
                }
                assert!(digits > 0, "empty unicode escape in {s:?}");
                out.push(char::from_u32(cp).expect("unicode escape names a scalar"));
            }
            '\n' if quote == '"' => {
                while chars
                    .next_if(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
                    .is_some()
                {}
            }
            other => panic!("unexpected rust escape \\{other} in {s:?}"),
        }
    }
    out
}

// ===========================================================================
// (A) round-trip properties
// ===========================================================================

/// asserts `decode(encode(input)) == input` with a helpful message.
fn assert_roundtrip(
    name: &str,
    input: &str,
    encode: impl Fn(&str) -> String,
    decode: impl Fn(&str) -> String,
) {
    let encoded = encode(input);
    let decoded = decode(&encoded);
    assert_eq!(
        decoded, input,
        "{name} round-trip failed: {input:?} -> {encoded:?} -> {decoded:?}"
    );
}

fn percent_encoded(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        assert_roundtrip(name, one(c, &mut buf), encode, |s| percent_decode(s, false));
    }
    for input in ["/", "//", "/a/b/c", "a/b", "/café/世/😀/"] {
        assert_roundtrip(name, input, encode, |s| percent_decode(s, false));
    }
}

fn form_encoded(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        assert_roundtrip(name, one(c, &mut buf), encode, |s| percent_decode(s, true));
    }
    // literal '+' in the input must not be confused with an encoded space
    for input in ["a+b", "a b", " + ", "a*b~c"] {
        assert_roundtrip(name, input, encode, |s| percent_decode(s, true));
    }
}

fn json_string(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        assert_roundtrip(name, one(c, &mut buf), encode, json_unescape);
    }
    for input in [
        "he said \"hi\"",
        "a\\b/c",
        "\u{2028}\u{2029}",
        "</script>",
        "\x00\x0b\x1f",
    ] {
        assert_roundtrip(name, input, encode, json_unescape);
    }
}

fn js_string(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        assert_roundtrip(name, one(c, &mut buf), encode, js_unescape);
    }
    // adjacency-sensitive cases (template `${`, `</script>`, backslashes)
    for input in ["${x}", "a${b}c", "`tpl`", "</script>", "a\\b", "'\"&/"] {
        assert_roundtrip(name, input, encode, js_unescape);
    }
}

/// [`js_string`], plus neither a raw `<`, which moves an HTML tokenizer out of
/// script data, nor a raw `&`, which an XHTML parser decodes as a character
/// reference before javascript sees the text.
fn js_script_data(name: &str, encode: ForFn) {
    js_string(name, encode);
    let mut buf = [0u8; 4];
    for c in scalars() {
        let out = encode(one(c, &mut buf));
        if let Some(bad) = out.chars().find(|&c| matches!(c, '<' | '&')) {
            panic!("{name}: raw {bad:?} in {out:?} for input {c:?}");
        }
    }
}

fn rust_byte_string(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        assert_roundtrip(name, one(c, &mut buf), encode, rust_byte_string_unescape);
    }
    for input in ["say \"hi\"", "a\\b", "café", "null\x00byte", "😀𐍈"] {
        assert_roundtrip(name, input, encode, rust_byte_string_unescape);
    }
}

/// asserts `encode(input)` is a `quote`-delimited rust literal body denoting
/// `input`, with each noncharacter read back as the space the encoder writes.
fn assert_rust_literal_holds(name: &str, encode: ForFn, input: &str, quote: char) {
    let out = encode(input);
    let want: String = input
        .chars()
        .map(|c| if is_noncharacter(c as u32) { ' ' } else { c })
        .collect();
    assert_eq!(
        rust_literal_unescape(&out, quote),
        want,
        "{name}: {input:?} -> {out:?}"
    );
}

fn rust_string(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        assert_rust_literal_holds(name, encode, one(c, &mut buf), '"');
    }
    for input in [
        "say \"hi\"",
        "a\\b",
        "it's",
        "a\r\nb",
        "\\\n  x",
        "\\u{41}",
        "a\u{202E}b\u{2069}c",
        "\u{FDD0}x\u{10FFFF}",
        "café 世界 😀",
    ] {
        assert_rust_literal_holds(name, encode, input, '"');
    }
}

/// [`rust_string`] for char literals: one char in, one char literal out.
fn rust_char(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        assert_rust_literal_holds(name, encode, one(c, &mut buf), '\'');
    }
}

// ===========================================================================
// (B) safety properties
// ===========================================================================

/// length of a valid html/xml entity at the start of `s` (which begins with
/// `&`), or `None` if `&` does not introduce one of the entities these
/// encoders emit (`&amp;`, `&lt;`, `&gt;`, `&#DDD;`, `&#xHH;`).
fn entity_len(s: &str) -> Option<usize> {
    if s.starts_with("&amp;") {
        return Some(5);
    }
    if s.starts_with("&lt;") || s.starts_with("&gt;") {
        return Some(4);
    }
    let bytes = s.as_bytes();
    if bytes.len() < 4 || bytes[1] != b'#' {
        return None;
    }
    let mut i = 2;
    let hex = bytes[i] == b'x';
    if hex {
        i += 1;
    }
    let start = i;
    while i < bytes.len()
        && (if hex {
            bytes[i].is_ascii_hexdigit()
        } else {
            bytes[i].is_ascii_digit()
        })
    {
        i += 1;
    }
    if i > start && i < bytes.len() && bytes[i] == b';' {
        Some(i + 1)
    } else {
        None
    }
}

/// true if every `&` in `s` introduces a valid entity — i.e. no raw ampersand
/// leaked through unencoded.
fn ampersands_are_entities(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            match entity_len(&s[i..]) {
                Some(n) => i += n,
                None => return false,
            }
        } else {
            i += 1;
        }
    }
    true
}

/// asserts a markup encoder's output over the full sweep: no character matching
/// `forbidden` appears raw, and every `&` is a valid entity.
fn assert_markup_safe(
    name: &str,
    encode: impl Fn(&str) -> String,
    forbidden: impl Fn(char) -> bool,
) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        let out = encode(one(c, &mut buf));
        if let Some(bad) = out.chars().find(|&c| forbidden(c)) {
            panic!("{name}: raw context-breaking char {bad:?} in output {out:?} for input {c:?}");
        }
        assert!(
            ampersands_are_entities(&out),
            "{name}: raw '&' in output {out:?} for input {c:?}"
        );
    }
}

// text + attribute context: encodes < > " ' and &
fn markup_text(name: &str, encode: ForFn) {
    assert_markup_safe(name, encode, |c| {
        matches!(c, '<' | '>' | '"' | '\'') || is_invalid_for_xml(c)
    });
}

// content context: does not encode quotes
fn markup_content(name: &str, encode: ForFn) {
    assert_markup_safe(name, encode, |c| {
        matches!(c, '<' | '>') || is_invalid_for_xml(c)
    });
}

// attribute context: does not encode '>'
fn markup_attribute(name: &str, encode: ForFn) {
    assert_markup_safe(name, encode, |c| {
        matches!(c, '<' | '"' | '\'') || is_invalid_for_xml(c)
    });
}

// the most aggressive: whitespace, delimiters, and controls (which become '-')
// must never appear raw
fn unquoted_attribute(name: &str, encode: ForFn) {
    assert_markup_safe(name, encode, |c| {
        let cp = c as u32;
        matches!(
            c,
            ' ' | '\t' | '\n' | '\x0C' | '\r' | '<' | '>' | '"' | '\'' | '/' | '=' | '`'
        ) || cp <= 0x1F
            || cp == 0x7F
            || (0x80..=0x9F).contains(&cp)
            || cp == 0x2028
            || cp == 0x2029
            || is_noncharacter(cp)
    });
}

// xml 1.1: restricted controls, NEL and U+2028 become &#xHH; (not space)
fn xml11_text(name: &str, encode: ForFn) {
    assert_markup_safe(name, encode, |c| {
        matches!(c, '<' | '>' | '"' | '\'') || is_xml11_restricted(c)
    });
}

fn xml11_content(name: &str, encode: ForFn) {
    assert_markup_safe(name, encode, |c| {
        matches!(c, '<' | '>') || is_xml11_restricted(c)
    });
}

fn xml11_attribute(name: &str, encode: ForFn) {
    assert_markup_safe(name, encode, |c| {
        matches!(c, '<' | '"' | '\'') || is_xml11_restricted(c)
    });
}

/// true if the char is a dangerous CSS char that must be hex-escaped, excluding
/// backslash (which legitimately appears as the escape introducer) — see
/// `css_backslashes_escaped` for that half of the invariant.
fn css_forbidden_raw(c: char) -> bool {
    let cp = c as u32;
    matches!(c, '"' | '\'' | '<' | '&' | '/' | '>' | '(' | ')')
        || cp <= 0x1F
        || (0x7F..=0x9F).contains(&cp)
        || cp == 0x2028
        || cp == 0x2029
        || (0x202A..=0x202E).contains(&cp)
        || (0x2066..=0x2069).contains(&cp)
        || is_noncharacter(cp)
}

/// every backslash in CSS output introduces a `\HH` hex escape, so it is always
/// immediately followed by a hex digit. this proves no raw backslash (which
/// could escape the closing quote) survives.
fn css_backslashes_escaped(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && !chars.peek().is_some_and(|n| n.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// asserts no raw dangerous char and no unescaped backslash in `encode(input)`.
fn assert_css_escaped(name: &str, encode: ForFn, input: &str) {
    let out = encode(input);
    if let Some(bad) = out.chars().find(|&c| css_forbidden_raw(c)) {
        panic!("{name}: raw {bad:?} in {out:?} for input {input:?}");
    }
    assert!(
        css_backslashes_escaped(&out),
        "{name}: unescaped backslash in {out:?} for input {input:?}"
    );
}

// ---------------------------------------------------------------------------
// css tokenizer (CSS Syntax Level 3 §4.3), used by the css breakout invariants
// ---------------------------------------------------------------------------

/// §3.3 preprocessing: CR, FF and CRLF become LF; NUL becomes U+FFFD.
/// (surrogates cannot occur in a rust `str`.)
fn css_preprocess(input: &str) -> Vec<char> {
    let mut out = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\u{c}' => out.push('\n'),
            '\0' => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// §4.2: whitespace is newline, tab and space — no other unicode space counts.
fn is_css_whitespace(c: char) -> bool {
    matches!(c, '\n' | '\t' | ' ')
}

/// §4.2 non-printable code point.
fn is_non_printable(c: char) -> bool {
    let cp = c as u32;
    cp <= 0x08 || cp == 0x0B || (0x0E..=0x1F).contains(&cp) || cp == 0x7F
}

/// §4.3.8 check if two code points are a valid escape, with `cs[i]` the `\`.
fn starts_valid_escape(cs: &[char], i: usize) -> bool {
    cs.get(i) == Some(&'\\') && cs.get(i + 1) != Some(&'\n')
}

/// §4.3.7 consume an escaped code point; `i` points just past the `\`.
fn consume_escaped(cs: &[char], i: &mut usize) -> char {
    let start = *i;
    while *i - start < 6 && cs.get(*i).is_some_and(char::is_ascii_hexdigit) {
        *i += 1;
    }
    if *i == start {
        return match cs.get(*i) {
            Some(&c) => {
                *i += 1;
                c
            }
            None => '\u{FFFD}',
        };
    }
    let cp = cs[start..*i]
        .iter()
        .fold(0u32, |acc, c| acc * 16 + c.to_digit(16).expect("hex digit"));
    if cs.get(*i).is_some_and(|&c| is_css_whitespace(c)) {
        *i += 1;
    }
    char::from_u32(cp).filter(|_| cp != 0).unwrap_or('\u{FFFD}')
}

/// §4.3.14 consume the remnants of a bad url.
fn consume_bad_url_remnants(cs: &[char], i: &mut usize) {
    while let Some(&c) = cs.get(*i) {
        if starts_valid_escape(cs, *i) {
            *i += 1;
            consume_escaped(cs, i);
            continue;
        }
        *i += 1;
        if c == ')' {
            return;
        }
    }
}

/// outcome of §4.3.6 "consume a url token".
enum UrlToken {
    /// a `<url-token>`: its unescaped value and the index just past the token.
    Url(String, usize),
    /// a `<bad-url-token>`: the index just past the remnants it swallowed.
    Bad(usize),
}

/// §4.3.6 consume a url token; `i` points just past `url(`.
fn consume_url_token(cs: &[char], mut i: usize) -> UrlToken {
    let mut value = String::new();
    let bad = |i: &mut usize| {
        consume_bad_url_remnants(cs, i);
        UrlToken::Bad(*i)
    };
    while cs.get(i).is_some_and(|&c| is_css_whitespace(c)) {
        i += 1;
    }
    loop {
        let Some(&c) = cs.get(i) else {
            return UrlToken::Url(value, i);
        };
        if c == '\\' {
            if !starts_valid_escape(cs, i) {
                return bad(&mut i);
            }
            i += 1;
            value.push(consume_escaped(cs, &mut i));
            continue;
        }
        i += 1;
        match c {
            ')' => return UrlToken::Url(value, i),
            c if is_css_whitespace(c) => {
                while cs.get(i).is_some_and(|&c| is_css_whitespace(c)) {
                    i += 1;
                }
                return match cs.get(i).copied() {
                    None => UrlToken::Url(value, i),
                    Some(')') => UrlToken::Url(value, i + 1),
                    Some(_) => bad(&mut i),
                };
            }
            '"' | '\'' | '(' => return bad(&mut i),
            c if is_non_printable(c) => return bad(&mut i),
            c => value.push(c),
        }
    }
}

/// outcome of §4.3.5 "consume a string token".
enum StringToken {
    /// a `<string-token>`: its unescaped value and the index just past the token.
    Str(String, usize),
    Bad,
}

/// §4.3.5 consume a string token; `i` points just past the opening `ending`.
fn consume_string_token(cs: &[char], mut i: usize, ending: char) -> StringToken {
    let mut value = String::new();
    loop {
        let Some(&c) = cs.get(i) else {
            return StringToken::Str(value, i);
        };
        i += 1;
        match c {
            c if c == ending => return StringToken::Str(value, i),
            '\n' => return StringToken::Bad,
            '\\' => match cs.get(i) {
                None => {}
                Some(&'\n') => i += 1,
                Some(_) => value.push(consume_escaped(cs, &mut i)),
            },
            c => value.push(c),
        }
    }
}

/// the value a conforming parser must recover: the css encoders replace
/// noncharacters with `_`, and a `\0` escape decodes to U+FFFD.
fn css_expected_value(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            c if is_noncharacter(c as u32) => '_',
            '\0' => '\u{FFFD}',
            c => c,
        })
        .collect()
}

/// a declaration placed after the encoded value, so that an early terminator or
/// a bad url's remnant consumption shows up as the token running past its `)`.
const CSS_TAIL: &str = ";color:green}";

/// asserts `url(<encode(input)>)` is one url-token spanning the whole value:
/// no early terminator, no bad-url-token, no change to the value.
fn assert_url_token_intact(name: &str, encode: ForFn, input: &str) {
    let encoded = encode(input);
    let sheet = css_preprocess(&format!("url({encoded}){CSS_TAIL}"));
    let expected_end = sheet.len() - CSS_TAIL.chars().count();
    match consume_url_token(&sheet, 4) {
        UrlToken::Url(value, end) => {
            assert_eq!(
                end, expected_end,
                "{name}: url-token did not end at its `)` for {input:?} -> {encoded:?}"
            );
            assert_eq!(
                value,
                css_expected_value(input),
                "{name}: value altered for {input:?} -> {encoded:?}"
            );
        }
        UrlToken::Bad(end) => panic!(
            "{name}: bad-url-token for {input:?} -> {encoded:?}, swallowing {:?}",
            sheet[..end].iter().collect::<String>()
        ),
    }
}

/// the [`assert_url_token_intact`] analogue for quoted string values, checked
/// against both delimiters.
fn assert_string_token_intact(name: &str, encode: ForFn, input: &str) {
    let encoded = encode(input);
    for quote in ['"', '\''] {
        let sheet = css_preprocess(&format!("{quote}{encoded}{quote}{CSS_TAIL}"));
        let expected_end = sheet.len() - CSS_TAIL.chars().count();
        match consume_string_token(&sheet, 1, quote) {
            StringToken::Str(value, end) => {
                assert_eq!(
                    end, expected_end,
                    "{name}: string-token did not end at its {quote:?} for {input:?} -> {encoded:?}"
                );
                assert_eq!(
                    value,
                    css_expected_value(input),
                    "{name}: value altered for {input:?} -> {encoded:?}"
                );
            }
            StringToken::Bad => {
                panic!("{name}: bad-string-token for {input:?} -> {encoded:?}")
            }
        }
    }
}

/// inputs aimed at the css tokenizer: every url-token terminator and bad-url
/// trigger, the issue #49 payload, and the suite's cross-context payloads.
const CSS_ADVERSARIAL: &[&str] = &[
    "",
    ");color:red}x{",
    ");}",
    ")",
    "(",
    "a(b)",
    " ",
    "  ",
    "a b",
    " )",
    "( )",
    "a\tb",
    "a\nb",
    "a\rb",
    "a\r\nb",
    "a\u{c}b",
    "\\",
    "\\)",
    "a\\",
    "url(x)",
    "image.png",
    "http://example.com/a(1).png",
    "expression(alert(1))",
    "<script>alert('xss')</script>",
    "a'b\"c&d/e",
    "]]>--`${x}`",
    "café 世界 😀 𐍈",
    "\x00\x0b\x1f\x7f\u{85}\u{2028}",
    "\u{FDD0}\u{FFFE}\u{FFFF}",
    "a\u{a0}b\u{2003}c\u{3000}d",
];

fn css_url(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        let s = one(c, &mut buf);
        assert_css_escaped(name, encode, s);
        assert_url_token_intact(name, encode, s);
    }
    for input in CSS_ADVERSARIAL {
        assert_url_token_intact(name, encode, input);
    }
}

fn css_string(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        let s = one(c, &mut buf);
        assert_css_escaped(name, encode, s);
        assert_string_token_intact(name, encode, s);
    }
    for input in CSS_ADVERSARIAL {
        assert_string_token_intact(name, encode, input);
    }
}

#[test]
fn css_url_encodes_a_superset_of_css_string() {
    let mut buf = [0u8; 4];
    for c in scalars() {
        let s = one(c, &mut buf);
        let expected = if c == ' ' {
            String::from(r"\20 ")
        } else {
            for_css_string(s)
        };
        assert_eq!(for_css_url(s), expected, "css_url vs css_string for {c:?}");
    }
}

/// true if every maximal run of single quotes has even length — i.e. every
/// logical quote was doubled (`'` -> `''`), so none is left unescaped.
fn sql_quotes_doubled(s: &str) -> bool {
    let mut run = 0usize;
    for c in s.chars() {
        if c == '\'' {
            run += 1;
        } else {
            if run % 2 != 0 {
                return false;
            }
            run = 0;
        }
    }
    run % 2 == 0
}

/// true if every single quote and backslash in MySQL-style output is escaped:
/// consuming each `\X` pair leaves a residue with no bare `'` or `\`.
fn sql_backslash_escaped(s: &str) -> bool {
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if chars.next().is_none() {
                    return false; // dangling backslash
                }
            }
            '\'' => return false, // unescaped quote
            _ => {}
        }
    }
    true
}

/// adversarial injection payloads for both sql encoders.
const SQL_ADVERSARIAL: &[&str] = &["'; DROP TABLE t; --", "''", "a'b'c", "\\'", "\\", "a\\'b"];

fn sql_string(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        let out = encode(one(c, &mut buf));
        assert!(
            sql_quotes_doubled(&out),
            "{name}: unescaped quote for {c:?}: {out:?}"
        );
        assert!(!out.contains('\0'), "{name}: nul survived for {c:?}");
        assert!(
            !out.chars().any(|c| is_noncharacter(c as u32)),
            "{name}: raw noncharacter for {c:?}"
        );
    }
    for input in SQL_ADVERSARIAL {
        assert!(sql_quotes_doubled(&encode(input)), "{name}: {input:?}");
    }
}

fn mysql_string(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        let out = encode(one(c, &mut buf));
        assert!(
            sql_backslash_escaped(&out),
            "{name}: unescaped quote/backslash for {c:?}: {out:?}"
        );
        assert!(
            !out.chars().any(|c| is_noncharacter(c as u32)),
            "{name}: raw noncharacter for {c:?}"
        );
    }
    for input in SQL_ADVERSARIAL {
        assert!(sql_backslash_escaped(&encode(input)), "{name}: {input:?}");
    }
}

/// asserts that `input`, encoded between trusted `prefix` and `suffix` in one
/// CDATA section, reads back as `prefix`, the input and `suffix`.
fn assert_cdata_holds_between(encode: ForFn, prefix: &str, input: &str, suffix: &str) {
    let section = format!("<![CDATA[{prefix}{}{suffix}]]>", encode(input));
    let want = format!("{prefix}{}{suffix}", cdata_expected_value(input));
    assert_eq!(
        decode_cdata_fragment(&section),
        Some(want),
        "{prefix:?}+{input:?}+{suffix:?} -> {section:?}"
    );
}

fn cdata(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        for probe in [
            String::from(one(c, &mut buf)),
            format!("]]{c}>"),
            format!("]]>{c}"),
            format!("{c}]]>"),
        ] {
            assert_cdata_holds_between(encode, "]]", &probe, "]>");
        }
        for probe in [
            String::from(one(c, &mut buf)),
            format!("]{c}"),
            format!("{c}]"),
            format!("{c}]]"),
        ] {
            let out = encode(&probe);
            assert!(
                !out.ends_with(']'),
                "{name}: output ends with `]` for {probe:?}: {out:?}"
            );
        }
    }
    for input in [
        "]]>",
        "]]]>",
        "]]]]>",
        "a]]>b",
        "]]>]]>",
        "]]",
        "]",
        "]>",
        "<![CDATA[",
        ">x<evil/><![CDATA[",
        "]>x<evil/><![CDATA[",
    ] {
        assert_cdata_holds_between(encode, "]]", input, "]>");
    }
}

/// the character data `for_cdata` output is meant to denote.
fn cdata_expected_value(input: &str) -> String {
    input
        .chars()
        .map(|c| if is_invalid_for_xml(c) { ' ' } else { c })
        .collect()
}

/// decodes a wrapped `for_cdata` output back to character data, returning
/// `None` if it is not well-formed: outside a CDATA section, `]]>` is
/// forbidden (XML 1.0 §2.4) and `<` and `&` start markup.
fn decode_cdata_fragment(fragment: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = fragment;
    while !rest.is_empty() {
        if let Some(body) = rest.strip_prefix("<![CDATA[") {
            let end = body.find("]]>")?;
            out.push_str(&body[..end]);
            rest = &body[end + 3..];
        } else {
            let end = rest.find("<![CDATA[").unwrap_or(rest.len());
            let text = &rest[..end];
            if text.contains("]]>") || text.contains('<') || text.contains('&') {
                return None;
            }
            out.push_str(text);
            rest = &rest[end..];
        }
    }
    Some(out)
}

/// encodes `head` then `tail` into one sink and wraps the result the way the
/// caller is documented to.
fn cdata_section(head: &str, tail: &str) -> String {
    let mut sink = String::from("<![CDATA[");
    write_cdata(&mut sink, head).unwrap();
    write_cdata(&mut sink, tail).unwrap();
    sink.push_str("]]>");
    sink
}

fn assert_cdata_boundary_holds(head: &str, tail: &str) {
    let section = cdata_section(head, tail);
    let want = cdata_expected_value(head) + &cdata_expected_value(tail);
    match decode_cdata_fragment(&section) {
        Some(got) => assert_eq!(
            got, want,
            "for_cdata: value altered for {head:?}+{tail:?} -> {section:?}"
        ),
        None => panic!("for_cdata: content escaped for {head:?}+{tail:?} -> {section:?}"),
    }
}

/// every string of length <= 4 over the alphabet the encoder branches on.
fn cdata_words() -> Vec<String> {
    let mut all = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..4 {
        let mut next = Vec::new();
        for s in &frontier {
            for c in [']', '>', 'a', '\u{1}'] {
                let mut w = s.clone();
                w.push(c);
                next.push(w);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}

#[test]
fn safety_cdata_across_a_write_boundary() {
    assert_cdata_boundary_holds("a]]", ">b");
    assert_cdata_boundary_holds("a]", "]>b");

    let words = cdata_words();
    for head in &words {
        for tail in &words {
            assert_cdata_boundary_holds(head, tail);
        }
    }
}

/// asserts that `input`, encoded between trusted `prefix` and `suffix`, still
/// forms a well-formed comment body.
fn assert_xml_comment_holds_between(encode: ForFn, prefix: &str, input: &str, suffix: &str) {
    let body = format!("{prefix}{}{suffix}", encode(input));
    assert!(
        xml_comment_body_is_well_formed(&body),
        "{prefix:?}+{input:?}+{suffix:?} -> {body:?}"
    );
}

fn xml_comment(name: &str, encode: ForFn) {
    let mut buf = [0u8; 4];
    for c in scalars() {
        let s = one(c, &mut buf);
        let out = encode(s);
        assert!(
            !out.chars().any(is_invalid_for_xml),
            "{name}: raw invalid-xml char in {out:?} for {c:?}"
        );
        for probe in [
            String::from(s),
            format!("-{c}-"),
            format!("{c}--"),
            format!("--{c}"),
        ] {
            assert_xml_comment_holds_between(encode, "a-", &probe, "-a");
        }
    }
    for input in [
        "-",
        "--",
        "---",
        "----",
        "a-",
        "-a",
        "a--b--c",
        "----x",
        "-><evil/>",
        "-x",
    ] {
        assert_xml_comment_holds_between(encode, "a-", input, "-a");
    }
}

// ===========================================================================
// (C) universal invariants for every for_* encoder
// ===========================================================================

include!("../src/encoders.rs");

struct Encoder {
    name: &'static str,
    for_fn: ForFn,
    write_fn: WriteFn,
    disp_fn: ForFn,
}

// the property each context is swept by; any other pairing fails to compile.
macro_rules! pinned {
    (html => markup_text) => {};
    (html_content => markup_content) => {};
    (html_attribute => markup_attribute) => {};
    (html_unquoted_attribute => unquoted_attribute) => {};
    (xml => markup_text) => {};
    (xml_content => markup_content) => {};
    (xml_attribute => markup_attribute) => {};
    (xml_comment => xml_comment) => {};
    (cdata => cdata) => {};
    (xml11 => xml11_text) => {};
    (xml11_content => xml11_content) => {};
    (xml11_attribute => xml11_attribute) => {};
    (javascript => js_script_data) => {};
    (javascript_attribute => js_string) => {};
    (javascript_block => js_script_data) => {};
    (javascript_source => js_string) => {};
    (js_template => js_script_data) => {};
    (css_string => css_string) => {};
    (css_url => css_url) => {};
    (uri_component => percent_encoded) => {};
    (uri_path => percent_encoded) => {};
    (form_urlencoded => form_encoded) => {};
    (json => json_string) => {};
    (rust_string => rust_string) => {};
    (rust_char => rust_char) => {};
    (rust_byte_string => rust_byte_string) => {};
    (sql => sql_string) => {};
    (sql_backslash => mysql_string) => {};
    ($context:ident => $property:ident) => {
        compile_error!(concat!(
            stringify!($context),
            " is not swept by ",
            stringify!($property)
        ));
    };
}

macro_rules! registry {
    (
        $($context:ident: $module:ident::{$for_fn:ident, $write_fn:ident, $display_fn:ident}
            => $property:ident,)*
    ) => {
        fn all_encoders() -> Vec<Encoder> {
            vec![$(Encoder {
                name: stringify!($context),
                for_fn: $for_fn,
                write_fn: $write_fn as WriteFn,
                disp_fn: |s| format!("{}", $display_fn(s)),
            },)*]
        }

        const LISTED_FNS: &[&str] = &[$(
            concat!(stringify!($module), "::", stringify!($for_fn)),
            concat!(stringify!($module), "::", stringify!($write_fn)),
        )*];

        mod sweep {$(
            pinned!($context => $property);

            #[test]
            fn $context() {
                super::$property(stringify!($for_fn), super::$for_fn);
            }
        )*}
    };
}

encoders!(registry);

#[test]
fn encoder_list_matches_the_public_encoders() {
    let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut declared = std::collections::BTreeSet::new();
    let mut dirs = vec![src.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for file in std::fs::read_dir(dir).unwrap() {
            let path = file.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let rel = path.strip_prefix(src).unwrap().with_extension("");
            let mut module: Vec<_> = rel.iter().map(|c| c.to_str().unwrap()).collect();
            if module.last() == Some(&"mod") {
                module.pop();
            }
            let module = module.join("::");
            for line in std::fs::read_to_string(&path).unwrap().lines() {
                let Some(name) = line
                    .strip_prefix("pub fn ")
                    .and_then(|l| l.split(['(', '<']).next())
                else {
                    continue;
                };
                // the checked variant returns `Option` and has no write_/display_ form.
                if (name.starts_with("for_") || name.starts_with("write_"))
                    && name != "for_rust_char_checked"
                {
                    declared.insert(format!("{module}::{name}"));
                }
            }
        }
    }
    let listed = LISTED_FNS.iter().map(|f| f.to_string()).collect();
    let diff: Vec<_> = declared.symmetric_difference(&listed).collect();
    assert!(
        diff.is_empty(),
        "src/ and the list in src/encoders.rs disagree on {diff:?}"
    );
}

// ---------------------------------------------------------------------------
// streaming boundaries: two write_* calls into one sink
// ---------------------------------------------------------------------------

/// true if the template-literal body opens an interpolation.
fn template_opens_interpolation(body: &str) -> bool {
    let cs: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '\\' => i += 2,
            '$' if cs.get(i + 1) == Some(&'{') => return true,
            _ => i += 1,
        }
    }
    false
}

/// true if `body` may sit between `<!--` and `-->`.
fn xml_comment_body_is_well_formed(body: &str) -> bool {
    !body.contains("--") && !body.ends_with('-')
}

/// encodes `head` then `tail` into one string with `write_fn`.
fn write_both(write_fn: WriteFn, head: &str, tail: &str) -> String {
    let mut sink = String::new();
    write_fn(&mut sink, head).unwrap();
    write_fn(&mut sink, tail).unwrap();
    sink
}

#[test]
fn boundary_js_template_cannot_reopen_interpolation() {
    let sink = write_both(write_js_template, "price: $", "{alert(1)}");
    assert_eq!(sink, r"price: \$\x7balert(1)}");
    assert_eq!(js_unescape(&sink), "price: ${alert(1)}");

    let mut buf = [0u8; 4];
    for c in scalars() {
        let sink = write_both(write_js_template, one(c, &mut buf), "{alert(1)}");
        assert!(
            !template_opens_interpolation(&sink),
            "js_template: interpolation opened across the boundary for {c:?} -> {sink:?}"
        );
    }
}

#[test]
fn boundary_js_template_trusted_dollar_cannot_open_interpolation() {
    let mut buf = [0u8; 4];
    for c in scalars() {
        let mut sink = String::from("price: $");
        write_js_template(&mut sink, one(c, &mut buf)).unwrap();
        assert!(
            !template_opens_interpolation(&sink),
            "js_template: interpolation opened after a trusted `$` for {c:?} -> {sink:?}"
        );
    }
}

/// asserts the two-write concatenation is still one string-token decoding to
/// `head` followed by `tail`.
fn assert_string_token_intact_across_boundary(head: &str, tail: &str) {
    let encoded = write_both(write_css_string, head, tail);
    let sheet = css_preprocess(&format!("\"{encoded}\"{CSS_TAIL}"));
    let expected_end = sheet.len() - CSS_TAIL.chars().count();
    match consume_string_token(&sheet, 1, '"') {
        StringToken::Str(value, end) => {
            assert_eq!(
                end, expected_end,
                "for_css_string: string-token did not end at its quote for {head:?}+{tail:?} -> {encoded:?}"
            );
            assert_eq!(
                value,
                css_expected_value(head) + &css_expected_value(tail),
                "for_css_string: value altered for {head:?}+{tail:?} -> {encoded:?}"
            );
        }
        StringToken::Bad => {
            panic!("for_css_string: bad-string-token for {head:?}+{tail:?} -> {encoded:?}")
        }
    }
}

/// the [`assert_string_token_intact_across_boundary`] analogue for `url()`.
fn assert_url_token_intact_across_boundary(head: &str, tail: &str) {
    let encoded = write_both(write_css_url, head, tail);
    let sheet = css_preprocess(&format!("url({encoded}){CSS_TAIL}"));
    let expected_end = sheet.len() - CSS_TAIL.chars().count();
    match consume_url_token(&sheet, 4) {
        UrlToken::Url(value, end) => {
            assert_eq!(
                end, expected_end,
                "for_css_url: url-token did not end at its `)` for {head:?}+{tail:?} -> {encoded:?}"
            );
            assert_eq!(
                value,
                css_expected_value(head) + &css_expected_value(tail),
                "for_css_url: value altered for {head:?}+{tail:?} -> {encoded:?}"
            );
        }
        UrlToken::Bad(end) => panic!(
            "for_css_url: bad-url-token for {head:?}+{tail:?} -> {encoded:?}, swallowing {:?}",
            sheet[..end].iter().collect::<String>()
        ),
    }
}

#[test]
fn boundary_css_escape_does_not_absorb_the_next_write() {
    assert_eq!(write_both(write_css_string, "a\"", "b"), r"a\22 b");
    assert_string_token_intact_across_boundary("a\"", "b");
    assert_url_token_intact_across_boundary("a\"", "b");

    let mut buf = [0u8; 4];
    for c in scalars() {
        let s = one(c, &mut buf);
        assert_string_token_intact_across_boundary(s, "b0");
        assert_url_token_intact_across_boundary(s, "b0");
    }
}

#[test]
fn boundary_xml_comment_cannot_form_a_double_hyphen() {
    assert_eq!(
        write_both(write_xml_comment, "value-", "-more"),
        "value~~more"
    );

    let mut buf = [0u8; 4];
    for c in scalars() {
        let sink = write_both(write_xml_comment, one(c, &mut buf), "-tail");
        assert!(
            xml_comment_body_is_well_formed(&sink),
            "xml_comment: `--` or trailing `-` across the boundary for {c:?} -> {sink:?}"
        );
    }
}

#[test]
fn ascii_alphanumeric_is_identity() {
    let alnum: String = ('0'..='9').chain('a'..='z').chain('A'..='Z').collect();
    for enc in all_encoders() {
        assert_eq!(
            (enc.for_fn)(&alnum),
            alnum,
            "{}: ascii-alphanumeric input was not identity",
            enc.name
        );
    }
}

#[test]
fn for_write_display_parity() {
    let encoders = all_encoders();
    let mut buf = [0u8; 4];
    let mut w = String::new();
    for c in scalars() {
        let s = one(c, &mut buf);
        for enc in &encoders {
            let f = (enc.for_fn)(s);
            w.clear();
            (enc.write_fn)(&mut w, s).unwrap();
            let d = (enc.disp_fn)(s);
            assert_eq!(f, w, "{}: for_ vs write_ mismatch for {c:?}", enc.name);
            assert_eq!(f, d, "{}: for_ vs display_ mismatch for {c:?}", enc.name);
        }
    }
    // multi-char inputs exercise lookahead-dependent paths (css separators,
    // template `${`)
    for input in [
        "",
        "<script>alert('xss')</script>",
        "a'b\"c&d/e",
        "]]>--`${x}`",
        "café 世界 😀 𐍈",
        "\x00\x0b\x1f\x7f\u{85}\u{2028}",
        "hello world",
        "<img src=x onerror=\"alert(1)\">",
        "Hello, <world> & \"friends\"!",
        "<café>",
        "<>&\"'",
        "&<>\"'/=`",
        "&&",
        "a&b&c",
        "&amp;",
        "&lt;",
        "&#34;",
        "a>b",
        "a\"b",
        "a'b",
        "it's",
        "café",
        "日本語テスト",
        "hello 😀 world",
        "a\u{2028}b\u{2029}c",
        "';alert(1);//",
        "</script><script>alert(1)</script>",
        "`template`",
        "${alert(1)}",
        "${a} and ${b}",
        "$100",
        "hello `world`",
        "`Hello ${name}`, welcome\\n",
        "\\\\",
        "\\n",
        "a\\b",
        "expression(alert(1))",
        "\"a",
        "key=value&other=more",
        "search term with spaces",
        "https://example.com",
        "</script>",
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "abc\x08\t\n\x0C\r",
        "\t\n\x0C\r ",
        "test\x00\"\\\n\u{2028}'café",
        "abc`${x}\\\t\n\r\x0C\x08\x00\x1F/\u{2028}\u{2029}café😀",
        "test\x01\x7F<>&\u{0085}",
        "C:\\Users\\test",
        "test--comment-",
        "x]]>y\x00z]]",
    ] {
        for enc in &encoders {
            let f = (enc.for_fn)(input);
            w.clear();
            (enc.write_fn)(&mut w, input).unwrap();
            let d = (enc.disp_fn)(input);
            assert_eq!(f, w, "{}: for_ vs write_ mismatch for {input:?}", enc.name);
            assert_eq!(
                f, d,
                "{}: for_ vs display_ mismatch for {input:?}",
                enc.name
            );
        }
    }
}
