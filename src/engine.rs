//! shared encoding engine used by all context-specific encoders.

use std::fmt;

/// shared encoding loop. writes safe runs of input directly and encodes
/// characters flagged by `needs_encoding` via `write_encoded`.
///
/// `needs_encoding` returns `true` for characters that require encoding.
/// `write_encoded` writes the encoded form for such characters. it receives
/// the current character and the next character (for lookahead-dependent
/// encodings like css hex escapes).
pub(crate) fn encode_loop<W, C, E>(
    out: &mut W,
    input: &str,
    needs_encoding: C,
    mut write_encoded: E,
) -> fmt::Result
where
    W: fmt::Write,
    C: Fn(char) -> bool,
    E: FnMut(&mut W, char, Option<char>) -> fmt::Result,
{
    let mut last_written = 0;
    let mut chars = input.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        if needs_encoding(c) {
            out.write_str(&input[last_written..i])?;
            let next = chars.peek().map(|(_, nc)| *nc);
            write_encoded(out, c, next)?;
            last_written = i + c.len_utf8();
        }
    }

    out.write_str(&input[last_written..])?;
    Ok(())
}

/// writes each UTF-8 byte of a non-ASCII character as `\xHH`.
pub(crate) fn write_utf8_hex_bytes<W: fmt::Write>(out: &mut W, c: char) -> fmt::Result {
    let mut buf = [0u8; 4];
    let encoded = c.encode_utf8(&mut buf);
    for b in encoded.as_bytes() {
        write!(out, "\\x{b:02x}")?;
    }
    Ok(())
}

/// returns true if the character is invalid in XML 1.0 output and should be
/// replaced (with space or dash depending on context).
///
/// covers:
/// - C0 controls except tab (U+0009), LF (U+000A), CR (U+000D)
/// - DEL (U+007F)
/// - C1 controls (U+0080-U+009F)
/// - unicode non-characters (U+FDD0-U+FDEF, U+nFFFE, U+nFFFF)
pub(crate) fn is_invalid_for_xml(c: char) -> bool {
    let cp = c as u32;
    cp <= 0x08
        || cp == 0x0B
        || cp == 0x0C
        || (0x0E..=0x1F).contains(&cp)
        || cp == 0x7F
        || (0x80..=0x9F).contains(&cp)
        || is_unicode_noncharacter(cp)
}

/// returns true if the character is restricted or invalid in XML 1.1 output.
///
/// unlike [`is_invalid_for_xml`], the C1 controls are split: NEL (U+0085) is
/// **not** restricted in XML 1.1 and passes through unchanged, while the rest
/// of the range is. covers:
/// - NUL (U+0000): invalid (not in the Char production)
/// - U+0001-U+0008, U+000B-U+000C, U+000E-U+001F (restricted C0 controls)
/// - U+007F-U+0084, U+0086-U+009F (DEL and restricted C1 controls, except NEL)
/// - unicode non-characters
pub(crate) fn is_xml11_restricted_or_invalid(c: char) -> bool {
    let cp = c as u32;
    cp == 0
        || (0x01..=0x08).contains(&cp)
        || cp == 0x0B
        || cp == 0x0C
        || (0x0E..=0x1F).contains(&cp)
        || (0x7F..=0x84).contains(&cp)
        || (0x86..=0x9F).contains(&cp)
        || is_unicode_noncharacter(cp)
}

/// how a markup encoder renders characters that are invalid or restricted for
/// its XML version. this is the only axis on which the HTML and XML 1.1 markup
/// families differ; the entity table and per-context masks are shared.
#[derive(Clone, Copy)]
pub(crate) enum InvalidCharPolicy {
    /// HTML / XML 1.0: every invalid character becomes a single space.
    HtmlSpace,
    /// XML 1.1: NUL and non-characters become a space; the restricted C0/C1
    /// controls become `&#xHH;` hex character references.
    Xml11Reference,
}

impl InvalidCharPolicy {
    /// returns true if `c` is invalid/restricted under this policy and so must
    /// be replaced or referenced rather than written literally.
    fn is_invalid(self, c: char) -> bool {
        match self {
            Self::HtmlSpace => is_invalid_for_xml(c),
            Self::Xml11Reference => is_xml11_restricted_or_invalid(c),
        }
    }

    /// writes the replacement for an invalid/restricted `c`.
    fn write_invalid<W: fmt::Write>(self, out: &mut W, c: char) -> fmt::Result {
        match self {
            Self::HtmlSpace => out.write_char(' '),
            Self::Xml11Reference if c == '\0' || is_unicode_noncharacter(c as u32) => {
                out.write_char(' ')
            }
            Self::Xml11Reference => write!(out, "&#x{:x};", c as u32),
        }
    }
}

/// per-context configuration for the shared HTML / XML 1.1 markup encoder.
///
/// the entity table is identical across every context (`&` → `&amp;`,
/// `<` → `&lt;`, `>` → `&gt;`, `"` → `&#34;`, `'` → `&#39;`), and `&` and `<`
/// are always encoded. the fields below capture the only differences between
/// the six public markup encoders.
#[derive(Clone, Copy)]
pub(crate) struct MarkupConfig {
    /// encode `>` as `&gt;` (true for the full and content contexts).
    pub(crate) encode_gt: bool,
    /// encode `"`/`'` as `&#34;`/`&#39;` (true for the full and attribute contexts).
    pub(crate) encode_quotes: bool,
    /// how invalid/restricted characters are rendered.
    pub(crate) invalid: InvalidCharPolicy,
}

/// writes `input` to `out`, encoding markup characters per `config`.
///
/// this is the shared core behind the HTML and XML 1.1 full/content/attribute
/// encoders; each public encoder is a thin wrapper over this with a `const`
/// [`MarkupConfig`].
pub(crate) fn write_markup<W: fmt::Write>(
    out: &mut W,
    input: &str,
    config: &MarkupConfig,
) -> fmt::Result {
    encode_loop(
        out,
        input,
        |c| needs_markup_encoding(c, config),
        |out, c, _next| write_markup_encoded(out, c, config),
    )
}

fn needs_markup_encoding(c: char, config: &MarkupConfig) -> bool {
    match c {
        '&' | '<' => true,
        '>' => config.encode_gt,
        '"' | '\'' => config.encode_quotes,
        _ => config.invalid.is_invalid(c),
    }
}

fn write_markup_encoded<W: fmt::Write>(out: &mut W, c: char, config: &MarkupConfig) -> fmt::Result {
    match c {
        '&' => out.write_str("&amp;"),
        '<' => out.write_str("&lt;"),
        '>' => out.write_str("&gt;"),
        '"' => out.write_str("&#34;"),
        '\'' => out.write_str("&#39;"),
        _ => config.invalid.write_invalid(out, c),
    }
}

/// attempts to write a rust-style named escape for the given character.
///
/// covers the escapes used by rust: NUL (`\0`), TAB (`\t`), LF (`\n`),
/// CR (`\r`), and backslash (`\\`).
///
/// returns `Some(Ok(()))` if an escape was written, `Some(Err(..))` on
/// write error, or `None` if the character has no named escape.
pub(crate) fn write_rust_named_escape<W: fmt::Write>(out: &mut W, c: char) -> Option<fmt::Result> {
    let s = match c {
        '\0' => "\\0",
        '\t' => "\\t",
        '\n' => "\\n",
        '\r' => "\\r",
        '\\' => "\\\\",
        _ => return None,
    };
    Some(out.write_str(s))
}

/// returns true if a character needs encoding in a byte string context.
///
/// this predicate is used by the rust byte string encoder. it flags
/// C0 controls, DEL, quotes, backslashes, and all non-ASCII characters.
pub(crate) fn needs_byte_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\') || !c.is_ascii()
}

/// byte string encoder used by the rust byte string context.
///
/// handles quote escaping (`"` → `\"`), non-ASCII → hex byte encoding,
/// and C0/DEL → `\xHH` fallback. named escapes are language-specific
/// and provided by the caller (e.g. `write_rust_named_escape` for rust).
pub(crate) fn write_byte_string_encoded<W, N>(out: &mut W, c: char, named_escape: N) -> fmt::Result
where
    W: fmt::Write,
    N: FnOnce(&mut W, char) -> Option<fmt::Result>,
{
    if let Some(r) = named_escape(out, c) {
        return r;
    }
    match c {
        '"' => out.write_str("\\\""),
        // non-ASCII → encode each UTF-8 byte
        c if !c.is_ascii() => write_utf8_hex_bytes(out, c),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

/// returns true if the code point is a unicode non-character.
///
/// non-characters are: U+FDD0-U+FDEF and every code point ending in
/// FFFE or FFFF (U+FFFE, U+FFFF, U+1FFFE, U+1FFFF, ..., U+10FFFE, U+10FFFF).
pub(crate) fn is_unicode_noncharacter(cp: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE == 0xFFFE)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;

    #[test]
    fn invalid_xml_detects_c0_controls() {
        assert!(is_invalid_for_xml('\x00'));
        assert!(is_invalid_for_xml('\x01'));
        assert!(is_invalid_for_xml('\x08'));
        assert!(is_invalid_for_xml('\x0B'));
        assert!(is_invalid_for_xml('\x0C'));
        assert!(is_invalid_for_xml('\x0E'));
        assert!(is_invalid_for_xml('\x1F'));
    }

    #[test]
    fn invalid_xml_allows_tab_lf_cr() {
        assert!(!is_invalid_for_xml('\t'));
        assert!(!is_invalid_for_xml('\n'));
        assert!(!is_invalid_for_xml('\r'));
    }

    #[test]
    fn invalid_xml_detects_del() {
        assert!(is_invalid_for_xml('\x7F'));
    }

    #[test]
    fn invalid_xml_detects_c1_controls() {
        assert!(is_invalid_for_xml('\u{0080}'));
        assert!(is_invalid_for_xml('\u{0085}')); // NEL
        assert!(is_invalid_for_xml('\u{009F}'));
    }

    #[test]
    fn invalid_xml_allows_normal_chars() {
        assert!(!is_invalid_for_xml(' '));
        assert!(!is_invalid_for_xml('a'));
        assert!(!is_invalid_for_xml('Z'));
        assert!(!is_invalid_for_xml('0'));
        assert!(!is_invalid_for_xml('\u{00A0}')); // NBSP
        assert!(!is_invalid_for_xml('\u{4E16}')); // CJK
    }

    #[test]
    fn noncharacter_detection() {
        assert!(is_unicode_noncharacter(0xFDD0));
        assert!(is_unicode_noncharacter(0xFDEF));
        assert!(is_unicode_noncharacter(0xFFFE));
        assert!(is_unicode_noncharacter(0xFFFF));
        assert!(is_unicode_noncharacter(0x1FFFE));
        assert!(is_unicode_noncharacter(0x1FFFF));
        assert!(is_unicode_noncharacter(0x10FFFE));
        assert!(is_unicode_noncharacter(0x10FFFF));

        assert!(!is_unicode_noncharacter(0xFDCF));
        assert!(!is_unicode_noncharacter(0xFDF0));
        assert!(!is_unicode_noncharacter(0xFFFD));
        assert!(!is_unicode_noncharacter(0x10000));
    }

    #[test]
    fn encode_loop_passthrough() {
        let mut out = String::new();
        encode_loop(&mut out, "hello", |_| false, |_, _, _| unreachable!()).unwrap();
        assert_eq!(out, "hello");
    }

    #[test]
    fn encode_loop_encodes_flagged_chars() {
        let mut out = String::new();
        encode_loop(
            &mut out,
            "a<b",
            |c| c == '<',
            |out, _, _| out.write_str("&lt;"),
        )
        .unwrap();
        assert_eq!(out, "a&lt;b");
    }

    #[test]
    fn encode_loop_empty_input() {
        let mut out = String::new();
        encode_loop(&mut out, "", |_| false, |_, _, _| unreachable!()).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn encode_loop_provides_lookahead() {
        let mut seen_next = Vec::new();
        let mut out = String::new();
        encode_loop(
            &mut out,
            "abc",
            |_| true,
            |out, c, next| {
                seen_next.push(next);
                out.write_char(c)
            },
        )
        .unwrap();
        assert_eq!(seen_next, vec![Some('b'), Some('c'), None]);
    }
}
