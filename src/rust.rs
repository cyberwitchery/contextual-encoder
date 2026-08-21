//! rust literal encoders.
//!
//! encodes untrusted strings for safe embedding in rust source literals.
//!
//! - [`for_rust_string`] — safe for rust string literals (`"..."`)
//! - [`for_rust_char`] — safe for rust char literals (`'...'`)
//! - [`for_rust_char_checked`] — as [`for_rust_char`], but rejects input that is
//!   not exactly one character
//! - [`for_rust_byte_string`] — safe for rust byte string literals (`b"..."`)
//!
//! # encoding rules
//!
//! all three encoders use rust's native escape syntax:
//!
//! - named escapes: `\0`, `\t`, `\n`, `\r`, `\\`
//! - C0 controls and DEL without named escapes → `\xHH`
//! - unicode non-characters → space (string/char) or `\xHH` per byte (byte string)
//! - bidi formatting controls → `\u{HHHH}` (string/char) or `\xHH` per byte
//!   (byte string)
//!
//! the encoders differ in which quote is escaped and how non-ASCII is handled:
//!
//! | encoder | quote escape | non-ASCII |
//! |---------|-------------|-----------|
//! | `for_rust_string` | `"` → `\"` | passes through |
//! | `for_rust_char` | `'` → `\'` | passes through |
//! | `for_rust_byte_string` | `"` → `\"` | each UTF-8 byte → `\xHH` |
//!
//! # char literal length
//!
//! a rust char literal holds exactly one unicode scalar value, so the char
//! encoders require input of exactly one character. empty or longer input
//! encodes to a literal body that does not compile.

use std::fmt;

use crate::engine::{
    encode_loop, is_unicode_noncharacter, needs_byte_string_encoding, write_byte_string_encoded,
    write_rust_named_escape,
};

/// encodes `input` for safe embedding in a rust string literal (`"..."`).
///
/// escapes backslashes, double quotes, and control characters using rust's
/// escape syntax. non-ASCII unicode passes through unchanged (valid in rust
/// string literals). unicode non-characters are replaced with space, and the
/// bidi formatting controls `rustc` rejects raw in a literal are escaped as
/// `\u{HHHH}`.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_rust_string;
///
/// assert_eq!(for_rust_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_rust_string("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_rust_string("café"), "café");
/// assert_eq!(for_rust_string("a\u{202E}b"), r"a\u{202e}b");
/// ```
pub fn for_rust_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_rust_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the rust-string-encoded form of `input` to `out`.
///
/// see [`for_rust_string`] for encoding rules.
pub fn write_rust_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_rust_string_encoding, |out, c, _next| {
        write_rust_text_encoded(out, c, '"')
    })
}

fn needs_rust_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\')
        || is_unicode_noncharacter(c as u32)
        || is_text_direction_control(c)
}

/// encodes `input` for safe embedding in a rust char literal (`'...'`).
///
/// `input` must be exactly one unicode scalar value; this function does not
/// check, and any other input encodes to a literal body that does not
/// compile. [`for_rust_char_checked`] reports that case instead.
///
/// escapes backslashes, single quotes, and control characters using rust's
/// escape syntax. non-ASCII unicode passes through unchanged. unicode
/// non-characters are replaced with space, and the bidi formatting controls
/// `rustc` rejects raw in a literal are escaped as `\u{HHHH}`.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_rust_char;
///
/// assert_eq!(for_rust_char("'"), r"\'");
/// assert_eq!(for_rust_char("\t"), r"\t");
/// assert_eq!(for_rust_char("é"), "é");
/// assert_eq!(for_rust_char("\u{202E}"), r"\u{202e}");
/// ```
pub fn for_rust_char(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_rust_char(&mut out, input).expect("writing to string cannot fail");
    out
}

/// encodes `input` for a rust char literal (`'...'`), or returns `None` if
/// `input` is not exactly one unicode scalar value.
///
/// the checked counterpart to [`for_rust_char`]; on `Some`, the encoding is
/// identical. a grapheme cluster spelled with several scalar values, such as
/// `"e\u{301}"`, is rejected — no char literal can hold it.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_rust_char_checked;
///
/// assert_eq!(for_rust_char_checked("'"), Some(r"\'".to_string()));
/// assert_eq!(for_rust_char_checked("é"), Some("é".to_string()));
/// assert_eq!(for_rust_char_checked("it's"), None);
/// assert_eq!(for_rust_char_checked(""), None);
/// ```
pub fn for_rust_char_checked(input: &str) -> Option<String> {
    let mut chars = input.chars();
    match (chars.next(), chars.next()) {
        (Some(_), None) => Some(for_rust_char(input)),
        (None, _) | (Some(_), Some(_)) => None,
    }
}

/// writes the rust-char-encoded form of `input` to `out`.
///
/// see [`for_rust_char`] for encoding rules and the one-character contract.
pub fn write_rust_char<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_rust_char_encoding, |out, c, _next| {
        write_rust_text_encoded(out, c, '\'')
    })
}

fn needs_rust_char_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '\'' | '\\')
        || is_unicode_noncharacter(c as u32)
        || is_text_direction_control(c)
}

/// returns true for the bidi formatting characters `rustc` rejects raw inside a
/// literal (the deny-by-default `text_direction_codepoint_in_literal` lint).
fn is_text_direction_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// writes the encoded form of a character for rust string or char context.
/// `quote` is the delimiter being escaped (`"` or `'`).
fn write_rust_text_encoded<W: fmt::Write>(out: &mut W, c: char, quote: char) -> fmt::Result {
    match c {
        '\0' => out.write_str("\\0"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\r' => out.write_str("\\r"),
        '\\' => out.write_str("\\\\"),
        '"' if quote == '"' => out.write_str("\\\""),
        '\'' if quote == '\'' => out.write_str("\\'"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        c if is_text_direction_control(c) => write!(out, "\\u{{{:04x}}}", c as u32),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

/// encodes `input` for safe embedding in a rust byte string literal (`b"..."`).
///
/// escapes backslashes, double quotes, and control characters. non-ASCII
/// characters are encoded as their individual UTF-8 bytes using `\xHH`
/// notation, since byte string literals only accept ASCII directly.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_rust_byte_string;
///
/// assert_eq!(for_rust_byte_string("hello"), "hello");
/// assert_eq!(for_rust_byte_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_rust_byte_string("café"), r"caf\xc3\xa9");
/// assert_eq!(for_rust_byte_string("null\x00byte"), r"null\0byte");
/// ```
pub fn for_rust_byte_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_rust_byte_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the rust-byte-string-encoded form of `input` to `out`.
///
/// see [`for_rust_byte_string`] for encoding rules.
pub fn write_rust_byte_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_byte_string_encoding, |out, c, _next| {
        write_byte_string_encoded(out, c, write_rust_named_escape)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_rust_string --

    #[test]
    fn string_passthrough() {
        assert_eq!(for_rust_string("hello world"), "hello world");
        assert_eq!(for_rust_string(""), "");
        assert_eq!(for_rust_string("café 日本語"), "café 日本語");
        assert_eq!(for_rust_string("😀"), "😀");
    }

    #[test]
    fn string_escapes_double_quote() {
        assert_eq!(for_rust_string(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn string_passes_single_quote() {
        assert_eq!(for_rust_string("a'b"), "a'b");
    }

    #[test]
    fn string_escapes_backslash() {
        assert_eq!(for_rust_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_named_escapes() {
        assert_eq!(for_rust_string("\0"), "\\0");
        assert_eq!(for_rust_string("\t"), "\\t");
        assert_eq!(for_rust_string("\n"), "\\n");
        assert_eq!(for_rust_string("\r"), "\\r");
    }

    #[test]
    fn string_hex_escapes_for_controls() {
        assert_eq!(for_rust_string("\x01"), "\\x01");
        assert_eq!(for_rust_string("\x08"), "\\x08");
        assert_eq!(for_rust_string("\x0B"), "\\x0b");
        assert_eq!(for_rust_string("\x0C"), "\\x0c");
        assert_eq!(for_rust_string("\x1F"), "\\x1f");
        assert_eq!(for_rust_string("\x7F"), "\\x7f");
    }

    #[test]
    fn string_nonchars_replaced() {
        assert_eq!(for_rust_string("\u{FDD0}"), " ");
        assert_eq!(for_rust_string("\u{FFFE}"), " ");
    }

    /// the codepoints `rustc` denies raw in a literal, with their escaped forms.
    const TEXT_DIRECTION: [(&str, &str); 9] = [
        ("\u{202A}", r"\u{202a}"),
        ("\u{202B}", r"\u{202b}"),
        ("\u{202C}", r"\u{202c}"),
        ("\u{202D}", r"\u{202d}"),
        ("\u{202E}", r"\u{202e}"),
        ("\u{2066}", r"\u{2066}"),
        ("\u{2067}", r"\u{2067}"),
        ("\u{2068}", r"\u{2068}"),
        ("\u{2069}", r"\u{2069}"),
    ];

    #[test]
    fn string_escapes_text_direction_controls() {
        for (raw, escaped) in TEXT_DIRECTION {
            assert_eq!(for_rust_string(raw), escaped);
            assert_eq!(for_rust_string(&format!("a{raw}b")), format!("a{escaped}b"));
        }
    }

    #[test]
    fn string_writer_matches() {
        let input = "test\0\"\\\n café";
        let mut w = String::new();
        write_rust_string(&mut w, input).unwrap();
        assert_eq!(for_rust_string(input), w);
    }

    // -- for_rust_char --

    #[test]
    fn char_passthrough() {
        assert_eq!(for_rust_char("hello world"), "hello world");
        assert_eq!(for_rust_char(""), "");
        assert_eq!(for_rust_char("café"), "café");
    }

    #[test]
    fn char_escapes_single_quote() {
        assert_eq!(for_rust_char("a'b"), r"a\'b");
    }

    #[test]
    fn char_passes_double_quote() {
        assert_eq!(for_rust_char(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn char_escapes_backslash() {
        assert_eq!(for_rust_char(r"a\b"), r"a\\b");
    }

    #[test]
    fn char_named_escapes() {
        assert_eq!(for_rust_char("\0"), "\\0");
        assert_eq!(for_rust_char("\t"), "\\t");
        assert_eq!(for_rust_char("\n"), "\\n");
        assert_eq!(for_rust_char("\r"), "\\r");
    }

    #[test]
    fn char_hex_escapes_for_controls() {
        assert_eq!(for_rust_char("\x01"), "\\x01");
        assert_eq!(for_rust_char("\x7F"), "\\x7f");
    }

    #[test]
    fn char_nonchars_replaced() {
        assert_eq!(for_rust_char("\u{FDD0}"), " ");
    }

    #[test]
    fn char_escapes_text_direction_controls() {
        for (raw, escaped) in TEXT_DIRECTION {
            assert_eq!(for_rust_char(raw), escaped);
        }
    }

    #[test]
    fn char_writer_matches() {
        let input = "test\0'\\\n café";
        let mut w = String::new();
        write_rust_char(&mut w, input).unwrap();
        assert_eq!(for_rust_char(input), w);
    }

    // -- for_rust_char_checked --

    #[test]
    fn char_checked_rejects_empty() {
        assert_eq!(for_rust_char_checked(""), None);
    }

    #[test]
    fn char_checked_accepts_single() {
        assert_eq!(for_rust_char_checked("a"), Some("a".to_string()));
        assert_eq!(for_rust_char_checked(" "), Some(" ".to_string()));
    }

    #[test]
    fn char_checked_rejects_multi() {
        assert_eq!(for_rust_char_checked("ab"), None);
        assert_eq!(for_rust_char_checked("it's"), None);
        assert_eq!(for_rust_char_checked("hello world"), None);
    }

    #[test]
    fn char_checked_rejects_multi_scalar_grapheme() {
        assert_eq!(for_rust_char_checked("e\u{301}"), None);
    }

    #[test]
    fn char_checked_escapes_single() {
        assert_eq!(for_rust_char_checked("'"), Some(r"\'".to_string()));
        assert_eq!(for_rust_char_checked("\\"), Some(r"\\".to_string()));
        assert_eq!(for_rust_char_checked("\0"), Some(r"\0".to_string()));
        assert_eq!(for_rust_char_checked("\n"), Some(r"\n".to_string()));
        assert_eq!(for_rust_char_checked("\x01"), Some(r"\x01".to_string()));
        assert_eq!(for_rust_char_checked("\u{FDD0}"), Some(" ".to_string()));
    }

    #[test]
    fn char_checked_accepts_non_ascii() {
        assert_eq!(for_rust_char_checked("é"), Some("é".to_string()));
        assert_eq!(for_rust_char_checked("日"), Some("日".to_string()));
        assert_eq!(for_rust_char_checked("😀"), Some("😀".to_string()));
    }

    #[test]
    fn char_checked_escapes_text_direction_controls() {
        for (raw, escaped) in TEXT_DIRECTION {
            assert_eq!(for_rust_char_checked(raw), Some(escaped.to_string()));
        }
    }

    #[test]
    fn char_checked_matches_unchecked_when_accepted() {
        for input in [
            "a", "'", "\\", "\0", "\t", "\n", "\r", "\x01", "\x7F", "é", "😀", "\u{202E}",
            "\u{2069}",
        ] {
            assert_eq!(for_rust_char_checked(input), Some(for_rust_char(input)));
        }
    }

    // -- for_rust_byte_string --

    #[test]
    fn byte_string_passthrough() {
        assert_eq!(for_rust_byte_string("hello world"), "hello world");
        assert_eq!(for_rust_byte_string(""), "");
    }

    #[test]
    fn byte_string_escapes_double_quote() {
        assert_eq!(for_rust_byte_string(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn byte_string_escapes_backslash() {
        assert_eq!(for_rust_byte_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn byte_string_named_escapes() {
        assert_eq!(for_rust_byte_string("\0"), "\\0");
        assert_eq!(for_rust_byte_string("\t"), "\\t");
        assert_eq!(for_rust_byte_string("\n"), "\\n");
        assert_eq!(for_rust_byte_string("\r"), "\\r");
    }

    #[test]
    fn byte_string_hex_for_controls() {
        assert_eq!(for_rust_byte_string("\x01"), "\\x01");
        assert_eq!(for_rust_byte_string("\x7F"), "\\x7f");
    }

    #[test]
    fn byte_string_non_ascii_as_utf8_bytes() {
        // é = U+00E9 → UTF-8: C3 A9
        assert_eq!(for_rust_byte_string("é"), r"\xc3\xa9");
        // café → only the é is encoded
        assert_eq!(for_rust_byte_string("café"), r"caf\xc3\xa9");
        // 日 = U+65E5 → UTF-8: E6 97 A5
        assert_eq!(for_rust_byte_string("日"), r"\xe6\x97\xa5");
        // 😀 = U+1F600 → UTF-8: F0 9F 98 80
        assert_eq!(for_rust_byte_string("😀"), r"\xf0\x9f\x98\x80");
    }

    #[test]
    fn byte_string_nonchars_as_bytes() {
        // U+FDD0 → UTF-8: EF B7 90
        assert_eq!(for_rust_byte_string("\u{FDD0}"), r"\xef\xb7\x90");
    }

    #[test]
    fn byte_string_text_direction_controls_as_bytes() {
        assert_eq!(for_rust_byte_string("\u{202E}"), r"\xe2\x80\xae");
        assert_eq!(for_rust_byte_string("\u{2069}"), r"\xe2\x81\xa9");
    }

    #[test]
    fn byte_string_single_quote_passes() {
        assert_eq!(for_rust_byte_string("a'b"), "a'b");
    }

    #[test]
    fn byte_string_writer_matches() {
        let input = "test\0\"\\café";
        let mut w = String::new();
        write_rust_byte_string(&mut w, input).unwrap();
        assert_eq!(for_rust_byte_string(input), w);
    }
}
