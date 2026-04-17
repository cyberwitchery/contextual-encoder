//! go literal encoders.
//!
//! encodes untrusted strings for safe embedding in go source literals.
//!
//! - [`for_go_string`] — safe for go interpreted string literals (`"..."`)
//! - [`for_go_char`] — safe for go rune literals (`'...'`)
//! - [`for_go_byte_string`] — safe for go byte-explicit string literals
//!   (`[]byte("...")`)
//!
//! # encoding rules
//!
//! all three encoders use go's native escape syntax:
//!
//! - named escapes: `\a`, `\b`, `\t`, `\n`, `\v`, `\f`, `\r`, `\\`
//! - other C0 controls and DEL → `\xHH`
//! - unicode non-characters → space (string/char) or `\xHH` per byte (byte string)
//!
//! the encoders differ in which quote is escaped and how non-ASCII is handled:
//!
//! | encoder | quote escape | non-ASCII |
//! |---------|-------------|-----------|
//! | `for_go_string` | `"` → `\"` | passes through |
//! | `for_go_char` | `'` → `\'` | passes through |
//! | `for_go_byte_string` | `"` → `\"` | each UTF-8 byte → `\xHH` |

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter, write_utf8_hex_bytes};

// ---------------------------------------------------------------------------
// for_go_string — safe for Go interpreted string literals ("...")
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a go interpreted string literal
/// (`"..."`).
///
/// escapes backslashes, double quotes, and control characters using go's
/// escape syntax. non-ASCII unicode passes through unchanged (go source files
/// are UTF-8). unicode non-characters are replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_go_string;
///
/// assert_eq!(for_go_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_go_string("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_go_string("cafe\u{0301}"), "cafe\u{0301}");
/// ```
pub fn for_go_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_go_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the go-string-encoded form of `input` to `out`.
///
/// see [`for_go_string`] for encoding rules.
pub fn write_go_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_go_string_encoding, |out, c, _next| {
        write_go_text_encoded(out, c, '"')
    })
}

fn needs_go_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\') || is_unicode_noncharacter(c as u32)
}

// ---------------------------------------------------------------------------
// for_go_char — safe for Go rune literals ('...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a go rune literal (`'...'`).
///
/// escapes backslashes, single quotes, and control characters using go's
/// escape syntax. non-ASCII unicode passes through unchanged. unicode
/// non-characters are replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_go_char;
///
/// assert_eq!(for_go_char("it's"), r"it\'s");
/// assert_eq!(for_go_char(r#"a"b"#), r#"a"b"#);
/// assert_eq!(for_go_char("tab\there"), r"tab\there");
/// ```
pub fn for_go_char(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_go_char(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the go-char-encoded form of `input` to `out`.
///
/// see [`for_go_char`] for encoding rules.
pub fn write_go_char<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_go_char_encoding, |out, c, _next| {
        write_go_text_encoded(out, c, '\'')
    })
}

fn needs_go_char_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '\'' | '\\') || is_unicode_noncharacter(c as u32)
}

// ---------------------------------------------------------------------------
// shared helper for string and char encoders
// ---------------------------------------------------------------------------

/// writes the encoded form of a character for go string or rune context.
/// `quote` is the delimiter being escaped (`"` or `'`).
fn write_go_text_encoded<W: fmt::Write>(out: &mut W, c: char, quote: char) -> fmt::Result {
    match c {
        '\x07' => out.write_str("\\a"),
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\v"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '\\' => out.write_str("\\\\"),
        '"' if quote == '"' => out.write_str("\\\""),
        '\'' if quote == '\'' => out.write_str("\\'"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

// ---------------------------------------------------------------------------
// for_go_byte_string — safe for Go byte-explicit string contexts
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a go string literal used in a
/// byte-explicit context (`[]byte("...")`).
///
/// escapes backslashes, double quotes, and control characters. non-ASCII
/// characters are encoded as their individual UTF-8 bytes using `\xHH`
/// notation, making every byte visible.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_go_byte_string;
///
/// assert_eq!(for_go_byte_string("hello"), "hello");
/// assert_eq!(for_go_byte_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_go_byte_string("cafe\u{0301}"), r"cafe\xcc\x81");
/// assert_eq!(for_go_byte_string("null\x00byte"), r"null\x00byte");
/// ```
pub fn for_go_byte_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_go_byte_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the go-byte-string-encoded form of `input` to `out`.
///
/// see [`for_go_byte_string`] for encoding rules.
pub fn write_go_byte_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_go_byte_string_encoding,
        write_go_byte_string_encoded,
    )
}

fn needs_go_byte_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\') || !c.is_ascii()
}

fn write_go_byte_string_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '\x07' => out.write_str("\\a"),
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\v"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '"' => out.write_str("\\\""),
        '\\' => out.write_str("\\\\"),
        // non-ASCII → encode each UTF-8 byte
        c if !c.is_ascii() => write_utf8_hex_bytes(out, c),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_go_string --

    #[test]
    fn string_passthrough() {
        assert_eq!(for_go_string("hello world"), "hello world");
        assert_eq!(for_go_string(""), "");
        assert_eq!(
            for_go_string("cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"),
            "cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"
        );
        assert_eq!(for_go_string("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn string_escapes_double_quote() {
        assert_eq!(for_go_string(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn string_passes_single_quote() {
        assert_eq!(for_go_string("a'b"), "a'b");
    }

    #[test]
    fn string_escapes_backslash() {
        assert_eq!(for_go_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_named_escapes() {
        assert_eq!(for_go_string("\x07"), "\\a");
        assert_eq!(for_go_string("\x08"), "\\b");
        assert_eq!(for_go_string("\t"), "\\t");
        assert_eq!(for_go_string("\n"), "\\n");
        assert_eq!(for_go_string("\x0B"), "\\v");
        assert_eq!(for_go_string("\x0C"), "\\f");
        assert_eq!(for_go_string("\r"), "\\r");
    }

    #[test]
    fn string_hex_escapes_for_controls() {
        assert_eq!(for_go_string("\x00"), "\\x00");
        assert_eq!(for_go_string("\x01"), "\\x01");
        assert_eq!(for_go_string("\x06"), "\\x06");
        assert_eq!(for_go_string("\x0E"), "\\x0e");
        assert_eq!(for_go_string("\x1F"), "\\x1f");
        assert_eq!(for_go_string("\x7F"), "\\x7f");
    }

    #[test]
    fn string_nonchars_replaced() {
        assert_eq!(for_go_string("\u{FDD0}"), " ");
        assert_eq!(for_go_string("\u{FFFE}"), " ");
    }

    #[test]
    fn string_writer_matches() {
        let input = "test\x00\"\\\n cafe\u{0301}";
        let mut w = String::new();
        write_go_string(&mut w, input).unwrap();
        assert_eq!(for_go_string(input), w);
    }

    // -- for_go_char --

    #[test]
    fn char_passthrough() {
        assert_eq!(for_go_char("hello world"), "hello world");
        assert_eq!(for_go_char(""), "");
        assert_eq!(for_go_char("cafe\u{0301}"), "cafe\u{0301}");
    }

    #[test]
    fn char_escapes_single_quote() {
        assert_eq!(for_go_char("a'b"), r"a\'b");
    }

    #[test]
    fn char_passes_double_quote() {
        assert_eq!(for_go_char(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn char_escapes_backslash() {
        assert_eq!(for_go_char(r"a\b"), r"a\\b");
    }

    #[test]
    fn char_named_escapes() {
        assert_eq!(for_go_char("\x07"), "\\a");
        assert_eq!(for_go_char("\x08"), "\\b");
        assert_eq!(for_go_char("\t"), "\\t");
        assert_eq!(for_go_char("\n"), "\\n");
        assert_eq!(for_go_char("\x0B"), "\\v");
        assert_eq!(for_go_char("\x0C"), "\\f");
        assert_eq!(for_go_char("\r"), "\\r");
    }

    #[test]
    fn char_hex_escapes_for_controls() {
        assert_eq!(for_go_char("\x01"), "\\x01");
        assert_eq!(for_go_char("\x7F"), "\\x7f");
    }

    #[test]
    fn char_nonchars_replaced() {
        assert_eq!(for_go_char("\u{FDD0}"), " ");
    }

    #[test]
    fn char_writer_matches() {
        let input = "test\x00'\\\n cafe\u{0301}";
        let mut w = String::new();
        write_go_char(&mut w, input).unwrap();
        assert_eq!(for_go_char(input), w);
    }

    // -- for_go_byte_string --

    #[test]
    fn byte_string_passthrough() {
        assert_eq!(for_go_byte_string("hello world"), "hello world");
        assert_eq!(for_go_byte_string(""), "");
    }

    #[test]
    fn byte_string_escapes_double_quote() {
        assert_eq!(for_go_byte_string(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn byte_string_escapes_backslash() {
        assert_eq!(for_go_byte_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn byte_string_named_escapes() {
        assert_eq!(for_go_byte_string("\x07"), "\\a");
        assert_eq!(for_go_byte_string("\x08"), "\\b");
        assert_eq!(for_go_byte_string("\t"), "\\t");
        assert_eq!(for_go_byte_string("\n"), "\\n");
        assert_eq!(for_go_byte_string("\x0B"), "\\v");
        assert_eq!(for_go_byte_string("\x0C"), "\\f");
        assert_eq!(for_go_byte_string("\r"), "\\r");
    }

    #[test]
    fn byte_string_hex_for_controls() {
        assert_eq!(for_go_byte_string("\x00"), "\\x00");
        assert_eq!(for_go_byte_string("\x01"), "\\x01");
        assert_eq!(for_go_byte_string("\x7F"), "\\x7f");
    }

    #[test]
    fn byte_string_non_ascii_as_utf8_bytes() {
        // combining accent U+0301 → UTF-8: CC 81
        assert_eq!(for_go_byte_string("\u{0301}"), r"\xcc\x81");
        // cafe + combining accent
        assert_eq!(for_go_byte_string("cafe\u{0301}"), r"cafe\xcc\x81");
        // 日 = U+65E5 → UTF-8: E6 97 A5
        assert_eq!(for_go_byte_string("\u{65E5}"), r"\xe6\x97\xa5");
        // 😀 = U+1F600 → UTF-8: F0 9F 98 80
        assert_eq!(for_go_byte_string("\u{1F600}"), r"\xf0\x9f\x98\x80");
    }

    #[test]
    fn byte_string_nonchars_as_bytes() {
        // U+FDD0 → UTF-8: EF B7 90
        assert_eq!(for_go_byte_string("\u{FDD0}"), r"\xef\xb7\x90");
    }

    #[test]
    fn byte_string_single_quote_passes() {
        assert_eq!(for_go_byte_string("a'b"), "a'b");
    }

    #[test]
    fn byte_string_writer_matches() {
        let input = "test\x00\"\\cafe\u{0301}";
        let mut w = String::new();
        write_go_byte_string(&mut w, input).unwrap();
        assert_eq!(for_go_byte_string(input), w);
    }
}
