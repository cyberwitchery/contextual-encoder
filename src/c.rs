//! C literal encoders.
//!
//! encodes untrusted strings for safe embedding in C source literals.
//!
//! - [`for_c_string`] — safe for C string literals (`"..."`)
//! - [`for_c_char`] — safe for C character constants (`'...'`)
//!
//! # encoding rules
//!
//! both encoders use C's native escape syntax:
//!
//! - named escapes: `\a`, `\b`, `\t`, `\n`, `\v`, `\f`, `\r`, `\\`
//! - trigraph avoidance: `?` → `\?` (prevents `??X` trigraph interpretation)
//! - other C0 controls and DEL → octal `\OOO` (3-digit, avoids greedy `\x`)
//! - unicode non-characters → space
//!
//! octal escapes are used instead of hex because C's `\x` hex escapes
//! greedily consume all following hex digits (`\x41F` is one character,
//! not `\x41` + `F`). octal escapes are bounded at 3 digits.
//!
//! the encoders differ only in which quote is escaped:
//!
//! | encoder | quote escape | non-ASCII |
//! |---------|-------------|-----------|
//! | `for_c_string` | `"` → `\"` | passes through |
//! | `for_c_char` | `'` → `\'` | passes through |

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

// ---------------------------------------------------------------------------
// for_c_string — safe for C string literals ("...")
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a C string literal (`"..."`).
///
/// escapes backslashes, double quotes, question marks, and control characters
/// using C's escape syntax. non-ASCII unicode passes through unchanged
/// (assuming UTF-8 source). unicode non-characters are replaced with space.
///
/// question marks are always escaped to prevent trigraph interpretation
/// (`??=` → `#`, `??/` → `\`, etc.). octal escapes are used for unnamed
/// controls to avoid C's greedy hex escape parsing.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_c_string;
///
/// assert_eq!(for_c_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_c_string("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_c_string("cafe\u{0301}"), "cafe\u{0301}");
/// assert_eq!(for_c_string("what??!"), r"what\?\?!");
/// ```
pub fn for_c_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_c_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the C-string-encoded form of `input` to `out`.
///
/// see [`for_c_string`] for encoding rules.
pub fn write_c_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_c_string_encoding, |out, c, next| {
        write_c_text_encoded(out, c, next, '"')
    })
}

fn needs_c_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\' | '?') || is_unicode_noncharacter(c as u32)
}

// ---------------------------------------------------------------------------
// for_c_char — safe for C character constants ('...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a C character constant (`'...'`).
///
/// escapes backslashes, single quotes, question marks, and control characters
/// using C's escape syntax. non-ASCII unicode passes through unchanged.
/// unicode non-characters are replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_c_char;
///
/// assert_eq!(for_c_char("it's"), r"it\'s");
/// assert_eq!(for_c_char(r#"a"b"#), r#"a"b"#);
/// assert_eq!(for_c_char("tab\there"), r"tab\there");
/// ```
pub fn for_c_char(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_c_char(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the C-char-encoded form of `input` to `out`.
///
/// see [`for_c_char`] for encoding rules.
pub fn write_c_char<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_c_char_encoding, |out, c, next| {
        write_c_text_encoded(out, c, next, '\'')
    })
}

fn needs_c_char_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '\'' | '\\' | '?') || is_unicode_noncharacter(c as u32)
}

// ---------------------------------------------------------------------------
// shared helper for string and char encoders
// ---------------------------------------------------------------------------

/// writes the encoded form of a character for C string or char context.
/// `quote` is the delimiter being escaped (`"` or `'`).
/// `next` is the following character (unused here but required by encode_loop).
fn write_c_text_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
    quote: char,
) -> fmt::Result {
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
        // trigraph avoidance: always escape ? (C provides \? for this purpose)
        '?' => out.write_str("\\?"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // other C0 controls and DEL → 3-digit octal (avoids hex greediness)
        c => write!(out, "\\{:03o}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_c_string --

    #[test]
    fn string_passthrough() {
        assert_eq!(for_c_string("hello world"), "hello world");
        assert_eq!(for_c_string(""), "");
        assert_eq!(
            for_c_string("cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"),
            "cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"
        );
        assert_eq!(for_c_string("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn string_escapes_double_quote() {
        assert_eq!(for_c_string(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn string_passes_single_quote() {
        assert_eq!(for_c_string("a'b"), "a'b");
    }

    #[test]
    fn string_escapes_backslash() {
        assert_eq!(for_c_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_named_escapes() {
        assert_eq!(for_c_string("\x07"), "\\a");
        assert_eq!(for_c_string("\x08"), "\\b");
        assert_eq!(for_c_string("\t"), "\\t");
        assert_eq!(for_c_string("\n"), "\\n");
        assert_eq!(for_c_string("\x0B"), "\\v");
        assert_eq!(for_c_string("\x0C"), "\\f");
        assert_eq!(for_c_string("\r"), "\\r");
    }

    #[test]
    fn string_octal_escapes_for_controls() {
        assert_eq!(for_c_string("\x00"), "\\000");
        assert_eq!(for_c_string("\x01"), "\\001");
        assert_eq!(for_c_string("\x06"), "\\006");
        assert_eq!(for_c_string("\x0E"), "\\016");
        assert_eq!(for_c_string("\x1F"), "\\037");
        assert_eq!(for_c_string("\x7F"), "\\177");
    }

    #[test]
    fn string_trigraph_avoidance() {
        // all trigraph sequences must be broken
        assert_eq!(for_c_string("??="), "\\?\\?=");
        assert_eq!(for_c_string("??/"), "\\?\\?/");
        assert_eq!(for_c_string("??("), "\\?\\?(");
        assert_eq!(for_c_string("??)"), "\\?\\?)");
        assert_eq!(for_c_string("??'"), "\\?\\?'");
        assert_eq!(for_c_string("??<"), "\\?\\?<");
        assert_eq!(for_c_string("??>"), "\\?\\?>");
        assert_eq!(for_c_string("??!"), "\\?\\?!");
        assert_eq!(for_c_string("??-"), "\\?\\?-");
    }

    #[test]
    fn string_single_question_mark() {
        // single ? is also escaped (consistent, prevents future trigraph risk)
        assert_eq!(for_c_string("what?"), "what\\?");
    }

    #[test]
    fn string_nonchars_replaced() {
        assert_eq!(for_c_string("\u{FDD0}"), " ");
        assert_eq!(for_c_string("\u{FFFE}"), " ");
    }

    #[test]
    fn string_writer_matches() {
        let input = "test\x00\"\\\n cafe\u{0301}??=";
        let mut w = String::new();
        write_c_string(&mut w, input).unwrap();
        assert_eq!(for_c_string(input), w);
    }

    // -- for_c_char --

    #[test]
    fn char_passthrough() {
        assert_eq!(for_c_char("hello world"), "hello world");
        assert_eq!(for_c_char(""), "");
        assert_eq!(for_c_char("cafe\u{0301}"), "cafe\u{0301}");
    }

    #[test]
    fn char_escapes_single_quote() {
        assert_eq!(for_c_char("a'b"), r"a\'b");
    }

    #[test]
    fn char_passes_double_quote() {
        assert_eq!(for_c_char(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn char_escapes_backslash() {
        assert_eq!(for_c_char(r"a\b"), r"a\\b");
    }

    #[test]
    fn char_named_escapes() {
        assert_eq!(for_c_char("\x07"), "\\a");
        assert_eq!(for_c_char("\x08"), "\\b");
        assert_eq!(for_c_char("\t"), "\\t");
        assert_eq!(for_c_char("\n"), "\\n");
        assert_eq!(for_c_char("\x0B"), "\\v");
        assert_eq!(for_c_char("\x0C"), "\\f");
        assert_eq!(for_c_char("\r"), "\\r");
    }

    #[test]
    fn char_octal_escapes_for_controls() {
        assert_eq!(for_c_char("\x01"), "\\001");
        assert_eq!(for_c_char("\x7F"), "\\177");
    }

    #[test]
    fn char_trigraph_avoidance() {
        assert_eq!(for_c_char("??="), "\\?\\?=");
    }

    #[test]
    fn char_nonchars_replaced() {
        assert_eq!(for_c_char("\u{FDD0}"), " ");
    }

    #[test]
    fn char_writer_matches() {
        let input = "test\x00'\\\n cafe\u{0301}??/";
        let mut w = String::new();
        write_c_char(&mut w, input).unwrap();
        assert_eq!(for_c_char(input), w);
    }
}
