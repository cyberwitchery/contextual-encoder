//! python literal encoders.
//!
//! encodes untrusted strings for safe embedding in python source literals.
//!
//! - [`for_python_string`] — safe for python string literals (`"..."` or `'...'`)
//! - [`for_python_bytes`] — safe for python bytes literals (`b"..."` or `b'...'`)
//! - [`for_python_raw_string`] — safe for python raw string literals
//!   (`r"..."` or `r'...'`)
//!
//! # encoding rules
//!
//! ## string and bytes
//!
//! both encoders use python's native escape syntax:
//!
//! - named escapes: `\a`, `\b`, `\t`, `\n`, `\v`, `\f`, `\r`, `\\`, `\"`, `\'`
//! - other C0 controls and DEL → `\xHH`
//! - unicode non-characters → space (string) or `\xHH` per byte (bytes)
//!
//! both quote characters are escaped, making the output safe regardless of
//! which delimiter (`"` or `'`) is used.
//!
//! the encoders differ in how non-ASCII is handled:
//!
//! | encoder | non-ASCII |
//! |---------|-----------|
//! | `for_python_string` | passes through |
//! | `for_python_bytes` | each UTF-8 byte → `\xHH` |
//!
//! ## raw string
//!
//! raw strings do not process escape sequences, so the encoder replaces
//! dangerous characters with space:
//!
//! - quotes (`"` and `'`) → space
//! - C0 controls and DEL → space
//! - unicode non-characters → space
//! - trailing odd backslash → replaced with space (raw strings cannot
//!   end with an odd number of backslashes)

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter, write_utf8_hex_bytes};

// ---------------------------------------------------------------------------
// for_python_string — safe for Python string literals ("..." or '...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a python string literal
/// (`"..."` or `'...'`).
///
/// escapes backslashes, both quote characters, and control characters using
/// python's escape syntax. non-ASCII unicode passes through unchanged
/// (python 3 source files are UTF-8 by default). unicode non-characters
/// are replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_python_string;
///
/// assert_eq!(for_python_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_python_string("it's"), r"it\'s");
/// assert_eq!(for_python_string("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_python_string("café"), "café");
/// ```
pub fn for_python_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_python_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the python-string-encoded form of `input` to `out`.
///
/// see [`for_python_string`] for encoding rules.
pub fn write_python_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_python_string_encoding, |out, c, _next| {
        write_python_text_encoded(out, c)
    })
}

fn needs_python_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\'' | '\\') || is_unicode_noncharacter(c as u32)
}

// ---------------------------------------------------------------------------
// for_python_bytes — safe for Python bytes literals (b"..." or b'...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a python bytes literal
/// (`b"..."` or `b'...'`).
///
/// escapes backslashes, both quote characters, and control characters.
/// non-ASCII characters are encoded as their individual UTF-8 bytes
/// using `\xHH` notation, since bytes literals only accept ASCII directly.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_python_bytes;
///
/// assert_eq!(for_python_bytes("hello"), "hello");
/// assert_eq!(for_python_bytes(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_python_bytes("café"), r"caf\xc3\xa9");
/// assert_eq!(for_python_bytes("null\x00byte"), r"null\x00byte");
/// ```
pub fn for_python_bytes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_python_bytes(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the python-bytes-encoded form of `input` to `out`.
///
/// see [`for_python_bytes`] for encoding rules.
pub fn write_python_bytes<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_python_bytes_encoding,
        write_python_bytes_encoded,
    )
}

fn needs_python_bytes_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\'' | '\\') || !c.is_ascii()
}

fn write_python_bytes_encoded<W: fmt::Write>(
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
        '\'' => out.write_str("\\'"),
        '\\' => out.write_str("\\\\"),
        // non-ASCII → encode each UTF-8 byte
        c if !c.is_ascii() => write_utf8_hex_bytes(out, c),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

// ---------------------------------------------------------------------------
// shared helper for string encoder
// ---------------------------------------------------------------------------

/// writes the encoded form of a character for python string context.
fn write_python_text_encoded<W: fmt::Write>(out: &mut W, c: char) -> fmt::Result {
    match c {
        '\x07' => out.write_str("\\a"),
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\v"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '\\' => out.write_str("\\\\"),
        '"' => out.write_str("\\\""),
        '\'' => out.write_str("\\'"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

// ---------------------------------------------------------------------------
// for_python_raw_string — safe for Python raw string literals (r"..." or r'...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a python raw string literal
/// (`r"..."` or `r'...'`).
///
/// raw strings do not process escape sequences, so dangerous characters
/// are replaced with space. both quote characters are replaced (making
/// the output safe regardless of which delimiter is used). if the input
/// would end with an odd number of backslashes, the last is replaced
/// with space (raw strings cannot end with an odd backslash count).
///
/// # examples
///
/// ```
/// use contextual_encoder::for_python_raw_string;
///
/// assert_eq!(for_python_raw_string("hello"), "hello");
/// assert_eq!(for_python_raw_string(r#"a"b"#), "a b");
/// assert_eq!(for_python_raw_string(r"path\to\file"), r"path\to\file");
/// assert_eq!(for_python_raw_string(r"trailing\"), "trailing ");
/// ```
pub fn for_python_raw_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_python_raw_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the python-raw-string-encoded form of `input` to `out`.
///
/// see [`for_python_raw_string`] for encoding rules.
pub fn write_python_raw_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    let trailing_bs = input.bytes().rev().take_while(|&b| b == b'\\').count();
    let cutoff = if trailing_bs % 2 == 1 {
        input.len() - 1
    } else {
        input.len()
    };

    for (i, c) in input.char_indices() {
        if i >= cutoff {
            // trailing odd backslash — replace with space
            out.write_char(' ')?;
        } else if needs_python_raw_string_encoding(c) {
            out.write_char(' ')?;
        } else {
            out.write_char(c)?;
        }
    }
    Ok(())
}

fn needs_python_raw_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\'') || is_unicode_noncharacter(c as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_python_string --

    #[test]
    fn string_passthrough() {
        assert_eq!(for_python_string("hello world"), "hello world");
        assert_eq!(for_python_string(""), "");
        assert_eq!(
            for_python_string("cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"),
            "cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"
        );
        assert_eq!(for_python_string("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn string_escapes_double_quote() {
        assert_eq!(for_python_string(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn string_escapes_single_quote() {
        assert_eq!(for_python_string("a'b"), r"a\'b");
    }

    #[test]
    fn string_escapes_backslash() {
        assert_eq!(for_python_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_named_escapes() {
        assert_eq!(for_python_string("\x07"), "\\a");
        assert_eq!(for_python_string("\x08"), "\\b");
        assert_eq!(for_python_string("\t"), "\\t");
        assert_eq!(for_python_string("\n"), "\\n");
        assert_eq!(for_python_string("\x0B"), "\\v");
        assert_eq!(for_python_string("\x0C"), "\\f");
        assert_eq!(for_python_string("\r"), "\\r");
    }

    #[test]
    fn string_hex_escapes_for_controls() {
        assert_eq!(for_python_string("\x00"), "\\x00");
        assert_eq!(for_python_string("\x01"), "\\x01");
        assert_eq!(for_python_string("\x06"), "\\x06");
        assert_eq!(for_python_string("\x0E"), "\\x0e");
        assert_eq!(for_python_string("\x1F"), "\\x1f");
        assert_eq!(for_python_string("\x7F"), "\\x7f");
    }

    #[test]
    fn string_nonchars_replaced() {
        assert_eq!(for_python_string("\u{FDD0}"), " ");
        assert_eq!(for_python_string("\u{FFFE}"), " ");
    }

    #[test]
    fn string_writer_matches() {
        let input = "test\x00\"'\\\n cafe\u{0301}";
        let mut w = String::new();
        write_python_string(&mut w, input).unwrap();
        assert_eq!(for_python_string(input), w);
    }

    // -- for_python_bytes --

    #[test]
    fn bytes_passthrough() {
        assert_eq!(for_python_bytes("hello world"), "hello world");
        assert_eq!(for_python_bytes(""), "");
    }

    #[test]
    fn bytes_escapes_double_quote() {
        assert_eq!(for_python_bytes(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn bytes_escapes_single_quote() {
        assert_eq!(for_python_bytes("a'b"), r"a\'b");
    }

    #[test]
    fn bytes_escapes_backslash() {
        assert_eq!(for_python_bytes(r"a\b"), r"a\\b");
    }

    #[test]
    fn bytes_named_escapes() {
        assert_eq!(for_python_bytes("\x07"), "\\a");
        assert_eq!(for_python_bytes("\x08"), "\\b");
        assert_eq!(for_python_bytes("\t"), "\\t");
        assert_eq!(for_python_bytes("\n"), "\\n");
        assert_eq!(for_python_bytes("\x0B"), "\\v");
        assert_eq!(for_python_bytes("\x0C"), "\\f");
        assert_eq!(for_python_bytes("\r"), "\\r");
    }

    #[test]
    fn bytes_hex_for_controls() {
        assert_eq!(for_python_bytes("\x00"), "\\x00");
        assert_eq!(for_python_bytes("\x01"), "\\x01");
        assert_eq!(for_python_bytes("\x7F"), "\\x7f");
    }

    #[test]
    fn bytes_non_ascii_as_utf8_bytes() {
        // combining accent U+0301 → UTF-8: CC 81
        assert_eq!(for_python_bytes("\u{0301}"), r"\xcc\x81");
        // cafe + combining accent
        assert_eq!(for_python_bytes("cafe\u{0301}"), r"cafe\xcc\x81");
        // 日 = U+65E5 → UTF-8: E6 97 A5
        assert_eq!(for_python_bytes("\u{65E5}"), r"\xe6\x97\xa5");
        // 😀 = U+1F600 → UTF-8: F0 9F 98 80
        assert_eq!(for_python_bytes("\u{1F600}"), r"\xf0\x9f\x98\x80");
    }

    #[test]
    fn bytes_nonchars_as_bytes() {
        // U+FDD0 → UTF-8: EF B7 90
        assert_eq!(for_python_bytes("\u{FDD0}"), r"\xef\xb7\x90");
    }

    #[test]
    fn bytes_writer_matches() {
        let input = "test\x00\"'\\cafe\u{0301}";
        let mut w = String::new();
        write_python_bytes(&mut w, input).unwrap();
        assert_eq!(for_python_bytes(input), w);
    }

    // -- for_python_raw_string --

    #[test]
    fn raw_passthrough() {
        assert_eq!(for_python_raw_string("hello world"), "hello world");
        assert_eq!(for_python_raw_string(""), "");
    }

    #[test]
    fn raw_quotes_replaced() {
        assert_eq!(for_python_raw_string(r#"a"b"#), "a b");
        assert_eq!(for_python_raw_string("a'b"), "a b");
        assert_eq!(for_python_raw_string(r#"a"b'c"#), "a b c");
    }

    #[test]
    fn raw_controls_replaced() {
        assert_eq!(for_python_raw_string("\x00"), " ");
        assert_eq!(for_python_raw_string("\x01"), " ");
        assert_eq!(for_python_raw_string("\t"), " ");
        assert_eq!(for_python_raw_string("\n"), " ");
        assert_eq!(for_python_raw_string("\x7F"), " ");
    }

    #[test]
    fn raw_backslash_in_middle() {
        assert_eq!(for_python_raw_string(r"a\b"), r"a\b");
        assert_eq!(for_python_raw_string(r"path\to\file"), r"path\to\file");
    }

    #[test]
    fn raw_trailing_even_backslashes() {
        assert_eq!(for_python_raw_string(r"ab\\"), r"ab\\");
        assert_eq!(for_python_raw_string(r"ab\\\\"), r"ab\\\\");
    }

    #[test]
    fn raw_trailing_odd_backslash_replaced() {
        assert_eq!(for_python_raw_string(r"trailing\"), "trailing ");
        assert_eq!(for_python_raw_string(r"ab\\\"), "ab\\\\ ");
        assert_eq!(for_python_raw_string(r"\"), " ");
    }

    #[test]
    fn raw_nonchars_replaced() {
        assert_eq!(for_python_raw_string("\u{FDD0}"), " ");
        assert_eq!(for_python_raw_string("\u{FFFE}"), " ");
    }

    #[test]
    fn raw_non_ascii_passes_through() {
        assert_eq!(for_python_raw_string("café"), "café");
        assert_eq!(for_python_raw_string("日本語"), "日本語");
        assert_eq!(for_python_raw_string("😀"), "😀");
    }

    #[test]
    fn raw_writer_matches() {
        let input = "test\x00\"'\\path\\to";
        let mut w = String::new();
        write_python_raw_string(&mut w, input).unwrap();
        assert_eq!(for_python_raw_string(input), w);
    }
}
