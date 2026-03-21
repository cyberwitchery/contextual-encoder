//! rust literal encoders.
//!
//! encodes untrusted strings for safe embedding in rust source literals.
//!
//! - [`for_rust_string`] — safe for rust string literals (`"..."`)
//! - [`for_rust_char`] — safe for rust char literals (`'...'`)
//! - [`for_rust_byte_string`] — safe for rust byte string literals (`b"..."`)
//!
//! # encoding rules
//!
//! all three encoders use rust's native escape syntax:
//!
//! - named escapes: `\0`, `\t`, `\n`, `\r`, `\\`
//! - C0 controls and DEL without named escapes → `\xHH`
//! - unicode non-characters → space (string/char) or `\xHH` per byte (byte string)
//!
//! the encoders differ in which quote is escaped and how non-ASCII is handled:
//!
//! | encoder | quote escape | non-ASCII |
//! |---------|-------------|-----------|
//! | `for_rust_string` | `"` → `\"` | passes through |
//! | `for_rust_char` | `'` → `\'` | passes through |
//! | `for_rust_byte_string` | `"` → `\"` | each UTF-8 byte → `\xHH` |

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

// ---------------------------------------------------------------------------
// for_rust_string — safe for Rust string literals ("...")
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a rust string literal (`"..."`).
///
/// escapes backslashes, double quotes, and control characters using rust's
/// escape syntax. non-ASCII unicode passes through unchanged (valid in rust
/// string literals). unicode non-characters are replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_rust_string;
///
/// assert_eq!(for_rust_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_rust_string("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_rust_string("café"), "café");
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
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\') || is_unicode_noncharacter(c as u32)
}

// ---------------------------------------------------------------------------
// for_rust_char — safe for Rust char literals ('...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a rust char literal (`'...'`).
///
/// escapes backslashes, single quotes, and control characters using rust's
/// escape syntax. non-ASCII unicode passes through unchanged. unicode
/// non-characters are replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_rust_char;
///
/// assert_eq!(for_rust_char("it's"), r"it\'s");
/// assert_eq!(for_rust_char(r#"a"b"#), r#"a"b"#);
/// assert_eq!(for_rust_char("tab\there"), r"tab\there");
/// ```
pub fn for_rust_char(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_rust_char(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the rust-char-encoded form of `input` to `out`.
///
/// see [`for_rust_char`] for encoding rules.
pub fn write_rust_char<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_rust_char_encoding, |out, c, _next| {
        write_rust_text_encoded(out, c, '\'')
    })
}

fn needs_rust_char_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '\'' | '\\') || is_unicode_noncharacter(c as u32)
}

// ---------------------------------------------------------------------------
// shared helper for string and char encoders
// ---------------------------------------------------------------------------

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
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

// ---------------------------------------------------------------------------
// for_rust_byte_string — safe for Rust byte string literals (b"...")
// ---------------------------------------------------------------------------

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
    encode_loop(
        out,
        input,
        needs_rust_byte_string_encoding,
        write_rust_byte_string_encoded,
    )
}

fn needs_rust_byte_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\') || !c.is_ascii()
}

fn write_rust_byte_string_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '\0' => out.write_str("\\0"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\r' => out.write_str("\\r"),
        '"' => out.write_str("\\\""),
        '\\' => out.write_str("\\\\"),
        // non-ASCII → encode each UTF-8 byte
        c if !c.is_ascii() => {
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            for b in encoded.as_bytes() {
                write!(out, "\\x{b:02x}")?;
            }
            Ok(())
        }
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
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
    fn char_writer_matches() {
        let input = "test\0'\\\n café";
        let mut w = String::new();
        write_rust_char(&mut w, input).unwrap();
        assert_eq!(for_rust_char(input), w);
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
