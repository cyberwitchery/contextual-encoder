//! php literal encoders.
//!
//! encodes untrusted strings for safe embedding in php source literals.
//!
//! - [`for_php_string`] — safe for php double-quoted string literals (`"..."`)
//! - [`for_php_single_string`] — safe for php single-quoted string literals
//!   (`'...'`)
//!
//! # encoding rules
//!
//! ## double-quoted strings
//!
//! uses php's native escape syntax:
//!
//! - named escapes: `\t`, `\n`, `\v`, `\e`, `\f`, `\r`, `\\`, `\"`, `\$`
//! - other C0 controls and DEL → `\xHH`
//! - unicode non-characters → space
//! - non-ASCII unicode passes through (php source files are typically UTF-8)
//!
//! the `$` sign is escaped to prevent variable interpolation. this also
//! prevents `{$...}` and `${...}` interpolation since both forms require
//! an unescaped `$`.
//!
//! ## single-quoted strings
//!
//! php single-quoted strings only recognise `\\` and `\'` as escape
//! sequences. there is no mechanism to hex-encode characters, so
//! dangerous characters are replaced:
//!
//! - `\` → `\\`, `'` → `\'`
//! - C0 controls and DEL → space
//! - unicode non-characters → space

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

// ---------------------------------------------------------------------------
// for_php_string — safe for PHP double-quoted string literals ("...")
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a php double-quoted string literal
/// (`"..."`).
///
/// escapes backslashes, double quotes, dollar signs, and control characters
/// using php's escape syntax. non-ASCII unicode passes through unchanged
/// (php source files are typically UTF-8). unicode non-characters are
/// replaced with space.
///
/// the `$` sign is escaped to `\$` to prevent variable interpolation,
/// including `{$var}` and `${var}` forms.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_php_string;
///
/// assert_eq!(for_php_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_php_string("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_php_string("$price"), r"\$price");
/// assert_eq!(for_php_string("café"), "café");
/// ```
pub fn for_php_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_php_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the php-double-quoted-string-encoded form of `input` to `out`.
///
/// see [`for_php_string`] for encoding rules.
pub fn write_php_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_php_string_encoding, |out, c, _next| {
        write_php_string_encoded(out, c)
    })
}

fn needs_php_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\' | '$') || is_unicode_noncharacter(c as u32)
}

/// writes the encoded form of a character for php double-quoted string context.
fn write_php_string_encoded<W: fmt::Write>(out: &mut W, c: char) -> fmt::Result {
    match c {
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\v"),
        '\x1B' => out.write_str("\\e"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '\\' => out.write_str("\\\\"),
        '"' => out.write_str("\\\""),
        '$' => out.write_str("\\$"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02X}", c as u32),
    }
}

// ---------------------------------------------------------------------------
// for_php_single_string — safe for PHP single-quoted string literals ('...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a php single-quoted string literal
/// (`'...'`).
///
/// php single-quoted strings only recognise `\\` and `\'` as escape
/// sequences. backslashes and single quotes are escaped; control characters
/// and unicode non-characters are replaced with space since there is no
/// hex escape mechanism.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_php_single_string;
///
/// assert_eq!(for_php_single_string("hello"), "hello");
/// assert_eq!(for_php_single_string("it's"), r"it\'s");
/// assert_eq!(for_php_single_string(r"path\to"), r"path\\to");
/// assert_eq!(for_php_single_string("line\nbreak"), "line break");
/// ```
pub fn for_php_single_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_php_single_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the php-single-quoted-string-encoded form of `input` to `out`.
///
/// see [`for_php_single_string`] for encoding rules.
pub fn write_php_single_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_php_single_string_encoding,
        |out, c, _next| write_php_single_string_encoded(out, c),
    )
}

fn needs_php_single_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '\'' | '\\') || is_unicode_noncharacter(c as u32)
}

fn write_php_single_string_encoded<W: fmt::Write>(out: &mut W, c: char) -> fmt::Result {
    match c {
        '\\' => out.write_str("\\\\"),
        '\'' => out.write_str("\\'"),
        // controls, DEL, and non-characters → space (no hex escapes available)
        _ => out.write_char(' '),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_php_string --

    #[test]
    fn string_passthrough() {
        assert_eq!(for_php_string("hello world"), "hello world");
        assert_eq!(for_php_string(""), "");
        assert_eq!(
            for_php_string("cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"),
            "cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"
        );
        assert_eq!(for_php_string("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn string_escapes_double_quote() {
        assert_eq!(for_php_string(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn string_passes_single_quote() {
        assert_eq!(for_php_string("a'b"), "a'b");
    }

    #[test]
    fn string_escapes_backslash() {
        assert_eq!(for_php_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_escapes_dollar() {
        assert_eq!(for_php_string("$var"), r"\$var");
        assert_eq!(for_php_string("${var}"), r"\${var}");
        assert_eq!(for_php_string("{$var}"), r"{\$var}");
        assert_eq!(for_php_string("price: $10"), r"price: \$10");
    }

    #[test]
    fn string_named_escapes() {
        assert_eq!(for_php_string("\t"), "\\t");
        assert_eq!(for_php_string("\n"), "\\n");
        assert_eq!(for_php_string("\x0B"), "\\v");
        assert_eq!(for_php_string("\x1B"), "\\e");
        assert_eq!(for_php_string("\x0C"), "\\f");
        assert_eq!(for_php_string("\r"), "\\r");
    }

    #[test]
    fn string_hex_escapes_for_controls() {
        assert_eq!(for_php_string("\x00"), "\\x00");
        assert_eq!(for_php_string("\x01"), "\\x01");
        assert_eq!(for_php_string("\x06"), "\\x06");
        assert_eq!(for_php_string("\x07"), "\\x07");
        assert_eq!(for_php_string("\x08"), "\\x08");
        assert_eq!(for_php_string("\x0E"), "\\x0E");
        assert_eq!(for_php_string("\x1F"), "\\x1F");
        assert_eq!(for_php_string("\x7F"), "\\x7F");
    }

    #[test]
    fn string_nonchars_replaced() {
        assert_eq!(for_php_string("\u{FDD0}"), " ");
        assert_eq!(for_php_string("\u{FFFE}"), " ");
    }

    #[test]
    fn string_writer_matches() {
        let input = "test\x00\"\\\n $var cafe\u{0301}";
        let mut w = String::new();
        write_php_string(&mut w, input).unwrap();
        assert_eq!(for_php_string(input), w);
    }

    // -- for_php_single_string --

    #[test]
    fn single_passthrough() {
        assert_eq!(for_php_single_string("hello world"), "hello world");
        assert_eq!(for_php_single_string(""), "");
        assert_eq!(for_php_single_string("cafe\u{0301}"), "cafe\u{0301}");
        assert_eq!(for_php_single_string("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn single_escapes_single_quote() {
        assert_eq!(for_php_single_string("a'b"), r"a\'b");
    }

    #[test]
    fn single_passes_double_quote() {
        assert_eq!(for_php_single_string(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn single_escapes_backslash() {
        assert_eq!(for_php_single_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn single_passes_dollar() {
        assert_eq!(for_php_single_string("$var"), "$var");
    }

    #[test]
    fn single_controls_replaced() {
        assert_eq!(for_php_single_string("\x00"), " ");
        assert_eq!(for_php_single_string("\x01"), " ");
        assert_eq!(for_php_single_string("\t"), " ");
        assert_eq!(for_php_single_string("\n"), " ");
        assert_eq!(for_php_single_string("\r"), " ");
        assert_eq!(for_php_single_string("\x0B"), " ");
        assert_eq!(for_php_single_string("\x1B"), " ");
        assert_eq!(for_php_single_string("\x7F"), " ");
    }

    #[test]
    fn single_nonchars_replaced() {
        assert_eq!(for_php_single_string("\u{FDD0}"), " ");
        assert_eq!(for_php_single_string("\u{FFFE}"), " ");
    }

    #[test]
    fn single_non_ascii_passes_through() {
        assert_eq!(for_php_single_string("café"), "café");
        assert_eq!(for_php_single_string("日本語"), "日本語");
        assert_eq!(for_php_single_string("😀"), "😀");
    }

    #[test]
    fn single_writer_matches() {
        let input = "test\x00'\\$var cafe\u{0301}";
        let mut w = String::new();
        write_php_single_string(&mut w, input).unwrap();
        assert_eq!(for_php_single_string(input), w);
    }
}
