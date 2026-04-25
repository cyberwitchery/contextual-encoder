//! ruby literal encoders.
//!
//! encodes untrusted strings for safe embedding in ruby source literals.
//!
//! - [`for_ruby_string`] — safe for ruby double-quoted string literals (`"..."`)
//! - [`for_ruby_single_quoted`] — safe for ruby single-quoted string literals
//!   (`'...'`)
//!
//! # encoding rules
//!
//! ## double-quoted string
//!
//! uses ruby's native escape syntax:
//!
//! - named escapes: `\a`, `\b`, `\t`, `\n`, `\v`, `\f`, `\r`, `\\`
//! - double quote: `"` → `\"`
//! - interpolation: `#` before `{`, `@`, or `$` → `\#` (prevents `#{}`
//!   expression, `#@var` instance-variable, and `#$var` global-variable
//!   interpolation injection)
//! - other C0 controls and DEL → `\xHH`
//! - unicode non-characters → space
//! - non-ASCII unicode passes through (ruby source files are UTF-8)
//!
//! ## single-quoted string
//!
//! single-quoted strings only recognise `\\` and `\'` as escape sequences,
//! so the encoder is minimal:
//!
//! - backslash → `\\`
//! - single quote → `\'`
//! - C0 controls and DEL → space (cannot be escaped in single-quoted context)
//! - unicode non-characters → space

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter, write_c0_named_escape};

// ---------------------------------------------------------------------------
// for_ruby_string — safe for Ruby double-quoted string literals ("...")
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a ruby double-quoted string literal
/// (`"..."`).
///
/// escapes backslashes, double quotes, interpolation delimiters (`#{`, `#@`,
/// `#$`), and control characters using ruby's escape syntax. non-ASCII unicode
/// passes through unchanged (ruby source files are UTF-8 by default). unicode
/// non-characters are replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_ruby_string;
///
/// assert_eq!(for_ruby_string(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_ruby_string("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_ruby_string("café"), "café");
/// assert_eq!(for_ruby_string("#{cmd}"), "\\#{cmd}");
/// ```
pub fn for_ruby_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_ruby_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the ruby-string-encoded form of `input` to `out`.
///
/// see [`for_ruby_string`] for encoding rules.
pub fn write_ruby_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_ruby_string_encoding,
        write_ruby_string_encoded,
    )
}

fn needs_ruby_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\' | '#') || is_unicode_noncharacter(c as u32)
}

fn write_ruby_string_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    next: Option<char>,
) -> fmt::Result {
    if let Some(r) = write_c0_named_escape(out, c) {
        return r;
    }
    match c {
        '"' => out.write_str("\\\""),
        '#' if matches!(next, Some('{') | Some('@') | Some('$')) => out.write_str("\\#"),
        '#' => out.write_char('#'),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

// ---------------------------------------------------------------------------
// for_ruby_single_quoted — safe for Ruby single-quoted string literals ('...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a ruby single-quoted string literal
/// (`'...'`).
///
/// single-quoted ruby strings only recognise `\\` and `\'` as escape
/// sequences. all other characters pass through literally, so control
/// characters and unicode non-characters are replaced with space since
/// they cannot be safely escaped.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_ruby_single_quoted;
///
/// assert_eq!(for_ruby_single_quoted("hello"), "hello");
/// assert_eq!(for_ruby_single_quoted("it's"), r"it\'s");
/// assert_eq!(for_ruby_single_quoted(r"back\slash"), r"back\\slash");
/// assert_eq!(for_ruby_single_quoted("café"), "café");
/// ```
pub fn for_ruby_single_quoted(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_ruby_single_quoted(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the ruby-single-quoted-encoded form of `input` to `out`.
///
/// see [`for_ruby_single_quoted`] for encoding rules.
pub fn write_ruby_single_quoted<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_ruby_single_quoted_encoding,
        |out, c, _next| write_ruby_single_quoted_encoded(out, c),
    )
}

fn needs_ruby_single_quoted_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '\'' | '\\') || is_unicode_noncharacter(c as u32)
}

fn write_ruby_single_quoted_encoded<W: fmt::Write>(out: &mut W, c: char) -> fmt::Result {
    match c {
        '\\' => out.write_str("\\\\"),
        '\'' => out.write_str("\\'"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // C0 controls and DEL → space (cannot be escaped in single-quoted strings)
        _ => out.write_char(' '),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_ruby_string --

    #[test]
    fn string_passthrough() {
        assert_eq!(for_ruby_string("hello world"), "hello world");
        assert_eq!(for_ruby_string(""), "");
        assert_eq!(
            for_ruby_string("cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"),
            "cafe\u{0301} \u{65E5}\u{672C}\u{8A9E}"
        );
        assert_eq!(for_ruby_string("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn string_escapes_double_quote() {
        assert_eq!(for_ruby_string(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn string_passes_single_quote() {
        assert_eq!(for_ruby_string("a'b"), "a'b");
    }

    #[test]
    fn string_escapes_backslash() {
        assert_eq!(for_ruby_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_escapes_interpolation_brace() {
        assert_eq!(for_ruby_string("#{cmd}"), "\\#{cmd}");
        assert_eq!(for_ruby_string("hello #{name}!"), "hello \\#{name}!");
        assert_eq!(for_ruby_string("#{a} and #{b}"), "\\#{a} and \\#{b}");
    }

    #[test]
    fn string_escapes_interpolation_ivar() {
        assert_eq!(for_ruby_string("#@name"), "\\#@name");
    }

    #[test]
    fn string_escapes_interpolation_gvar() {
        assert_eq!(for_ruby_string("#$LOAD_PATH"), "\\#$LOAD_PATH");
    }

    #[test]
    fn string_hash_without_interpolation_passes_through() {
        assert_eq!(for_ruby_string("#tag"), "#tag");
        assert_eq!(for_ruby_string("a # comment"), "a # comment");
        assert_eq!(for_ruby_string("#"), "#");
        assert_eq!(for_ruby_string("#!"), "#!");
        assert_eq!(for_ruby_string("##"), "##");
    }

    #[test]
    fn string_named_escapes() {
        assert_eq!(for_ruby_string("\x07"), "\\a");
        assert_eq!(for_ruby_string("\x08"), "\\b");
        assert_eq!(for_ruby_string("\t"), "\\t");
        assert_eq!(for_ruby_string("\n"), "\\n");
        assert_eq!(for_ruby_string("\x0B"), "\\v");
        assert_eq!(for_ruby_string("\x0C"), "\\f");
        assert_eq!(for_ruby_string("\r"), "\\r");
    }

    #[test]
    fn string_hex_escapes_for_controls() {
        assert_eq!(for_ruby_string("\x00"), "\\x00");
        assert_eq!(for_ruby_string("\x01"), "\\x01");
        assert_eq!(for_ruby_string("\x06"), "\\x06");
        assert_eq!(for_ruby_string("\x0E"), "\\x0e");
        assert_eq!(for_ruby_string("\x1F"), "\\x1f");
        assert_eq!(for_ruby_string("\x7F"), "\\x7f");
    }

    #[test]
    fn string_nonchars_replaced() {
        assert_eq!(for_ruby_string("\u{FDD0}"), " ");
        assert_eq!(for_ruby_string("\u{FFFE}"), " ");
    }

    #[test]
    fn string_writer_matches() {
        let input = "test\x00\"\\\n#{cmd} cafe\u{0301}";
        let mut w = String::new();
        write_ruby_string(&mut w, input).unwrap();
        assert_eq!(for_ruby_string(input), w);
    }

    // -- for_ruby_single_quoted --

    #[test]
    fn single_passthrough() {
        assert_eq!(for_ruby_single_quoted("hello world"), "hello world");
        assert_eq!(for_ruby_single_quoted(""), "");
    }

    #[test]
    fn single_escapes_single_quote() {
        assert_eq!(for_ruby_single_quoted("a'b"), r"a\'b");
    }

    #[test]
    fn single_passes_double_quote() {
        assert_eq!(for_ruby_single_quoted(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn single_escapes_backslash() {
        assert_eq!(for_ruby_single_quoted(r"a\b"), r"a\\b");
    }

    #[test]
    fn single_hash_brace_passes_through() {
        // single-quoted strings do not interpolate — safe to pass through
        assert_eq!(for_ruby_single_quoted("#{cmd}"), "#{cmd}");
    }

    #[test]
    fn single_controls_replaced_with_space() {
        assert_eq!(for_ruby_single_quoted("\x00"), " ");
        assert_eq!(for_ruby_single_quoted("\x01"), " ");
        assert_eq!(for_ruby_single_quoted("\t"), " ");
        assert_eq!(for_ruby_single_quoted("\n"), " ");
        assert_eq!(for_ruby_single_quoted("\x7F"), " ");
    }

    #[test]
    fn single_nonchars_replaced() {
        assert_eq!(for_ruby_single_quoted("\u{FDD0}"), " ");
        assert_eq!(for_ruby_single_quoted("\u{FFFE}"), " ");
    }

    #[test]
    fn single_non_ascii_passes_through() {
        assert_eq!(for_ruby_single_quoted("café"), "café");
        assert_eq!(for_ruby_single_quoted("日本語"), "日本語");
        assert_eq!(for_ruby_single_quoted("😀"), "😀");
    }

    #[test]
    fn single_writer_matches() {
        let input = "test\x00'\\hello";
        let mut w = String::new();
        write_ruby_single_quoted(&mut w, input).unwrap();
        assert_eq!(for_ruby_single_quoted(input), w);
    }
}
