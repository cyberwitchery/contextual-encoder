//! ruby literal encoder.
//!
//! encodes untrusted strings for safe embedding in ruby source literals.
//!
//! - [`for_ruby_string`] — safe for ruby double-quoted string literals (`"..."`)
//!
//! # encoding rules
//!
//! the encoder uses ruby's native escape syntax:
//!
//! - named escapes: `\a`, `\b`, `\t`, `\n`, `\v`, `\f`, `\r`, `\e`, `\\`
//! - double quote → `\"`
//! - hash sign → `\#` (prevents `#{}`, `#$`, `#@` interpolation)
//! - other C0 controls and DEL → `\xHH`
//! - unicode non-characters → space
//! - non-ASCII unicode passes through (ruby 2.0+ source files are UTF-8
//!   by default)
//!
//! the output is safe for double-quoted string literals only. ruby
//! single-quoted strings (`'...'`) use different escape rules and are
//! not covered by this encoder.

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter, write_c0_named_escape};

// ---------------------------------------------------------------------------
// for_ruby_string — safe for Ruby double-quoted string literals ("...")
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a ruby double-quoted string literal
/// (`"..."`).
///
/// escapes backslashes, double quotes, hash signs (to prevent interpolation),
/// and control characters using ruby's escape syntax. non-ASCII unicode passes
/// through unchanged (ruby 2.0+ source files are UTF-8 by default). unicode
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
/// assert_eq!(for_ruby_string("hello #{name}"), r"hello \#{name}");
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
    encode_loop(out, input, needs_ruby_string_encoding, |out, c, _next| {
        write_ruby_text_encoded(out, c)
    })
}

fn needs_ruby_string_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '#' | '\\') || is_unicode_noncharacter(c as u32)
}

/// writes the encoded form of a character for ruby string context.
fn write_ruby_text_encoded<W: fmt::Write>(out: &mut W, c: char) -> fmt::Result {
    if let Some(r) = write_c0_named_escape(out, c) {
        return r;
    }
    match c {
        '\x1B' => out.write_str("\\e"),
        '"' => out.write_str("\\\""),
        '#' => out.write_str("\\#"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // other C0 controls and DEL
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn string_escapes_hash() {
        assert_eq!(for_ruby_string("hello #{name}"), r"hello \#{name}");
        assert_eq!(for_ruby_string("#$global"), r"\#$global");
        assert_eq!(for_ruby_string("#@ivar"), r"\#@ivar");
        assert_eq!(for_ruby_string("color #ff0000"), r"color \#ff0000");
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
        assert_eq!(for_ruby_string("\x1B"), "\\e");
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
        let input = "test\x00\"\\\n#{}café\x1B";
        let mut w = String::new();
        write_ruby_string(&mut w, input).unwrap();
        assert_eq!(for_ruby_string(input), w);
    }
}
