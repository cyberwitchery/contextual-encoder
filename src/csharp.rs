//! C# string literal encoder.
//!
//! encodes untrusted strings for safe embedding in C# string literals.
//!
//! - [`for_csharp`] — safe for C# string and char literal contexts
//!
//! # encoding rules
//!
//! - named escapes: `\0`, `\a`, `\b`, `\t`, `\n`, `\v`, `\f`, `\r`, `\\`
//! - `"` → `\"`
//! - other C0 controls and DEL → `\u00HH` (4-digit unicode escape, not
//!   `\xHH` which is variable-length in C# and can consume following hex
//!   digits)
//! - U+0085 (NEL), U+2028 (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR)
//!   → `\u0085`, `\u2028`, `\u2029` (C# line terminators)
//! - supplementary plane characters (U+10000+) → `\UHHHHHHHH` (8-digit
//!   unicode escape)
//! - unicode non-characters → space

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

/// encodes `input` for safe embedding in a C# string literal.
///
/// produces output suitable for embedding between double quotes in C#
/// source code.
///
/// # encoding rules
///
/// | input | output |
/// |-------|--------|
/// | NUL | `\0` |
/// | BEL, BS, TAB, LF, VT, FF, CR | named escape (`\a`, `\b`, etc.) |
/// | `"`, `\` | `\"`, `\\` |
/// | other C0 controls, DEL | `\u00HH` |
/// | U+0085 (NEL), U+2028, U+2029 | `\uHHHH` (line terminators) |
/// | supplementary plane (U+10000+) | `\UHHHHHHHH` |
/// | unicode non-characters | space |
///
/// uses `\u00HH` rather than `\xHH` for control characters because C#'s
/// `\x` escape is variable-length (1-4 hex digits) and will greedily
/// consume following hex digits, producing incorrect results.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_csharp;
///
/// assert_eq!(for_csharp(r#"he said "hello""#), r#"he said \"hello\""#);
/// assert_eq!(for_csharp("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_csharp("null\x00byte"), r"null\0byte");
/// assert_eq!(for_csharp("tab\there"), r"tab\there");
/// ```
pub fn for_csharp(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_csharp(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the C#-encoded form of `input` to `out`.
///
/// see [`for_csharp`] for encoding rules.
pub fn write_csharp<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_csharp_encoding, write_csharp_encoded)
}

fn needs_csharp_encoding(c: char) -> bool {
    match c {
        '\x00'..='\x1F' | '\x7F' | '"' | '\\' => true,
        // C# line terminators that break string literals
        '\u{0085}' | '\u{2028}' | '\u{2029}' => true,
        c if (c as u32) >= 0x10000 => true,
        c if is_unicode_noncharacter(c as u32) => true,
        _ => false,
    }
}

fn write_csharp_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
    match c {
        '\0' => out.write_str("\\0"),
        '\x07' => out.write_str("\\a"),
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\v"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '"' => out.write_str("\\\""),
        '\\' => out.write_str("\\\\"),
        // C# line terminators
        '\u{0085}' => out.write_str("\\u0085"),
        '\u{2028}' => out.write_str("\\u2028"),
        '\u{2029}' => out.write_str("\\u2029"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // supplementary plane → \UHHHHHHHH
        c if (c as u32) >= 0x10000 => {
            write!(out, "\\U{:08x}", c as u32)
        }
        // other C0 controls and DEL → \u00HH (safe from greedy \x parsing)
        c => write!(out, "\\u{:04x}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough() {
        assert_eq!(for_csharp("hello world"), "hello world");
        assert_eq!(for_csharp(""), "");
        assert_eq!(for_csharp("café"), "café");
    }

    #[test]
    fn named_escapes() {
        assert_eq!(for_csharp("\0"), "\\0");
        assert_eq!(for_csharp("\x07"), "\\a");
        assert_eq!(for_csharp("\x08"), "\\b");
        assert_eq!(for_csharp("\t"), "\\t");
        assert_eq!(for_csharp("\n"), "\\n");
        assert_eq!(for_csharp("\x0B"), "\\v");
        assert_eq!(for_csharp("\x0C"), "\\f");
        assert_eq!(for_csharp("\r"), "\\r");
    }

    #[test]
    fn quotes_and_backslash() {
        assert_eq!(for_csharp(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_csharp(r"a\b"), r"a\\b");
    }

    #[test]
    fn unicode_escape_for_controls() {
        // C0 controls without named escapes use \u00HH
        assert_eq!(for_csharp("\x01"), "\\u0001");
        assert_eq!(for_csharp("\x02"), "\\u0002");
        assert_eq!(for_csharp("\x06"), "\\u0006");
        assert_eq!(for_csharp("\x0E"), "\\u000e");
        assert_eq!(for_csharp("\x1F"), "\\u001f");
        // DEL
        assert_eq!(for_csharp("\x7F"), "\\u007f");
    }

    #[test]
    fn supplementary_plane() {
        // U+1F600 GRINNING FACE
        assert_eq!(for_csharp("\u{1F600}"), "\\U0001f600");
        // U+10000
        assert_eq!(for_csharp("\u{10000}"), "\\U00010000");
        // U+10FFFD
        assert_eq!(for_csharp("\u{10FFFD}"), "\\U0010fffd");
    }

    #[test]
    fn noncharacters_replaced_with_space() {
        assert_eq!(for_csharp("\u{FDD0}"), " ");
        assert_eq!(for_csharp("\u{FFFE}"), " ");
    }

    #[test]
    fn line_terminators_escaped() {
        // U+0085 NEL
        assert_eq!(for_csharp("\u{0085}"), "\\u0085");
        // U+2028 LINE SEPARATOR
        assert_eq!(for_csharp("\u{2028}"), "\\u2028");
        // U+2029 PARAGRAPH SEPARATOR
        assert_eq!(for_csharp("\u{2029}"), "\\u2029");
        // embedded in text
        assert_eq!(for_csharp("a\u{2028}b"), "a\\u2028b");
    }

    #[test]
    fn single_quote_passes_through() {
        // C# string literals use double quotes; single quotes are not special
        assert_eq!(for_csharp("it's"), "it's");
    }

    #[test]
    fn multibyte_utf8_passthrough() {
        assert_eq!(for_csharp("café"), "café");
        assert_eq!(for_csharp("世界"), "世界");
    }

    #[test]
    fn mixed_input() {
        assert_eq!(
            for_csharp("he said \"hello\"\nnew line"),
            "he said \\\"hello\\\"\\nnew line"
        );
    }

    #[test]
    fn writer_matches_string() {
        let input = "test\x00\"\\\u{1F600}";
        let string_result = for_csharp(input);
        let mut writer_result = String::new();
        write_csharp(&mut writer_result, input).unwrap();
        assert_eq!(string_result, writer_result);
    }
}
