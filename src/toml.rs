//! TOML basic string encoder.
//!
//! encodes untrusted strings for safe embedding in TOML basic string values
//! (`"..."`).
//!
//! - [`for_toml_basic`] — safe for TOML basic string contexts
//!
//! # encoding rules
//!
//! TOML basic strings (delimited by double quotes) support backslash escape
//! sequences. the encoder uses these to handle control characters and
//! delimiters:
//!
//! - named escapes: `\b`, `\t`, `\n`, `\f`, `\r`, `\"`, `\\`
//! - other C0 controls (U+0000–U+001F) → `\uXXXX`
//! - DEL (U+007F) → `\u007F`
//! - unicode non-characters → space
//! - all other characters (including non-ASCII) pass through unchanged
//!
//! # literal strings
//!
//! TOML literal strings (`'...'`) have no escape mechanism — what you see
//! is what you get. since there is no way to encode a single quote or
//! control character inside a literal string, no encoder is provided for
//! that context. if you need literal strings, validate the input yourself
//! (no `'`, no control characters other than tab).

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

/// encodes `input` for safe embedding in a TOML basic string value (`"..."`).
///
/// produces output suitable for embedding between double quotes in a TOML
/// document. the result conforms to [TOML v1.0](https://toml.io/en/v1.0.0).
///
/// # encoding rules
///
/// | input | output |
/// |-------|--------|
/// | `\b` (U+0008) | `\b` |
/// | `\t` (U+0009) | `\t` |
/// | `\n` (U+000A) | `\n` |
/// | `\f` (U+000C) | `\f` |
/// | `\r` (U+000D) | `\r` |
/// | `"` | `\"` |
/// | `\` | `\\` |
/// | other C0 controls (U+0000–U+001F) | `\uXXXX` |
/// | DEL (U+007F) | `\u007F` |
/// | unicode non-characters | space |
/// | single quotes, non-ASCII | unchanged |
///
/// # difference from JSON encoder
///
/// - forward slash (`/`) is **not** escaped (TOML has no `</script>` concern)
/// - U+2028/U+2029 are **not** escaped (TOML is not embedded in HTML)
/// - unicode escapes use uppercase hex (`\u001F` not `\u001f`)
///
/// # examples
///
/// ```
/// use contextual_encoder::for_toml_basic;
///
/// assert_eq!(for_toml_basic(r#"he said "hello""#), r#"he said \"hello\""#);
/// assert_eq!(for_toml_basic("it's fine"), "it's fine");
/// assert_eq!(for_toml_basic("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_toml_basic("path\\to\\file"), r"path\\to\\file");
/// ```
pub fn for_toml_basic(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_toml_basic(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the TOML-basic-string-encoded form of `input` to `out`.
///
/// see [`for_toml_basic`] for encoding rules.
pub fn write_toml_basic<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_toml_basic_encoding,
        write_toml_basic_encoded,
    )
}

fn needs_toml_basic_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F' | '"' | '\\') || is_unicode_noncharacter(c as u32)
}

fn write_toml_basic_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '"' => out.write_str("\\\""),
        '\\' => out.write_str("\\\\"),
        _ if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // other C0 controls and DEL → \uXXXX (uppercase hex per TOML spec)
        c => write!(out, "\\u{:04X}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough() {
        assert_eq!(for_toml_basic("hello world"), "hello world");
        assert_eq!(for_toml_basic(""), "");
        assert_eq!(for_toml_basic("café"), "café");
        assert_eq!(for_toml_basic("日本語"), "日本語");
        assert_eq!(for_toml_basic("😀"), "😀");
    }

    #[test]
    fn single_quotes_not_escaped() {
        assert_eq!(for_toml_basic("it's"), "it's");
        assert_eq!(for_toml_basic("'quoted'"), "'quoted'");
    }

    #[test]
    fn double_quotes_escaped() {
        assert_eq!(for_toml_basic(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_toml_basic(r#""hello""#), r#"\"hello\""#);
    }

    #[test]
    fn backslash() {
        assert_eq!(for_toml_basic(r"a\b"), r"a\\b");
        assert_eq!(for_toml_basic(r"\\"), r"\\\\");
    }

    #[test]
    fn named_escapes() {
        assert_eq!(for_toml_basic("\x08"), "\\b");
        assert_eq!(for_toml_basic("\t"), "\\t");
        assert_eq!(for_toml_basic("\n"), "\\n");
        assert_eq!(for_toml_basic("\x0C"), "\\f");
        assert_eq!(for_toml_basic("\r"), "\\r");
    }

    #[test]
    fn control_chars_use_unicode_escapes() {
        assert_eq!(for_toml_basic("\x00"), "\\u0000");
        assert_eq!(for_toml_basic("\x01"), "\\u0001");
        assert_eq!(for_toml_basic("\x07"), "\\u0007");
        assert_eq!(for_toml_basic("\x0B"), "\\u000B");
        assert_eq!(for_toml_basic("\x0E"), "\\u000E");
        assert_eq!(for_toml_basic("\x1F"), "\\u001F");
    }

    #[test]
    fn del_escaped() {
        assert_eq!(for_toml_basic("\x7F"), "\\u007F");
    }

    #[test]
    fn forward_slash_not_escaped() {
        assert_eq!(for_toml_basic("/"), "/");
        assert_eq!(for_toml_basic("a/b"), "a/b");
    }

    #[test]
    fn line_separators_not_escaped() {
        // unlike JSON, TOML has no reason to escape these
        assert_eq!(for_toml_basic("\u{2028}"), "\u{2028}");
        assert_eq!(for_toml_basic("\u{2029}"), "\u{2029}");
    }

    #[test]
    fn nonchars_replaced() {
        assert_eq!(for_toml_basic("\u{FDD0}"), " ");
        assert_eq!(for_toml_basic("\u{FFFE}"), " ");
        assert_eq!(for_toml_basic("\u{1FFFE}"), " ");
    }

    #[test]
    fn mixed_input() {
        assert_eq!(
            for_toml_basic("name = \"value\"\nnext = true"),
            "name = \\\"value\\\"\\nnext = true"
        );
    }

    #[test]
    fn writer_matches_string() {
        let input = "test\x00\"\\\n\tcafé\u{FDD0}";
        let string_result = for_toml_basic(input);
        let mut writer_result = String::new();
        write_toml_basic(&mut writer_result, input).unwrap();
        assert_eq!(string_result, writer_result);
    }

    // -- key differences from for_json --

    #[test]
    fn differs_from_json_on_forward_slash() {
        assert_eq!(for_toml_basic("/"), "/");
        assert_ne!(for_toml_basic("/"), crate::for_json("/"));
    }

    #[test]
    fn differs_from_json_on_line_separators() {
        assert_eq!(for_toml_basic("\u{2028}"), "\u{2028}");
        assert_ne!(for_toml_basic("\u{2028}"), crate::for_json("\u{2028}"));
    }

    #[test]
    fn differs_from_json_on_hex_case() {
        // TOML uses uppercase hex; JSON uses lowercase
        assert_eq!(for_toml_basic("\x01"), "\\u0001");
        assert_eq!(crate::for_json("\x01"), "\\u0001");
        // difference shows on hex letters
        assert_eq!(for_toml_basic("\x0E"), "\\u000E");
        assert_eq!(crate::for_json("\x0E"), "\\u000e");
    }
}
