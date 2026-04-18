//! JSON string encoder.
//!
//! encodes untrusted strings for safe embedding in JSON string values.
//!
//! - [`for_json`] — safe for JSON string contexts
//!
//! # why not `for_javascript_source`?
//!
//! JSON looks like JavaScript but has two critical encoding differences:
//!
//! - **no `\x` escapes.** JSON only supports `\uHHHH` for unicode escapes.
//!   the `\xHH` form that JavaScript uses for control characters is invalid JSON.
//! - **no single-quote escaping.** `\'` is not a valid JSON escape sequence.
//!   single quotes are ordinary characters in JSON strings.
//!
//! using `for_javascript_source` for JSON output produces strings that may be
//! rejected by strict JSON parsers.
//!
//! # encoding rules
//!
//! - named escapes: `\b`, `\t`, `\n`, `\f`, `\r`, `\"`, `\\`
//! - other C0 controls (U+0000–U+001F) → `\u00HH`
//! - U+2028 → `\u2028`, U+2029 → `\u2029` (line/paragraph separators;
//!   mandatory because JSON is often embedded in `<script>` blocks where
//!   these would terminate the JavaScript string literal)
//! - all other characters pass through unchanged

use std::fmt;

use crate::engine::encode_loop;

/// encodes `input` for safe embedding in a JSON string value.
///
/// produces output suitable for embedding between double quotes in a JSON
/// document. the result conforms to [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)
/// and additionally escapes U+2028/U+2029 for safe embedding in HTML
/// `<script>` blocks.
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
/// | other C0 controls (U+0000–U+001F) | `\u00HH` |
/// | U+2028 (line separator) | `\u2028` |
/// | U+2029 (paragraph separator) | `\u2029` |
/// | single quotes, `/`, `&` | unchanged |
///
/// # difference from JavaScript encoders
///
/// - single quotes are **not** escaped (JSON has no `\'` escape sequence)
/// - control characters use `\u00HH` (JSON has no `\xHH` escape sequence)
///
/// # examples
///
/// ```
/// use contextual_encoder::for_json;
///
/// assert_eq!(for_json(r#"he said "hello""#), r#"he said \"hello\""#);
/// assert_eq!(for_json("it's fine"), "it's fine");
/// assert_eq!(for_json("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_json("\u{2028}"), r"\u2028");
/// ```
pub fn for_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_json(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the JSON-encoded form of `input` to `out`.
///
/// see [`for_json`] for encoding rules.
pub fn write_json<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_json_encoding, write_json_encoded)
}

fn needs_json_encoding(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '"' | '\\' | '\u{2028}' | '\u{2029}')
}

fn write_json_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
    match c {
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '"' => out.write_str("\\\""),
        '\\' => out.write_str("\\\\"),
        '\u{2028}' => out.write_str("\\u2028"),
        '\u{2029}' => out.write_str("\\u2029"),
        // other C0 controls → \u00HH (JSON does not support \xHH)
        c => write!(out, "\\u{:04x}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough() {
        assert_eq!(for_json("hello world"), "hello world");
        assert_eq!(for_json(""), "");
        assert_eq!(for_json("café"), "café");
        assert_eq!(for_json("日本語"), "日本語");
        assert_eq!(for_json("😀"), "😀");
    }

    #[test]
    fn single_quotes_not_escaped() {
        assert_eq!(for_json("it's"), "it's");
        assert_eq!(for_json("'quoted'"), "'quoted'");
    }

    #[test]
    fn double_quotes_escaped() {
        assert_eq!(for_json(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_json(r#""hello""#), r#"\"hello\""#);
    }

    #[test]
    fn backslash() {
        assert_eq!(for_json(r"a\b"), r"a\\b");
        assert_eq!(for_json(r"\\"), r"\\\\");
    }

    #[test]
    fn named_escapes() {
        assert_eq!(for_json("\x08"), "\\b");
        assert_eq!(for_json("\t"), "\\t");
        assert_eq!(for_json("\n"), "\\n");
        assert_eq!(for_json("\x0C"), "\\f");
        assert_eq!(for_json("\r"), "\\r");
    }

    #[test]
    fn control_chars_use_unicode_escapes() {
        // JSON requires \u00HH, not \xHH
        assert_eq!(for_json("\x00"), "\\u0000");
        assert_eq!(for_json("\x01"), "\\u0001");
        assert_eq!(for_json("\x07"), "\\u0007");
        assert_eq!(for_json("\x0B"), "\\u000b");
        assert_eq!(for_json("\x0E"), "\\u000e");
        assert_eq!(for_json("\x1F"), "\\u001f");
    }

    #[test]
    fn line_separators() {
        assert_eq!(for_json("\u{2028}"), "\\u2028");
        assert_eq!(for_json("\u{2029}"), "\\u2029");
        assert_eq!(for_json("a\u{2028}b\u{2029}c"), "a\\u2028b\\u2029c");
    }

    #[test]
    fn slash_and_ampersand_not_escaped() {
        assert_eq!(for_json("a/b"), "a/b");
        assert_eq!(for_json("a&b"), "a&b");
    }

    #[test]
    fn mixed_input() {
        assert_eq!(
            for_json("he said \"hello\"\nnew line"),
            "he said \\\"hello\\\"\\nnew line"
        );
    }

    #[test]
    fn writer_matches_string() {
        let input = "test\x00\"\\\n\u{2028}café";
        let string_result = for_json(input);
        let mut writer_result = String::new();
        write_json(&mut writer_result, input).unwrap();
        assert_eq!(string_result, writer_result);
    }

    // -- key differences from for_javascript_source --

    #[test]
    fn differs_from_js_source_on_single_quotes() {
        // JS source escapes single quotes; JSON does not
        assert_eq!(for_json("a'b"), "a'b");
        assert_ne!(for_json("a'b"), crate::for_javascript_source("a'b"));
    }

    #[test]
    fn differs_from_js_source_on_control_format() {
        // JS source uses \xHH; JSON uses \u00HH
        assert_eq!(for_json("\x01"), "\\u0001");
        assert_eq!(crate::for_javascript_source("\x01"), "\\x01");
    }
}
