//! JSON string encoder.

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
/// | `/` | `\/` |
/// | `<` | `\u003c` |
/// | other C0 controls (U+0000–U+001F) | `\u00HH` |
/// | U+2028 (line separator) | `\u2028` |
/// | U+2029 (paragraph separator) | `\u2029` |
/// | single quotes, `&` | unchanged |
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
    matches!(
        c,
        '\x00'..='\x1F' | '"' | '\\' | '/' | '<' | '\u{2028}' | '\u{2029}'
    )
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
        '/' => out.write_str("\\/"),
        '<' => out.write_str("\\u003c"),
        '\u{2028}' => out.write_str("\\u2028"),
        '\u{2029}' => out.write_str("\\u2029"),
        // other C0 controls → \u00HH (JSON does not support \xHH)
        c => write!(out, "\\u{:04x}", c as u32),
    }
}
