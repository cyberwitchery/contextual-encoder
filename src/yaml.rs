//! YAML string encoder.
//!
//! encodes untrusted strings for safe embedding in YAML double-quoted scalar
//! values (`"..."`).
//!
//! - [`for_yaml`] — safe for YAML double-quoted string contexts
//!
//! # why double-quoting is mandatory
//!
//! YAML interprets unquoted (plain) scalars as typed values:
//!
//! - `true`, `false`, `yes`, `no`, `on`, `off` → boolean
//! - `null`, `~` → null
//! - `123`, `0x1a`, `1.5`, `.inf`, `.nan` → numeric
//! - `2024-01-01` → date
//!
//! double-quoting prevents all type coercion and neutralizes special characters
//! (`:`, `#`, `{`, `[`, `&`, `*`, etc.) that can cause injection in plain or
//! flow scalar contexts.
//!
//! the output of this encoder **must** be placed inside double quotes:
//!
//! ```yaml
//! key: "<encoded value here>"
//! ```
//!
//! # encoding rules
//!
//! | input | output |
//! |-------|--------|
//! | `\` | `\\` |
//! | `"` | `\"` |
//! | NUL (U+0000) | `\0` |
//! | BEL (U+0007) | `\a` |
//! | BS (U+0008) | `\b` |
//! | TAB (U+0009) | `\t` |
//! | LF (U+000A) | `\n` |
//! | VT (U+000B) | `\v` |
//! | FF (U+000C) | `\f` |
//! | CR (U+000D) | `\r` |
//! | ESC (U+001B) | `\e` |
//! | other C0 controls | `\xHH` |
//! | DEL (U+007F) | `\x7f` |
//! | NEL (U+0085) | `\N` |
//! | other C1 controls (U+0080–U+009F) | `\xHH` |
//! | NBSP (U+00A0) | `\_` |
//! | LS (U+2028) | `\L` |
//! | PS (U+2029) | `\P` |
//! | all other characters | unchanged |
//!
//! # security notes
//!
//! - **always wrap the output in double quotes.** without quotes, YAML will
//!   attempt type coercion on the value.
//! - **do not use this for YAML keys** that contain arbitrary input — validate
//!   key names separately.
//! - the encoder does not produce the surrounding quotes; the caller must
//!   supply them.

use std::fmt;

use crate::engine::encode_loop;

/// encodes `input` for safe embedding in a YAML double-quoted scalar value
/// (`"..."`).
///
/// escapes backslashes, double quotes, control characters, and unicode
/// characters with special YAML semantics (NEL, NBSP, LS, PS). combined
/// with mandatory double-quoting by the caller, this prevents type coercion
/// and injection of YAML structure characters.
///
/// # encoding rules
///
/// | input | output |
/// |-------|--------|
/// | `\` | `\\` |
/// | `"` | `\"` |
/// | NUL (U+0000) | `\0` |
/// | BEL (U+0007) | `\a` |
/// | BS (U+0008) | `\b` |
/// | TAB (U+0009) | `\t` |
/// | LF (U+000A) | `\n` |
/// | VT (U+000B) | `\v` |
/// | FF (U+000C) | `\f` |
/// | CR (U+000D) | `\r` |
/// | ESC (U+001B) | `\e` |
/// | other C0 controls (U+0001–U+001F) | `\xHH` |
/// | DEL (U+007F) | `\x7f` |
/// | NEL (U+0085) | `\N` |
/// | other C1 controls (U+0080–U+009F) | `\xHH` |
/// | NBSP (U+00A0) | `\_` |
/// | LS (U+2028) | `\L` |
/// | PS (U+2029) | `\P` |
///
/// # examples
///
/// ```
/// use contextual_encoder::for_yaml;
///
/// // type coercion is prevented by quoting — the encoder handles the content
/// assert_eq!(for_yaml("true"), "true");
/// assert_eq!(for_yaml("null"), "null");
/// assert_eq!(for_yaml("123"), "123");
///
/// // special characters inside double quotes are safe
/// assert_eq!(for_yaml("key: value"), "key: value");
/// assert_eq!(for_yaml("a # comment"), "a # comment");
///
/// // actual double-quote/backslash escaping
/// assert_eq!(for_yaml(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_yaml("back\\slash"), "back\\\\slash");
///
/// // control characters use YAML escape sequences
/// assert_eq!(for_yaml("line\nbreak"), "line\\nbreak");
/// assert_eq!(for_yaml("\t"), "\\t");
/// ```
pub fn for_yaml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_yaml(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the YAML-double-quoted-encoded form of `input` to `out`.
///
/// see [`for_yaml`] for encoding rules.
pub fn write_yaml<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_yaml_encoding, write_yaml_encoded)
}

fn needs_yaml_encoding(c: char) -> bool {
    matches!(
        c,
        '\x00'..='\x1F'
            | '\x7F'
            | '\u{0080}'..='\u{009F}'
            | '\u{00A0}'
            | '\u{2028}'
            | '\u{2029}'
            | '"'
            | '\\'
    )
}

fn write_yaml_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
    match c {
        // YAML named escapes for common C0 controls
        '\x00' => out.write_str("\\0"),
        '\x07' => out.write_str("\\a"),
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\v"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '\x1B' => out.write_str("\\e"),
        // structural characters
        '\\' => out.write_str("\\\\"),
        '"' => out.write_str("\\\""),
        // DEL
        '\x7F' => out.write_str("\\x7f"),
        // YAML-specific named escapes for problematic unicode
        '\u{0085}' => out.write_str("\\N"),
        '\u{00A0}' => out.write_str("\\_"),
        '\u{2028}' => out.write_str("\\L"),
        '\u{2029}' => out.write_str("\\P"),
        // remaining C0 and C1 controls → \xHH
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough() {
        assert_eq!(for_yaml("hello world"), "hello world");
        assert_eq!(for_yaml(""), "");
        assert_eq!(for_yaml("café"), "café");
        assert_eq!(for_yaml("日本語"), "日本語");
        assert_eq!(for_yaml("😀"), "😀");
    }

    #[test]
    fn safe_yaml_values_pass_through() {
        // these would cause type coercion in plain scalars, but are safe
        // inside double quotes — the encoder doesn't need to modify them
        assert_eq!(for_yaml("true"), "true");
        assert_eq!(for_yaml("false"), "false");
        assert_eq!(for_yaml("yes"), "yes");
        assert_eq!(for_yaml("no"), "no");
        assert_eq!(for_yaml("null"), "null");
        assert_eq!(for_yaml("~"), "~");
        assert_eq!(for_yaml("123"), "123");
        assert_eq!(for_yaml("1.5"), "1.5");
        assert_eq!(for_yaml("0x1a"), "0x1a");
        assert_eq!(for_yaml(".inf"), ".inf");
        assert_eq!(for_yaml(".nan"), ".nan");
        assert_eq!(for_yaml("2024-01-01"), "2024-01-01");
    }

    #[test]
    fn special_yaml_chars_pass_through_in_double_quotes() {
        // these are only special in plain/flow scalars
        assert_eq!(for_yaml("key: value"), "key: value");
        assert_eq!(for_yaml("a # comment"), "a # comment");
        assert_eq!(for_yaml("{flow}"), "{flow}");
        assert_eq!(for_yaml("[sequence]"), "[sequence]");
        assert_eq!(for_yaml("&anchor"), "&anchor");
        assert_eq!(for_yaml("*alias"), "*alias");
        assert_eq!(for_yaml("!tag"), "!tag");
        assert_eq!(for_yaml("a, b, c"), "a, b, c");
        assert_eq!(for_yaml("- item"), "- item");
        assert_eq!(for_yaml("?"), "?");
        assert_eq!(for_yaml("|"), "|");
        assert_eq!(for_yaml(">"), ">");
    }

    #[test]
    fn double_quotes_escaped() {
        assert_eq!(for_yaml(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(for_yaml(r#"""#), r#"\""#);
        assert_eq!(for_yaml(r#"a"b"c"#), r#"a\"b\"c"#);
    }

    #[test]
    fn backslash_escaped() {
        assert_eq!(for_yaml(r"a\b"), r"a\\b");
        assert_eq!(for_yaml(r"\\"), r"\\\\");
        assert_eq!(for_yaml(r"\n"), r"\\n");
    }

    #[test]
    fn named_c0_escapes() {
        assert_eq!(for_yaml("\x00"), "\\0");
        assert_eq!(for_yaml("\x07"), "\\a");
        assert_eq!(for_yaml("\x08"), "\\b");
        assert_eq!(for_yaml("\t"), "\\t");
        assert_eq!(for_yaml("\n"), "\\n");
        assert_eq!(for_yaml("\x0B"), "\\v");
        assert_eq!(for_yaml("\x0C"), "\\f");
        assert_eq!(for_yaml("\r"), "\\r");
        assert_eq!(for_yaml("\x1B"), "\\e");
    }

    #[test]
    fn other_c0_controls_hex_escaped() {
        assert_eq!(for_yaml("\x01"), "\\x01");
        assert_eq!(for_yaml("\x02"), "\\x02");
        assert_eq!(for_yaml("\x06"), "\\x06");
        assert_eq!(for_yaml("\x0E"), "\\x0e");
        assert_eq!(for_yaml("\x1F"), "\\x1f");
    }

    #[test]
    fn del_hex_escaped() {
        assert_eq!(for_yaml("\x7F"), "\\x7f");
    }

    #[test]
    fn yaml_named_unicode_escapes() {
        assert_eq!(for_yaml("\u{0085}"), "\\N"); // NEL
        assert_eq!(for_yaml("\u{00A0}"), "\\_"); // NBSP
        assert_eq!(for_yaml("\u{2028}"), "\\L"); // line separator
        assert_eq!(for_yaml("\u{2029}"), "\\P"); // paragraph separator
    }

    #[test]
    fn c1_controls_hex_escaped() {
        assert_eq!(for_yaml("\u{0080}"), "\\x80");
        assert_eq!(for_yaml("\u{0081}"), "\\x81");
        assert_eq!(for_yaml("\u{008F}"), "\\x8f");
        assert_eq!(for_yaml("\u{009F}"), "\\x9f");
    }

    #[test]
    fn mixed_input() {
        assert_eq!(
            for_yaml("name: \"hello\"\nage: 42"),
            "name: \\\"hello\\\"\\nage: 42"
        );
    }

    #[test]
    fn injection_via_multiline() {
        // attacker tries to inject a new YAML key via newline
        assert_eq!(
            for_yaml("innocent\nmalicious_key: evil"),
            "innocent\\nmalicious_key: evil"
        );
    }

    #[test]
    fn injection_via_quote_escape() {
        // attacker tries to break out of double-quoted scalar
        assert_eq!(
            for_yaml(r#"value" injected: true"#),
            r#"value\" injected: true"#
        );
    }

    #[test]
    fn writer_matches_string() {
        let input = "test\x00\"\\\n\t\u{0085}\u{00A0}\u{2028}\u{2029}café";
        let string_result = for_yaml(input);
        let mut writer_result = String::new();
        write_yaml(&mut writer_result, input).unwrap();
        assert_eq!(string_result, writer_result);
    }
}
