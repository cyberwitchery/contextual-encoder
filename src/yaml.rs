//! YAML string encoders.
//!
//! encodes untrusted strings for safe embedding in YAML string values.
//!
//! - [`for_yaml`] — safe for YAML double-quoted string contexts (`"..."`)
//! - [`for_yaml_single_quoted`] — safe for YAML single-quoted string contexts (`'...'`)
//!
//! # encoding rules
//!
//! ## double-quoted (`for_yaml`)
//!
//! YAML double-quoted scalars support C-style backslash escapes plus several
//! YAML-specific named escapes. the encoder uses these to neutralise characters
//! that could break or confuse parsing:
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `\` | `\\` |
//! | `"` | `\"` |
//! | NUL (`\0`) | `\0` |
//! | BEL (`\x07`) | `\a` |
//! | BS (`\x08`) | `\b` |
//! | TAB (`\x09`) | `\t` |
//! | LF (`\x0A`) | `\n` |
//! | VT (`\x0B`) | `\v` |
//! | FF (`\x0C`) | `\f` |
//! | CR (`\x0D`) | `\r` |
//! | ESC (`\x1B`) | `\e` |
//! | other C0 controls | `\xHH` |
//! | DEL (`\x7F`) | `\x7f` |
//! | NEL (`\u0085`) | `\N` |
//! | other C1 controls (`\x80`–`\x9F`) | `\xHH` |
//! | NBSP (`\u00A0`) | `\_` |
//! | U+2028 (line separator) | `\L` |
//! | U+2029 (paragraph separator) | `\P` |
//! | unicode non-characters | space |
//!
//! ## single-quoted (`for_yaml_single_quoted`)
//!
//! YAML single-quoted scalars have no backslash escaping — the only escape
//! mechanism is doubling single quotes. control characters cannot be
//! represented, so they are replaced:
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `'` | `''` |
//! | NUL (`\0`) | removed |
//! | C0 controls (except TAB, LF, CR) | space |
//! | DEL (`\x7F`) | space |
//! | C1 controls (`\x80`–`\x9F`) | space |
//! | unicode non-characters | space |
//!
//! # security notes
//!
//! - **always quote untrusted values.** these encoders produce content for
//!   *quoted* YAML scalars. unquoted (plain) scalars have complex rules and
//!   can be interpreted as booleans, nulls, or other types — never embed
//!   untrusted data as a plain scalar.
//! - **double-quoted is safer.** single-quoted strings cannot represent
//!   arbitrary control characters. if the input may contain control characters
//!   that must be preserved, use double-quoted.

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

// ---------------------------------------------------------------------------
// for_yaml — safe for YAML double-quoted string literals ("...")
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a YAML double-quoted string (`"..."`).
///
/// uses YAML's backslash escape sequences including the YAML-specific named
/// escapes `\N` (NEL), `\_` (NBSP), `\L` (line separator), and `\P`
/// (paragraph separator).
///
/// # examples
///
/// ```
/// use contextual_encoder::for_yaml;
///
/// assert_eq!(for_yaml(r#"he said "hello""#), r#"he said \"hello\""#);
/// assert_eq!(for_yaml("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_yaml(r"back\slash"), r"back\\slash");
/// assert_eq!(for_yaml("\u{0085}"), r"\N");
/// assert_eq!(for_yaml("\u{00A0}"), r"\_");
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
    let cp = c as u32;
    cp <= 0x1F
        || (0x7F..=0x9F).contains(&cp)
        || c == '"'
        || c == '\\'
        || cp == 0xA0
        || cp == 0x2028
        || cp == 0x2029
        || is_unicode_noncharacter(cp)
}

fn write_yaml_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
    match c {
        '\x00' => out.write_str("\\0"),
        '\x07' => out.write_str("\\a"),
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\v"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '\x1B' => out.write_str("\\e"),
        '"' => out.write_str("\\\""),
        '\\' => out.write_str("\\\\"),
        '\u{0085}' => out.write_str("\\N"),
        '\u{00A0}' => out.write_str("\\_"),
        '\u{2028}' => out.write_str("\\L"),
        '\u{2029}' => out.write_str("\\P"),
        _ if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // other C0 controls (0x01-0x06, 0x0E-0x1A, 0x1C-0x1F),
        // DEL (0x7F), and C1 controls (0x80-0x84, 0x86-0x9F)
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

// ---------------------------------------------------------------------------
// for_yaml_single_quoted — safe for YAML single-quoted string literals ('...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a YAML single-quoted string (`'...'`).
///
/// YAML single-quoted strings have no backslash escaping. the only escape
/// mechanism is doubling single quotes (`'` → `''`). control characters that
/// cannot be represented in single-quoted context are replaced with space,
/// and NUL bytes are removed.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_yaml_single_quoted;
///
/// assert_eq!(for_yaml_single_quoted("it's"), "it''s");
/// assert_eq!(for_yaml_single_quoted("hello"), "hello");
/// assert_eq!(for_yaml_single_quoted(r"back\slash"), r"back\slash");
/// ```
pub fn for_yaml_single_quoted(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_yaml_single_quoted(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the YAML-single-quoted-encoded form of `input` to `out`.
///
/// see [`for_yaml_single_quoted`] for encoding rules.
pub fn write_yaml_single_quoted<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_yaml_single_quoted_encoding,
        write_yaml_single_quoted_encoded,
    )
}

fn needs_yaml_single_quoted_encoding(c: char) -> bool {
    let cp = c as u32;
    c == '\''
        || c == '\0'
        || (0x01..=0x08).contains(&cp)
        || cp == 0x0B
        || cp == 0x0C
        || (0x0E..=0x1F).contains(&cp)
        || cp == 0x7F
        || (0x80..=0x9F).contains(&cp)
        || is_unicode_noncharacter(cp)
}

fn write_yaml_single_quoted_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '\'' => out.write_str("''"),
        '\0' => Ok(()), // remove NUL bytes
        _ if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        _ => out.write_char(' '), // control characters → space
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // for_yaml (double-quoted)
    // =====================================================================

    #[test]
    fn passthrough() {
        assert_eq!(for_yaml("hello world"), "hello world");
        assert_eq!(for_yaml(""), "");
        assert_eq!(for_yaml("café"), "café");
        assert_eq!(for_yaml("日本語"), "日本語");
        assert_eq!(for_yaml("😀"), "😀");
    }

    #[test]
    fn double_quotes_escaped() {
        assert_eq!(for_yaml(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_yaml(r#""hello""#), r#"\"hello\""#);
    }

    #[test]
    fn single_quotes_not_escaped() {
        assert_eq!(for_yaml("it's"), "it's");
        assert_eq!(for_yaml("'quoted'"), "'quoted'");
    }

    #[test]
    fn backslash() {
        assert_eq!(for_yaml(r"a\b"), r"a\\b");
        assert_eq!(for_yaml(r"\\"), r"\\\\");
    }

    #[test]
    fn named_escapes() {
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
    fn yaml_specific_named_escapes() {
        assert_eq!(for_yaml("\u{0085}"), "\\N");
        assert_eq!(for_yaml("\u{00A0}"), "\\_");
        assert_eq!(for_yaml("\u{2028}"), "\\L");
        assert_eq!(for_yaml("\u{2029}"), "\\P");
    }

    #[test]
    fn hex_for_unnamed_c0_controls() {
        assert_eq!(for_yaml("\x01"), "\\x01");
        assert_eq!(for_yaml("\x02"), "\\x02");
        assert_eq!(for_yaml("\x06"), "\\x06");
        assert_eq!(for_yaml("\x0E"), "\\x0e");
        assert_eq!(for_yaml("\x1A"), "\\x1a");
        assert_eq!(for_yaml("\x1C"), "\\x1c");
        assert_eq!(for_yaml("\x1F"), "\\x1f");
    }

    #[test]
    fn del_hex_escape() {
        assert_eq!(for_yaml("\x7F"), "\\x7f");
    }

    #[test]
    fn c1_controls_hex() {
        assert_eq!(for_yaml("\u{0080}"), "\\x80");
        assert_eq!(for_yaml("\u{0084}"), "\\x84");
        assert_eq!(for_yaml("\u{0086}"), "\\x86");
        assert_eq!(for_yaml("\u{009F}"), "\\x9f");
    }

    #[test]
    fn nonchars_replaced() {
        assert_eq!(for_yaml("\u{FDD0}"), " ");
        assert_eq!(for_yaml("\u{FFFE}"), " ");
        assert_eq!(for_yaml("\u{1FFFE}"), " ");
    }

    #[test]
    fn supplementary_plane_passes_through() {
        assert_eq!(for_yaml("😀"), "😀");
        assert_eq!(for_yaml("\u{10000}"), "\u{10000}");
    }

    #[test]
    fn mixed_input() {
        assert_eq!(
            for_yaml("he said \"hello\"\nnew line"),
            "he said \\\"hello\\\"\\nnew line"
        );
    }

    #[test]
    fn yaml_injection_key_colon() {
        // colons and other YAML structure chars are safe inside double quotes
        assert_eq!(for_yaml("key: value"), "key: value");
    }

    #[test]
    fn yaml_injection_multiline() {
        assert_eq!(
            for_yaml("value\nother_key: injected"),
            "value\\nother_key: injected"
        );
    }

    #[test]
    fn yaml_injection_anchor() {
        // anchors/aliases are safe inside quoted strings
        assert_eq!(for_yaml("*alias"), "*alias");
        assert_eq!(for_yaml("&anchor"), "&anchor");
    }

    #[test]
    fn yaml_injection_comment() {
        // # is safe inside quoted strings
        assert_eq!(for_yaml("value # comment"), "value # comment");
    }

    #[test]
    fn yaml_injection_flow_indicators() {
        // flow indicators are safe inside quoted strings
        assert_eq!(for_yaml("[a, b]"), "[a, b]");
        assert_eq!(for_yaml("{a: b}"), "{a: b}");
    }

    #[test]
    fn writer_matches_string() {
        let input = "test\x00\"\\\n\u{0085}\u{00A0}\u{2028}café";
        let string_result = for_yaml(input);
        let mut writer_result = String::new();
        write_yaml(&mut writer_result, input).unwrap();
        assert_eq!(string_result, writer_result);
    }

    // =====================================================================
    // for_yaml_single_quoted
    // =====================================================================

    #[test]
    fn single_passthrough() {
        assert_eq!(for_yaml_single_quoted("hello world"), "hello world");
        assert_eq!(for_yaml_single_quoted(""), "");
        assert_eq!(for_yaml_single_quoted("café"), "café");
        assert_eq!(for_yaml_single_quoted("日本語"), "日本語");
        assert_eq!(for_yaml_single_quoted("😀"), "😀");
    }

    #[test]
    fn single_doubles_quotes() {
        assert_eq!(for_yaml_single_quoted("it's"), "it''s");
        assert_eq!(for_yaml_single_quoted("'quoted'"), "''quoted''");
        assert_eq!(for_yaml_single_quoted("a''b"), "a''''b");
    }

    #[test]
    fn single_double_quote_passes_through() {
        assert_eq!(for_yaml_single_quoted(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn single_backslash_passes_through() {
        assert_eq!(for_yaml_single_quoted(r"back\slash"), r"back\slash");
        assert_eq!(for_yaml_single_quoted(r"a\\b"), r"a\\b");
    }

    #[test]
    fn single_removes_nul() {
        assert_eq!(for_yaml_single_quoted("before\x00after"), "beforeafter");
        assert_eq!(for_yaml_single_quoted("\x00"), "");
        assert_eq!(for_yaml_single_quoted("\x00\x00"), "");
    }

    #[test]
    fn single_tab_lf_cr_pass_through() {
        assert_eq!(for_yaml_single_quoted("\t"), "\t");
        assert_eq!(for_yaml_single_quoted("\n"), "\n");
        assert_eq!(for_yaml_single_quoted("\r"), "\r");
    }

    #[test]
    fn single_controls_replaced() {
        assert_eq!(for_yaml_single_quoted("\x01"), " ");
        assert_eq!(for_yaml_single_quoted("\x08"), " ");
        assert_eq!(for_yaml_single_quoted("\x0B"), " ");
        assert_eq!(for_yaml_single_quoted("\x0C"), " ");
        assert_eq!(for_yaml_single_quoted("\x0E"), " ");
        assert_eq!(for_yaml_single_quoted("\x1F"), " ");
        assert_eq!(for_yaml_single_quoted("\x7F"), " ");
    }

    #[test]
    fn single_c1_controls_replaced() {
        assert_eq!(for_yaml_single_quoted("\u{0080}"), " ");
        assert_eq!(for_yaml_single_quoted("\u{0085}"), " ");
        assert_eq!(for_yaml_single_quoted("\u{009F}"), " ");
    }

    #[test]
    fn single_nonchars_replaced() {
        assert_eq!(for_yaml_single_quoted("\u{FDD0}"), " ");
        assert_eq!(for_yaml_single_quoted("\u{FFFE}"), " ");
    }

    #[test]
    fn single_injection_attempt() {
        assert_eq!(
            for_yaml_single_quoted("value' : injected"),
            "value'' : injected"
        );
    }

    #[test]
    fn single_writer_matches() {
        let input = "test\x00'\x01café\u{FDD0}";
        let mut w = String::new();
        write_yaml_single_quoted(&mut w, input).unwrap();
        assert_eq!(for_yaml_single_quoted(input), w);
    }

    // =====================================================================
    // double-quoted vs single-quoted
    // =====================================================================

    #[test]
    fn double_vs_single_backslash() {
        // double-quoted escapes backslash; single-quoted does not
        assert_eq!(for_yaml(r"\"), r"\\");
        assert_eq!(for_yaml_single_quoted(r"\"), r"\");
    }

    #[test]
    fn double_vs_single_control_chars() {
        // double-quoted preserves via escape sequences; single-quoted replaces
        assert_eq!(for_yaml("\x01"), "\\x01");
        assert_eq!(for_yaml_single_quoted("\x01"), " ");
    }

    #[test]
    fn double_vs_single_quotes() {
        // double-quoted escapes " but not '
        assert_eq!(for_yaml(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_yaml("a'b"), "a'b");
        // single-quoted doubles ' but passes through "
        assert_eq!(for_yaml_single_quoted("a'b"), "a''b");
        assert_eq!(for_yaml_single_quoted(r#"a"b"#), r#"a"b"#);
    }
}
