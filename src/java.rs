//! java string literal encoder.
//!
//! encodes untrusted strings for safe embedding in java string literals.
//!
//! - [`for_java`] — safe for java string and char literal contexts
//!
//! # encoding rules
//!
//! - named escapes: `\b`, `\t`, `\n`, `\f`, `\r`, `\"`, `\'`, `\\`
//! - other C0 controls and DEL → octal escapes (shortest form, or 3-digit
//!   when the next character is an octal digit to avoid ambiguity)
//! - U+2028, U+2029 → `\u2028`, `\u2029` (java line terminators)
//! - supplementary plane characters (U+10000+) → UTF-16 surrogate pairs
//!   (`\uHHHH\uHHHH`)
//! - unicode non-characters → space

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

/// encodes `input` for safe embedding in a java string literal.
///
/// produces output suitable for embedding between double quotes in java
/// source code. also safe for char literals (single quotes are escaped).
///
/// # encoding rules
///
/// | input | output |
/// |-------|--------|
/// | C0 named (`\b`, `\t`, `\n`, `\f`, `\r`) | named escape |
/// | `"`, `'`, `\` | `\"`, `\'`, `\\` |
/// | other C0 controls, DEL | octal escape |
/// | U+2028, U+2029 | `\u2028`, `\u2029` |
/// | supplementary plane (U+10000+) | surrogate pair `\uHHHH\uHHHH` |
/// | unicode non-characters | space |
///
/// octal escapes use the shortest form (`\0` for NUL) unless the next
/// character is an octal digit, in which case the 3-digit form is used
/// (`\000`) to prevent ambiguity.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_java;
///
/// assert_eq!(for_java(r#"he said "hello""#), r#"he said \"hello\""#);
/// assert_eq!(for_java("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_java("null\x00byte"), r"null\0byte");
/// assert_eq!(for_java("\x007"), r"\0007");
/// ```
pub fn for_java(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_java(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the java-encoded form of `input` to `out`.
///
/// see [`for_java`] for encoding rules.
pub fn write_java<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_java_encoding, write_java_encoded)
}

fn needs_java_encoding(c: char) -> bool {
    match c {
        '\x00'..='\x1F' | '\x7F' | '"' | '\'' | '\\' | '\u{2028}' | '\u{2029}' => true,
        c if (c as u32) >= 0x10000 => true,
        c if is_unicode_noncharacter(c as u32) => true,
        _ => false,
    }
}

fn write_java_encoded<W: fmt::Write>(out: &mut W, c: char, next: Option<char>) -> fmt::Result {
    match c {
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '"' => out.write_str("\\\""),
        '\'' => out.write_str("\\'"),
        '\\' => out.write_str("\\\\"),
        '\u{2028}' => out.write_str("\\u2028"),
        '\u{2029}' => out.write_str("\\u2029"),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // supplementary plane → UTF-16 surrogate pair
        c if (c as u32) >= 0x10000 => {
            let cp = c as u32 - 0x10000;
            let high = 0xD800 + (cp >> 10);
            let low = 0xDC00 + (cp & 0x3FF);
            write!(out, "\\u{high:04x}\\u{low:04x}")
        }
        // C0 controls (without named escapes) and DEL → octal
        c => {
            let val = c as u32;
            let next_is_octal = next.is_some_and(|n| ('0'..='7').contains(&n));
            if next_is_octal {
                write!(out, "\\{val:03o}")
            } else {
                write!(out, "\\{val:o}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough() {
        assert_eq!(for_java("hello world"), "hello world");
        assert_eq!(for_java(""), "");
        assert_eq!(for_java("café"), "café");
    }

    #[test]
    fn named_escapes() {
        assert_eq!(for_java("\x08"), "\\b");
        assert_eq!(for_java("\t"), "\\t");
        assert_eq!(for_java("\n"), "\\n");
        assert_eq!(for_java("\x0C"), "\\f");
        assert_eq!(for_java("\r"), "\\r");
    }

    #[test]
    fn quotes_and_backslash() {
        assert_eq!(for_java(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_java("a'b"), r"a\'b");
        assert_eq!(for_java(r"a\b"), r"a\\b");
    }

    #[test]
    fn octal_shortest_form() {
        // NUL followed by non-octal → shortest form
        assert_eq!(for_java("\x00a"), "\\0a");
        // SOH
        assert_eq!(for_java("\x01a"), "\\1a");
        // BEL
        assert_eq!(for_java("\x07a"), "\\7a");
        // VT (0x0B = 0o13)
        assert_eq!(for_java("\x0Ba"), "\\13a");
        // DEL (0x7F = 0o177)
        assert_eq!(for_java("\x7Fa"), "\\177a");
    }

    #[test]
    fn octal_three_digit_before_octal_char() {
        // NUL followed by octal digit → 3-digit form
        assert_eq!(for_java("\x000"), "\\0000");
        assert_eq!(for_java("\x007"), "\\0007");
        assert_eq!(for_java("\x015"), "\\0015");
    }

    #[test]
    fn octal_at_end_of_input() {
        // no next char → shortest form
        assert_eq!(for_java("\x00"), "\\0");
        assert_eq!(for_java("\x07"), "\\7");
        assert_eq!(for_java("\x7F"), "\\177");
    }

    #[test]
    fn line_separators() {
        assert_eq!(for_java("\u{2028}"), "\\u2028");
        assert_eq!(for_java("\u{2029}"), "\\u2029");
    }

    #[test]
    fn supplementary_plane_surrogate_pairs() {
        // U+1F600 (GRINNING FACE) = 0x1F600 - 0x10000 = 0xF600
        // high = 0xD800 + (0xF600 >> 10) = 0xD800 + 0x3D = 0xD83D
        // low  = 0xDC00 + (0xF600 & 0x3FF) = 0xDC00 + 0x200 = 0xDE00
        assert_eq!(for_java("\u{1F600}"), "\\ud83d\\ude00");

        // U+10000 (LINEAR B SYLLABLE B008 A)
        // high = 0xD800, low = 0xDC00
        assert_eq!(for_java("\u{10000}"), "\\ud800\\udc00");

        // U+10FFFD (last non-char-adjacent codepoint)
        // 0x10FFFD - 0x10000 = 0xFFFD
        // high = 0xD800 + (0xFFFD >> 10) = 0xD800 + 0x3FF = 0xDBFF
        // low  = 0xDC00 + (0xFFFD & 0x3FF) = 0xDC00 + 0x3FD = 0xDFFD
        assert_eq!(for_java("\u{10FFFD}"), "\\udbff\\udffd");
    }

    #[test]
    fn noncharacters_replaced_with_space() {
        assert_eq!(for_java("\u{FDD0}"), " ");
        assert_eq!(for_java("\u{FFFE}"), " ");
    }

    #[test]
    fn mixed_input() {
        assert_eq!(
            for_java("he said \"hello\"\nnew line"),
            "he said \\\"hello\\\"\\nnew line"
        );
    }

    #[test]
    fn writer_matches_string() {
        let input = "test\x00\"\\\u{1F600}";
        let string_result = for_java(input);
        let mut writer_result = String::new();
        write_java(&mut writer_result, input).unwrap();
        assert_eq!(string_result, writer_result);
    }
}
