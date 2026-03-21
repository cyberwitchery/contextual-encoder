//! CSS contextual output encoders.
//!
//! provides two encoding contexts:
//!
//! - [`for_css_string`] — safe for CSS string values (inside quotes)
//! - [`for_css_url`] — safe for CSS `url()` values
//!
//! both use CSS hex escape syntax (`\XX`) with a trailing space appended
//! when the next character could be misinterpreted as part of the hex value.
//!
//! # security notes
//!
//! - CSS string values **must** be quoted. these encoders produce output safe
//!   inside `"..."` or `'...'` delimiters.
//! - these encoders do not validate CSS property names, selectors, or
//!   expressions. encoding cannot make arbitrary CSS safe — validate the
//!   structure separately.
//! - for `url()` values, the URL itself must be validated (scheme whitelist,
//!   etc.) before encoding. encoding only prevents syntax breakout.

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

// ---------------------------------------------------------------------------
// for_css_string — safe for quoted CSS string values
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a quoted CSS string value.
///
/// uses CSS hex escape syntax (`\XX`) with shortest hex representation.
/// a trailing space is appended after the hex escape when the next character
/// is a hex digit or whitespace, to prevent ambiguous parsing.
///
/// unicode non-characters are replaced with `_`.
///
/// # encoded characters
///
/// C0 controls (U+0000-U+001F), `"`, `'`, `\`, `<`, `&`, `(`, `)`, `/`,
/// `>`, DEL (U+007F), U+2028, U+2029.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_css_string;
///
/// assert_eq!(for_css_string("background"), "background");
/// assert_eq!(for_css_string(r#"a"b"#), r"a\22 b");
/// // z is not a hex digit, so no trailing space
/// assert_eq!(for_css_string("a'z"), r"a\27z");
/// ```
pub fn for_css_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_css_string(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the CSS-string-encoded form of `input` to `out`.
///
/// see [`for_css_string`] for encoding rules.
pub fn write_css_string<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_css_string_encoding, write_css_encoded)
}

fn needs_css_string_encoding(c: char) -> bool {
    needs_css_common_encoding(c) || matches!(c, '(' | ')')
}

// ---------------------------------------------------------------------------
// for_css_url — safe for CSS url() values
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a CSS `url()` value.
///
/// identical to [`for_css_string`] except parentheses `(` and `)` are
/// **not** encoded (they are part of the `url()` syntax, not the value).
///
/// the URL **must be validated** before encoding (e.g., ensure the scheme
/// is allowed). encoding only prevents syntax breakout, not malicious URLs.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_css_url;
///
/// assert_eq!(for_css_url("image.png"), "image.png");
/// // b is a hex digit, so trailing space after \27
/// assert_eq!(for_css_url("a'b"), r"a\27 b");
/// assert_eq!(for_css_url("a(b)"), "a(b)");
/// ```
pub fn for_css_url(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_css_url(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the CSS-url-encoded form of `input` to `out`.
///
/// see [`for_css_url`] for encoding rules.
pub fn write_css_url<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_css_url_encoding, write_css_encoded)
}

fn needs_css_url_encoding(c: char) -> bool {
    needs_css_common_encoding(c)
    // parentheses NOT encoded in url context
}

// ---------------------------------------------------------------------------
// shared implementation
// ---------------------------------------------------------------------------

fn needs_css_common_encoding(c: char) -> bool {
    let cp = c as u32;
    cp <= 0x1F
        || matches!(c, '"' | '\'' | '\\' | '<' | '&' | '/' | '>')
        || cp == 0x7F
        || cp == 0x2028
        || cp == 0x2029
        || is_unicode_noncharacter(cp)
}

fn write_css_encoded<W: fmt::Write>(out: &mut W, c: char, next: Option<char>) -> fmt::Result {
    let cp = c as u32;

    // non-characters → underscore
    if is_unicode_noncharacter(cp) {
        return out.write_char('_');
    }

    // hex escape: shortest representation, no zero-padding
    write!(out, "\\{:x}", cp)?;

    // append a space if the next character could extend the hex value
    if needs_css_separator(next) {
        out.write_char(' ')?;
    }

    Ok(())
}

/// returns true if a trailing space is needed after a CSS hex escape
/// to prevent ambiguous parsing with the next character.
fn needs_css_separator(next: Option<char>) -> bool {
    match next {
        Some(c) => c.is_ascii_hexdigit() || matches!(c, ' ' | '\t' | '\n' | '\x0C' | '\r'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_css_string --

    #[test]
    fn css_string_no_encoding_needed() {
        assert_eq!(for_css_string("hello"), "hello");
        assert_eq!(for_css_string(""), "");
    }

    #[test]
    fn css_string_encodes_double_quote() {
        // " (0x22) → \22, followed by space because 'b' is a hex digit
        assert_eq!(for_css_string(r#"a"b"#), r"a\22 b");
        // " at end → no trailing space
        assert_eq!(for_css_string(r#"a""#), r"a\22");
    }

    #[test]
    fn css_string_encodes_single_quote() {
        // ' (0x27) → \27, 'z' is not a hex digit → no space
        assert_eq!(for_css_string("a'z"), r"a\27z");
        // ' (0x27) → \27, '1' is a hex digit → space
        assert_eq!(for_css_string("a'1"), r"a\27 1");
    }

    #[test]
    fn css_string_encodes_backslash() {
        assert_eq!(for_css_string(r"a\b"), r"a\5c b");
    }

    #[test]
    fn css_string_encodes_angle_brackets() {
        // x is not a hex digit, so no trailing space after \3c
        assert_eq!(for_css_string("<x>"), r"\3cx\3e");
    }

    #[test]
    fn css_string_encodes_ampersand() {
        assert_eq!(for_css_string("a&b"), r"a\26 b");
    }

    #[test]
    fn css_string_encodes_parens() {
        assert_eq!(for_css_string("a(b)"), r"a\28 b\29");
    }

    #[test]
    fn css_string_encodes_slash() {
        assert_eq!(for_css_string("a/b"), r"a\2f b");
    }

    #[test]
    fn css_string_encodes_control_chars() {
        assert_eq!(for_css_string("\x00"), r"\0");
        assert_eq!(for_css_string("\x01x"), r"\1x");
        assert_eq!(for_css_string("\x1F"), r"\1f");
    }

    #[test]
    fn css_string_encodes_del() {
        assert_eq!(for_css_string("\x7F"), r"\7f");
    }

    #[test]
    fn css_string_encodes_line_separators() {
        assert_eq!(for_css_string("\u{2028}"), r"\2028");
        assert_eq!(for_css_string("\u{2029}"), r"\2029");
    }

    #[test]
    fn css_string_replaces_nonchars_with_underscore() {
        assert_eq!(for_css_string("\u{FDD0}"), "_");
        assert_eq!(for_css_string("\u{FFFE}"), "_");
        assert_eq!(for_css_string("\u{FFFF}"), "_");
    }

    #[test]
    fn css_string_separator_before_whitespace() {
        // \27 followed by space → needs separator → \27 + space + space
        // first space is the separator, second is the content space
        assert_eq!(for_css_string("' "), r"\27  ");
    }

    #[test]
    fn css_string_preserves_non_ascii() {
        assert_eq!(for_css_string("café"), "café");
    }

    #[test]
    fn css_string_writer_variant() {
        let mut out = String::new();
        // b is a hex digit, so trailing space after \27
        write_css_string(&mut out, "a'b").unwrap();
        assert_eq!(out, r"a\27 b");
    }

    // -- for_css_url --

    #[test]
    fn css_url_does_not_encode_parens() {
        assert_eq!(for_css_url("a(b)c"), "a(b)c");
    }

    #[test]
    fn css_url_encodes_quotes() {
        // b is a hex digit, so trailing space after \27
        assert_eq!(for_css_url("a'b"), r"a\27 b");
    }

    #[test]
    fn css_url_encodes_backslash() {
        assert_eq!(for_css_url(r"a\b"), r"a\5c b");
    }
}
