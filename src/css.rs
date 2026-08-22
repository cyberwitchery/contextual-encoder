//! CSS contextual output encoders.
//!
//! provides two encoding contexts:
//!
//! - [`for_css_string`] — safe for CSS string values (inside quotes)
//! - [`for_css_url`] — safe for CSS `url()` values, quoted or unquoted
//!
//! both use CSS hex escape syntax (`\XX`) with a trailing space appended
//! when the next character could be misinterpreted as part of the hex value,
//! or when the escape ends the output.
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
//! - both encoders escape the bidi formatting controls (U+202A-U+202E,
//!   U+2066-U+2069), so a direction override in the data cannot reorder how the
//!   surrounding stylesheet source reads.

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

/// encodes `input` for safe embedding in a quoted CSS string value.
///
/// uses CSS hex escape syntax (`\XX`) with shortest hex representation.
/// a trailing space is appended after the hex escape when the next character
/// is a hex digit or whitespace, and when the escape ends the output. a CSS
/// escape consumes exactly one following whitespace character, so the space
/// never changes the decoded value.
///
/// unicode non-characters are replaced with `_`.
///
/// # encoded characters
///
/// C0 controls (U+0000-U+001F), `"`, `'`, `\`, `<`, `&`, `(`, `)`, `/`,
/// `>`, DEL (U+007F), C1 controls (U+0080-U+009F), U+2028, U+2029, and the
/// bidi formatting controls (U+202A-U+202E, U+2066-U+2069).
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
/// // an escape at the end always gets one; the escape consumes it again
/// assert_eq!(for_css_string(r#"a""#), r"a\22 ");
/// assert_eq!(for_css_string("a\u{202E}b"), r"a\202e b");
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

/// encodes `input` for safe embedding in a CSS `url()` value.
///
/// whatever the input, `url(<output>)` is exactly one url-token: nothing can
/// terminate it early or turn it into a bad-url-token. the CSS parser unescapes
/// the value before resolving it, so a URL that genuinely contains `(`, `)` or
/// a space still points at the same resource.
///
/// the URL **must be validated** before encoding (e.g., ensure the scheme
/// is allowed). encoding only prevents syntax breakout, not malicious URLs.
///
/// # encoded characters
///
/// everything [`for_css_string`] encodes, plus space (U+0020).
///
/// # examples
///
/// ```
/// use contextual_encoder::for_css_url;
///
/// assert_eq!(for_css_url("image.png"), "image.png");
/// // b is a hex digit, so trailing space after \27
/// assert_eq!(for_css_url("a'b"), r"a\27 b");
/// assert_eq!(for_css_url("a(b)"), r"a\28 b\29 ");
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
    // css whitespace is space, tab and newline; only space is not a C0 control
    needs_css_string_encoding(c) || c == ' '
}

fn needs_css_common_encoding(c: char) -> bool {
    let cp = c as u32;
    cp <= 0x1F
        || matches!(c, '"' | '\'' | '\\' | '<' | '&' | '/' | '>')
        || (0x7F..=0x9F).contains(&cp) // DEL + C1 controls
        || cp == 0x2028
        || cp == 0x2029
        || (0x202A..=0x202E).contains(&cp) // bidi embeddings and overrides
        || (0x2066..=0x2069).contains(&cp) // bidi isolates
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

/// returns true if a trailing space is needed after a CSS hex escape to
/// prevent ambiguous parsing with the next character, or — at the end of the
/// input — with whatever the caller appends.
fn needs_css_separator(next: Option<char>) -> bool {
    match next {
        Some(c) => c.is_ascii_hexdigit() || matches!(c, ' ' | '\t' | '\n' | '\x0C' | '\r'),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the bidi formatting controls, with their escaped forms.
    const TEXT_DIRECTION: [(&str, &str); 9] = [
        ("\u{202A}", r"\202a"),
        ("\u{202B}", r"\202b"),
        ("\u{202C}", r"\202c"),
        ("\u{202D}", r"\202d"),
        ("\u{202E}", r"\202e"),
        ("\u{2066}", r"\2066"),
        ("\u{2067}", r"\2067"),
        ("\u{2068}", r"\2068"),
        ("\u{2069}", r"\2069"),
    ];

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
        // " at end → separator space, absorbed by the escape on decode
        assert_eq!(for_css_string(r#"a""#), r"a\22 ");
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
        assert_eq!(for_css_string("<x>"), r"\3cx\3e ");
    }

    #[test]
    fn css_string_encodes_ampersand() {
        assert_eq!(for_css_string("a&b"), r"a\26 b");
    }

    #[test]
    fn css_string_encodes_parens() {
        assert_eq!(for_css_string("a(b)"), r"a\28 b\29 ");
    }

    #[test]
    fn css_string_encodes_slash() {
        assert_eq!(for_css_string("a/b"), r"a\2f b");
    }

    #[test]
    fn css_string_encodes_control_chars() {
        assert_eq!(for_css_string("\x00"), r"\0 ");
        assert_eq!(for_css_string("\x01x"), r"\1x");
        assert_eq!(for_css_string("\x1F"), r"\1f ");
    }

    #[test]
    fn css_string_encodes_del() {
        assert_eq!(for_css_string("\x7F"), r"\7f ");
    }

    #[test]
    fn css_string_encodes_c1_controls() {
        assert_eq!(for_css_string("\u{0080}"), r"\80 ");
        assert_eq!(for_css_string("\u{0085}"), r"\85 ");
        assert_eq!(for_css_string("\u{009F}"), r"\9f ");
        // next char is hex digit → trailing space
        assert_eq!(for_css_string("\u{0080}a"), r"\80 a");
        // next char is not hex → no trailing space
        assert_eq!(for_css_string("\u{0080}z"), r"\80z");
    }

    #[test]
    fn css_string_encodes_line_separators() {
        assert_eq!(for_css_string("\u{2028}"), r"\2028 ");
        assert_eq!(for_css_string("\u{2029}"), r"\2029 ");
    }

    #[test]
    fn css_string_encodes_text_direction_controls() {
        for (raw, escaped) in TEXT_DIRECTION {
            assert_eq!(for_css_string(&format!("a{raw}z")), format!("a{escaped}z"));
        }
    }

    #[test]
    fn css_string_text_direction_separator() {
        for (raw, escaped) in TEXT_DIRECTION {
            // b is a hex digit, z is not
            assert_eq!(for_css_string(&format!("{raw}b")), format!("{escaped} b"));
            assert_eq!(for_css_string(&format!("{raw}z")), format!("{escaped}z"));
            assert_eq!(for_css_string(raw), format!("{escaped} "));
        }
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
    fn css_url_encodes_parens() {
        assert_eq!(for_css_url("a(b)c"), r"a\28 b\29 c");
    }

    #[test]
    fn css_url_encodes_space() {
        assert_eq!(for_css_url("a b"), r"a\20 b");
        assert_eq!(for_css_url(" "), r"\20 ");
    }

    #[test]
    fn css_url_preserves_unicode_spaces() {
        assert_eq!(for_css_url("a\u{a0}b"), "a\u{a0}b");
        assert_eq!(for_css_url("a\u{2003}b"), "a\u{2003}b");
        assert_eq!(for_css_url("a\u{3000}b"), "a\u{3000}b");
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

    #[test]
    fn css_url_encodes_c1_controls() {
        assert_eq!(for_css_url("\u{0080}"), r"\80 ");
        assert_eq!(for_css_url("\u{0085}"), r"\85 ");
        assert_eq!(for_css_url("\u{009F}"), r"\9f ");
    }

    #[test]
    fn css_url_encodes_text_direction_controls() {
        for (raw, escaped) in TEXT_DIRECTION {
            assert_eq!(for_css_url(&format!("a{raw}z")), format!("a{escaped}z"));
            assert_eq!(for_css_url(&format!("{raw}b")), format!("{escaped} b"));
            assert_eq!(for_css_url(raw), format!("{escaped} "));
        }
    }
}
