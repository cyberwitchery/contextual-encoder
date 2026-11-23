//! CSS encoders.

use std::fmt;

use crate::engine::{encode_loop, is_text_direction_control, is_unicode_noncharacter};

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
    let cp = c as u32;
    cp <= 0x1F
        || matches!(c, '"' | '\'' | '\\' | '<' | '&' | '/' | '>' | '(' | ')')
        || (0x7F..=0x9F).contains(&cp) // DEL + C1 controls
        || cp == 0x2028
        || cp == 0x2029
        || is_text_direction_control(c)
        || is_unicode_noncharacter(cp)
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
