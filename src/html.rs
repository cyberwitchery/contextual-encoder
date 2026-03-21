//! HTML / XML contextual output encoders.
//!
//! provides four encoding contexts with different safety guarantees:
//!
//! - [`for_html`] — safe for both text content and quoted attributes (most conservative)
//! - [`for_html_content`] — safe for text content only (does not encode quotes)
//! - [`for_html_attribute`] — safe for quoted attributes only (does not encode `>`)
//! - [`for_html_unquoted_attribute`] — safe for unquoted attribute values (most aggressive)
//!
//! all encoders replace invalid XML characters (C0/C1 controls, DEL, unicode
//! non-characters) with a replacement character (space or dash depending on
//! context).
//!
//! # security notes
//!
//! - these encoders produce output safe for embedding in the specified context.
//!   they do not sanitize HTML — encoding is not a substitute for input validation.
//! - never use `for_html_content` output in an attribute context.
//! - never use `for_html_attribute` output in a text content context where `>` matters.
//! - `for_html` is the safe default when the exact context is unknown.
//! - tag names, attribute names, and event handler names must be validated
//!   separately — encoding cannot make arbitrary names safe.

use std::fmt;

use crate::engine::{encode_loop, is_invalid_for_xml, is_unicode_noncharacter};

// ---------------------------------------------------------------------------
// for_html — safe for text content AND quoted attributes
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in HTML text content and quoted attributes.
///
/// this is the most conservative HTML encoder — it encodes characters needed
/// for both text content and attribute contexts. use [`for_html_content`] or
/// [`for_html_attribute`] for more minimal encoding when the exact context is
/// known.
///
/// # encoded characters
///
/// | input | output |
/// |-------|--------|
/// | `&`   | `&amp;`  |
/// | `<`   | `&lt;`   |
/// | `>`   | `&gt;`   |
/// | `"`   | `&#34;`  |
/// | `'`   | `&#39;`  |
///
/// invalid XML characters are replaced with a space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_html;
///
/// assert_eq!(for_html("<script>alert('xss')</script>"),
///            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");
/// assert_eq!(for_html("safe text"), "safe text");
/// ```
pub fn for_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_html(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the HTML-encoded form of `input` to `out`.
///
/// see [`for_html`] for encoding rules.
pub fn write_html<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_html_encoding, write_html_encoded)
}

fn needs_html_encoding(c: char) -> bool {
    matches!(c, '&' | '<' | '>' | '"' | '\'') || is_invalid_for_xml(c)
}

fn write_html_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
    match c {
        '&' => out.write_str("&amp;"),
        '<' => out.write_str("&lt;"),
        '>' => out.write_str("&gt;"),
        '"' => out.write_str("&#34;"),
        '\'' => out.write_str("&#39;"),
        // invalid XML char → space
        _ => out.write_char(' '),
    }
}

// ---------------------------------------------------------------------------
// for_html_content — safe for text content only (NOT attributes)
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in HTML text content.
///
/// this encoder does **not** encode quote characters and is therefore
/// **not safe for attribute values**. use [`for_html`] or
/// [`for_html_attribute`] for attribute contexts.
///
/// # encoded characters
///
/// | input | output |
/// |-------|--------|
/// | `&`   | `&amp;` |
/// | `<`   | `&lt;`  |
/// | `>`   | `&gt;`  |
///
/// invalid XML characters are replaced with a space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_html_content;
///
/// assert_eq!(for_html_content("1 < 2 & 3 > 0"), "1 &lt; 2 &amp; 3 &gt; 0");
/// // quotes are NOT encoded — do not use in attributes
/// assert_eq!(for_html_content(r#"she said "hi""#), r#"she said "hi""#);
/// ```
pub fn for_html_content(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_html_content(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the HTML-content-encoded form of `input` to `out`.
///
/// see [`for_html_content`] for encoding rules.
pub fn write_html_content<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_html_content_encoding,
        write_html_content_encoded,
    )
}

fn needs_html_content_encoding(c: char) -> bool {
    matches!(c, '&' | '<' | '>') || is_invalid_for_xml(c)
}

fn write_html_content_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '&' => out.write_str("&amp;"),
        '<' => out.write_str("&lt;"),
        '>' => out.write_str("&gt;"),
        _ => out.write_char(' '),
    }
}

// ---------------------------------------------------------------------------
// for_html_attribute — safe for quoted attributes only
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a quoted HTML attribute value.
///
/// this encoder does **not** encode `>` (harmless inside quoted attributes)
/// and is slightly more minimal than [`for_html`]. it encodes both `"` and
/// `'` so the output is safe regardless of which quote delimiter is used.
///
/// **not safe for unquoted attributes** — use [`for_html_unquoted_attribute`]
/// for that context.
///
/// # encoded characters
///
/// | input | output |
/// |-------|--------|
/// | `&`   | `&amp;` |
/// | `<`   | `&lt;`  |
/// | `"`   | `&#34;` |
/// | `'`   | `&#39;` |
///
/// invalid XML characters are replaced with a space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_html_attribute;
///
/// // safe for both quote styles
/// assert_eq!(
///     for_html_attribute(r#"it's a "test""#),
///     "it&#39;s a &#34;test&#34;"
/// );
/// // > is not encoded
/// assert_eq!(for_html_attribute("a > b"), "a > b");
/// ```
pub fn for_html_attribute(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_html_attribute(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the HTML-attribute-encoded form of `input` to `out`.
///
/// see [`for_html_attribute`] for encoding rules.
pub fn write_html_attribute<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_html_attribute_encoding,
        write_html_attribute_encoded,
    )
}

fn needs_html_attribute_encoding(c: char) -> bool {
    matches!(c, '&' | '<' | '"' | '\'') || is_invalid_for_xml(c)
}

fn write_html_attribute_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '&' => out.write_str("&amp;"),
        '<' => out.write_str("&lt;"),
        '"' => out.write_str("&#34;"),
        '\'' => out.write_str("&#39;"),
        _ => out.write_char(' '),
    }
}

// ---------------------------------------------------------------------------
// for_html_unquoted_attribute — safe for unquoted attribute values
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in an unquoted HTML attribute value.
///
/// this is the most aggressive HTML encoder, encoding whitespace, quote
/// characters, grave accents, and many punctuation characters that could
/// terminate an unquoted attribute value.
///
/// **prefer quoted attributes** whenever possible. unquoted attributes are
/// fragile and this encoder exists only for cases where quoting is not an
/// option.
///
/// # caveat: grave accent
///
/// the grave accent (`` ` ``, U+0060) is encoded as `&#96;` because
/// unpatched internet explorer treats it as an attribute delimiter.
/// however, numeric character references decode back to the original
/// character, so this encoding cannot fully protect against the IE bug
/// in all injection scenarios. the safest mitigation is to avoid
/// unquoted attributes entirely.
///
/// # encoded characters (partial list)
///
/// | input  | output    |
/// |--------|-----------|
/// | tab    | `&#9;`    |
/// | LF     | `&#10;`   |
/// | FF     | `&#12;`   |
/// | CR     | `&#13;`   |
/// | space  | `&#32;`   |
/// | `&`    | `&amp;`   |
/// | `<`    | `&lt;`    |
/// | `>`    | `&gt;`    |
/// | `"`    | `&#34;`   |
/// | `'`    | `&#39;`   |
/// | `/`    | `&#47;`   |
/// | `=`    | `&#61;`   |
/// | `` ` ``| `&#96;`   |
///
/// C0/C1 control characters, DEL, and unicode non-characters are replaced
/// with `-`. NEL (U+0085) is encoded as `&#133;`. line separator (U+2028)
/// and paragraph separator (U+2029) are encoded as `&#8232;` and `&#8233;`.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_html_unquoted_attribute;
///
/// assert_eq!(for_html_unquoted_attribute("hello world"), "hello&#32;world");
/// assert_eq!(for_html_unquoted_attribute("a=b"), "a&#61;b");
/// ```
pub fn for_html_unquoted_attribute(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_html_unquoted_attribute(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the unquoted-HTML-attribute-encoded form of `input` to `out`.
///
/// see [`for_html_unquoted_attribute`] for encoding rules.
pub fn write_html_unquoted_attribute<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_html_unquoted_attribute_encoding,
        write_html_unquoted_attribute_encoded,
    )
}

fn needs_html_unquoted_attribute_encoding(c: char) -> bool {
    let cp = c as u32;

    // specific ASCII characters that need encoding
    if matches!(
        c,
        '\t' | '\n' | '\x0C' | '\r' | ' ' | '&' | '<' | '>' | '"' | '\'' | '/' | '=' | '`'
    ) {
        return true;
    }

    // C0 controls not matched above
    if cp <= 0x1F {
        return true;
    }

    // DEL
    if cp == 0x7F {
        return true;
    }

    // C1 controls (includes NEL U+0085)
    if (0x80..=0x9F).contains(&cp) {
        return true;
    }

    // line / paragraph separators
    if cp == 0x2028 || cp == 0x2029 {
        return true;
    }

    // unicode non-characters
    if is_unicode_noncharacter(cp) {
        return true;
    }

    false
}

fn write_html_unquoted_attribute_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '\t' => out.write_str("&#9;"),
        '\n' => out.write_str("&#10;"),
        '\x0C' => out.write_str("&#12;"),
        '\r' => out.write_str("&#13;"),
        ' ' => out.write_str("&#32;"),
        '&' => out.write_str("&amp;"),
        '<' => out.write_str("&lt;"),
        '>' => out.write_str("&gt;"),
        '"' => out.write_str("&#34;"),
        '\'' => out.write_str("&#39;"),
        '/' => out.write_str("&#47;"),
        '=' => out.write_str("&#61;"),
        '`' => out.write_str("&#96;"),
        '\u{0085}' => out.write_str("&#133;"),
        '\u{2028}' => out.write_str("&#8232;"),
        '\u{2029}' => out.write_str("&#8233;"),
        // remaining: C0/C1 controls, DEL, non-characters → dash
        _ => out.write_char('-'),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_html --

    #[test]
    fn html_no_encoding_needed() {
        assert_eq!(for_html("hello world"), "hello world");
        assert_eq!(for_html(""), "");
        assert_eq!(for_html("abc123"), "abc123");
    }

    #[test]
    fn html_encodes_ampersand() {
        assert_eq!(for_html("a&b"), "a&amp;b");
    }

    #[test]
    fn html_encodes_angle_brackets() {
        assert_eq!(for_html("<div>"), "&lt;div&gt;");
    }

    #[test]
    fn html_encodes_quotes() {
        assert_eq!(for_html(r#"a"b'c"#), "a&#34;b&#39;c");
    }

    #[test]
    fn html_replaces_controls_with_space() {
        assert_eq!(for_html("a\x01b"), "a b");
        assert_eq!(for_html("a\x7Fb"), "a b");
    }

    #[test]
    fn html_preserves_tab_lf_cr() {
        assert_eq!(for_html("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn html_writer_variant() {
        let mut out = String::new();
        write_html(&mut out, "<b>").unwrap();
        assert_eq!(out, "&lt;b&gt;");
    }

    // -- for_html_content --

    #[test]
    fn html_content_does_not_encode_quotes() {
        assert_eq!(for_html_content(r#"a"b'c"#), r#"a"b'c"#);
    }

    #[test]
    fn html_content_encodes_angle_brackets_and_amp() {
        assert_eq!(for_html_content("a<b&c>d"), "a&lt;b&amp;c&gt;d");
    }

    // -- for_html_attribute --

    #[test]
    fn html_attribute_does_not_encode_gt() {
        assert_eq!(for_html_attribute("a>b"), "a>b");
    }

    #[test]
    fn html_attribute_encodes_quotes_and_amp_and_lt() {
        assert_eq!(
            for_html_attribute(r#"a"b'c&d<e"#),
            "a&#34;b&#39;c&amp;d&lt;e"
        );
    }

    // -- for_html_unquoted_attribute --

    #[test]
    fn unquoted_attr_encodes_whitespace() {
        assert_eq!(
            for_html_unquoted_attribute("a b\tc\nd"),
            "a&#32;b&#9;c&#10;d"
        );
    }

    #[test]
    fn unquoted_attr_encodes_grave_accent() {
        assert_eq!(for_html_unquoted_attribute("a`b"), "a&#96;b");
    }

    #[test]
    fn unquoted_attr_encodes_equals_and_slash() {
        assert_eq!(for_html_unquoted_attribute("a=b/c"), "a&#61;b&#47;c");
    }

    #[test]
    fn unquoted_attr_replaces_controls_with_dash() {
        assert_eq!(for_html_unquoted_attribute("a\x01b"), "a-b");
        assert_eq!(for_html_unquoted_attribute("a\x7Fb"), "a-b");
    }

    #[test]
    fn unquoted_attr_encodes_nel() {
        assert_eq!(for_html_unquoted_attribute("a\u{0085}b"), "a&#133;b");
    }

    #[test]
    fn unquoted_attr_encodes_line_separators() {
        assert_eq!(
            for_html_unquoted_attribute("a\u{2028}b\u{2029}c"),
            "a&#8232;b&#8233;c"
        );
    }

    #[test]
    fn unquoted_attr_passes_through_safe_chars() {
        let safe = "ABCxyz019!#$%()*+,-.[]\\^_}";
        assert_eq!(for_html_unquoted_attribute(safe), safe);
    }

    #[test]
    fn unquoted_attr_passes_through_non_ascii() {
        assert_eq!(for_html_unquoted_attribute("café"), "café");
        assert_eq!(for_html_unquoted_attribute("日本語"), "日本語");
    }
}
