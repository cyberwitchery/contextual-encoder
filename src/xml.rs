//! XML-specific contextual output encoders.
//!
//! provides XML aliases for the HTML encoders, plus XML-only contexts:
//!
//! ## XML 1.0 aliases
//!
//! - [`for_xml`] — alias for [`crate::for_html`]
//! - [`for_xml_content`] — alias for [`crate::for_html_content`]
//! - [`for_xml_attribute`] — alias for [`crate::for_html_attribute`]
//!
//! ## XML-only contexts
//!
//! - [`for_xml_comment`] — safe for XML comment content
//! - [`for_cdata`] — safe for CDATA section content
//!
//! ## XML 1.1
//!
//! - [`for_xml11`] — XML 1.1 content + attributes
//! - [`for_xml11_content`] — XML 1.1 content only
//! - [`for_xml11_attribute`] — XML 1.1 attributes only
//!
//! # security notes
//!
//! - `for_xml_comment` is **not safe for HTML comments**. HTML comments have
//!   vendor-specific extensions (e.g., `<!--[if IE]>`) that make safe encoding
//!   impractical. this encoder is for XML comments only.
//! - `for_cdata` splits CDATA sections to prevent premature closing. the
//!   caller is responsible for wrapping the output in `<![CDATA[...]]>`.

use std::fmt;

use crate::engine::{encode_loop, is_invalid_for_xml, is_unicode_noncharacter};

// ---------------------------------------------------------------------------
// XML 1.0 aliases
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in XML text content and quoted attributes.
///
/// this is an alias for [`crate::for_html`] — the encoding rules are identical.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_xml;
///
/// assert_eq!(for_xml("<root attr=\"val\">"), "&lt;root attr=&#34;val&#34;&gt;");
/// ```
pub fn for_xml(input: &str) -> String {
    crate::html::for_html(input)
}

/// writes the XML-encoded form of `input` to `out`.
///
/// see [`for_xml`] for encoding rules.
pub fn write_xml<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    crate::html::write_html(out, input)
}

/// encodes `input` for safe embedding in XML text content only.
///
/// this is an alias for [`crate::for_html_content`] — the encoding rules are
/// identical. **not safe for attributes** (does not encode quotes).
///
/// # examples
///
/// ```
/// use contextual_encoder::for_xml_content;
///
/// assert_eq!(for_xml_content("a < b & c"), "a &lt; b &amp; c");
/// ```
pub fn for_xml_content(input: &str) -> String {
    crate::html::for_html_content(input)
}

/// writes the XML-content-encoded form of `input` to `out`.
///
/// see [`for_xml_content`] for encoding rules.
pub fn write_xml_content<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    crate::html::write_html_content(out, input)
}

/// encodes `input` for safe embedding in a quoted XML attribute value.
///
/// this is an alias for [`crate::for_html_attribute`] — the encoding rules
/// are identical. **not safe for text content** (does not encode `>`).
///
/// # examples
///
/// ```
/// use contextual_encoder::for_xml_attribute;
///
/// assert_eq!(for_xml_attribute("a\"b"), "a&#34;b");
/// ```
pub fn for_xml_attribute(input: &str) -> String {
    crate::html::for_html_attribute(input)
}

/// writes the XML-attribute-encoded form of `input` to `out`.
///
/// see [`for_xml_attribute`] for encoding rules.
pub fn write_xml_attribute<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    crate::html::write_html_attribute(out, input)
}

// ---------------------------------------------------------------------------
// for_xml_comment — safe for XML comment content
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in an XML comment (`<!-- ... -->`).
///
/// the XML specification forbids `--` inside comments and a trailing `-`
/// (which would form `--->` with the closing delimiter). this encoder
/// replaces the second hyphen in any `--` sequence with `~`, and replaces
/// a trailing `-` with `~`.
///
/// invalid XML characters are replaced with a space.
///
/// # security warning
///
/// this encoder is **not safe for HTML comments**. browsers interpret
/// vendor-specific extensions like `<!--[if IE]>` that cannot be neutralized
/// by encoding. never embed untrusted data in HTML comments.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_xml_comment;
///
/// assert_eq!(for_xml_comment("safe text"), "safe text");
/// assert_eq!(for_xml_comment("a--b"), "a-~b");
/// assert_eq!(for_xml_comment("trailing-"), "trailing~");
/// ```
pub fn for_xml_comment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_xml_comment(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the XML-comment-encoded form of `input` to `out`.
///
/// see [`for_xml_comment`] for encoding rules.
pub fn write_xml_comment<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    let mut last_was_hyphen = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '-' {
            if last_was_hyphen {
                // second hyphen in -- sequence → replace with ~
                out.write_char('~')?;
                last_was_hyphen = false;
            } else if chars.peek().is_none() {
                // trailing hyphen → replace with ~
                out.write_char('~')?;
            } else {
                out.write_char('-')?;
                last_was_hyphen = true;
            }
        } else if is_invalid_for_xml(c) {
            out.write_char(' ')?;
            last_was_hyphen = false;
        } else {
            out.write_char(c)?;
            last_was_hyphen = false;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// for_cdata — safe for CDATA section content
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in an XML CDATA section.
///
/// the CDATA closing delimiter `]]>` cannot appear in CDATA content. when
/// this sequence is found, the encoder splits it by closing the current
/// CDATA section and immediately opening a new one:
///
/// `]]>` → `]]]]><![CDATA[>`
///
/// the caller is responsible for wrapping the output in `<![CDATA[...]]>`.
///
/// invalid XML characters are replaced with a space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_cdata;
///
/// assert_eq!(for_cdata("safe text"), "safe text");
/// assert_eq!(for_cdata("a]]>b"), "a]]]]><![CDATA[>b");
/// assert_eq!(for_cdata("]]"), "]]");
/// ```
pub fn for_cdata(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_cdata(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the CDATA-encoded form of `input` to `out`.
///
/// see [`for_cdata`] for encoding rules.
pub fn write_cdata<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    let mut bracket_count: u32 = 0;

    for c in input.chars() {
        if c == ']' {
            bracket_count += 1;
        } else if c == '>' && bracket_count >= 2 {
            // found ]]> — flush extra brackets, then split
            for _ in 0..(bracket_count - 2) {
                out.write_char(']')?;
            }
            out.write_str("]]]]><![CDATA[>")?;
            bracket_count = 0;
        } else {
            // flush buffered brackets
            for _ in 0..bracket_count {
                out.write_char(']')?;
            }
            bracket_count = 0;

            if is_invalid_for_xml(c) {
                out.write_char(' ')?;
            } else {
                out.write_char(c)?;
            }
        }
    }

    // flush remaining brackets
    for _ in 0..bracket_count {
        out.write_char(']')?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// XML 1.1 encoders
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in XML 1.1 text content and quoted
/// attributes.
///
/// like [`for_xml`] but encodes restricted characters as `&#xHH;` character
/// references instead of replacing them with space. NUL (U+0000) and unicode
/// non-characters are still replaced with space (they are invalid in XML 1.1).
///
/// NEL (U+0085) is **not** restricted in XML 1.1 and passes through unchanged.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_xml11;
///
/// assert_eq!(for_xml11("<b>"), "&lt;b&gt;");
/// // control chars get character references instead of space
/// assert_eq!(for_xml11("a\x01b"), "a&#x1;b");
/// // NEL passes through in XML 1.1
/// assert_eq!(for_xml11("a\u{0085}b"), "a\u{0085}b");
/// ```
pub fn for_xml11(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_xml11(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the XML-1.1-encoded form of `input` to `out`.
///
/// see [`for_xml11`] for encoding rules.
pub fn write_xml11<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_xml11_encoding, write_xml11_encoded)
}

/// encodes `input` for safe embedding in XML 1.1 text content only.
///
/// like [`for_xml_content`] but encodes restricted characters as `&#xHH;`
/// character references. does **not** encode quotes — not safe for attributes.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_xml11_content;
///
/// assert_eq!(for_xml11_content("a\x01b"), "a&#x1;b");
/// assert_eq!(for_xml11_content(r#"a"b"#), r#"a"b"#);
/// ```
pub fn for_xml11_content(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_xml11_content(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the XML-1.1-content-encoded form of `input` to `out`.
///
/// see [`for_xml11_content`] for encoding rules.
pub fn write_xml11_content<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_xml11_content_encoding,
        write_xml11_content_encoded,
    )
}

/// encodes `input` for safe embedding in a quoted XML 1.1 attribute value.
///
/// like [`for_xml_attribute`] but encodes restricted characters as `&#xHH;`
/// character references. does **not** encode `>`.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_xml11_attribute;
///
/// assert_eq!(for_xml11_attribute("a\x01b"), "a&#x1;b");
/// assert_eq!(for_xml11_attribute("a>b"), "a>b");
/// ```
pub fn for_xml11_attribute(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_xml11_attribute(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the XML-1.1-attribute-encoded form of `input` to `out`.
///
/// see [`for_xml11_attribute`] for encoding rules.
pub fn write_xml11_attribute<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_xml11_attribute_encoding,
        write_xml11_attribute_encoded,
    )
}

// ---------------------------------------------------------------------------
// XML 1.1 shared helpers
// ---------------------------------------------------------------------------

/// returns true if the character is restricted in XML 1.1.
///
/// restricted characters are: U+0001-U+0008, U+000B-U+000C, U+000E-U+001F,
/// U+007F-U+0084, U+0086-U+009F. note that NUL (U+0000) is not restricted
/// but is *invalid* (not in the Char production). NEL (U+0085) is NOT
/// restricted in XML 1.1.
fn is_xml11_restricted_or_invalid(c: char) -> bool {
    let cp = c as u32;
    cp == 0
        || (0x01..=0x08).contains(&cp)
        || cp == 0x0B
        || cp == 0x0C
        || (0x0E..=0x1F).contains(&cp)
        || (0x7F..=0x84).contains(&cp)
        || (0x86..=0x9F).contains(&cp)
        || is_unicode_noncharacter(cp)
}

// --- for_xml11 (content + attributes) ---

fn needs_xml11_encoding(c: char) -> bool {
    matches!(c, '&' | '<' | '>' | '"' | '\'') || is_xml11_restricted_or_invalid(c)
}

fn write_xml11_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
    match c {
        '&' => out.write_str("&amp;"),
        '<' => out.write_str("&lt;"),
        '>' => out.write_str("&gt;"),
        '"' => out.write_str("&#34;"),
        '\'' => out.write_str("&#39;"),
        '\0' => out.write_char(' '),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        // restricted controls → hex character reference
        c => write!(out, "&#x{:x};", c as u32),
    }
}

// --- for_xml11_content ---

fn needs_xml11_content_encoding(c: char) -> bool {
    matches!(c, '&' | '<' | '>') || is_xml11_restricted_or_invalid(c)
}

fn write_xml11_content_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '&' => out.write_str("&amp;"),
        '<' => out.write_str("&lt;"),
        '>' => out.write_str("&gt;"),
        '\0' => out.write_char(' '),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        c => write!(out, "&#x{:x};", c as u32),
    }
}

// --- for_xml11_attribute ---

fn needs_xml11_attribute_encoding(c: char) -> bool {
    matches!(c, '&' | '<' | '"' | '\'') || is_xml11_restricted_or_invalid(c)
}

fn write_xml11_attribute_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '&' => out.write_str("&amp;"),
        '<' => out.write_str("&lt;"),
        '"' => out.write_str("&#34;"),
        '\'' => out.write_str("&#39;"),
        '\0' => out.write_char(' '),
        c if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        c => write!(out, "&#x{:x};", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- XML 1.0 aliases --

    #[test]
    fn xml_aliases_match_html() {
        let input = r#"<b attr="val">&amp;</b>"#;
        assert_eq!(for_xml(input), crate::html::for_html(input));
        assert_eq!(for_xml_content(input), crate::html::for_html_content(input));
        assert_eq!(
            for_xml_attribute(input),
            crate::html::for_html_attribute(input)
        );
    }

    // -- XML comment --

    #[test]
    fn comment_passthrough() {
        assert_eq!(for_xml_comment("safe text"), "safe text");
        assert_eq!(for_xml_comment(""), "");
    }

    #[test]
    fn comment_double_hyphen() {
        assert_eq!(for_xml_comment("a--b"), "a-~b");
        assert_eq!(for_xml_comment("--"), "-~");
        assert_eq!(for_xml_comment("---"), "-~~");
        assert_eq!(for_xml_comment("----"), "-~-~");
        assert_eq!(for_xml_comment("a--b--c"), "a-~b-~c");
    }

    #[test]
    fn comment_trailing_hyphen() {
        assert_eq!(for_xml_comment("trailing-"), "trailing~");
        assert_eq!(for_xml_comment("-"), "~");
    }

    #[test]
    fn comment_replaces_invalid_xml() {
        assert_eq!(for_xml_comment("a\x01b"), "a b");
        assert_eq!(for_xml_comment("a\x7Fb"), "a b");
    }

    #[test]
    fn comment_preserves_non_ascii() {
        assert_eq!(for_xml_comment("café"), "café");
    }

    #[test]
    fn comment_writer_variant() {
        let mut out = String::new();
        write_xml_comment(&mut out, "a--b").unwrap();
        assert_eq!(out, "a-~b");
    }

    // -- CDATA --

    #[test]
    fn cdata_passthrough() {
        assert_eq!(for_cdata("safe text"), "safe text");
        assert_eq!(for_cdata(""), "");
    }

    #[test]
    fn cdata_splits_closing_delimiter() {
        assert_eq!(for_cdata("a]]>b"), "a]]]]><![CDATA[>b");
    }

    #[test]
    fn cdata_double_split() {
        assert_eq!(for_cdata("a]]>b]]>c"), "a]]]]><![CDATA[>b]]]]><![CDATA[>c");
    }

    #[test]
    fn cdata_brackets_without_gt() {
        assert_eq!(for_cdata("]]"), "]]");
        assert_eq!(for_cdata("]"), "]");
        assert_eq!(for_cdata("]]a"), "]]a");
    }

    #[test]
    fn cdata_extra_brackets() {
        // ]]]> → ] + ]]> split
        assert_eq!(for_cdata("]]]>"), "]]]]]><![CDATA[>");
    }

    #[test]
    fn cdata_replaces_invalid_xml() {
        assert_eq!(for_cdata("a\x01b"), "a b");
    }

    #[test]
    fn cdata_single_bracket_gt() {
        // ]> is not ]]>, should pass through
        assert_eq!(for_cdata("]>"), "]>");
    }

    #[test]
    fn cdata_writer_variant() {
        let mut out = String::new();
        write_cdata(&mut out, "a]]>b").unwrap();
        assert_eq!(out, "a]]]]><![CDATA[>b");
    }

    // -- XML 1.1 --

    #[test]
    fn xml11_encodes_entities() {
        assert_eq!(for_xml11("<&>\"'"), "&lt;&amp;&gt;&#34;&#39;");
    }

    #[test]
    fn xml11_controls_as_references() {
        // C0 controls get &#xHH; instead of space
        assert_eq!(for_xml11("a\x01b"), "a&#x1;b");
        assert_eq!(for_xml11("a\x08b"), "a&#x8;b");
        assert_eq!(for_xml11("a\x0Bb"), "a&#xb;b");
        assert_eq!(for_xml11("a\x1Fb"), "a&#x1f;b");
    }

    #[test]
    fn xml11_nel_passes_through() {
        // NEL (U+0085) is NOT restricted in XML 1.1
        assert_eq!(for_xml11("a\u{0085}b"), "a\u{0085}b");
    }

    #[test]
    fn xml11_del_and_c1_as_references() {
        assert_eq!(for_xml11("a\x7Fb"), "a&#x7f;b");
        assert_eq!(for_xml11("a\u{0080}b"), "a&#x80;b");
        assert_eq!(for_xml11("a\u{009F}b"), "a&#x9f;b");
    }

    #[test]
    fn xml11_nul_replaced_with_space() {
        assert_eq!(for_xml11("a\x00b"), "a b");
    }

    #[test]
    fn xml11_nonchars_replaced_with_space() {
        assert_eq!(for_xml11("a\u{FDD0}b"), "a b");
    }

    #[test]
    fn xml11_preserves_tab_lf_cr() {
        assert_eq!(for_xml11("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn xml11_content_no_quotes() {
        assert_eq!(for_xml11_content(r#"a"b'c"#), r#"a"b'c"#);
        assert_eq!(for_xml11_content("a\x01b"), "a&#x1;b");
    }

    #[test]
    fn xml11_attribute_no_gt() {
        assert_eq!(for_xml11_attribute("a>b"), "a>b");
        assert_eq!(for_xml11_attribute("a\x01b"), "a&#x1;b");
    }
}
