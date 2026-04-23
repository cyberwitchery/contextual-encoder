//! javascript contextual output encoders.
//!
//! provides five encoding contexts:
//!
//! - [`for_javascript`] — universal encoder, safe in HTML attributes, script
//!   blocks, and standalone .js files
//! - [`for_javascript_attribute`] — optimized for HTML event attributes
//!   (e.g., `onclick="..."`)
//! - [`for_javascript_block`] — optimized for `<script>` blocks
//! - [`for_javascript_source`] — optimized for standalone .js / JSON files
//! - [`for_js_template`] — for ES6 template literal content (`` `...` ``)
//!
//! # security notes
//!
//! - the string literal encoders ([`for_javascript`], [`for_javascript_attribute`],
//!   [`for_javascript_block`], [`for_javascript_source`]) do **not** encode the
//!   grave accent (`` ` ``). do not use them to embed data inside template
//!   literals — use [`for_js_template`] instead.
//! - these encoders are for string/template literal contexts only. they cannot
//!   make arbitrary javascript expressions, variable names, or property
//!   accessors safe.
//! - `for_javascript_block` and `for_javascript_source` use backslash escapes
//!   for quotes (`\"`, `\'`) which are **not safe in HTML attribute contexts**.
//! - `for_javascript_attribute` does not escape `/` and is **not safe in
//!   `<script>` blocks** where `</script>` could appear.

use std::fmt;

use crate::engine::encode_loop;

/// configuration flags controlling context-specific encoding differences.
#[derive(Clone, Copy)]
struct JsConfig {
    /// true: `"` → `\x22`, `'` → `\x27` (safe in HTML attributes).
    /// false: `"` → `\"`, `'` → `\'` (more readable, not HTML-attr safe).
    hex_quotes: bool,
    /// true: encode `&` as `\x26` (prevents HTML entity interpretation).
    encode_ampersand: bool,
    /// true: encode `/` as `\/` (prevents `</script>` injection).
    encode_slash: bool,
}

const JS_UNIVERSAL: JsConfig = JsConfig {
    hex_quotes: true,
    encode_ampersand: true,
    encode_slash: true,
};

const JS_ATTRIBUTE: JsConfig = JsConfig {
    hex_quotes: true,
    encode_ampersand: true,
    encode_slash: false,
};

const JS_BLOCK: JsConfig = JsConfig {
    hex_quotes: false,
    encode_ampersand: true,
    encode_slash: true,
};

const JS_SOURCE: JsConfig = JsConfig {
    hex_quotes: false,
    encode_ampersand: false,
    encode_slash: false,
};

// ---------------------------------------------------------------------------
// for_javascript — universal encoder (safe everywhere)
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a javascript string literal.
///
/// this is the universal javascript encoder — its output is safe in HTML
/// event attributes, `<script>` blocks, and standalone .js files. it is
/// slightly more conservative than the context-specific encoders.
///
/// # encoding rules
///
/// - C0 controls → named escapes (`\b`, `\t`, `\n`, `\f`, `\r`) or hex
///   (`\xHH`)
/// - `"` → `\x22`, `'` → `\x27` (hex escapes for HTML attribute safety)
/// - `&` → `\x26` (prevents HTML entity interpretation)
/// - `/` → `\/` (prevents `</script>` injection)
/// - `\` → `\\`
/// - U+2028 → `\u2028`, U+2029 → `\u2029` (javascript line terminators)
///
/// # caveat: template literals
///
/// this encoder does **not** encode the grave accent (`` ` ``). never
/// embed untrusted data directly inside template literals. instead:
///
/// ```js
/// // WRONG — vulnerable to XSS:
/// // `Hello ${unsafeInput}`
/// //
/// // RIGHT — encode into a variable first:
/// // var x = '<encoded>';
/// // `Hello ${x}`
/// ```
///
/// # examples
///
/// ```
/// use contextual_encoder::for_javascript;
///
/// assert_eq!(for_javascript(r#"it's "unsafe" </script>"#),
///            r"it\x27s \x22unsafe\x22 <\/script>");
/// assert_eq!(for_javascript("safe"), "safe");
/// ```
pub fn for_javascript(input: &str) -> String {
    encode_js(input, &JS_UNIVERSAL)
}

/// writes the javascript-encoded form of `input` to `out`.
///
/// see [`for_javascript`] for encoding rules.
pub fn write_javascript<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    write_js(out, input, &JS_UNIVERSAL)
}

// ---------------------------------------------------------------------------
// for_javascript_attribute — optimized for HTML event attributes
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a javascript string literal inside
/// an HTML event attribute (e.g., `onclick="..."`).
///
/// identical to [`for_javascript`] except `/` is **not** escaped (not
/// needed in event attributes where `</script>` is not a concern).
///
/// **not safe in `<script>` blocks** — use [`for_javascript`] or
/// [`for_javascript_block`] instead.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_javascript_attribute;
///
/// assert_eq!(for_javascript_attribute("a/b"), "a/b");
/// assert_eq!(for_javascript_attribute("a'b"), r"a\x27b");
/// ```
pub fn for_javascript_attribute(input: &str) -> String {
    encode_js(input, &JS_ATTRIBUTE)
}

/// writes the javascript-attribute-encoded form of `input` to `out`.
///
/// see [`for_javascript_attribute`] for encoding rules.
pub fn write_javascript_attribute<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    write_js(out, input, &JS_ATTRIBUTE)
}

// ---------------------------------------------------------------------------
// for_javascript_block — optimized for <script> blocks
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a javascript string literal inside
/// an HTML `<script>` block.
///
/// uses backslash escapes for quotes (`\"`, `\'`) which are more readable
/// but **not safe in HTML attribute contexts**. still encodes `&` (for XHTML
/// compatibility) and `/` (to prevent `</script>` injection).
///
/// # examples
///
/// ```
/// use contextual_encoder::for_javascript_block;
///
/// assert_eq!(for_javascript_block(r#"he said "hi""#), r#"he said \"hi\""#);
/// assert_eq!(for_javascript_block("</script>"), r"<\/script>");
/// ```
pub fn for_javascript_block(input: &str) -> String {
    encode_js(input, &JS_BLOCK)
}

/// writes the javascript-block-encoded form of `input` to `out`.
///
/// see [`for_javascript_block`] for encoding rules.
pub fn write_javascript_block<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    write_js(out, input, &JS_BLOCK)
}

// ---------------------------------------------------------------------------
// for_javascript_source — optimized for standalone .js files
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a javascript string literal in a
/// standalone .js or JSON file.
///
/// the most minimal javascript encoder — does not encode `/` or `&` since
/// there is no HTML context. **not safe for any HTML-embedded context.**
///
/// # examples
///
/// ```
/// use contextual_encoder::for_javascript_source;
///
/// assert_eq!(for_javascript_source("a/b&c"), "a/b&c");
/// assert_eq!(for_javascript_source("line\nbreak"), r"line\nbreak");
/// ```
pub fn for_javascript_source(input: &str) -> String {
    encode_js(input, &JS_SOURCE)
}

/// writes the javascript-source-encoded form of `input` to `out`.
///
/// see [`for_javascript_source`] for encoding rules.
pub fn write_javascript_source<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    write_js(out, input, &JS_SOURCE)
}

// ---------------------------------------------------------------------------
// for_js_template — ES6 template literal encoder
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding inside an ES6 template literal
/// (`` `...` ``).
///
/// template literals use backticks as delimiters and `${...}` for
/// interpolation. this encoder escapes both so untrusted data cannot break
/// out of the literal or inject expressions.
///
/// # encoding rules
///
/// - `` ` `` → `` \` `` (prevents breaking out of the template literal)
/// - `$` followed by `{` → `\${` (prevents expression interpolation)
/// - `\` → `\\`
/// - `/` → `\/` (prevents `</script>` injection)
/// - C0 controls → named escapes (`\b`, `\t`, `\n`, `\f`, `\r`) or hex
///   (`\xHH`)
/// - U+2028 → `\u2028`, U+2029 → `\u2029` (line/paragraph separators)
///
/// unlike the string literal encoders, this does **not** escape `"` or `'`
/// (they are ordinary characters inside template literals).
///
/// # examples
///
/// ```
/// use contextual_encoder::for_js_template;
///
/// assert_eq!(for_js_template("hello `world`"), r"hello \`world\`");
/// assert_eq!(for_js_template("${alert(1)}"), r"\${alert(1)}");
/// assert_eq!(for_js_template("safe"), "safe");
/// assert_eq!(for_js_template("a $ b"), "a $ b");
/// ```
pub fn for_js_template(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_js_template(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the template-literal-encoded form of `input` to `out`.
///
/// see [`for_js_template`] for encoding rules.
pub fn write_js_template<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_js_template_encoding,
        write_js_template_encoded,
    )
}

fn needs_js_template_encoding(c: char) -> bool {
    matches!(
        c,
        '\x00'..='\x1F' | '\\' | '`' | '$' | '/' | '\u{2028}' | '\u{2029}'
    )
}

fn write_js_template_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    next: Option<char>,
) -> fmt::Result {
    match c {
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\x0b"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '`' => out.write_str("\\`"),
        '$' if next == Some('{') => out.write_str("\\$"),
        '$' => out.write_char('$'),
        '/' => out.write_str("\\/"),
        '\\' => out.write_str("\\\\"),
        '\u{2028}' => out.write_str("\\u2028"),
        '\u{2029}' => out.write_str("\\u2029"),
        // other C0 controls
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

// ---------------------------------------------------------------------------
// shared implementation (string literal encoders)
// ---------------------------------------------------------------------------

fn encode_js(input: &str, config: &JsConfig) -> String {
    let mut out = String::with_capacity(input.len());
    write_js(&mut out, input, config).expect("writing to string cannot fail");
    out
}

fn write_js<W: fmt::Write>(out: &mut W, input: &str, config: &JsConfig) -> fmt::Result {
    encode_loop(
        out,
        input,
        |c| needs_js_encoding(c, config),
        |out, c, _next| write_js_encoded(out, c, config),
    )
}

fn needs_js_encoding(c: char, config: &JsConfig) -> bool {
    match c {
        '\x00'..='\x1F' | '\\' | '"' | '\'' | '\u{2028}' | '\u{2029}' => true,
        '&' => config.encode_ampersand,
        '/' => config.encode_slash,
        _ => false,
    }
}

fn write_js_encoded<W: fmt::Write>(out: &mut W, c: char, config: &JsConfig) -> fmt::Result {
    match c {
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\x0b"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '"' if config.hex_quotes => out.write_str("\\x22"),
        '"' => out.write_str("\\\""),
        '\'' if config.hex_quotes => out.write_str("\\x27"),
        '\'' => out.write_str("\\'"),
        '&' => out.write_str("\\x26"),
        '/' => out.write_str("\\/"),
        '\\' => out.write_str("\\\\"),
        '\u{2028}' => out.write_str("\\u2028"),
        '\u{2029}' => out.write_str("\\u2029"),
        // other C0 controls
        c => write!(out, "\\x{:02x}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_javascript (universal) --

    #[test]
    fn js_no_encoding_needed() {
        assert_eq!(for_javascript("hello world"), "hello world");
        assert_eq!(for_javascript(""), "");
    }

    #[test]
    fn js_encodes_quotes_as_hex() {
        assert_eq!(for_javascript(r#"a"b"#), r"a\x22b");
        assert_eq!(for_javascript("a'b"), r"a\x27b");
    }

    #[test]
    fn js_encodes_backslash() {
        assert_eq!(for_javascript(r"a\b"), r"a\\b");
    }

    #[test]
    fn js_encodes_ampersand() {
        assert_eq!(for_javascript("a&b"), r"a\x26b");
    }

    #[test]
    fn js_encodes_slash() {
        assert_eq!(for_javascript("</script>"), r"<\/script>");
    }

    #[test]
    fn js_encodes_control_chars() {
        assert_eq!(for_javascript("\x00"), r"\x00");
        assert_eq!(for_javascript("\x08"), r"\b");
        assert_eq!(for_javascript("\t"), r"\t");
        assert_eq!(for_javascript("\n"), r"\n");
        assert_eq!(for_javascript("\x0B"), r"\x0b");
        assert_eq!(for_javascript("\x0C"), r"\f");
        assert_eq!(for_javascript("\r"), r"\r");
        assert_eq!(for_javascript("\x1F"), r"\x1f");
    }

    #[test]
    fn js_encodes_line_separators() {
        assert_eq!(for_javascript("\u{2028}"), r"\u2028");
        assert_eq!(for_javascript("\u{2029}"), r"\u2029");
    }

    #[test]
    fn js_preserves_non_ascii() {
        assert_eq!(for_javascript("café"), "café");
        assert_eq!(for_javascript("日本語"), "日本語");
    }

    #[test]
    fn js_writer_variant() {
        let mut out = String::new();
        write_javascript(&mut out, "a'b").unwrap();
        assert_eq!(out, r"a\x27b");
    }

    // -- for_javascript_attribute --

    #[test]
    fn js_attr_does_not_encode_slash() {
        assert_eq!(for_javascript_attribute("a/b"), "a/b");
    }

    #[test]
    fn js_attr_encodes_quotes_as_hex() {
        assert_eq!(for_javascript_attribute("a'b"), r"a\x27b");
    }

    #[test]
    fn js_attr_encodes_ampersand() {
        assert_eq!(for_javascript_attribute("a&b"), r"a\x26b");
    }

    // -- for_javascript_block --

    #[test]
    fn js_block_uses_backslash_quotes() {
        assert_eq!(for_javascript_block(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_javascript_block("a'b"), r"a\'b");
    }

    #[test]
    fn js_block_encodes_slash() {
        assert_eq!(for_javascript_block("a/b"), r"a\/b");
    }

    #[test]
    fn js_block_encodes_ampersand() {
        assert_eq!(for_javascript_block("a&b"), r"a\x26b");
    }

    // -- for_javascript_source --

    #[test]
    fn js_source_uses_backslash_quotes() {
        assert_eq!(for_javascript_source(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_javascript_source("a'b"), r"a\'b");
    }

    #[test]
    fn js_source_does_not_encode_slash_or_ampersand() {
        assert_eq!(for_javascript_source("a/b&c"), "a/b&c");
    }

    #[test]
    fn js_source_encodes_line_separators() {
        assert_eq!(for_javascript_source("\u{2028}"), r"\u2028");
    }

    // -- for_js_template --

    #[test]
    fn js_template_no_encoding_needed() {
        assert_eq!(for_js_template("hello world"), "hello world");
        assert_eq!(for_js_template(""), "");
    }

    #[test]
    fn js_template_encodes_backtick() {
        assert_eq!(for_js_template("hello `world`"), r"hello \`world\`");
        assert_eq!(for_js_template("`"), r"\`");
    }

    #[test]
    fn js_template_encodes_interpolation() {
        assert_eq!(for_js_template("${alert(1)}"), r"\${alert(1)}");
        assert_eq!(for_js_template("a${b}c"), r"a\${b}c");
        assert_eq!(for_js_template("${a}${b}"), r"\${a}\${b}");
    }

    #[test]
    fn js_template_dollar_without_brace_passes_through() {
        assert_eq!(for_js_template("a $ b"), "a $ b");
        assert_eq!(for_js_template("$100"), "$100");
        assert_eq!(for_js_template("a$"), "a$");
    }

    #[test]
    fn js_template_encodes_backslash() {
        assert_eq!(for_js_template(r"a\b"), r"a\\b");
    }

    #[test]
    fn js_template_encodes_slash() {
        assert_eq!(for_js_template("</script>"), r"<\/script>");
    }

    #[test]
    fn js_template_does_not_encode_quotes() {
        assert_eq!(for_js_template(r#"a"b"#), r#"a"b"#);
        assert_eq!(for_js_template("a'b"), "a'b");
    }

    #[test]
    fn js_template_encodes_control_chars() {
        assert_eq!(for_js_template("\x00"), r"\x00");
        assert_eq!(for_js_template("\x08"), r"\b");
        assert_eq!(for_js_template("\t"), r"\t");
        assert_eq!(for_js_template("\n"), r"\n");
        assert_eq!(for_js_template("\x0B"), r"\x0b");
        assert_eq!(for_js_template("\x0C"), r"\f");
        assert_eq!(for_js_template("\r"), r"\r");
        assert_eq!(for_js_template("\x1F"), r"\x1f");
    }

    #[test]
    fn js_template_encodes_line_separators() {
        assert_eq!(for_js_template("\u{2028}"), r"\u2028");
        assert_eq!(for_js_template("\u{2029}"), r"\u2029");
    }

    #[test]
    fn js_template_preserves_non_ascii() {
        assert_eq!(for_js_template("café"), "café");
        assert_eq!(for_js_template("日本語"), "日本語");
        assert_eq!(for_js_template("😀"), "😀");
    }

    #[test]
    fn js_template_mixed_input() {
        assert_eq!(
            for_js_template("`Hello ${name}`, welcome\\n"),
            r"\`Hello \${name}\`, welcome\\n"
        );
    }

    #[test]
    fn js_template_writer_variant() {
        let input = "`test` ${x} café";
        let string_result = for_js_template(input);
        let mut writer_result = String::new();
        write_js_template(&mut writer_result, input).unwrap();
        assert_eq!(string_result, writer_result);
    }
}
