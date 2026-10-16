//! javascript contextual output encoders.
//!
//! provides five encoding contexts:
//!
//! - [`for_javascript`] — universal encoder, safe in HTML attributes, script
//!   blocks, and standalone .js files
//! - [`for_javascript_attribute`] — optimized for HTML event attributes
//!   (e.g., `onclick="..."`)
//! - [`for_javascript_block`] — optimized for `<script>` blocks
//! - [`for_javascript_source`] — optimized for standalone .js files
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
//! - `for_javascript_attribute` does not escape `<` or `/` and is **not safe
//!   in `<script>` blocks** where `</script>` could appear.
//! - `for_javascript_source` does not escape `&`, so it is **not safe in an
//!   XHTML `<script>`**, where character references are decoded before
//!   javascript sees the text. the other four encoders escape it.
//! - all five encoders escape the bidi formatting controls (U+202A-U+202E,
//!   U+2066-U+2069) as `\uHHHH`, so a direction override in the data cannot
//!   reorder how the generated javascript reads.
//! - none of these encoders produce valid JSON — the `\xHH` escapes they emit
//!   for control characters are not permitted in JSON. use
//!   [`for_json`](crate::for_json) for JSON string values.

use std::fmt;

use crate::engine::{encode_loop, is_text_direction_control};

/// configuration flags controlling context-specific encoding differences.
#[derive(Clone, Copy)]
struct JsConfig {
    /// true: `"` → `\x22`, `'` → `\x27` (safe in HTML attributes).
    /// false: `"` → `\"`, `'` → `\'` (more readable, not HTML-attr safe).
    hex_quotes: bool,
    /// true: encode `&` as `\x26` (prevents HTML entity interpretation).
    encode_ampersand: bool,
    /// true: the output can land in HTML script data, so encode every
    /// character that can move the tokenizer out of it — `<` → `\x3c` and
    /// `/` → `\/`.
    script_data: bool,
}

const JS_UNIVERSAL: JsConfig = JsConfig {
    hex_quotes: true,
    encode_ampersand: true,
    script_data: true,
};

const JS_ATTRIBUTE: JsConfig = JsConfig {
    hex_quotes: true,
    encode_ampersand: true,
    script_data: false,
};

const JS_BLOCK: JsConfig = JsConfig {
    hex_quotes: false,
    encode_ampersand: true,
    script_data: true,
};

const JS_SOURCE: JsConfig = JsConfig {
    hex_quotes: false,
    encode_ampersand: false,
    script_data: false,
};

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
/// - `<` → `\x3c`, `/` → `\/` (keeps the HTML tokenizer in script data state,
///   so the enclosing `</script>` still closes the block)
/// - `\` → `\\`
/// - U+2028 → `\u2028`, U+2029 → `\u2029` (javascript line terminators)
/// - bidi formatting controls (U+202A-U+202E, U+2066-U+2069) → `\uHHHH`
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
///            r"it\x27s \x22unsafe\x22 \x3c\/script>");
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

/// encodes `input` for safe embedding in a javascript string literal inside
/// an HTML event attribute (e.g., `onclick="..."`).
///
/// identical to [`for_javascript`] except `<` and `/` are **not** escaped. an
/// attribute value is never tokenized as script data, so neither character can
/// affect where the enclosing element ends.
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
/// assert_eq!(for_javascript_attribute("a<b"), "a<b");
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

/// encodes `input` for safe embedding in a javascript string literal inside
/// an HTML `<script>` block.
///
/// uses backslash escapes for quotes (`\"`, `\'`) which are more readable
/// but **not safe in HTML attribute contexts**. still encodes `&` (for XHTML
/// compatibility) and `<`/`/`, which keep the HTML tokenizer in script data
/// state so the enclosing `</script>` still closes the block.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_javascript_block;
///
/// assert_eq!(for_javascript_block(r#"he said "hi""#), r#"he said \"hi\""#);
/// assert_eq!(for_javascript_block("</script>"), r"\x3c\/script>");
/// assert_eq!(for_javascript_block("<!--<script>"), r"\x3c!--\x3cscript>");
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

/// encodes `input` for safe embedding in a javascript string literal in a
/// standalone .js file.
///
/// the most minimal javascript encoder — does not encode `<`, `/` or `&`
/// since a standalone .js file is never HTML-tokenized. **not safe for any
/// HTML-embedded context.**
///
/// **not a JSON encoder.** it emits `\'` for single quotes and `\xHH` for
/// control characters, neither of which JSON permits. use
/// [`for_json`](crate::for_json) for JSON string values.
///
/// # examples
///
/// ```
/// use contextual_encoder::{for_javascript_source, for_json};
///
/// assert_eq!(for_javascript_source("a/b&c<d"), "a/b&c<d");
/// assert_eq!(for_javascript_source("line\nbreak"), r"line\nbreak");
///
/// assert_eq!(for_javascript_source("it's"), r"it\'s");
/// assert_eq!(for_json("it's"), "it's");
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
/// - `$` followed by `{`, and `$` at the end of the input → `\$` (prevents
///   expression interpolation, including a `${` the caller completes)
/// - `\` → `\\`
/// - `<` → `\x3c`, `/` → `\/` (keeps the HTML tokenizer in script data state,
///   so the enclosing `</script>` still closes the block)
/// - `&` → `\x26` (stops an XHTML parser decoding a character reference into
///   a `` ` `` or a `${` before javascript sees the text)
/// - C0 controls → named escapes (`\b`, `\t`, `\n`, `\f`, `\r`) or hex
///   (`\xHH`)
/// - U+2028 → `\u2028`, U+2029 → `\u2029` (line/paragraph separators)
/// - bidi formatting controls (U+202A-U+202E, U+2066-U+2069) → `\uHHHH`
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
/// // `\x26` is `&` in a template literal, so the decoded value is unchanged
/// assert_eq!(for_js_template("a&b"), r"a\x26b");
/// assert_eq!(for_js_template("&#96;"), r"\x26#96;");
/// assert_eq!(for_js_template("a $ b"), "a $ b");
/// // `\$` is `$` in a template literal, so the decoded value is unchanged
/// assert_eq!(for_js_template("cost: $"), r"cost: \$");
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
        '\x00'..='\x1F' | '\\' | '`' | '$' | '&' | '/' | '<' | '\u{2028}' | '\u{2029}'
    ) || is_text_direction_control(c)
}

fn write_js_template_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    next: Option<char>,
) -> fmt::Result {
    match c {
        // template-specific characters
        '`' => out.write_str("\\`"),
        '$' if matches!(next, Some('{') | None) => out.write_str("\\$"),
        '$' => out.write_char('$'),
        '&' => out.write_str("\\x26"),
        '/' => out.write_str("\\/"),
        '<' => out.write_str("\\x3c"),
        c => write_js_shared_escape(out, c),
    }
}

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
        '/' | '<' => config.script_data,
        c => is_text_direction_control(c),
    }
}

fn write_js_encoded<W: fmt::Write>(out: &mut W, c: char, config: &JsConfig) -> fmt::Result {
    match c {
        // string-literal-specific characters
        '"' if config.hex_quotes => out.write_str("\\x22"),
        '"' => out.write_str("\\\""),
        '\'' if config.hex_quotes => out.write_str("\\x27"),
        '\'' => out.write_str("\\'"),
        '&' => out.write_str("\\x26"),
        '/' => out.write_str("\\/"),
        '<' => out.write_str("\\x3c"),
        c => write_js_shared_escape(out, c),
    }
}

/// writes the escape shared by both js encoders. any other character falls back
/// to `\u{...}` so a character a predicate flags can never be dropped from the
/// output.
fn write_js_shared_escape<W: fmt::Write>(out: &mut W, c: char) -> fmt::Result {
    match c {
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\x0B' => out.write_str("\\x0b"),
        '\x0C' => out.write_str("\\f"),
        '\r' => out.write_str("\\r"),
        '\\' => out.write_str("\\\\"),
        '\u{2028}' => out.write_str("\\u2028"),
        '\u{2029}' => out.write_str("\\u2029"),
        '\x00'..='\x1F' => write!(out, "\\x{:02x}", c as u32),
        c if is_text_direction_control(c) => write!(out, "\\u{:04x}", c as u32),
        c => write!(out, "\\u{{{:x}}}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type ForFn = fn(&str) -> String;

    /// the bidi formatting controls, with their escaped forms.
    const TEXT_DIRECTION: [(&str, &str); 9] = [
        ("\u{202A}", r"\u202a"),
        ("\u{202B}", r"\u202b"),
        ("\u{202C}", r"\u202c"),
        ("\u{202D}", r"\u202d"),
        ("\u{202E}", r"\u202e"),
        ("\u{2066}", r"\u2066"),
        ("\u{2067}", r"\u2067"),
        ("\u{2068}", r"\u2068"),
        ("\u{2069}", r"\u2069"),
    ];

    #[test]
    fn escapes_text_direction_controls() {
        let encoders: [(&str, ForFn); 5] = [
            ("javascript", for_javascript),
            ("javascript_attribute", for_javascript_attribute),
            ("javascript_block", for_javascript_block),
            ("javascript_source", for_javascript_source),
            ("js_template", for_js_template),
        ];
        for (name, encode) in encoders {
            for (raw, escaped) in TEXT_DIRECTION {
                assert_eq!(encode(raw), escaped, "{name}: {raw:?}");
                assert_eq!(
                    encode(&format!("a{raw}b")),
                    format!("a{escaped}b"),
                    "{name}: a{raw:?}b"
                );
            }
        }
        for (raw, escaped) in TEXT_DIRECTION {
            assert_eq!(
                for_javascript_source(&format!("var x = '{raw}';")),
                format!(r"var x = \'{escaped}\';")
            );
        }
    }

    // -- for_javascript_block --

    #[test]
    fn js_block_encodes_slash() {
        assert_eq!(for_javascript_block("a/b"), r"a\/b");
    }

    // -- for_javascript_source --

    #[test]
    fn js_source_uses_backslash_quotes() {
        assert_eq!(for_javascript_source(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_javascript_source("a'b"), r"a\'b");
    }

    // -- write_js_shared_escape helper --

    #[test]
    fn shared_escape_never_drops_a_character() {
        for (c, expected) in [('a', r"\u{61}"), ('"', r"\u{22}"), ('é', r"\u{e9}")] {
            let mut out = String::new();
            assert_eq!(write_js_shared_escape(&mut out, c), Ok(()));
            assert_eq!(out, expected);
        }
    }
}
