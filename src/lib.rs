#![forbid(unsafe_code)]

//! contextual output encoding for XSS defense and safe literal embedding.
//!
//! this crate provides context-aware encoding functions whose web encoders are
//! derived from the [OWASP Java Encoder](https://owasp.org/owasp-java-encoder/).
//! each function encodes input for safe embedding in a specific output
//! context — web contexts (HTML, XML, JavaScript, CSS, URI) and source literal
//! contexts (JSON, Rust, SQL).
//!
//! **disclaimer:** contextual-encoder is an independent Rust crate. its API and security model
//! are derived from the OWASP Java Encoder, but this project is not affiliated with,
//! endorsed by, or maintained by the OWASP Foundation.
//!
//! # quick start
//!
//! ```
//! use contextual_encoder::{for_html, for_javascript, for_css_string, for_uri_component};
//!
//! let user_input = "<script>alert('xss')</script>";
//!
//! // safe for HTML text content and quoted attributes
//! let html_safe = for_html(user_input);
//! assert!(html_safe.contains("&lt;script&gt;"));
//!
//! // safe for javascript string literals (universal)
//! let js_safe = for_javascript(user_input);
//! assert!(js_safe.contains(r"\x3c\/script>"));
//!
//! // safe for quoted CSS string values
//! let css_safe = for_css_string(user_input);
//! assert!(css_safe.contains(r"\3c"));
//!
//! // safe as a URI query parameter value
//! let uri_safe = for_uri_component(user_input);
//! assert!(uri_safe.contains("%3C"));
//! ```
//!
//! # available contexts
//!
//! ## HTML
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_html`] | text content + quoted attributes |
//! | [`for_html_content`] | text content only |
//! | [`for_html_attribute`] | quoted attributes only |
//! | [`for_html_unquoted_attribute`] | unquoted attribute values |
//!
//! all encoders replace invalid XML characters (C0/C1 controls, DEL, unicode
//! non-characters) with a replacement character (space or dash depending on
//! context).
//!
//! ### security notes
//!
//! - these encoders produce output safe for embedding in the specified context.
//!   they do not sanitize HTML — encoding is not a substitute for input validation.
//! - never use `for_html_content` output in an attribute context.
//! - never use `for_html_attribute` output in a text content context where `>` matters.
//! - `for_html` is the safe default when the exact context is unknown.
//! - tag names, attribute names, and event handler names must be validated
//!   separately — encoding cannot make arbitrary names safe.
//!
//! ## XML
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_xml`] | XML text content + quoted attributes (alias for `for_html`) |
//! | [`for_xml_content`] | XML text content only (alias for `for_html_content`) |
//! | [`for_xml_attribute`] | quoted XML attributes only (alias for `for_html_attribute`) |
//! | [`for_xml_comment`] | XML comment content |
//! | [`for_cdata`] | CDATA section content |
//!
//! ### security notes
//!
//! - `for_xml_comment` is **not safe for HTML comments**. HTML comments have
//!   vendor-specific extensions (e.g., `<!--[if IE]>`) that make safe encoding
//!   impractical. this encoder is for XML comments only.
//! - `for_cdata` splits the CDATA section at every `]` and `>`, so its output
//!   can be up to 13 times longer than the input. the caller is responsible
//!   for wrapping the output in `<![CDATA[...]]>`.
//!
//! ## XML 1.1
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_xml11`] | XML 1.1 content + quoted attributes |
//! | [`for_xml11_content`] | XML 1.1 content only |
//! | [`for_xml11_attribute`] | XML 1.1 quoted attributes only |
//!
//! ## JavaScript
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_javascript`] | general JS string contexts |
//! | [`for_javascript_attribute`] | HTML event attributes |
//! | [`for_javascript_block`] | `<script>` blocks |
//! | [`for_javascript_source`] | standalone .js files |
//! | [`for_js_template`] | ES6 template literal content (`` `...` ``) |
//!
//! ### security notes
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
//!   [`for_json`] for JSON string values.
//!
//! ## CSS
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_css_string`] | quoted CSS string values |
//! | [`for_css_url`] | CSS `url()` values, quoted or unquoted |
//!
//! both use CSS hex escape syntax (`\XX`) with a trailing space appended
//! when the next character could be misinterpreted as part of the hex value,
//! or when the escape ends the output.
//!
//! ### security notes
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
//!
//! ## URI
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_uri_component`] | URI components (query params, path segments) |
//! | [`for_uri_path`] | URI paths (preserves `/` separators) |
//! | [`for_form_urlencoded`] | `application/x-www-form-urlencoded` values |
//!
//! provides percent-encoding for URI components and paths per RFC 3986, and
//! for form values per the WHATWG URL Standard
//! (`application/x-www-form-urlencoded`).
//!
//! ### security notes
//!
//! - these encoders are for **URI components, paths, and form values**, not
//!   entire URLs.
//! - they **cannot** make an untrusted full URL safe. a `javascript:` URL will
//!   be percent-encoded but still execute. always validate the URL scheme and
//!   structure separately before embedding untrusted URLs.
//! - the output is safe for direct embedding in HTML, CSS, and javascript
//!   contexts because all context-significant characters are percent-encoded.
//!
//! ## additional literal contexts
//!
//! these encoders are not part of the OWASP Java Encoder's scope. they encode
//! untrusted strings for safe embedding in source code literals.
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_json`] | JSON string values |
//! | [`for_rust_string`] | Rust string literals (`"..."`) |
//! | [`for_rust_char`] | Rust char literals (`'...'`), input must be exactly one character |
//! | [`for_rust_char_checked`] | Rust char literals, `None` unless the input is exactly one character |
//! | [`for_rust_byte_string`] | Rust byte string literals (`b"..."`) |
//! | [`for_sql`] | Standard SQL string literals (`'...'`) |
//! | [`for_sql_backslash`] | MySQL/MariaDB string literals with backslash escaping (`'...'`) |
//!
//! ### JSON
//!
//! #### why not `for_javascript_source`?
//!
//! JSON looks like JavaScript but has two critical encoding differences:
//!
//! - **no `\x` escapes.** JSON only supports `\uHHHH` for unicode escapes.
//!   the `\xHH` form that JavaScript uses for control characters is invalid JSON.
//! - **no single-quote escaping.** `\'` is not a valid JSON escape sequence.
//!   single quotes are ordinary characters in JSON strings.
//!
//! using `for_javascript_source` for JSON output produces strings that may be
//! rejected by strict JSON parsers.
//!
//! #### encoding rules
//!
//! - named escapes: `\b`, `\t`, `\n`, `\f`, `\r`, `\"`, `\\`
//! - other C0 controls (U+0000–U+001F) → `\u00HH`
//! - `<` → `\u003c`, `/` → `\/` (keeps the HTML tokenizer in script data
//!   state when JSON is embedded in an HTML `<script>` block, so the block's
//!   `</script>` still closes it. RFC 8259 §7 explicitly permits `\/`)
//! - U+2028 → `\u2028`, U+2029 → `\u2029` (line/paragraph separators;
//!   mandatory because JSON is often embedded in `<script>` blocks where
//!   these would terminate the JavaScript string literal)
//! - all other characters pass through unchanged
//!
//! ### Rust
//!
//! #### encoding rules
//!
//! all three encoders use rust's native escape syntax:
//!
//! - named escapes: `\0`, `\t`, `\n`, `\r`, `\\`
//! - C0 controls and DEL without named escapes → `\xHH`
//! - unicode non-characters → space (string/char) or `\xHH` per byte (byte string)
//! - bidi formatting controls → `\u{HHHH}` (string/char) or `\xHH` per byte
//!   (byte string)
//!
//! the encoders differ in which quote is escaped and how non-ASCII is handled:
//!
//! | encoder | quote escape | non-ASCII |
//! |---------|-------------|-----------|
//! | `for_rust_string` | `"` → `\"` | passes through |
//! | `for_rust_char` | `'` → `\'` | passes through |
//! | `for_rust_byte_string` | `"` → `\"` | each UTF-8 byte → `\xHH` |
//!
//! #### char literal length
//!
//! a rust char literal holds exactly one unicode scalar value, so the char
//! encoders require input of exactly one character. empty or longer input
//! encodes to a literal body that does not compile.
//!
//! ### SQL
//!
//! #### encoding rules
//!
//! ##### standard SQL (`for_sql`)
//!
//! standard SQL escapes single quotes by doubling them:
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `'` | `''` |
//! | NUL (`\0`) | removed |
//! | unicode non-characters | space |
//!
//! all other characters (including backslash) pass through unchanged — they
//! have no special meaning in standard SQL string literals.
//!
//! ##### MySQL/MariaDB backslash escaping (`for_sql_backslash`)
//!
//! MySQL and MariaDB (when `NO_BACKSLASH_ESCAPES` is not set) use C-style
//! backslash escape sequences:
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `'` | `\'` |
//! | `\` | `\\` |
//! | NUL (`\0`) | `\0` |
//! | newline (`\n`) | `\n` |
//! | carriage return (`\r`) | `\r` |
//! | tab (`\t`) | `\t` |
//! | backspace (`\x08`) | `\b` |
//! | Control-Z (`\x1A`) | `\Z` |
//! | unicode non-characters | space |
//!
//! #### security notes
//!
//! - **parameterized queries are always preferred.** these encoders exist for
//!   cases where parameterized queries are not possible (e.g. string literals
//!   in DDL, legacy code).
//! - **identifiers cannot be encoded.** these encoders are for string literal
//!   values. a table or column name is delimited by `"..."` (standard) or
//!   `` `...` `` (MySQL), and neither delimiter is escaped — both pass through
//!   unchanged. validate an untrusted identifier against a whitelist instead.
//! - **know your dialect.** use `for_sql` for databases that follow the SQL
//!   standard (PostgreSQL, SQLite, SQL Server, Oracle). use
//!   `for_sql_backslash` for MySQL/MariaDB when `NO_BACKSLASH_ESCAPES` is
//!   not enabled.
//! - **do not use `for_sql` with MySQL** unless `NO_BACKSLASH_ESCAPES` is
//!   set — a backslash can be used to escape the closing quote.
//!
//! # security model
//!
//! this is a **contextual output encoder**, not a sanitizer. it prevents
//! cross-site scripting by encoding output for specific contexts, but it
//! does not validate or sanitize input.
//!
//! **important caveats:**
//!
//! - **encoding is not sanitization.** encoding `<script>` as `&lt;script&gt;`
//!   makes it display safely in HTML, but does not remove it. if you need to
//!   allow a subset of HTML, use a dedicated sanitizer.
//! - **context matters.** using the wrong encoder for a context can leave
//!   you vulnerable. `for_html_content` output is not safe in attributes.
//! - **tag and attribute names cannot be encoded.** never pass untrusted data
//!   as a tag name, attribute name, or event handler name. validate these
//!   against a whitelist.
//! - **SQL identifiers cannot be encoded.** [`for_sql`] and
//!   [`for_sql_backslash`] encode string literals (`'...'`). an identifier is
//!   delimited by `"..."` or `` `...` ``, and neither delimiter is escaped.
//!   validate an untrusted table or column name against a whitelist.
//! - **full URLs must be validated separately.** `for_uri_component` encodes
//!   a component, not a full URL. to embed an untrusted URL, validate its
//!   scheme and structure first, then encode for the final sink.
//! - **template literals.** the string literal JavaScript encoders do not
//!   encode backticks. use [`for_js_template`] to embed data directly in
//!   ES2015+ template literals.
//! - **grave accent.** unpatched Internet Explorer treats `` ` `` as an
//!   attribute delimiter. `for_html_unquoted_attribute` encodes it, but
//!   numeric entities decode back to the original character, so this is
//!   not a complete fix. avoid unquoted attributes.
//! - **HTML comments.** no HTML comment encoder is provided because HTML
//!   comments have vendor-specific extensions (e.g., conditional comments)
//!   that make safe encoding impractical. [`for_xml_comment`] is for XML
//!   comments only.
//!
//! # writer-based API
//!
//! every `for_*` function except [`for_rust_char_checked`] has a corresponding
//! `write_*` function that writes to any `std::fmt::Write` implementor,
//! avoiding allocation when writing to an existing buffer:
//!
//! ```
//! use contextual_encoder::write_html;
//!
//! let mut buf = String::new();
//! write_html(&mut buf, "safe & sound").unwrap();
//! assert_eq!(buf, "safe &amp; sound");
//! ```
//!
//! # display wrappers
//!
//! those same functions each have a corresponding `display_*` function that
//! returns a [`Display`](std::fmt::Display) wrapper that writes the encoded
//! output as it is formatted. use these
//! when embedding encoded output inline in `format!` or `write!`:
//!
//! ```
//! use contextual_encoder::display_html;
//!
//! let user_input = "<script>alert('xss')</script>";
//! // one allocation (the final String), zero intermediate allocations
//! let safe = format!("<p>{}</p>", display_html(user_input));
//! assert!(safe.contains("&lt;script&gt;"));
//! ```
//!
//! ## formatting parameters
//!
//! width, fill/alignment and precision apply to the *encoded* output, exactly
//! as `format!` applies them to the `String` returned by the `for_*`
//! counterpart:
//!
//! ```
//! use contextual_encoder::{display_html, for_html};
//!
//! assert_eq!(
//!     format!("{:*^12}", display_html("a<b")),
//!     format!("{:*^12}", for_html("a<b")),
//! );
//! ```
//!
//! a wrapper formatted with a width or a precision buffers the encoded output
//! into one intermediate `String`; the bare `{}` case stays allocation-free.
//!
//! precision counts characters of the *encoded* output, so it can cut an
//! escape or entity in half: `{:.4}` turns `a&lt;b` into `a&lt`, which an HTML
//! parser can read back as `a<`. `for_*` truncates the same way. do not use
//! precision to bound untrusted output — truncate the input before encoding it.

// compiles the README's examples as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[macro_use]
mod encoders;

mod css;
mod display;
mod html;
mod javascript;
mod json;
mod rust;
mod sql;
mod uri;
mod xml;

mod engine;

pub use css::{for_css_string, for_css_url, write_css_string, write_css_url};
pub use display::{
    display_cdata, display_css_string, display_css_url, display_form_urlencoded, display_html,
    display_html_attribute, display_html_content, display_html_unquoted_attribute,
    display_javascript, display_javascript_attribute, display_javascript_block,
    display_javascript_source, display_js_template, display_json, display_rust_byte_string,
    display_rust_char, display_rust_string, display_sql, display_sql_backslash,
    display_uri_component, display_uri_path, display_xml, display_xml11, display_xml11_attribute,
    display_xml11_content, display_xml_attribute, display_xml_comment, display_xml_content,
};
pub use html::{
    for_html, for_html_attribute, for_html_content, for_html_unquoted_attribute, write_html,
    write_html_attribute, write_html_content, write_html_unquoted_attribute,
};
pub use javascript::{
    for_javascript, for_javascript_attribute, for_javascript_block, for_javascript_source,
    for_js_template, write_javascript, write_javascript_attribute, write_javascript_block,
    write_javascript_source, write_js_template,
};
pub use json::{for_json, write_json};
pub use rust::{
    for_rust_byte_string, for_rust_char, for_rust_char_checked, for_rust_string,
    write_rust_byte_string, write_rust_char, write_rust_string,
};
pub use sql::{for_sql, for_sql_backslash, write_sql, write_sql_backslash};
pub use uri::{
    for_form_urlencoded, for_uri_component, for_uri_path, write_form_urlencoded,
    write_uri_component, write_uri_path,
};
pub use xml::{
    for_cdata, for_xml, for_xml11, for_xml11_attribute, for_xml11_content, for_xml_attribute,
    for_xml_comment, for_xml_content, write_cdata, write_xml, write_xml11, write_xml11_attribute,
    write_xml11_content, write_xml_attribute, write_xml_comment, write_xml_content,
};

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_empty {
        (
            $($context:ident: $module:ident::{$for_fn:ident, $write_fn:ident, $display_fn:ident}
                => $property:ident,)*
        ) => {
            $(assert_eq!($for_fn(""), "", stringify!($for_fn));)*
        };
    }

    #[test]
    fn empty_string_returns_empty() {
        encoders!(assert_empty);
    }

    #[test]
    fn multibyte_utf8_xml() {
        assert_eq!(for_xml("café"), "café");
        assert_eq!(for_xml("世界"), "世界");
        assert_eq!(for_xml("😀"), "😀");
    }
}
