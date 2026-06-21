#![forbid(unsafe_code)]

//! contextual output encoding for XSS defense and safe literal embedding.
//!
//! this crate provides context-aware encoding functions inspired by the
//! [OWASP Java Encoder](https://owasp.org/owasp-java-encoder/). each function
//! encodes input for safe embedding in a specific output context — web contexts
//! (HTML, XML, JavaScript, CSS, URI) and source literal contexts (Rust).
//!
//! **disclaimer:** contextual-encoder is an independent Rust crate. its API and security model
//! are inspired by the OWASP Java Encoder, but this project is not affiliated with,
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
//! assert!(js_safe.contains(r"<\/script>"));
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
//! ## CSS
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_css_string`] | quoted CSS string values |
//! | [`for_css_url`] | CSS `url()` values |
//!
//! ## URI
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_uri_component`] | URI components (query params, path segments) |
//! | [`for_uri_path`] | URI paths (preserves `/` separators) |
//! | [`for_form_urlencoded`] | `application/x-www-form-urlencoded` values |
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
//! | [`for_rust_char`] | Rust char literals (`'...'`) |
//! | [`for_rust_byte_string`] | Rust byte string literals (`b"..."`) |
//! | [`for_sql`] | Standard SQL string literals (`'...'`) |
//! | [`for_sql_backslash`] | MySQL/MariaDB string literals with backslash escaping (`'...'`) |
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
//! every `for_*` function has a corresponding `write_*` function that writes
//! to any `std::fmt::Write` implementor, avoiding allocation when writing to
//! an existing buffer:
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
//! every `for_*` function also has a corresponding `display_*` function that
//! returns a zero-allocation [`Display`](std::fmt::Display) wrapper. use these
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

pub mod css;
pub mod display;
pub mod html;
pub mod javascript;
pub mod json;
pub mod rust;
pub mod sql;
pub mod uri;
pub mod xml;

mod engine;

// convenience re-exports — users can `use contextual_encoder::for_html` directly
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
    for_rust_byte_string, for_rust_char, for_rust_string, write_rust_byte_string, write_rust_char,
    write_rust_string,
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

    #[test]
    fn empty_string_returns_empty() {
        assert_eq!(for_html(""), "");
        assert_eq!(for_html_content(""), "");
        assert_eq!(for_html_attribute(""), "");
        assert_eq!(for_html_unquoted_attribute(""), "");
        assert_eq!(for_javascript(""), "");
        assert_eq!(for_javascript_attribute(""), "");
        assert_eq!(for_javascript_block(""), "");
        assert_eq!(for_javascript_source(""), "");
        assert_eq!(for_css_string(""), "");
        assert_eq!(for_css_url(""), "");
        assert_eq!(for_uri_component(""), "");
        assert_eq!(for_uri_path(""), "");
        assert_eq!(for_xml(""), "");
        assert_eq!(for_xml_content(""), "");
        assert_eq!(for_xml_attribute(""), "");
        assert_eq!(for_xml_comment(""), "");
        assert_eq!(for_cdata(""), "");
        assert_eq!(for_xml11(""), "");
        assert_eq!(for_xml11_content(""), "");
        assert_eq!(for_xml11_attribute(""), "");
        assert_eq!(for_json(""), "");
        assert_eq!(for_rust_string(""), "");
        assert_eq!(for_rust_char(""), "");
        assert_eq!(for_rust_byte_string(""), "");
        assert_eq!(for_js_template(""), "");
        assert_eq!(for_sql(""), "");
        assert_eq!(for_sql_backslash(""), "");
        assert_eq!(for_form_urlencoded(""), "");
    }

    #[test]
    fn empty_string_writer_variants() {
        let mut buf = String::new();
        write_html(&mut buf, "").unwrap();
        assert_eq!(buf, "");

        buf.clear();
        write_javascript(&mut buf, "").unwrap();
        assert_eq!(buf, "");

        buf.clear();
        write_css_string(&mut buf, "").unwrap();
        assert_eq!(buf, "");

        buf.clear();
        write_uri_component(&mut buf, "").unwrap();
        assert_eq!(buf, "");

        buf.clear();
        write_uri_path(&mut buf, "").unwrap();
        assert_eq!(buf, "");

        buf.clear();
        write_form_urlencoded(&mut buf, "").unwrap();
        assert_eq!(buf, "");
    }

    // two-byte: é (U+00E9), ñ (U+00F1)
    // three-byte: 世 (U+4E16), € (U+20AC)
    // four-byte: 😀 (U+1F600), 𐍈 (U+10348)

    #[test]
    fn multibyte_utf8_html() {
        assert_eq!(for_html("café"), "café");
        assert_eq!(for_html("世界"), "世界");
        assert_eq!(for_html("😀"), "😀");
        assert_eq!(for_html("é<世>&😀"), "é&lt;世&gt;&amp;😀");
    }

    #[test]
    fn multibyte_utf8_javascript() {
        assert_eq!(for_javascript("café"), "café");
        assert_eq!(for_javascript("世界"), "世界");
        assert_eq!(for_javascript("😀"), "😀");
    }

    #[test]
    fn multibyte_utf8_css_string() {
        assert_eq!(for_css_string("café"), "café");
        assert_eq!(for_css_string("世界"), "世界");
        assert_eq!(for_css_string("😀"), "😀");
    }

    #[test]
    fn multibyte_utf8_uri_component() {
        assert_eq!(for_uri_component("é"), "%C3%A9");
        assert_eq!(for_uri_component("世"), "%E4%B8%96");
        assert_eq!(for_uri_component("😀"), "%F0%9F%98%80");
        assert_eq!(for_uri_component("café"), "caf%C3%A9");
    }

    #[test]
    fn multibyte_utf8_uri_path() {
        assert_eq!(for_uri_path("é"), "%C3%A9");
        assert_eq!(for_uri_path("世"), "%E4%B8%96");
        assert_eq!(for_uri_path("😀"), "%F0%9F%98%80");
        assert_eq!(for_uri_path("/café"), "/caf%C3%A9");
    }

    #[test]
    fn multibyte_utf8_form_urlencoded() {
        assert_eq!(for_form_urlencoded("é"), "%C3%A9");
        assert_eq!(for_form_urlencoded("世"), "%E4%B8%96");
        assert_eq!(for_form_urlencoded("😀"), "%F0%9F%98%80");
        assert_eq!(for_form_urlencoded("café"), "caf%C3%A9");
    }

    #[test]
    fn multibyte_utf8_rust_byte_string() {
        assert_eq!(for_rust_byte_string("é"), r"\xc3\xa9");
        assert_eq!(for_rust_byte_string("世"), r"\xe4\xb8\x96");
        assert_eq!(for_rust_byte_string("😀"), r"\xf0\x9f\x98\x80");
    }

    #[test]
    fn multibyte_utf8_rust_string_passthrough() {
        assert_eq!(for_rust_string("café"), "café");
        assert_eq!(for_rust_string("世界"), "世界");
        assert_eq!(for_rust_string("😀"), "😀");
    }

    #[test]
    fn multibyte_utf8_json() {
        assert_eq!(for_json("café"), "café");
        assert_eq!(for_json("世界"), "世界");
        assert_eq!(for_json("😀"), "😀");
    }

    #[test]
    fn multibyte_utf8_sql() {
        assert_eq!(for_sql("café"), "café");
        assert_eq!(for_sql("世界"), "世界");
        assert_eq!(for_sql("😀"), "😀");
    }

    #[test]
    fn multibyte_utf8_sql_backslash() {
        assert_eq!(for_sql_backslash("café"), "café");
        assert_eq!(for_sql_backslash("世界"), "世界");
        assert_eq!(for_sql_backslash("😀"), "😀");
    }

    #[test]
    fn multibyte_utf8_xml() {
        assert_eq!(for_xml("café"), "café");
        assert_eq!(for_xml("世界"), "世界");
        assert_eq!(for_xml("😀"), "😀");
    }
}
