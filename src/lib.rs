//! contextual output encoding for XSS defense and safe literal embedding.
//!
//! this crate provides context-aware encoding functions inspired by the
//! [OWASP Java Encoder](https://owasp.org/owasp-java-encoder/). each function
//! encodes input for safe embedding in a specific output context — web contexts
//! (HTML, XML, JavaScript, CSS, URI) and source literal contexts (Java, Rust).
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
//!
//! ## additional literal contexts
//!
//! these encoders are not part of the OWASP Java Encoder's scope. they encode
//! untrusted strings for safe embedding in source code literals.
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_java`] | Java string / char literals |
//! | [`for_go_string`] | Go interpreted string literals (`"..."`) |
//! | [`for_go_char`] | Go rune literals (`'...'`) |
//! | [`for_go_byte_string`] | Go byte-explicit string literals (`[]byte("...")`) |
//! | [`for_rust_string`] | Rust string literals (`"..."`) |
//! | [`for_rust_char`] | Rust char literals (`'...'`) |
//! | [`for_rust_byte_string`] | Rust byte string literals (`b"..."`) |
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
//! - **template literals.** the JavaScript encoders do not encode backticks.
//!   never embed untrusted data directly in ES2015+ template literals.
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

pub mod css;
pub mod go;
pub mod html;
pub mod java;
pub mod javascript;
pub mod rust;
pub mod uri;
pub mod xml;

mod engine;

// convenience re-exports — users can `use contextual_encoder::for_html` directly
pub use css::{for_css_string, for_css_url, write_css_string, write_css_url};
pub use go::{
    for_go_byte_string, for_go_char, for_go_string, write_go_byte_string, write_go_char,
    write_go_string,
};
pub use html::{
    for_html, for_html_attribute, for_html_content, for_html_unquoted_attribute, write_html,
    write_html_attribute, write_html_content, write_html_unquoted_attribute,
};
pub use java::{for_java, write_java};
pub use javascript::{
    for_javascript, for_javascript_attribute, for_javascript_block, for_javascript_source,
    write_javascript, write_javascript_attribute, write_javascript_block, write_javascript_source,
};
pub use rust::{
    for_rust_byte_string, for_rust_char, for_rust_string, write_rust_byte_string, write_rust_char,
    write_rust_string,
};
pub use uri::{for_uri_component, write_uri_component};
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
        assert_eq!(for_xml(""), "");
        assert_eq!(for_xml_content(""), "");
        assert_eq!(for_xml_attribute(""), "");
        assert_eq!(for_xml_comment(""), "");
        assert_eq!(for_cdata(""), "");
        assert_eq!(for_xml11(""), "");
        assert_eq!(for_xml11_content(""), "");
        assert_eq!(for_xml11_attribute(""), "");
        assert_eq!(for_java(""), "");
        assert_eq!(for_go_string(""), "");
        assert_eq!(for_go_char(""), "");
        assert_eq!(for_go_byte_string(""), "");
        assert_eq!(for_rust_string(""), "");
        assert_eq!(for_rust_char(""), "");
        assert_eq!(for_rust_byte_string(""), "");
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
    fn multibyte_utf8_go_string_passthrough() {
        assert_eq!(for_go_string("caf\u{00e9}"), "caf\u{00e9}");
        assert_eq!(for_go_string("\u{4e16}\u{754c}"), "\u{4e16}\u{754c}");
        assert_eq!(for_go_string("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn multibyte_utf8_go_byte_string() {
        assert_eq!(for_go_byte_string("\u{00e9}"), r"\xc3\xa9");
        assert_eq!(for_go_byte_string("\u{4e16}"), r"\xe4\xb8\x96");
        assert_eq!(for_go_byte_string("\u{1F600}"), r"\xf0\x9f\x98\x80");
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
    fn multibyte_utf8_java() {
        assert_eq!(for_java("café"), "café");
        assert_eq!(for_java("世界"), "世界");
        assert_eq!(for_java("😀"), "\\ud83d\\ude00");
    }

    #[test]
    fn multibyte_utf8_xml() {
        assert_eq!(for_xml("café"), "café");
        assert_eq!(for_xml("世界"), "世界");
        assert_eq!(for_xml("😀"), "😀");
    }
}
