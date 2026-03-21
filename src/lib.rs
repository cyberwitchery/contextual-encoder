//! contextual output encoding for XSS defense.
//!
//! this crate provides context-aware encoding functions inspired by the
//! [OWASP Java Encoder](https://owasp.org/owasp-java-encoder/). each function
//! encodes input for safe embedding in a specific output context (HTML, JavaScript,
//! CSS, or URI).
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
//!
//! // safe for javascript string literals (universal)
//! let js_safe = for_javascript(user_input);
//!
//! // safe for quoted CSS string values
//! let css_safe = for_css_string(user_input);
//!
//! // safe as a URI query parameter value
//! let uri_safe = for_uri_component(user_input);
//! ```
//!
//! # available contexts
//!
//! ## HTML / XML
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_html`] | text content + quoted attributes |
//! | [`for_html_content`] | text content only |
//! | [`for_html_attribute`] | quoted attributes only |
//! | [`for_html_unquoted_attribute`] | unquoted attribute values |
//!
//! ## JavaScript
//!
//! | function | safe for |
//! |----------|----------|
//! | [`for_javascript`] | all JS contexts (universal) |
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
//!   a component, not a full URL. a `javascript:` URL will be encoded but
//!   still execute. always validate the scheme.
//! - **template literals.** the JavaScript encoders do not encode backticks.
//!   never embed untrusted data directly in ES2015+ template literals.
//! - **grave accent.** unpatched Internet Explorer treats `` ` `` as an
//!   attribute delimiter. `for_html_unquoted_attribute` encodes it, but
//!   numeric entities decode back to the original character, so this is
//!   not a complete fix. avoid unquoted attributes.
//! - **HTML comments.** no HTML comment encoder is provided because HTML
//!   comments have vendor-specific extensions (e.g., conditional comments)
//!   that make safe encoding impractical.
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
pub mod html;
pub mod javascript;
pub mod uri;

mod engine;

// convenience re-exports — users can `use contextual_encoder::for_html` directly
pub use css::{for_css_string, for_css_url, write_css_string, write_css_url};
pub use html::{
    for_html, for_html_attribute, for_html_content, for_html_unquoted_attribute, write_html,
    write_html_attribute, write_html_content, write_html_unquoted_attribute,
};
pub use javascript::{
    for_javascript, for_javascript_attribute, for_javascript_block, for_javascript_source,
    write_javascript, write_javascript_attribute, write_javascript_block, write_javascript_source,
};
pub use uri::{for_uri_component, write_uri_component};
