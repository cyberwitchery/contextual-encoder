//! URI and form percent-encoders.
//!
//! provides percent-encoding for URI components and paths per RFC 3986, and
//! for form values per the WHATWG URL Standard
//! (`application/x-www-form-urlencoded`).
//!
//! # security notes
//!
//! - these encoders are for **URI components, paths, and form values**, not
//!   entire URLs.
//! - they **cannot** make an untrusted full URL safe. a `javascript:` URL will
//!   be percent-encoded but still execute. always validate the URL scheme and
//!   structure separately before embedding untrusted URLs.
//! - the output is safe for direct embedding in HTML, CSS, and javascript
//!   contexts because all context-significant characters are percent-encoded.

use std::fmt;

/// percent-encodes `input` for safe use as a URI component.
///
/// only unreserved characters per RFC 3986 pass through unencoded:
/// `A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`. everything else is encoded
/// as percent-encoded UTF-8 bytes.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_uri_component;
///
/// assert_eq!(for_uri_component("hello world"), "hello%20world");
/// assert_eq!(for_uri_component("a=1&b=2"), "a%3D1%26b%3D2");
/// assert_eq!(for_uri_component("safe-text_v2.0"), "safe-text_v2.0");
/// assert_eq!(for_uri_component("café"), "caf%C3%A9");
/// ```
pub fn for_uri_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_uri_component(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the percent-encoded form of `input` to `out`.
///
/// see [`for_uri_component`] for encoding rules.
pub fn write_uri_component<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    percent_encode(out, input, is_unreserved)
}

/// percent-encodes `input` for safe use as a URI path.
///
/// this encoder preserves forward-slash (`/`) separators while encoding each
/// path segment. only unreserved characters per RFC 3986 and `/` pass through
/// unencoded: `A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`, `/`. everything else
/// is encoded as percent-encoded UTF-8 bytes.
///
/// use this when you need to encode a full URI path from untrusted input.
/// for individual path segments or query parameters, use
/// [`for_uri_component`] instead (which also encodes `/`).
///
/// # security notes
///
/// - this encoder does **not** normalize `.` or `..` segments. callers must
///   validate and normalize paths separately to prevent path traversal.
/// - multiple consecutive slashes are preserved as-is.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_uri_path;
///
/// assert_eq!(for_uri_path("/users/café/profile"), "/users/caf%C3%A9/profile");
/// assert_eq!(for_uri_path("/a b/c&d"), "/a%20b/c%26d");
/// assert_eq!(for_uri_path("/safe-text_v2.0/~user"), "/safe-text_v2.0/~user");
/// assert_eq!(for_uri_path("/path/segment"), "/path/segment");
/// ```
pub fn for_uri_path(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_uri_path(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the percent-encoded URI path form of `input` to `out`.
///
/// see [`for_uri_path`] for encoding rules.
pub fn write_uri_path<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    percent_encode(out, input, |b| is_unreserved(b) || b == b'/')
}

/// percent-encodes `input` for use as an
/// `application/x-www-form-urlencoded` value.
///
/// follows the [WHATWG URL Standard](https://url.spec.whatwg.org/#concept-urlencoded-byte-serializer)
/// byte serializer: spaces become `+`, the bytes `*`, `-`, `.`, `0-9`,
/// `A-Z`, `_`, `a-z` pass through unencoded, and everything else is
/// percent-encoded as UTF-8 bytes.
///
/// this encodes a single form **value** (or name). it does not insert `=`
/// or `&` delimiters — the caller constructs the `key=value&key=value`
/// structure using already-encoded parts.
///
/// # differences from [`for_uri_component`]
///
/// | character | `for_uri_component` (RFC 3986) | `for_form_urlencoded` (WHATWG) |
/// |-----------|-------------------------------|-------------------------------|
/// | space     | `%20`                         | `+`                           |
/// | `~`       | passthrough                   | `%7E`                         |
/// | `*`       | `%2A`                         | passthrough                   |
///
/// # examples
///
/// ```
/// use contextual_encoder::for_form_urlencoded;
///
/// assert_eq!(for_form_urlencoded("hello world"), "hello+world");
/// assert_eq!(for_form_urlencoded("a=1&b=2"), "a%3D1%26b%3D2");
/// assert_eq!(for_form_urlencoded("safe-text_v2.0"), "safe-text_v2.0");
/// assert_eq!(for_form_urlencoded("café"), "caf%C3%A9");
/// assert_eq!(for_form_urlencoded("a~b"), "a%7Eb");
/// assert_eq!(for_form_urlencoded("a*b"), "a*b");
/// ```
pub fn for_form_urlencoded(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_form_urlencoded(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the `application/x-www-form-urlencoded` encoded form of `input`
/// to `out`.
///
/// see [`for_form_urlencoded`] for encoding rules.
pub fn write_form_urlencoded<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    // space maps to '+'; every other byte follows the shared percent-encoder.
    let mut segments = input.split(' ');
    percent_encode(out, segments.next().unwrap_or(""), is_form_safe)?;
    for segment in segments {
        out.write_char('+')?;
        percent_encode(out, segment, is_form_safe)?;
    }
    Ok(())
}

/// percent-encodes `input` to `out`, passing bytes for which `keep` returns
/// true through verbatim and encoding every other byte as `%XX`.
///
/// consecutive kept bytes are flushed in a single `write_str`. this batching is
/// sound because every keep-predicate here admits only ASCII bytes, so a kept
/// run never splits a multi-byte UTF-8 sequence and each slice is valid UTF-8.
fn percent_encode<W: fmt::Write>(
    out: &mut W,
    input: &str,
    keep: impl Fn(u8) -> bool,
) -> fmt::Result {
    let bytes = input.as_bytes();
    let mut last_written = 0;

    for (i, &byte) in bytes.iter().enumerate() {
        if !keep(byte) {
            if last_written < i {
                out.write_str(&input[last_written..i])?;
            }
            write!(out, "%{:02X}", byte)?;
            last_written = i + 1;
        }
    }

    if last_written < bytes.len() {
        out.write_str(&input[last_written..])?;
    }
    Ok(())
}

/// returns true if the byte represents an unreserved character per RFC 3986.
fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

/// returns true if the byte passes through unencoded in
/// `application/x-www-form-urlencoded` per the WHATWG URL Standard.
/// space is handled separately (mapped to `+`).
fn is_form_safe(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_')
}
