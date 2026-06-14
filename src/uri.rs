//! URI component and path encoders.
//!
//! provides percent-encoding for URI components and paths per RFC 3986.
//!
//! # security notes
//!
//! - these encoders are for **URI components and paths**, not entire URLs.
//! - they **cannot** make an untrusted full URL safe. a `javascript:` URL will
//!   be percent-encoded but still execute. always validate the URL scheme and
//!   structure separately before embedding untrusted URLs.
//! - the output is safe for direct embedding in HTML, CSS, and javascript
//!   contexts because all context-significant characters are percent-encoded.

use std::fmt;

// ---------------------------------------------------------------------------
// for_uri_component
// ---------------------------------------------------------------------------

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
    let bytes = input.as_bytes();
    let unreserved = bytes.iter().filter(|b| is_unreserved(**b)).count();
    let capacity = unreserved + 3 * (bytes.len() - unreserved);
    let mut out = String::with_capacity(capacity);
    write_uri_component(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the percent-encoded form of `input` to `out`.
///
/// see [`for_uri_component`] for encoding rules.
pub fn write_uri_component<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    let bytes = input.as_bytes();
    let mut last_written = 0;

    for (i, &byte) in bytes.iter().enumerate() {
        if !is_unreserved(byte) {
            // flush the preceding run of unreserved (ASCII) bytes
            if last_written < i {
                // safe: unreserved chars are all ASCII, so this slice is valid UTF-8
                out.write_str(&input[last_written..i])?;
            }
            write!(out, "%{:02X}", byte)?;
            last_written = i + 1;
        }
    }

    // flush any trailing safe run
    if last_written < bytes.len() {
        out.write_str(&input[last_written..])?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// for_uri_path
// ---------------------------------------------------------------------------

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
    let bytes = input.as_bytes();
    let safe = bytes
        .iter()
        .filter(|b| is_unreserved(**b) || **b == b'/')
        .count();
    let capacity = safe + 3 * (bytes.len() - safe);
    let mut out = String::with_capacity(capacity);
    write_uri_path(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the percent-encoded URI path form of `input` to `out`.
///
/// see [`for_uri_path`] for encoding rules.
pub fn write_uri_path<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    let bytes = input.as_bytes();
    let mut last_written = 0;

    for (i, &byte) in bytes.iter().enumerate() {
        if !is_unreserved(byte) && byte != b'/' {
            // flush the preceding run of safe bytes
            if last_written < i {
                out.write_str(&input[last_written..i])?;
            }
            write!(out, "%{:02X}", byte)?;
            last_written = i + 1;
        }
    }

    // flush any trailing safe run
    if last_written < bytes.len() {
        out.write_str(&input[last_written..])?;
    }
    Ok(())
}

/// returns true if the byte represents an unreserved character per RFC 3986.
fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_component_no_encoding_needed() {
        assert_eq!(for_uri_component("hello"), "hello");
        assert_eq!(for_uri_component(""), "");
        assert_eq!(for_uri_component("ABCxyz019"), "ABCxyz019");
        assert_eq!(for_uri_component("-._~"), "-._~");
    }

    #[test]
    fn uri_component_encodes_space() {
        assert_eq!(for_uri_component("a b"), "a%20b");
    }

    #[test]
    fn uri_component_encodes_reserved_chars() {
        assert_eq!(for_uri_component("a=b"), "a%3Db");
        assert_eq!(for_uri_component("a&b"), "a%26b");
        assert_eq!(for_uri_component("a+b"), "a%2Bb");
        assert_eq!(for_uri_component("a?b"), "a%3Fb");
        assert_eq!(for_uri_component("a#b"), "a%23b");
        assert_eq!(for_uri_component("a/b"), "a%2Fb");
    }

    #[test]
    fn uri_component_encodes_html_significant() {
        assert_eq!(for_uri_component("<script>"), "%3Cscript%3E");
        assert_eq!(for_uri_component(r#""quoted""#), "%22quoted%22");
    }

    #[test]
    fn uri_component_encodes_two_byte_utf8() {
        // U+00A0 (NBSP) → 0xC2 0xA0
        assert_eq!(for_uri_component("\u{00A0}"), "%C2%A0");
        // U+00E9 (é) → 0xC3 0xA9
        assert_eq!(for_uri_component("é"), "%C3%A9");
    }

    #[test]
    fn uri_component_encodes_three_byte_utf8() {
        // U+0800 → 0xE0 0xA0 0x80
        assert_eq!(for_uri_component("\u{0800}"), "%E0%A0%80");
        // U+4E16 (世) → 0xE4 0xB8 0x96
        assert_eq!(for_uri_component("世"), "%E4%B8%96");
    }

    #[test]
    fn uri_component_encodes_four_byte_utf8() {
        // U+10000 → 0xF0 0x90 0x80 0x80
        assert_eq!(for_uri_component("\u{10000}"), "%F0%90%80%80");
        // U+1F600 (😀) → 0xF0 0x9F 0x98 0x80
        assert_eq!(for_uri_component("😀"), "%F0%9F%98%80");
    }

    #[test]
    fn uri_component_encodes_control_chars() {
        assert_eq!(for_uri_component("\x00"), "%00");
        assert_eq!(for_uri_component("\x1F"), "%1F");
        assert_eq!(for_uri_component("\x7F"), "%7F");
    }

    #[test]
    fn uri_component_mixed() {
        assert_eq!(
            for_uri_component("key=hello world&foo=bar"),
            "key%3Dhello%20world%26foo%3Dbar"
        );
    }

    #[test]
    fn uri_component_writer_variant() {
        let mut out = String::new();
        write_uri_component(&mut out, "a b").unwrap();
        assert_eq!(out, "a%20b");
    }

    // -- uri path --

    #[test]
    fn uri_path_no_encoding_needed() {
        assert_eq!(for_uri_path("hello"), "hello");
        assert_eq!(for_uri_path(""), "");
        assert_eq!(for_uri_path("-._~"), "-._~");
    }

    #[test]
    fn uri_path_preserves_slashes() {
        assert_eq!(for_uri_path("/a/b/c"), "/a/b/c");
        assert_eq!(for_uri_path("/"), "/");
        assert_eq!(for_uri_path("//"), "//");
        assert_eq!(for_uri_path("a/b"), "a/b");
    }

    #[test]
    fn uri_path_encodes_reserved_except_slash() {
        assert_eq!(for_uri_path("a=b"), "a%3Db");
        assert_eq!(for_uri_path("a&b"), "a%26b");
        assert_eq!(for_uri_path("a?b"), "a%3Fb");
        assert_eq!(for_uri_path("a#b"), "a%23b");
    }

    #[test]
    fn uri_path_encodes_space() {
        assert_eq!(for_uri_path("/a b/c d"), "/a%20b/c%20d");
    }

    #[test]
    fn uri_path_encodes_multibyte() {
        assert_eq!(for_uri_path("/café"), "/caf%C3%A9");
        assert_eq!(for_uri_path("/世界"), "/%E4%B8%96%E7%95%8C");
        assert_eq!(for_uri_path("/😀"), "/%F0%9F%98%80");
    }

    #[test]
    fn uri_path_writer_variant() {
        let mut out = String::new();
        write_uri_path(&mut out, "/a b/c").unwrap();
        assert_eq!(out, "/a%20b/c");
    }
}
