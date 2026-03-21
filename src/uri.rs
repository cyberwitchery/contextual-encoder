//! URI component encoder.
//!
//! provides percent-encoding for URI components per RFC 3986.
//!
//! # security notes
//!
//! - this encoder is for **URI components** (query parameters, path segments,
//!   fragment identifiers), not entire URLs.
//! - it **cannot** make an untrusted full URL safe. a `javascript:` URL will
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
    let mut out = String::with_capacity(input.len());
    write_uri_component(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the percent-encoded form of `input` to `out`.
///
/// see [`for_uri_component`] for encoding rules.
pub fn write_uri_component<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    for byte in input.as_bytes() {
        if is_unreserved(*byte) {
            out.write_char(*byte as char)?;
        } else {
            write!(out, "%{:02X}", byte)?;
        }
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
}
