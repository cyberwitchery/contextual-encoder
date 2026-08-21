//! zero-allocation [`Display`](std::fmt::Display) wrappers for all encoding
//! contexts.
//!
//! every `for_*` function allocates a `String`. when embedding encoded output
//! in a larger format string (e.g., `format!("<p>{}</p>", for_html(s))`), the
//! intermediate string is immediately consumed and discarded — a wasted
//! allocation.
//!
//! the `display_*` functions return lightweight wrappers that implement
//! [`Display`](std::fmt::Display) by delegating to the corresponding `write_*`
//! function. this enables zero-allocation inline formatting:
//!
//! ```
//! use contextual_encoder::display_html;
//!
//! let user_input = "<script>alert('xss')</script>";
//! // one allocation (the final String), zero intermediate allocations
//! let output = format!("<p>{}</p>", display_html(user_input));
//! assert!(output.contains("&lt;script&gt;"));
//! ```
//!
//! each `display_*` wrapper encodes identically to its `for_*` / `write_*`
//! counterpart. see the corresponding `for_*` function for encoding rules.
//!
//! # formatting parameters
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

use std::fmt;

use crate::{css, html, javascript, json, rust, sql, uri, xml};

macro_rules! display_fn {
    (
        $(#[$meta:meta])*
        $name:ident => $module:ident :: $write_fn:ident
    ) => {
        $(#[$meta])*
        pub fn $name(input: &str) -> impl fmt::Display + '_ {
            struct W<'a>(&'a str);
            impl fmt::Display for W<'_> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    if f.width().is_none() && f.precision().is_none() {
                        return $module::$write_fn(f, self.0);
                    }
                    let mut encoded = String::with_capacity(self.0.len());
                    $module::$write_fn(&mut encoded, self.0)?;
                    f.pad(&encoded)
                }
            }
            W(input)
        }
    };
}

display_fn! {
    /// zero-allocation display wrapper for [`for_html`](crate::for_html).
    display_html => html::write_html
}

display_fn! {
    /// zero-allocation display wrapper for [`for_html_content`](crate::for_html_content).
    display_html_content => html::write_html_content
}

display_fn! {
    /// zero-allocation display wrapper for [`for_html_attribute`](crate::for_html_attribute).
    display_html_attribute => html::write_html_attribute
}

display_fn! {
    /// zero-allocation display wrapper for
    /// [`for_html_unquoted_attribute`](crate::for_html_unquoted_attribute).
    display_html_unquoted_attribute => html::write_html_unquoted_attribute
}

display_fn! {
    /// zero-allocation display wrapper for [`for_xml`](crate::for_xml).
    display_xml => xml::write_xml
}

display_fn! {
    /// zero-allocation display wrapper for [`for_xml_content`](crate::for_xml_content).
    display_xml_content => xml::write_xml_content
}

display_fn! {
    /// zero-allocation display wrapper for [`for_xml_attribute`](crate::for_xml_attribute).
    display_xml_attribute => xml::write_xml_attribute
}

display_fn! {
    /// zero-allocation display wrapper for [`for_xml_comment`](crate::for_xml_comment).
    display_xml_comment => xml::write_xml_comment
}

display_fn! {
    /// zero-allocation display wrapper for [`for_cdata`](crate::for_cdata).
    display_cdata => xml::write_cdata
}

display_fn! {
    /// zero-allocation display wrapper for [`for_xml11`](crate::for_xml11).
    display_xml11 => xml::write_xml11
}

display_fn! {
    /// zero-allocation display wrapper for [`for_xml11_content`](crate::for_xml11_content).
    display_xml11_content => xml::write_xml11_content
}

display_fn! {
    /// zero-allocation display wrapper for [`for_xml11_attribute`](crate::for_xml11_attribute).
    display_xml11_attribute => xml::write_xml11_attribute
}

display_fn! {
    /// zero-allocation display wrapper for [`for_javascript`](crate::for_javascript).
    display_javascript => javascript::write_javascript
}

display_fn! {
    /// zero-allocation display wrapper for
    /// [`for_javascript_attribute`](crate::for_javascript_attribute).
    display_javascript_attribute => javascript::write_javascript_attribute
}

display_fn! {
    /// zero-allocation display wrapper for
    /// [`for_javascript_block`](crate::for_javascript_block).
    display_javascript_block => javascript::write_javascript_block
}

display_fn! {
    /// zero-allocation display wrapper for
    /// [`for_javascript_source`](crate::for_javascript_source).
    display_javascript_source => javascript::write_javascript_source
}

display_fn! {
    /// zero-allocation display wrapper for [`for_js_template`](crate::for_js_template).
    display_js_template => javascript::write_js_template
}

display_fn! {
    /// zero-allocation display wrapper for [`for_css_string`](crate::for_css_string).
    display_css_string => css::write_css_string
}

display_fn! {
    /// zero-allocation display wrapper for [`for_css_url`](crate::for_css_url).
    display_css_url => css::write_css_url
}

display_fn! {
    /// zero-allocation display wrapper for [`for_uri_component`](crate::for_uri_component).
    display_uri_component => uri::write_uri_component
}

display_fn! {
    /// zero-allocation display wrapper for [`for_uri_path`](crate::for_uri_path).
    display_uri_path => uri::write_uri_path
}

display_fn! {
    /// zero-allocation display wrapper for
    /// [`for_form_urlencoded`](crate::for_form_urlencoded).
    display_form_urlencoded => uri::write_form_urlencoded
}

display_fn! {
    /// zero-allocation display wrapper for [`for_json`](crate::for_json).
    display_json => json::write_json
}

display_fn! {
    /// zero-allocation display wrapper for [`for_rust_string`](crate::for_rust_string).
    display_rust_string => rust::write_rust_string
}

display_fn! {
    /// zero-allocation display wrapper for [`for_rust_char`](crate::for_rust_char).
    display_rust_char => rust::write_rust_char
}

display_fn! {
    /// zero-allocation display wrapper for
    /// [`for_rust_byte_string`](crate::for_rust_byte_string).
    display_rust_byte_string => rust::write_rust_byte_string
}

display_fn! {
    /// zero-allocation display wrapper for [`for_sql`](crate::for_sql).
    display_sql => sql::write_sql
}

display_fn! {
    /// zero-allocation display wrapper for [`for_sql_backslash`](crate::for_sql_backslash).
    display_sql_backslash => sql::write_sql_backslash
}

#[cfg(test)]
mod tests {
    use super::*;

    // verify that every display_* wrapper formats identically to its for_* counterpart.

    macro_rules! assert_fmt_parity {
        ($fmt:literal, $display_fn:ident, $input:expr, $encoded:expr) => {
            assert_eq!(
                format!($fmt, $display_fn($input)),
                format!($fmt, $encoded),
                "mismatch for {:?} formatted as {:?} on {}",
                $input,
                $fmt,
                stringify!($display_fn),
            );
        };
    }

    macro_rules! display_matches_for {
        ($name:ident, $display_fn:ident, $for_fn:path) => {
            #[test]
            fn $name() {
                for input in [
                    "",
                    "hello",
                    "<script>alert('xss')</script>",
                    "café",
                    "世界",
                    "😀",
                    "a&b<c>d\"e'f",
                    "\x00\x01\x1F\x7F",
                    "\t\n\r",
                    "\u{0080}\u{009F}",
                    "\u{2028}\u{2029}",
                    "a\\b/c",
                    "key=val&foo=bar",
                    "`${inject}`",
                ] {
                    let encoded = $for_fn(input);
                    assert_fmt_parity!("{}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:>12}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:<12}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:*^12}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:.0}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:.4}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:.99}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:*>20.7}", $display_fn, input, encoded);
                }
            }
        };
    }

    // html
    display_matches_for!(html, display_html, crate::for_html);
    display_matches_for!(html_content, display_html_content, crate::for_html_content);
    display_matches_for!(
        html_attribute,
        display_html_attribute,
        crate::for_html_attribute
    );
    display_matches_for!(
        html_unquoted_attribute,
        display_html_unquoted_attribute,
        crate::for_html_unquoted_attribute
    );

    // xml
    display_matches_for!(xml, display_xml, crate::for_xml);
    display_matches_for!(xml_content, display_xml_content, crate::for_xml_content);
    display_matches_for!(
        xml_attribute,
        display_xml_attribute,
        crate::for_xml_attribute
    );
    display_matches_for!(xml_comment, display_xml_comment, crate::for_xml_comment);
    display_matches_for!(cdata, display_cdata, crate::for_cdata);
    display_matches_for!(xml11, display_xml11, crate::for_xml11);
    display_matches_for!(
        xml11_content,
        display_xml11_content,
        crate::for_xml11_content
    );
    display_matches_for!(
        xml11_attribute,
        display_xml11_attribute,
        crate::for_xml11_attribute
    );

    // javascript
    display_matches_for!(javascript, display_javascript, crate::for_javascript);
    display_matches_for!(
        javascript_attribute,
        display_javascript_attribute,
        crate::for_javascript_attribute
    );
    display_matches_for!(
        javascript_block,
        display_javascript_block,
        crate::for_javascript_block
    );
    display_matches_for!(
        javascript_source,
        display_javascript_source,
        crate::for_javascript_source
    );
    display_matches_for!(js_template, display_js_template, crate::for_js_template);

    // css
    display_matches_for!(css_string, display_css_string, crate::for_css_string);
    display_matches_for!(css_url, display_css_url, crate::for_css_url);

    // uri
    display_matches_for!(
        uri_component,
        display_uri_component,
        crate::for_uri_component
    );
    display_matches_for!(uri_path, display_uri_path, crate::for_uri_path);
    display_matches_for!(
        form_urlencoded,
        display_form_urlencoded,
        crate::for_form_urlencoded
    );

    // json
    display_matches_for!(json, display_json, crate::for_json);

    // rust
    display_matches_for!(rust_string, display_rust_string, crate::for_rust_string);
    display_matches_for!(rust_char, display_rust_char, crate::for_rust_char);
    display_matches_for!(
        rust_byte_string,
        display_rust_byte_string,
        crate::for_rust_byte_string
    );

    // sql
    display_matches_for!(sql, display_sql, crate::for_sql);
    display_matches_for!(
        sql_backslash,
        display_sql_backslash,
        crate::for_sql_backslash
    );

    // -- usage pattern tests --

    #[test]
    fn inline_format_html() {
        let input = "<b>bold</b>";
        let result = format!("<p>{}</p>", display_html(input));
        assert_eq!(result, "<p>&lt;b&gt;bold&lt;/b&gt;</p>");
    }

    #[test]
    fn inline_format_nested_contexts() {
        let query = "hello world & goodbye";
        let href = format!("/search?q={}", display_uri_component(query));
        let attr = format!(r#"<a href="{}">"#, display_html_attribute(&href));
        assert!(attr.contains("/search?q=hello%20world%20%26%20goodbye"));
    }

    #[test]
    fn write_macro_integration() {
        use std::fmt::Write;
        let mut buf = String::new();
        write!(buf, "<p>{}</p>", display_html("a & b")).unwrap();
        assert_eq!(buf, "<p>a &amp; b</p>");
    }

    #[test]
    fn display_wrapper_is_reusable() {
        let wrapper = display_html("<b>");
        let first = format!("{wrapper}");
        let second = format!("{wrapper}");
        assert_eq!(first, second);
        assert_eq!(first, "&lt;b&gt;");
    }

    #[derive(Default)]
    struct ChunkCounter {
        out: String,
        chunks: usize,
    }

    impl fmt::Write for ChunkCounter {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            if !s.is_empty() {
                self.chunks += 1;
            }
            self.out.push_str(s);
            Ok(())
        }
    }

    #[test]
    fn bare_spec_writes_through_without_buffering() {
        use std::fmt::Write;
        let mut sink = ChunkCounter::default();
        write!(sink, "{}", display_html("a&b<c")).unwrap();
        assert_eq!(sink.out, crate::for_html("a&b<c"));
        assert!(
            sink.chunks > 1,
            "expected the encoder to write runs straight to the formatter, got {} chunk(s)",
            sink.chunks
        );
    }

    #[test]
    fn format_spec_buffers_into_a_single_chunk() {
        use std::fmt::Write;
        let mut sink = ChunkCounter::default();
        write!(sink, "{:.99}", display_html("a&b<c")).unwrap();
        assert_eq!(sink.out, format!("{:.99}", crate::for_html("a&b<c")));
        assert_eq!(sink.chunks, 1);
    }
}
