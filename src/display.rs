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

use std::fmt;

use crate::{css, go, html, java, javascript, json, python, ruby, rust, sql, uri, xml, yaml};

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
                    $module::$write_fn(f, self.0)
                }
            }
            W(input)
        }
    };
}

// -- html --

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

// -- xml --

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

// -- javascript --

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

// -- css --

display_fn! {
    /// zero-allocation display wrapper for [`for_css_string`](crate::for_css_string).
    display_css_string => css::write_css_string
}

display_fn! {
    /// zero-allocation display wrapper for [`for_css_url`](crate::for_css_url).
    display_css_url => css::write_css_url
}

// -- uri --

display_fn! {
    /// zero-allocation display wrapper for [`for_uri_component`](crate::for_uri_component).
    display_uri_component => uri::write_uri_component
}

// -- json --

display_fn! {
    /// zero-allocation display wrapper for [`for_json`](crate::for_json).
    display_json => json::write_json
}

// -- java --

display_fn! {
    /// zero-allocation display wrapper for [`for_java`](crate::for_java).
    display_java => java::write_java
}

// -- go --

display_fn! {
    /// zero-allocation display wrapper for [`for_go_string`](crate::for_go_string).
    display_go_string => go::write_go_string
}

display_fn! {
    /// zero-allocation display wrapper for [`for_go_char`](crate::for_go_char).
    display_go_char => go::write_go_char
}

display_fn! {
    /// zero-allocation display wrapper for [`for_go_byte_string`](crate::for_go_byte_string).
    display_go_byte_string => go::write_go_byte_string
}

// -- rust --

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

// -- ruby --

display_fn! {
    /// zero-allocation display wrapper for [`for_ruby_string`](crate::for_ruby_string).
    display_ruby_string => ruby::write_ruby_string
}

// -- python --

display_fn! {
    /// zero-allocation display wrapper for [`for_python_string`](crate::for_python_string).
    display_python_string => python::write_python_string
}

display_fn! {
    /// zero-allocation display wrapper for [`for_python_bytes`](crate::for_python_bytes).
    display_python_bytes => python::write_python_bytes
}

display_fn! {
    /// zero-allocation display wrapper for
    /// [`for_python_raw_string`](crate::for_python_raw_string).
    display_python_raw_string => python::write_python_raw_string
}

// -- sql --

display_fn! {
    /// zero-allocation display wrapper for [`for_sql`](crate::for_sql).
    display_sql => sql::write_sql
}

display_fn! {
    /// zero-allocation display wrapper for [`for_sql_backslash`](crate::for_sql_backslash).
    display_sql_backslash => sql::write_sql_backslash
}

// -- yaml --

display_fn! {
    /// zero-allocation display wrapper for [`for_yaml`](crate::for_yaml).
    display_yaml => yaml::write_yaml
}

#[cfg(test)]
mod tests {
    use super::*;

    // verify that every display_* wrapper produces identical output to its for_* counterpart.

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
                    assert_eq!(
                        format!("{}", $display_fn(input)),
                        $for_fn(input),
                        "mismatch for {:?} on {}",
                        input,
                        stringify!($display_fn),
                    );
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

    // json
    display_matches_for!(json, display_json, crate::for_json);

    // java
    display_matches_for!(java, display_java, crate::for_java);

    // go
    display_matches_for!(go_string, display_go_string, crate::for_go_string);
    display_matches_for!(go_char, display_go_char, crate::for_go_char);
    display_matches_for!(
        go_byte_string,
        display_go_byte_string,
        crate::for_go_byte_string
    );

    // rust
    display_matches_for!(rust_string, display_rust_string, crate::for_rust_string);
    display_matches_for!(rust_char, display_rust_char, crate::for_rust_char);
    display_matches_for!(
        rust_byte_string,
        display_rust_byte_string,
        crate::for_rust_byte_string
    );

    // ruby
    display_matches_for!(ruby_string, display_ruby_string, crate::for_ruby_string);

    // python
    display_matches_for!(
        python_string,
        display_python_string,
        crate::for_python_string
    );
    display_matches_for!(python_bytes, display_python_bytes, crate::for_python_bytes);
    display_matches_for!(
        python_raw_string,
        display_python_raw_string,
        crate::for_python_raw_string
    );

    // sql
    display_matches_for!(sql, display_sql, crate::for_sql);
    display_matches_for!(
        sql_backslash,
        display_sql_backslash,
        crate::for_sql_backslash
    );

    // yaml
    display_matches_for!(yaml, display_yaml, crate::for_yaml);

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
}
