// the encoder list: `encoders!(callback)` invokes `callback!` with every entry.
// tests/invariants.rs `include!`s this file.
macro_rules! encoders {
    ($callback:ident) => {
        $callback! {
            html: html::{for_html, write_html, display_html},
            html_content: html::{for_html_content, write_html_content, display_html_content},
            html_attribute: html::{
                for_html_attribute, write_html_attribute, display_html_attribute
            },
            html_unquoted_attribute: html::{
                for_html_unquoted_attribute,
                write_html_unquoted_attribute,
                display_html_unquoted_attribute
            },
            xml: xml::{for_xml, write_xml, display_xml},
            xml_content: xml::{for_xml_content, write_xml_content, display_xml_content},
            xml_attribute: xml::{for_xml_attribute, write_xml_attribute, display_xml_attribute},
            xml_comment: xml::{for_xml_comment, write_xml_comment, display_xml_comment},
            cdata: xml::{for_cdata, write_cdata, display_cdata},
            xml11: xml::{for_xml11, write_xml11, display_xml11},
            xml11_content: xml::{for_xml11_content, write_xml11_content, display_xml11_content},
            xml11_attribute: xml::{
                for_xml11_attribute, write_xml11_attribute, display_xml11_attribute
            },
            javascript: javascript::{for_javascript, write_javascript, display_javascript},
            javascript_attribute: javascript::{
                for_javascript_attribute,
                write_javascript_attribute,
                display_javascript_attribute
            },
            javascript_block: javascript::{
                for_javascript_block, write_javascript_block, display_javascript_block
            },
            javascript_source: javascript::{
                for_javascript_source, write_javascript_source, display_javascript_source
            },
            js_template: javascript::{for_js_template, write_js_template, display_js_template},
            css_string: css::{for_css_string, write_css_string, display_css_string},
            css_url: css::{for_css_url, write_css_url, display_css_url},
            uri_component: uri::{for_uri_component, write_uri_component, display_uri_component},
            uri_path: uri::{for_uri_path, write_uri_path, display_uri_path},
            form_urlencoded: uri::{
                for_form_urlencoded, write_form_urlencoded, display_form_urlencoded
            },
            json: json::{for_json, write_json, display_json},
            rust_string: rust::{for_rust_string, write_rust_string, display_rust_string},
            rust_char: rust::{for_rust_char, write_rust_char, display_rust_char},
            rust_byte_string: rust::{
                for_rust_byte_string, write_rust_byte_string, display_rust_byte_string
            },
            sql: sql::{for_sql, write_sql, display_sql},
            sql_backslash: sql::{for_sql_backslash, write_sql_backslash, display_sql_backslash},
        }
    };
}
