//! conformance test suite.
//!
//! these tests verify encoding behavior against the OWASP Java Encoder
//! specification. test vectors are derived from the OWASP documentation,
//! Java Encoder source and test cases, and hand-written edge cases.
//!
//! where Rust behavior necessarily differs from Java (e.g., surrogate
//! handling), the tests document the Rust contract and note the difference.

use contextual_encoder::*;

// ===========================================================================
// HTML context tests
// ===========================================================================

mod html {
    use super::*;

    // -- basic dangerous characters --

    #[test]
    fn script_tag_injection() {
        assert_eq!(
            for_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn img_tag_injection() {
        assert_eq!(
            for_html(r#"<img src=x onerror="alert(1)">"#),
            "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;"
        );
    }

    #[test]
    fn ampersand_in_various_positions() {
        assert_eq!(for_html("&"), "&amp;");
        assert_eq!(for_html("&&"), "&amp;&amp;");
        assert_eq!(for_html("a&b&c"), "a&amp;b&amp;c");
        assert_eq!(for_html("&amp;"), "&amp;amp;");
    }

    #[test]
    fn already_encoded_input() {
        // encoding should be idempotent in the sense that re-encoding
        // produces a safely displayable result (double-encoded)
        assert_eq!(for_html("&lt;"), "&amp;lt;");
        assert_eq!(for_html("&#34;"), "&amp;#34;");
    }

    #[test]
    fn mixed_safe_and_unsafe() {
        assert_eq!(
            for_html("Hello, <world> & \"friends\"!"),
            "Hello, &lt;world&gt; &amp; &#34;friends&#34;!"
        );
    }

    // -- unicode --

    #[test]
    fn cjk_characters() {
        assert_eq!(for_html("日本語テスト"), "日本語テスト");
    }

    #[test]
    fn emoji() {
        assert_eq!(for_html("hello 😀 world"), "hello 😀 world");
    }

    #[test]
    fn mixed_unicode_and_html() {
        assert_eq!(for_html("<café>"), "&lt;café&gt;");
    }

    #[test]
    fn supplementary_plane_characters() {
        // U+10000 LINEAR B SYLLABLE B008 A
        assert_eq!(for_html("\u{10000}"), "\u{10000}");
        // U+1F600 GRINNING FACE
        assert_eq!(for_html("😀"), "😀");
    }

    // -- control characters --

    #[test]
    fn null_byte() {
        assert_eq!(for_html("\x00"), " ");
    }

    #[test]
    fn all_c0_controls() {
        // 0x00-0x08: replaced with space
        for cp in 0x00u8..=0x08 {
            let s = String::from(char::from(cp));
            assert_eq!(for_html(&s), " ", "C0 control 0x{:02x}", cp);
        }
        // 0x09 (tab), 0x0A (LF), 0x0D (CR): preserved
        assert_eq!(for_html("\x09"), "\x09");
        assert_eq!(for_html("\x0A"), "\x0A");
        assert_eq!(for_html("\x0D"), "\x0D");
        // 0x0B, 0x0C: replaced with space
        assert_eq!(for_html("\x0B"), " ");
        assert_eq!(for_html("\x0C"), " ");
        // 0x0E-0x1F: replaced with space
        for cp in 0x0Eu8..=0x1F {
            let s = String::from(char::from(cp));
            assert_eq!(for_html(&s), " ", "C0 control 0x{:02x}", cp);
        }
    }

    #[test]
    fn del_replaced() {
        assert_eq!(for_html("\x7F"), " ");
    }

    #[test]
    fn c1_controls_replaced() {
        for cp in 0x80u32..=0x9F {
            let c = char::from_u32(cp).unwrap();
            let s = String::from(c);
            assert_eq!(for_html(&s), " ", "C1 control U+{:04X}", cp);
        }
    }

    // -- unicode non-characters --

    #[test]
    fn noncharacters_replaced() {
        assert_eq!(for_html("\u{FDD0}"), " ");
        assert_eq!(for_html("\u{FDEF}"), " ");
        assert_eq!(for_html("\u{FFFE}"), " ");
        assert_eq!(for_html("\u{FFFF}"), " ");
        assert_eq!(for_html("\u{1FFFE}"), " ");
        assert_eq!(for_html("\u{10FFFF}"), " ");
    }

    // -- boundary conditions --

    #[test]
    fn empty_string() {
        assert_eq!(for_html(""), "");
    }

    #[test]
    fn single_safe_char() {
        assert_eq!(for_html("a"), "a");
    }

    #[test]
    fn single_unsafe_char() {
        assert_eq!(for_html("<"), "&lt;");
    }

    #[test]
    fn long_safe_string() {
        let s = "a".repeat(10000);
        assert_eq!(for_html(&s), s);
    }

    #[test]
    fn all_unsafe_string() {
        assert_eq!(for_html("<>&\"'"), "&lt;&gt;&amp;&#34;&#39;");
    }

    // -- context-specific behavior --

    #[test]
    fn content_vs_attribute_gt_handling() {
        // for_html_content encodes >
        assert_eq!(for_html_content("a>b"), "a&gt;b");
        // for_html_attribute does NOT encode >
        assert_eq!(for_html_attribute("a>b"), "a>b");
        // for_html encodes > (union of both)
        assert_eq!(for_html("a>b"), "a&gt;b");
    }

    #[test]
    fn content_vs_attribute_quote_handling() {
        // for_html_content does NOT encode quotes
        assert_eq!(for_html_content(r#"a"b"#), r#"a"b"#);
        assert_eq!(for_html_content("a'b"), "a'b");
        // for_html_attribute encodes quotes
        assert_eq!(for_html_attribute(r#"a"b"#), "a&#34;b");
        assert_eq!(for_html_attribute("a'b"), "a&#39;b");
    }

    #[test]
    fn unquoted_attr_comprehensive() {
        // all whitespace encoded
        assert_eq!(
            for_html_unquoted_attribute("\t\n\x0C\r "),
            "&#9;&#10;&#12;&#13;&#32;"
        );
        // all HTML-significant chars
        assert_eq!(
            for_html_unquoted_attribute("&<>\"'/=`"),
            "&amp;&lt;&gt;&#34;&#39;&#47;&#61;&#96;"
        );
    }

    // -- Rust-specific: no surrogates --
    // Rust str is guaranteed valid UTF-8, so there are no invalid surrogate
    // pairs to handle. this is a documented deviation from the Java encoder,
    // which replaces unpaired surrogates with space.
}

// ===========================================================================
// JavaScript context tests
// ===========================================================================

mod javascript {
    use super::*;

    #[test]
    fn xss_in_string_literal() {
        // typical XSS payload in a JS string
        assert_eq!(for_javascript("';alert(1);//"), r"\x27;alert(1);\/\/");
    }

    #[test]
    fn script_block_breakout() {
        assert_eq!(
            for_javascript("</script><script>alert(1)</script>"),
            r"<\/script><script>alert(1)<\/script>"
        );
    }

    #[test]
    fn all_named_escapes() {
        assert_eq!(for_javascript("\x08"), r"\b");
        assert_eq!(for_javascript("\t"), r"\t");
        assert_eq!(for_javascript("\n"), r"\n");
        assert_eq!(for_javascript("\x0C"), r"\f");
        assert_eq!(for_javascript("\r"), r"\r");
    }

    #[test]
    fn hex_escapes_for_c0_controls() {
        assert_eq!(for_javascript("\x00"), r"\x00");
        assert_eq!(for_javascript("\x01"), r"\x01");
        assert_eq!(for_javascript("\x07"), r"\x07");
        assert_eq!(for_javascript("\x0B"), r"\x0b");
        assert_eq!(for_javascript("\x0E"), r"\x0e");
        assert_eq!(for_javascript("\x1F"), r"\x1f");
    }

    #[test]
    fn unicode_line_terminators() {
        assert_eq!(for_javascript("\u{2028}"), r"\u2028");
        assert_eq!(for_javascript("\u{2029}"), r"\u2029");
        // these are JS line terminators that would break string literals
        assert_eq!(for_javascript("a\u{2028}b\u{2029}c"), r"a\u2028b\u2029c");
    }

    #[test]
    fn backslash_escaping() {
        assert_eq!(for_javascript(r"\"), r"\\");
        assert_eq!(for_javascript(r"\\"), r"\\\\");
        assert_eq!(for_javascript(r"\n"), r"\\n");
    }

    #[test]
    fn preserves_non_ascii() {
        assert_eq!(for_javascript("café"), "café");
        assert_eq!(for_javascript("日本語"), "日本語");
        assert_eq!(for_javascript("😀"), "😀");
    }

    #[test]
    fn backtick_not_encoded() {
        // documented: backtick is NOT encoded — template literals are unsafe
        assert_eq!(for_javascript("`template`"), "`template`");
    }

    // -- context comparisons --

    #[test]
    fn universal_vs_attribute_slash() {
        assert_eq!(for_javascript("a/b"), r"a\/b");
        assert_eq!(for_javascript_attribute("a/b"), "a/b");
    }

    #[test]
    fn universal_vs_block_quotes() {
        assert_eq!(for_javascript(r#"a"b"#), r"a\x22b");
        assert_eq!(for_javascript_block(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_javascript("a'b"), r"a\x27b");
        assert_eq!(for_javascript_block("a'b"), r"a\'b");
    }

    #[test]
    fn source_minimal_encoding() {
        // source doesn't encode / or &
        assert_eq!(for_javascript_source("a/b&c"), "a/b&c");
        // but still encodes control chars and line terminators
        assert_eq!(for_javascript_source("\n"), r"\n");
        assert_eq!(for_javascript_source("\u{2028}"), r"\u2028");
    }

    #[test]
    fn block_vs_source_ampersand() {
        assert_eq!(for_javascript_block("a&b"), r"a\x26b");
        assert_eq!(for_javascript_source("a&b"), "a&b");
    }

    // -- edge cases --

    #[test]
    fn empty_string() {
        assert_eq!(for_javascript(""), "");
    }

    #[test]
    fn already_escaped_input() {
        // encoding a string that already has JS escapes should double-escape
        assert_eq!(for_javascript(r"\n"), r"\\n");
        assert_eq!(for_javascript(r"\x22"), r"\\x22");
    }
}

// ===========================================================================
// CSS context tests
// ===========================================================================

mod css {
    use super::*;

    #[test]
    fn basic_encoding() {
        assert_eq!(for_css_string("hello"), "hello");
        assert_eq!(for_css_string(""), "");
    }

    #[test]
    fn hex_escape_format() {
        // shortest hex, no zero-padding
        assert_eq!(for_css_string("\x00"), r"\0");
        assert_eq!(for_css_string("\x01"), r"\1");
        assert_eq!(for_css_string("\""), r"\22");
        assert_eq!(for_css_string("'"), r"\27");
    }

    #[test]
    fn trailing_space_before_hex_digit() {
        // next char is hex digit → space needed
        assert_eq!(for_css_string("\"a"), r"\22 a"); // a is hex
        assert_eq!(for_css_string("\"0"), r"\22 0"); // 0 is hex
        assert_eq!(for_css_string("\"f"), r"\22 f"); // f is hex
        assert_eq!(for_css_string("\"F"), r"\22 F"); // F is hex
                                                     // next char is NOT hex → no space
        assert_eq!(for_css_string("\"g"), r"\22g"); // g is not hex
        assert_eq!(for_css_string("\"z"), r"\22z");
        assert_eq!(for_css_string("\"!"), r"\22!");
    }

    #[test]
    fn trailing_space_before_whitespace() {
        // space after hex escape before whitespace chars
        assert_eq!(for_css_string("\" "), r"\22  "); // space
        assert_eq!(for_css_string("\"\t"), r"\22 \9"); // tab (also encoded)
        assert_eq!(for_css_string("\"\n"), r"\22 \a"); // LF (also encoded)
    }

    #[test]
    fn no_trailing_space_at_end() {
        assert_eq!(for_css_string("\""), r"\22");
        assert_eq!(for_css_string("'"), r"\27");
    }

    #[test]
    fn consecutive_encoded_chars() {
        assert_eq!(for_css_string("\"'"), r"\22\27");
        // \ → \5c, next input char is " which is not a hex digit (it will
        // be encoded separately), so no trailing space after \5c
        assert_eq!(for_css_string("\\\""), r"\5c\22");
    }

    #[test]
    fn css_string_xss_payload() {
        assert_eq!(
            for_css_string("expression(alert(1))"),
            r"expression\28 alert\28 1\29\29"
        );
    }

    #[test]
    fn noncharacters() {
        assert_eq!(for_css_string("\u{FDD0}"), "_");
        assert_eq!(for_css_string("\u{FFFE}"), "_");
        assert_eq!(for_css_string("\u{FFFF}"), "_");
    }

    #[test]
    fn preserves_non_ascii() {
        assert_eq!(for_css_string("café"), "café");
        assert_eq!(for_css_string("日本語"), "日本語");
    }

    // -- for_css_url vs for_css_string --

    #[test]
    fn url_does_not_encode_parens() {
        assert_eq!(for_css_url("a(b)c"), "a(b)c");
        // but css_string does — c is a hex digit so space after \29
        assert_eq!(for_css_string("a(b)c"), r"a\28 b\29 c");
    }

    #[test]
    fn url_encodes_everything_else() {
        assert_eq!(for_css_url("\""), r"\22");
        assert_eq!(for_css_url("'"), r"\27");
        assert_eq!(for_css_url("\\"), r"\5c");
        assert_eq!(for_css_url("<"), r"\3c");
    }
}

// ===========================================================================
// URI component tests
// ===========================================================================

mod uri {
    use super::*;

    #[test]
    fn unreserved_chars_pass_through() {
        let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assert_eq!(for_uri_component(unreserved), unreserved);
    }

    #[test]
    fn reserved_chars_encoded() {
        assert_eq!(for_uri_component(":"), "%3A");
        assert_eq!(for_uri_component("/"), "%2F");
        assert_eq!(for_uri_component("?"), "%3F");
        assert_eq!(for_uri_component("#"), "%23");
        assert_eq!(for_uri_component("["), "%5B");
        assert_eq!(for_uri_component("]"), "%5D");
        assert_eq!(for_uri_component("@"), "%40");
        assert_eq!(for_uri_component("!"), "%21");
        assert_eq!(for_uri_component("$"), "%24");
        assert_eq!(for_uri_component("&"), "%26");
        assert_eq!(for_uri_component("'"), "%27");
        assert_eq!(for_uri_component("("), "%28");
        assert_eq!(for_uri_component(")"), "%29");
        assert_eq!(for_uri_component("*"), "%2A");
        assert_eq!(for_uri_component("+"), "%2B");
        assert_eq!(for_uri_component(","), "%2C");
        assert_eq!(for_uri_component(";"), "%3B");
        assert_eq!(for_uri_component("="), "%3D");
    }

    #[test]
    fn space_encoded() {
        assert_eq!(for_uri_component(" "), "%20");
    }

    #[test]
    fn html_significant_chars_encoded() {
        assert_eq!(for_uri_component("<"), "%3C");
        assert_eq!(for_uri_component(">"), "%3E");
        assert_eq!(for_uri_component("\""), "%22");
    }

    // -- UTF-8 multi-byte encoding --

    #[test]
    fn two_byte_utf8() {
        // U+00A0 NBSP → C2 A0
        assert_eq!(for_uri_component("\u{00A0}"), "%C2%A0");
        // U+00E9 é → C3 A9
        assert_eq!(for_uri_component("é"), "%C3%A9");
        // U+07FF → DF BF
        assert_eq!(for_uri_component("\u{07FF}"), "%DF%BF");
    }

    #[test]
    fn three_byte_utf8() {
        // U+0800 → E0 A0 80
        assert_eq!(for_uri_component("\u{0800}"), "%E0%A0%80");
        // U+4E16 世 → E4 B8 96
        assert_eq!(for_uri_component("世"), "%E4%B8%96");
        // U+FFFD → EF BF BD
        assert_eq!(for_uri_component("\u{FFFD}"), "%EF%BF%BD");
    }

    #[test]
    fn four_byte_utf8() {
        // U+10000 → F0 90 80 80
        assert_eq!(for_uri_component("\u{10000}"), "%F0%90%80%80");
        // U+1F600 😀 → F0 9F 98 80
        assert_eq!(for_uri_component("😀"), "%F0%9F%98%80");
    }

    #[test]
    fn control_chars() {
        assert_eq!(for_uri_component("\x00"), "%00");
        assert_eq!(for_uri_component("\x01"), "%01");
        assert_eq!(for_uri_component("\x1F"), "%1F");
        assert_eq!(for_uri_component("\x7F"), "%7F");
    }

    // -- practical cases --

    #[test]
    fn query_parameter_encoding() {
        assert_eq!(
            for_uri_component("search term with spaces"),
            "search%20term%20with%20spaces"
        );
    }

    #[test]
    fn full_query_value() {
        assert_eq!(
            for_uri_component("key=value&other=more"),
            "key%3Dvalue%26other%3Dmore"
        );
    }

    #[test]
    fn unicode_path_segment() {
        assert_eq!(
            for_uri_component("ファイル"),
            "%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB"
        );
    }

    // -- boundary conditions --

    #[test]
    fn empty_string() {
        assert_eq!(for_uri_component(""), "");
    }

    #[test]
    fn single_unreserved() {
        assert_eq!(for_uri_component("a"), "a");
    }

    #[test]
    fn all_percent_encoded() {
        assert_eq!(for_uri_component("   "), "%20%20%20");
    }

    // -- Rust-specific: no surrogates --
    // the Java encoder handles surrogate pairs in char[] input and replaces
    // invalid surrogates with "-". Rust str is always valid UTF-8, so
    // surrogates cannot appear. supplementary plane characters (U+10000+)
    // are valid UTF-8 and encoded as 4-byte percent-encoded sequences.
}

// ===========================================================================
// cross-context tests
// ===========================================================================

mod cross_context {
    use super::*;

    #[test]
    fn same_input_different_contexts() {
        let input = r#"<img src="x" onerror="alert('xss')">"#;

        let html = for_html(input);
        let js = for_javascript(input);
        let css = for_css_string(input);
        let uri = for_uri_component(input);

        // each produces different output appropriate for its context
        assert_ne!(html, js);
        assert_ne!(js, css);
        assert_ne!(css, uri);

        // html uses HTML entities
        assert!(html.contains("&lt;"));
        // js uses backslash escapes
        assert!(js.contains("\\x22"));
        // css uses hex escapes
        assert!(css.contains("\\3c"));
        // uri uses percent encoding
        assert!(uri.contains("%3C"));
    }

    #[test]
    fn writer_matches_string() {
        let input = r#"test <b>"bold"</b> & 'italic' café 日本語"#;

        let mut html_w = String::new();
        write_html(&mut html_w, input).unwrap();
        assert_eq!(for_html(input), html_w);

        let mut js_w = String::new();
        write_javascript(&mut js_w, input).unwrap();
        assert_eq!(for_javascript(input), js_w);

        let mut css_w = String::new();
        write_css_string(&mut css_w, input).unwrap();
        assert_eq!(for_css_string(input), css_w);

        let mut uri_w = String::new();
        write_uri_component(&mut uri_w, input).unwrap();
        assert_eq!(for_uri_component(input), uri_w);
    }

    #[test]
    fn safe_string_unchanged_in_all_contexts() {
        let safe = "hello world 123";
        // safe in HTML (no angle brackets, quotes, or ampersands)
        assert_eq!(for_html(safe), safe);
        // safe in JS (no quotes, backslash, or control chars)
        assert_eq!(for_javascript(safe), safe);
        // safe in CSS (no special chars)
        assert_eq!(for_css_string(safe), safe);
        // NOT safe in URI (space is encoded)
        assert_ne!(for_uri_component(safe), safe);
    }
}
