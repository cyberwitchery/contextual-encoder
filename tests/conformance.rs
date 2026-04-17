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
// XML context tests
// ===========================================================================

mod xml {
    use super::*;

    // -- XML 1.0 aliases --

    #[test]
    fn aliases_identical_to_html() {
        let input = r#"<root attr="val">&amp; 'x' </root>"#;
        assert_eq!(for_xml(input), for_html(input));
        assert_eq!(for_xml_content(input), for_html_content(input));
        assert_eq!(for_xml_attribute(input), for_html_attribute(input));
    }

    #[test]
    fn xml_writer_matches_string() {
        let input = r#"<test attr="val">&'</test>"#;
        let mut w = String::new();
        write_xml(&mut w, input).unwrap();
        assert_eq!(for_xml(input), w);

        let mut w = String::new();
        write_xml_content(&mut w, input).unwrap();
        assert_eq!(for_xml_content(input), w);

        let mut w = String::new();
        write_xml_attribute(&mut w, input).unwrap();
        assert_eq!(for_xml_attribute(input), w);
    }

    // -- XML comment --

    #[test]
    fn comment_safe_passthrough() {
        assert_eq!(for_xml_comment("safe comment text"), "safe comment text");
        assert_eq!(for_xml_comment(""), "");
    }

    #[test]
    fn comment_neutralizes_double_hyphen() {
        assert_eq!(for_xml_comment("a--b"), "a-~b");
        assert_eq!(for_xml_comment("a---b"), "a-~-b");
        assert_eq!(for_xml_comment("----"), "-~-~");
    }

    #[test]
    fn comment_trailing_hyphen() {
        assert_eq!(for_xml_comment("abc-"), "abc~");
        assert_eq!(for_xml_comment("-"), "~");
        assert_eq!(for_xml_comment("--"), "-~");
    }

    #[test]
    fn comment_invalid_xml_chars_replaced() {
        // C0 controls (except tab/LF/CR)
        assert_eq!(for_xml_comment("a\x00b"), "a b");
        assert_eq!(for_xml_comment("a\x01b"), "a b");
        // DEL
        assert_eq!(for_xml_comment("a\x7Fb"), "a b");
        // C1 controls
        assert_eq!(for_xml_comment("a\u{0080}b"), "a b");
        // non-characters
        assert_eq!(for_xml_comment("a\u{FDD0}b"), "a b");
    }

    #[test]
    fn comment_preserves_allowed_chars() {
        assert_eq!(for_xml_comment("café 日本語"), "café 日本語");
        assert_eq!(for_xml_comment("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn comment_combined_edge_cases() {
        // hyphen + invalid char + hyphen
        assert_eq!(for_xml_comment("-\x00-"), "- ~");
    }

    #[test]
    fn comment_writer_matches_string() {
        let input = "test--comment-";
        let mut w = String::new();
        write_xml_comment(&mut w, input).unwrap();
        assert_eq!(for_xml_comment(input), w);
    }

    // -- CDATA --

    #[test]
    fn cdata_safe_passthrough() {
        assert_eq!(for_cdata("safe text"), "safe text");
        assert_eq!(for_cdata(""), "");
        // angle brackets are fine inside CDATA
        assert_eq!(for_cdata("<b>bold</b>"), "<b>bold</b>");
    }

    #[test]
    fn cdata_splits_closing_delimiter() {
        assert_eq!(for_cdata("a]]>b"), "a]]]]><![CDATA[>b");
    }

    #[test]
    fn cdata_multiple_splits() {
        assert_eq!(for_cdata("x]]>y]]>z"), "x]]]]><![CDATA[>y]]]]><![CDATA[>z");
    }

    #[test]
    fn cdata_brackets_without_gt() {
        // just brackets, no >
        assert_eq!(for_cdata("]]"), "]]");
        assert_eq!(for_cdata("]]]"), "]]]");
        // single bracket + >
        assert_eq!(for_cdata("]>"), "]>");
    }

    #[test]
    fn cdata_extra_brackets_before_gt() {
        // ]]]> = ] + ]]>
        assert_eq!(for_cdata("]]]>"), "]]]]]><![CDATA[>");
        // ]]]]> = ]] + ]]>
        assert_eq!(for_cdata("]]]]>"), "]]]]]]><![CDATA[>");
    }

    #[test]
    fn cdata_at_start() {
        assert_eq!(for_cdata("]]>rest"), "]]]]><![CDATA[>rest");
    }

    #[test]
    fn cdata_at_end() {
        assert_eq!(for_cdata("start]]>"), "start]]]]><![CDATA[>");
    }

    #[test]
    fn cdata_invalid_xml_replaced() {
        assert_eq!(for_cdata("a\x00b"), "a b");
        assert_eq!(for_cdata("a\x01b"), "a b");
        assert_eq!(for_cdata("a\u{FDD0}b"), "a b");
    }

    #[test]
    fn cdata_writer_matches_string() {
        let input = "x]]>y\x00z]]";
        let mut w = String::new();
        write_cdata(&mut w, input).unwrap();
        assert_eq!(for_cdata(input), w);
    }

    // -- XML 1.1 --

    #[test]
    fn xml11_entities() {
        assert_eq!(for_xml11("<&>\"'"), "&lt;&amp;&gt;&#34;&#39;");
    }

    #[test]
    fn xml11_controls_as_char_references() {
        // C0 controls (not tab/LF/CR) → &#xHH;
        assert_eq!(for_xml11("a\x01b"), "a&#x1;b");
        assert_eq!(for_xml11("a\x08b"), "a&#x8;b");
        assert_eq!(for_xml11("a\x0Bb"), "a&#xb;b");
        assert_eq!(for_xml11("a\x0Cb"), "a&#xc;b");
        assert_eq!(for_xml11("a\x1Fb"), "a&#x1f;b");
    }

    #[test]
    fn xml11_preserves_tab_lf_cr() {
        assert_eq!(for_xml11("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn xml11_nel_passes_through() {
        // NEL (U+0085) is NOT restricted in XML 1.1
        assert_eq!(for_xml11("a\u{0085}b"), "a\u{0085}b");
    }

    #[test]
    fn xml11_del_and_c1_as_references() {
        assert_eq!(for_xml11("a\x7Fb"), "a&#x7f;b");
        assert_eq!(for_xml11("a\u{0080}b"), "a&#x80;b");
        assert_eq!(for_xml11("a\u{0084}b"), "a&#x84;b");
        assert_eq!(for_xml11("a\u{0086}b"), "a&#x86;b");
        assert_eq!(for_xml11("a\u{009F}b"), "a&#x9f;b");
    }

    #[test]
    fn xml11_nul_replaced_with_space() {
        // NUL is invalid (not representable) in XML 1.1
        assert_eq!(for_xml11("a\x00b"), "a b");
    }

    #[test]
    fn xml11_nonchars_replaced_with_space() {
        assert_eq!(for_xml11("a\u{FDD0}b"), "a b");
        assert_eq!(for_xml11("a\u{FFFE}b"), "a b");
    }

    #[test]
    fn xml11_content_no_quotes() {
        assert_eq!(for_xml11_content(r#"a"b'c"#), r#"a"b'c"#);
        assert_eq!(for_xml11_content("a\x01b"), "a&#x1;b");
    }

    #[test]
    fn xml11_attribute_no_gt() {
        assert_eq!(for_xml11_attribute("a>b"), "a>b");
        assert_eq!(for_xml11_attribute(r#"a"b"#), "a&#34;b");
        assert_eq!(for_xml11_attribute("a\x01b"), "a&#x1;b");
    }

    #[test]
    fn xml11_writer_matches_string() {
        let input = "test\x01\x7F<>&\u{0085}";
        let mut w = String::new();
        write_xml11(&mut w, input).unwrap();
        assert_eq!(for_xml11(input), w);

        let mut w = String::new();
        write_xml11_content(&mut w, input).unwrap();
        assert_eq!(for_xml11_content(input), w);

        let mut w = String::new();
        write_xml11_attribute(&mut w, input).unwrap();
        assert_eq!(for_xml11_attribute(input), w);
    }
}

// ===========================================================================
// Java context tests
// ===========================================================================

mod java {
    use super::*;

    #[test]
    fn passthrough() {
        assert_eq!(for_java("hello world"), "hello world");
        assert_eq!(for_java(""), "");
        assert_eq!(for_java("café 日本語"), "café 日本語");
    }

    #[test]
    fn named_escapes() {
        assert_eq!(for_java("\x08"), "\\b");
        assert_eq!(for_java("\t"), "\\t");
        assert_eq!(for_java("\n"), "\\n");
        assert_eq!(for_java("\x0C"), "\\f");
        assert_eq!(for_java("\r"), "\\r");
    }

    #[test]
    fn quotes_and_backslash() {
        assert_eq!(for_java(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(for_java("it's"), r"it\'s");
        assert_eq!(for_java(r"back\slash"), r"back\\slash");
    }

    #[test]
    fn octal_escapes_shortest() {
        // NUL before non-octal → shortest form
        assert_eq!(for_java("\x00a"), "\\0a");
        assert_eq!(for_java("\x01a"), "\\1a");
        assert_eq!(for_java("\x07a"), "\\7a");
    }

    #[test]
    fn octal_escapes_three_digit_disambiguation() {
        // NUL before octal digit → 3-digit form
        assert_eq!(for_java("\x000"), "\\0000");
        assert_eq!(for_java("\x007"), "\\0007");
        assert_eq!(for_java("\x015"), "\\0015");
    }

    #[test]
    fn octal_at_end_shortest() {
        assert_eq!(for_java("\x00"), "\\0");
        assert_eq!(for_java("\x07"), "\\7");
        assert_eq!(for_java("\x7F"), "\\177");
    }

    #[test]
    fn del_octal() {
        // DEL = 0x7F = 0o177
        assert_eq!(for_java("a\x7Fb"), "a\\177b");
    }

    #[test]
    fn line_separators() {
        assert_eq!(for_java("\u{2028}"), "\\u2028");
        assert_eq!(for_java("\u{2029}"), "\\u2029");
    }

    #[test]
    fn supplementary_plane() {
        // U+1F600 GRINNING FACE → surrogate pair
        assert_eq!(for_java("\u{1F600}"), "\\ud83d\\ude00");
        // U+10000 → first supplementary code point
        assert_eq!(for_java("\u{10000}"), "\\ud800\\udc00");
    }

    #[test]
    fn noncharacters() {
        assert_eq!(for_java("\u{FDD0}"), " ");
        assert_eq!(for_java("\u{FFFE}"), " ");
    }

    #[test]
    fn mixed_xss_payload() {
        // Java encoder does not encode < / > — they are not special
        // in Java string literals (unlike JS where </script> matters)
        assert_eq!(
            for_java("<script>alert(\"xss\")</script>"),
            "<script>alert(\\\"xss\\\")</script>"
        );
    }

    #[test]
    fn writer_matches_string() {
        let input = "test\x00\"\\\u{1F600}\u{2028}";
        let mut w = String::new();
        write_java(&mut w, input).unwrap();
        assert_eq!(for_java(input), w);
    }
}

// ===========================================================================
// Go literal context tests
// ===========================================================================

mod go_literals {
    use super::*;

    // -- for_go_string --

    #[test]
    fn string_passthrough() {
        assert_eq!(for_go_string("hello world"), "hello world");
        assert_eq!(for_go_string(""), "");
        assert_eq!(
            for_go_string("caf\u{00e9} \u{65E5}\u{672C}\u{8A9E} \u{1F600}"),
            "caf\u{00e9} \u{65E5}\u{672C}\u{8A9E} \u{1F600}"
        );
    }

    #[test]
    fn string_escapes_double_quote_not_single() {
        assert_eq!(for_go_string(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_go_string("a'b"), "a'b");
    }

    #[test]
    fn string_all_named_escapes() {
        assert_eq!(for_go_string("\x07"), "\\a");
        assert_eq!(for_go_string("\x08"), "\\b");
        assert_eq!(for_go_string("\t"), "\\t");
        assert_eq!(for_go_string("\n"), "\\n");
        assert_eq!(for_go_string("\x0B"), "\\v");
        assert_eq!(for_go_string("\x0C"), "\\f");
        assert_eq!(for_go_string("\r"), "\\r");
    }

    #[test]
    fn string_hex_for_controls() {
        assert_eq!(for_go_string("\x00"), "\\x00");
        assert_eq!(for_go_string("\x01"), "\\x01");
        assert_eq!(for_go_string("\x06"), "\\x06");
        assert_eq!(for_go_string("\x0E"), "\\x0e");
        assert_eq!(for_go_string("\x1F"), "\\x1f");
        assert_eq!(for_go_string("\x7F"), "\\x7f");
    }

    #[test]
    fn string_backslash() {
        assert_eq!(for_go_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_nonchars_replaced() {
        assert_eq!(for_go_string("\u{FDD0}"), " ");
        assert_eq!(for_go_string("\u{FFFE}"), " ");
    }

    #[test]
    fn string_supplementary_plane_passes_through() {
        // Go source is UTF-8 — no surrogate pairs needed
        assert_eq!(for_go_string("\u{1F600}"), "\u{1F600}");
        assert_eq!(for_go_string("\u{10000}"), "\u{10000}");
    }

    #[test]
    fn string_writer_matches() {
        let input = "test\x00\"\\\ncaf\u{00e9}\u{1F600}";
        let mut w = String::new();
        write_go_string(&mut w, input).unwrap();
        assert_eq!(for_go_string(input), w);
    }

    // -- for_go_char --

    #[test]
    fn char_passthrough() {
        assert_eq!(for_go_char("hello world"), "hello world");
        assert_eq!(for_go_char("caf\u{00e9}"), "caf\u{00e9}");
    }

    #[test]
    fn char_escapes_single_quote_not_double() {
        assert_eq!(for_go_char("a'b"), r"a\'b");
        assert_eq!(for_go_char(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn char_all_named_escapes() {
        assert_eq!(for_go_char("\x07"), "\\a");
        assert_eq!(for_go_char("\x08"), "\\b");
        assert_eq!(for_go_char("\t"), "\\t");
        assert_eq!(for_go_char("\n"), "\\n");
        assert_eq!(for_go_char("\x0B"), "\\v");
        assert_eq!(for_go_char("\x0C"), "\\f");
        assert_eq!(for_go_char("\r"), "\\r");
    }

    #[test]
    fn char_hex_for_controls() {
        assert_eq!(for_go_char("\x01"), "\\x01");
        assert_eq!(for_go_char("\x7F"), "\\x7f");
    }

    #[test]
    fn char_nonchars_replaced() {
        assert_eq!(for_go_char("\u{FDD0}"), " ");
    }

    #[test]
    fn char_writer_matches() {
        let input = "test\x00'\\\ncaf\u{00e9}";
        let mut w = String::new();
        write_go_char(&mut w, input).unwrap();
        assert_eq!(for_go_char(input), w);
    }

    // -- for_go_byte_string --

    #[test]
    fn byte_string_ascii_passthrough() {
        assert_eq!(for_go_byte_string("hello world"), "hello world");
        assert_eq!(for_go_byte_string(""), "");
    }

    #[test]
    fn byte_string_escapes_double_quote_not_single() {
        assert_eq!(for_go_byte_string(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_go_byte_string("a'b"), "a'b");
    }

    #[test]
    fn byte_string_all_named_escapes() {
        assert_eq!(for_go_byte_string("\x07"), "\\a");
        assert_eq!(for_go_byte_string("\x08"), "\\b");
        assert_eq!(for_go_byte_string("\t"), "\\t");
        assert_eq!(for_go_byte_string("\n"), "\\n");
        assert_eq!(for_go_byte_string("\x0B"), "\\v");
        assert_eq!(for_go_byte_string("\x0C"), "\\f");
        assert_eq!(for_go_byte_string("\r"), "\\r");
    }

    #[test]
    fn byte_string_hex_for_controls() {
        assert_eq!(for_go_byte_string("\x00"), "\\x00");
        assert_eq!(for_go_byte_string("\x01"), "\\x01");
        assert_eq!(for_go_byte_string("\x7F"), "\\x7f");
    }

    #[test]
    fn byte_string_non_ascii_as_utf8_bytes() {
        // é = U+00E9 → UTF-8: C3 A9
        assert_eq!(for_go_byte_string("caf\u{00e9}"), r"caf\xc3\xa9");
        // 日 = U+65E5 → UTF-8: E6 97 A5
        assert_eq!(for_go_byte_string("\u{65E5}"), r"\xe6\x97\xa5");
        // 😀 = U+1F600 → UTF-8: F0 9F 98 80
        assert_eq!(for_go_byte_string("\u{1F600}"), r"\xf0\x9f\x98\x80");
    }

    #[test]
    fn byte_string_nonchars_as_bytes() {
        // non-characters get byte-encoded (not replaced with space)
        // U+FDD0 → UTF-8: EF B7 90
        assert_eq!(for_go_byte_string("\u{FDD0}"), r"\xef\xb7\x90");
    }

    #[test]
    fn byte_string_vs_string_non_ascii() {
        // string passes non-ASCII through; byte string encodes it
        assert_eq!(for_go_string("\u{00e9}"), "\u{00e9}");
        assert_eq!(for_go_byte_string("\u{00e9}"), r"\xc3\xa9");
    }

    #[test]
    fn byte_string_writer_matches() {
        let input = "test\x00\"\\caf\u{00e9}\u{1F600}";
        let mut w = String::new();
        write_go_byte_string(&mut w, input).unwrap();
        assert_eq!(for_go_byte_string(input), w);
    }

    // -- Go vs Java: key differences --
    // Go strings are UTF-8 and don't need surrogate pairs for supplementary
    // plane characters. Go has \a and \v named escapes that Java lacks.
    // Go uses \xHH for unnamed controls (not octal like Java).

    #[test]
    fn go_vs_java_supplementary_plane() {
        // Go passes through; Java uses surrogate pairs
        assert_eq!(for_go_string("\u{1F600}"), "\u{1F600}");
        assert_eq!(for_java("\u{1F600}"), "\\ud83d\\ude00");
    }

    #[test]
    fn go_has_alert_and_vtab() {
        // Go has \a and \v; Java does not (Java uses octal for these)
        assert_eq!(for_go_string("\x07"), "\\a");
        assert_eq!(for_go_string("\x0B"), "\\v");
        assert_eq!(for_java("\x07a"), "\\7a");
        assert_eq!(for_java("\x0Ba"), "\\13a");
    }
}

// ===========================================================================
// Rust literal context tests
// ===========================================================================

mod rust_literals {
    use super::*;

    // -- for_rust_string --

    #[test]
    fn string_passthrough() {
        assert_eq!(for_rust_string("hello world"), "hello world");
        assert_eq!(for_rust_string(""), "");
        assert_eq!(for_rust_string("café 日本語 😀"), "café 日本語 😀");
    }

    #[test]
    fn string_escapes_double_quote_not_single() {
        assert_eq!(for_rust_string(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_rust_string("a'b"), "a'b");
    }

    #[test]
    fn string_named_escapes() {
        assert_eq!(for_rust_string("\0"), "\\0");
        assert_eq!(for_rust_string("\t"), "\\t");
        assert_eq!(for_rust_string("\n"), "\\n");
        assert_eq!(for_rust_string("\r"), "\\r");
    }

    #[test]
    fn string_hex_for_controls() {
        assert_eq!(for_rust_string("\x01"), "\\x01");
        assert_eq!(for_rust_string("\x08"), "\\x08");
        assert_eq!(for_rust_string("\x0B"), "\\x0b");
        assert_eq!(for_rust_string("\x0C"), "\\x0c");
        assert_eq!(for_rust_string("\x1F"), "\\x1f");
        assert_eq!(for_rust_string("\x7F"), "\\x7f");
    }

    #[test]
    fn string_backslash() {
        assert_eq!(for_rust_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_nonchars_replaced() {
        assert_eq!(for_rust_string("\u{FDD0}"), " ");
        assert_eq!(for_rust_string("\u{FFFE}"), " ");
    }

    #[test]
    fn string_supplementary_plane_passes_through() {
        // unlike Java, Rust strings are UTF-8 — no surrogate pairs needed
        assert_eq!(for_rust_string("😀"), "😀");
        assert_eq!(for_rust_string("\u{10000}"), "\u{10000}");
    }

    #[test]
    fn string_writer_matches() {
        let input = "test\0\"\\\ncafé\u{1F600}";
        let mut w = String::new();
        write_rust_string(&mut w, input).unwrap();
        assert_eq!(for_rust_string(input), w);
    }

    // -- for_rust_char --

    #[test]
    fn char_passthrough() {
        assert_eq!(for_rust_char("hello world"), "hello world");
        assert_eq!(for_rust_char("café"), "café");
    }

    #[test]
    fn char_escapes_single_quote_not_double() {
        assert_eq!(for_rust_char("a'b"), r"a\'b");
        assert_eq!(for_rust_char(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn char_named_escapes() {
        assert_eq!(for_rust_char("\0"), "\\0");
        assert_eq!(for_rust_char("\t"), "\\t");
        assert_eq!(for_rust_char("\n"), "\\n");
        assert_eq!(for_rust_char("\r"), "\\r");
    }

    #[test]
    fn char_hex_for_controls() {
        assert_eq!(for_rust_char("\x01"), "\\x01");
        assert_eq!(for_rust_char("\x7F"), "\\x7f");
    }

    #[test]
    fn char_nonchars_replaced() {
        assert_eq!(for_rust_char("\u{FDD0}"), " ");
    }

    #[test]
    fn char_writer_matches() {
        let input = "test\0'\\\ncafé";
        let mut w = String::new();
        write_rust_char(&mut w, input).unwrap();
        assert_eq!(for_rust_char(input), w);
    }

    // -- for_rust_byte_string --

    #[test]
    fn byte_string_ascii_passthrough() {
        assert_eq!(for_rust_byte_string("hello world"), "hello world");
        assert_eq!(for_rust_byte_string(""), "");
    }

    #[test]
    fn byte_string_escapes_double_quote_not_single() {
        assert_eq!(for_rust_byte_string(r#"a"b"#), r#"a\"b"#);
        assert_eq!(for_rust_byte_string("a'b"), "a'b");
    }

    #[test]
    fn byte_string_named_escapes() {
        assert_eq!(for_rust_byte_string("\0"), "\\0");
        assert_eq!(for_rust_byte_string("\t"), "\\t");
        assert_eq!(for_rust_byte_string("\n"), "\\n");
        assert_eq!(for_rust_byte_string("\r"), "\\r");
    }

    #[test]
    fn byte_string_hex_for_controls() {
        assert_eq!(for_rust_byte_string("\x01"), "\\x01");
        assert_eq!(for_rust_byte_string("\x7F"), "\\x7f");
    }

    #[test]
    fn byte_string_non_ascii_as_utf8_bytes() {
        // é = U+00E9 → UTF-8: C3 A9
        assert_eq!(for_rust_byte_string("café"), r"caf\xc3\xa9");
        // 日 = U+65E5 → UTF-8: E6 97 A5
        assert_eq!(for_rust_byte_string("日"), r"\xe6\x97\xa5");
        // 😀 = U+1F600 → UTF-8: F0 9F 98 80
        assert_eq!(for_rust_byte_string("😀"), r"\xf0\x9f\x98\x80");
    }

    #[test]
    fn byte_string_nonchars_as_bytes() {
        // non-characters get byte-encoded (not replaced with space)
        // U+FDD0 → UTF-8: EF B7 90
        assert_eq!(for_rust_byte_string("\u{FDD0}"), r"\xef\xb7\x90");
    }

    #[test]
    fn byte_string_vs_string_non_ascii() {
        // string passes non-ASCII through; byte string encodes it
        assert_eq!(for_rust_string("é"), "é");
        assert_eq!(for_rust_byte_string("é"), r"\xc3\xa9");
    }

    #[test]
    fn byte_string_writer_matches() {
        let input = "test\0\"\\café😀";
        let mut w = String::new();
        write_rust_byte_string(&mut w, input).unwrap();
        assert_eq!(for_rust_byte_string(input), w);
    }
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
