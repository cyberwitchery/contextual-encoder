//! conformance test suite.
//!
//! these tests verify encoding behavior against the OWASP Java Encoder
//! specification. test vectors are derived from the OWASP documentation,
//! Java Encoder source and test cases, and hand-written edge cases.
//!
//! where Rust behavior necessarily differs from Java (e.g., surrogate
//! handling), the tests document the Rust contract and note the difference.
//!
//! every vector is written with `upstream!`, `deviation!` or `non_owasp!`; a
//! plain `assert_eq!` does not compile here. with `CONFORMANCE_EXPORT=<file>`
//! set, the vectors are appended to `<file>` for `differential/owasp/Check.java`.

use std::io::Write as _;
use std::sync::Mutex;

use contextual_encoder::*;

use Deviation::*;
use Parity::{NonOwasp, Upstream};

/// signature shared by every `for_*` encoder.
type ForFn = fn(&str) -> String;

/// how a vector relates to the OWASP Java Encoder.
#[derive(Clone, Copy, Debug)]
enum Parity {
    /// OWASP produces exactly this output.
    Upstream,
    /// this crate deliberately differs from OWASP.
    Deviation(Deviation),
    /// OWASP has no encoder for this context.
    NonOwasp,
}

/// a deliberate difference from the OWASP Java Encoder 1.5.0.
#[derive(Clone, Copy, Debug)]
enum Deviation {
    /// NEL (U+0085) becomes a space like the other C1 controls.
    Nel,
    /// script data escapes `<` and `&`, not every character of `<!--`, `</script` or `${`.
    JsFragmentGuards,
    /// a css hex escape at the end of the input keeps its trailing space.
    CssTrailingSpace,
    /// `for_css_string` escapes `(` and `)`.
    CssStringParens,
    /// css noncharacters become `_`.
    CssNoncharacters,
    /// xml 1.1 character references have no leading zero (`&#x1;`).
    Xml11RefWidth,
    /// `for_json` escapes `/` and leaves `&` and `>` raw.
    Json,
}

#[allow(unused_macros)]
macro_rules! assert_eq {
    ($($t:tt)*) => {
        compile_error!("tag the vector with upstream!, deviation! or non_owasp!")
    };
}

macro_rules! upstream {
    ($encode:ident($input:expr), $expected:expr $(,)?) => {
        check(Upstream, stringify!($encode), $encode, &$input, &$expected)
    };
}

macro_rules! deviation {
    ($deviation:ident, $encode:ident($input:expr), $expected:expr $(,)?) => {
        check(
            Parity::Deviation($deviation),
            stringify!($encode),
            $encode,
            &$input,
            &$expected,
        )
    };
}

macro_rules! non_owasp {
    ($encode:ident($input:expr), $expected:expr $(,)?) => {{
        let input: &str = &$input;
        std::assert_eq!(
            $encode(input),
            $expected,
            "{}({input:?})",
            stringify!($encode)
        );
        export(NonOwasp, stringify!($encode), input, "");
    }};
}

#[track_caller]
fn check(parity: Parity, encoder: &str, encode: ForFn, input: &str, expected: &str) {
    std::assert_eq!(encode(input), expected, "{encoder}({input:?}), {parity:?}");
    export(parity, encoder, input, expected);
}

/// appends the vector to `$CONFORMANCE_EXPORT`, if set, as one escaped TSV row.
#[track_caller]
fn export(parity: Parity, encoder: &str, input: &str, expected: &str) {
    static FILE: Mutex<()> = Mutex::new(());
    let Some(path) = std::env::var_os("CONFORMANCE_EXPORT") else {
        return;
    };
    let tag = match parity {
        Upstream => String::from("upstream"),
        Parity::Deviation(deviation) => format!("deviation:{deviation:?}"),
        NonOwasp => String::from("non_owasp"),
    };
    let line = std::panic::Location::caller().line();
    let row = format!(
        "{tag}\t{line}\t{encoder}\t{}\t{}\n",
        tsv_escape(input),
        tsv_escape(expected)
    );
    let _guard = FILE.lock().unwrap();
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(row.as_bytes()))
        .unwrap();
}

/// printable ascii stays; everything else, and `\`, becomes `\u{HEX}`.
fn tsv_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ' '..='~' if c != '\\' => c.to_string(),
            c => format!("\\u{{{:x}}}", c as u32),
        })
        .collect()
}

// ===========================================================================
// HTML context tests
// ===========================================================================

mod html {
    use super::*;

    // -- basic dangerous characters --

    #[test]
    fn script_tag_injection() {
        upstream!(
            for_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn img_tag_injection() {
        upstream!(
            for_html(r#"<img src=x onerror="alert(1)">"#),
            "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;"
        );
    }

    #[test]
    fn ampersand_in_various_positions() {
        upstream!(for_html("&"), "&amp;");
        upstream!(for_html("&&"), "&amp;&amp;");
        upstream!(for_html("a&b&c"), "a&amp;b&amp;c");
        upstream!(for_html("&amp;"), "&amp;amp;");
    }

    #[test]
    fn already_encoded_input() {
        // encoding should be idempotent in the sense that re-encoding
        // produces a safely displayable result (double-encoded)
        upstream!(for_html("&lt;"), "&amp;lt;");
        upstream!(for_html("&#34;"), "&amp;#34;");
    }

    #[test]
    fn mixed_safe_and_unsafe() {
        upstream!(
            for_html("Hello, <world> & \"friends\"!"),
            "Hello, &lt;world&gt; &amp; &#34;friends&#34;!"
        );
    }

    // -- unicode --

    #[test]
    fn unicode() {
        for (input, expected) in [
            ("日本語テスト", "日本語テスト"),
            ("hello 😀 world", "hello 😀 world"),
            // U+1F600 GRINNING FACE
            ("😀", "😀"),
            // U+10000 LINEAR B SYLLABLE B008 A
            ("\u{10000}", "\u{10000}"),
            ("<café>", "&lt;café&gt;"),
            ("é<世>&😀", "é&lt;世&gt;&amp;😀"),
        ] {
            upstream!(for_html(input), expected);
        }
    }

    // -- control characters --

    #[test]
    fn all_c0_controls() {
        // 0x00-0x08: replaced with space
        for cp in 0x00u8..=0x08 {
            let s = String::from(char::from(cp));
            upstream!(for_html(&s), " ");
        }
        // 0x09 (tab), 0x0A (LF), 0x0D (CR): preserved
        upstream!(for_html("\x09"), "\x09");
        upstream!(for_html("\x0A"), "\x0A");
        upstream!(for_html("\x0D"), "\x0D");
        // 0x0B, 0x0C: replaced with space
        upstream!(for_html("\x0B"), " ");
        upstream!(for_html("\x0C"), " ");
        // 0x0E-0x1F: replaced with space
        for cp in 0x0Eu8..=0x1F {
            let s = String::from(char::from(cp));
            upstream!(for_html(&s), " ");
        }
    }

    #[test]
    fn del_replaced() {
        upstream!(for_html("\x7F"), " ");
    }

    #[test]
    fn c1_controls_replaced() {
        for cp in 0x80u32..=0x9F {
            let c = char::from_u32(cp).unwrap();
            let s = String::from(c);
            if c == '\u{85}' {
                deviation!(Nel, for_html(&s), " ");
            } else {
                upstream!(for_html(&s), " ");
            }
        }
    }

    // -- unicode non-characters --

    #[test]
    fn noncharacters_replaced() {
        upstream!(for_html("\u{FDD0}"), " ");
        upstream!(for_html("\u{FDEF}"), " ");
        upstream!(for_html("\u{FFFE}"), " ");
        upstream!(for_html("\u{FFFF}"), " ");
        upstream!(for_html("\u{1FFFE}"), " ");
        upstream!(for_html("\u{10FFFF}"), " ");
    }

    // -- boundary conditions --

    #[test]
    fn all_unsafe_string() {
        upstream!(for_html("<>&\"'"), "&lt;&gt;&amp;&#34;&#39;");
    }

    // -- context-specific behavior --

    #[test]
    fn content_vs_attribute_gt_handling() {
        // for_html_content encodes >
        upstream!(for_html_content("a>b"), "a&gt;b");
        // for_html_attribute does NOT encode >
        upstream!(for_html_attribute("a>b"), "a>b");
        // for_html encodes > (union of both)
        upstream!(for_html("a>b"), "a&gt;b");
    }

    #[test]
    fn content_vs_attribute_quote_handling() {
        // for_html_content does NOT encode quotes
        upstream!(for_html_content(r#"a"b"#), r#"a"b"#);
        upstream!(for_html_content("a'b"), "a'b");
        // for_html_attribute encodes quotes
        upstream!(for_html_attribute(r#"a"b"#), "a&#34;b");
        upstream!(for_html_attribute("a'b"), "a&#39;b");
    }

    #[test]
    fn unquoted_attr_comprehensive() {
        // all whitespace encoded
        upstream!(
            for_html_unquoted_attribute("\t\n\x0C\r "),
            "&#9;&#10;&#12;&#13;&#32;"
        );
        // all HTML-significant chars
        upstream!(
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
        deviation!(
            JsFragmentGuards,
            for_javascript("';alert(1);//"),
            r"\x27;alert(1);\/\/"
        );
    }

    #[test]
    fn script_block_breakout() {
        deviation!(
            JsFragmentGuards,
            for_javascript("</script><script>alert(1)</script>"),
            r"\x3c\/script>\x3cscript>alert(1)\x3c\/script>"
        );
    }

    // `<` opens every script-data escape (`</script>`, `<!--`, and
    // `<!--<script>`, which reaches script-data-double-escaped state where
    // the block's own `</script>` stops closing it)
    #[test]
    fn script_data_lt_encoded() {
        let guards = Parity::Deviation(JsFragmentGuards);
        let cases = [
            (Upstream, "a<b", r"a\x3cb"),
            (Upstream, "<", r"\x3c"),
            (guards, "<!--", r"\x3c!--"),
            (guards, "<script", r"\x3cscript"),
            (guards, "</script>", r"\x3c\/script>"),
            (guards, "<!--<script>", r"\x3c!--\x3cscript>"),
            (guards, "<!--<script >", r"\x3c!--\x3cscript >"),
        ];
        for (parity, input, expected) in cases {
            check(parity, "javascript", for_javascript, input, expected);
            check(
                parity,
                "javascript_block",
                for_javascript_block,
                input,
                expected,
            );
            check(NonOwasp, "js_template", for_js_template, input, expected);
        }
    }

    // an XHTML parser decodes character references inside `<script>`, so a
    // surviving `&` hands javascript a delimiter the encoder never saw.
    // attribute values are decoded by the html parser too; a .js file never is
    #[test]
    fn entity_introducer_encoded() {
        let guards = Parity::Deviation(JsFragmentGuards);
        let cases = [
            (Upstream, "a&b", r"a\x26b"),
            (Upstream, "&", r"\x26"),
            (Upstream, "&&", r"\x26\x26"),
            (Upstream, "&#96;", r"\x26#96;"),
            (Upstream, "&#x60;", r"\x26#x60;"),
            (guards, "&grave;", r"\x26grave;"),
            (Upstream, "&#36;&#123;", r"\x26#36;\x26#123;"),
            (guards, "&amp;", r"\x26amp;"),
        ];
        for (parity, input, expected) in cases {
            check(parity, "javascript", for_javascript, input, expected);
            check(
                Upstream,
                "javascript_attribute",
                for_javascript_attribute,
                input,
                expected,
            );
            check(
                parity,
                "javascript_block",
                for_javascript_block,
                input,
                expected,
            );
            check(NonOwasp, "js_template", for_js_template, input, expected);
        }
        for (_, input, _) in cases {
            upstream!(for_javascript_source(input), input);
        }
    }

    // an attribute value and a .js file are never tokenized as script data
    #[test]
    fn script_data_encoders_are_opt_in() {
        upstream!(for_javascript_attribute("<!--<script>"), "<!--<script>");
        upstream!(for_javascript_source("<!--<script>"), "<!--<script>");
    }

    #[test]
    fn all_named_escapes() {
        upstream!(for_javascript("\x08"), r"\b");
        upstream!(for_javascript("\t"), r"\t");
        upstream!(for_javascript("\n"), r"\n");
        upstream!(for_javascript("\x0C"), r"\f");
        upstream!(for_javascript("\r"), r"\r");
    }

    #[test]
    fn hex_escapes_for_c0_controls() {
        upstream!(for_javascript("\x00"), r"\x00");
        upstream!(for_javascript("\x01"), r"\x01");
        upstream!(for_javascript("\x07"), r"\x07");
        upstream!(for_javascript("\x0B"), r"\x0b");
        upstream!(for_javascript("\x0E"), r"\x0e");
        upstream!(for_javascript("\x1F"), r"\x1f");
    }

    #[test]
    fn unicode_line_terminators() {
        upstream!(for_javascript("\u{2028}"), r"\u2028");
        upstream!(for_javascript("\u{2029}"), r"\u2029");
        // these are JS line terminators that would break string literals
        deviation!(
            JsFragmentGuards,
            for_javascript("a\u{2028}b\u{2029}c"),
            r"a\u2028b\u2029c"
        );
    }

    #[test]
    fn backslash_escaping() {
        upstream!(for_javascript(r"\"), r"\\");
        upstream!(for_javascript(r"\\"), r"\\\\");
        upstream!(for_javascript(r"\n"), r"\\n");
    }

    #[test]
    fn preserves_non_ascii() {
        deviation!(JsFragmentGuards, for_javascript("café"), "café");
        upstream!(for_javascript("日本語"), "日本語");
        upstream!(for_javascript("😀"), "😀");
    }

    #[test]
    fn backtick_not_encoded() {
        // documented: backtick is NOT encoded — template literals are unsafe
        deviation!(JsFragmentGuards, for_javascript("`template`"), "`template`");
    }

    // -- context comparisons --

    #[test]
    fn universal_vs_attribute_slash() {
        upstream!(for_javascript("a/b"), r"a\/b");
        upstream!(for_javascript_attribute("a/b"), "a/b");
    }

    #[test]
    fn universal_vs_block_quotes() {
        upstream!(for_javascript(r#"a"b"#), r"a\x22b");
        upstream!(for_javascript_block(r#"a"b"#), r#"a\"b"#);
        upstream!(for_javascript("a'b"), r"a\x27b");
        upstream!(for_javascript_block("a'b"), r"a\'b");
    }

    #[test]
    fn source_minimal_encoding() {
        // source doesn't encode / or &
        upstream!(for_javascript_source("a/b&c"), "a/b&c");
        // but still encodes control chars and line terminators
        upstream!(for_javascript_source("\n"), r"\n");
        upstream!(for_javascript_source("\u{2028}"), r"\u2028");
    }

    // -- edge cases --

    #[test]
    fn already_escaped_input() {
        // encoding a string that already has JS escapes should double-escape
        upstream!(for_javascript(r"\n"), r"\\n");
        upstream!(for_javascript(r"\x22"), r"\\x22");
    }
}

// ===========================================================================
// JS template literal context tests
// ===========================================================================

mod js_template {
    use super::*;

    // -- interpolation injection --

    #[test]
    fn interpolation_breakout() {
        non_owasp!(for_js_template("${alert(1)}"), r"\${alert(1)}");
    }

    #[test]
    fn multiple_interpolations() {
        non_owasp!(for_js_template("${a} and ${b}"), r"\${a} and \${b}");
        non_owasp!(for_js_template("${a}${b}"), r"\${a}\${b}");
    }

    #[test]
    fn dollar_without_brace_passes_through() {
        non_owasp!(for_js_template("$100"), "$100");
        non_owasp!(for_js_template("a $ b"), "a $ b");
    }

    #[test]
    fn trailing_dollar_escaped() {
        non_owasp!(for_js_template("a$"), r"a\$");
        non_owasp!(for_js_template("$"), r"\$");
        non_owasp!(for_js_template("$$"), r"$\$");
    }

    #[test]
    fn leading_brace_escaped() {
        non_owasp!(for_js_template("{alert(1)}"), r"\x7balert(1)}");
        non_owasp!(for_js_template("{"), r"\x7b");
        non_owasp!(for_js_template("{{"), r"\x7b{");
        non_owasp!(for_js_template("a{b}"), "a{b}");
    }

    #[test]
    fn nested_interpolation() {
        // ${${...}} — both $ should be escaped
        non_owasp!(for_js_template("${${x}}"), r"\${\${x}}");
    }

    // -- backtick breakout --

    #[test]
    fn backtick_escaped() {
        non_owasp!(for_js_template("`"), r"\`");
        non_owasp!(for_js_template("hello `world`"), r"hello \`world\`");
    }

    #[test]
    fn tagged_template_breakout() {
        // attacker tries to close template and start a tagged template
        non_owasp!(for_js_template("`+evil`"), r"\`+evil\`");
    }

    // -- script block breakout --

    #[test]
    fn script_block_breakout() {
        non_owasp!(
            for_js_template("</script><script>alert(1)</script>"),
            r"\x3c\/script>\x3cscript>alert(1)\x3c\/script>"
        );
    }

    // -- backslash escaping --

    #[test]
    fn backslash_escaped() {
        non_owasp!(for_js_template(r"\"), r"\\");
        non_owasp!(for_js_template(r"\\"), r"\\\\");
        // backslash before backtick — both are encoded
        non_owasp!(for_js_template("\\`"), "\\\\\\`");
    }

    // -- control characters --

    #[test]
    fn all_named_escapes() {
        non_owasp!(for_js_template("\x08"), r"\b");
        non_owasp!(for_js_template("\t"), r"\t");
        non_owasp!(for_js_template("\n"), r"\n");
        non_owasp!(for_js_template("\x0C"), r"\f");
        non_owasp!(for_js_template("\r"), r"\r");
    }

    #[test]
    fn hex_escapes_for_c0_controls() {
        non_owasp!(for_js_template("\x00"), r"\x00");
        non_owasp!(for_js_template("\x01"), r"\x01");
        non_owasp!(for_js_template("\x07"), r"\x07");
        non_owasp!(for_js_template("\x0B"), r"\x0b");
        non_owasp!(for_js_template("\x0E"), r"\x0e");
        non_owasp!(for_js_template("\x1F"), r"\x1f");
    }

    // -- unicode line terminators --

    #[test]
    fn unicode_line_terminators() {
        non_owasp!(for_js_template("\u{2028}"), r"\u2028");
        non_owasp!(for_js_template("\u{2029}"), r"\u2029");
        non_owasp!(for_js_template("a\u{2028}b\u{2029}c"), r"a\u2028b\u2029c");
    }

    // -- quotes NOT encoded --

    #[test]
    fn quotes_pass_through() {
        // unlike string literal encoders, quotes are ordinary in template literals
        non_owasp!(for_js_template(r#"a"b"#), r#"a"b"#);
        non_owasp!(for_js_template("a'b"), "a'b");
        non_owasp!(for_js_template(r#"say "it's" fine"#), r#"say "it's" fine"#);
    }

    // -- unicode --

    #[test]
    fn preserves_non_ascii() {
        for input in ["café", "日本語", "😀", "hello 😀 world", "\u{10000}"] {
            non_owasp!(for_js_template(input), input);
        }
    }

    // -- boundary conditions --

    #[test]
    fn already_escaped_input() {
        // encoding should double-escape
        non_owasp!(for_js_template(r"\n"), r"\\n");
        non_owasp!(for_js_template(r"\`"), r"\\\`");
        non_owasp!(for_js_template(r"\${x}"), r"\\\${x}");
    }

    // -- context comparisons --

    #[test]
    fn template_vs_string_interpolation() {
        // for_javascript passes ${...} through; for_js_template escapes it
        deviation!(JsFragmentGuards, for_javascript("${x}"), "${x}");
        non_owasp!(for_js_template("${x}"), r"\${x}");
    }

    // -- mixed payloads --

    #[test]
    fn mixed_xss_payload() {
        non_owasp!(
            for_js_template("`Hello ${name}`, welcome\\n"),
            r"\`Hello \${name}\`, welcome\\n"
        );
    }
}

// ===========================================================================
// CSS context tests
// ===========================================================================

mod css {
    use super::*;

    #[test]
    fn hex_escape_format() {
        // shortest hex, no zero-padding
        deviation!(CssTrailingSpace, for_css_string("\x00"), r"\0 ");
        deviation!(CssTrailingSpace, for_css_string("\x01"), r"\1 ");
        deviation!(CssTrailingSpace, for_css_string("\""), r"\22 ");
        deviation!(CssTrailingSpace, for_css_string("'"), r"\27 ");
    }

    #[test]
    fn trailing_space_before_hex_digit() {
        // next char is hex digit → space needed
        upstream!(for_css_string("\"a"), r"\22 a"); // a is hex
        upstream!(for_css_string("\"0"), r"\22 0"); // 0 is hex
        upstream!(for_css_string("\"f"), r"\22 f"); // f is hex
        upstream!(for_css_string("\"F"), r"\22 F"); // F is hex
        upstream!(for_css_string("a'1"), r"a\27 1"); // 1 is hex
        upstream!(for_css_string(r"a\b"), r"a\5c b"); // b is hex
                                                      // next char is NOT hex → no space
        upstream!(for_css_string("\"g"), r"\22g"); // g is not hex
        upstream!(for_css_string("\"z"), r"\22z");
        upstream!(for_css_string("\"!"), r"\22!");
    }

    #[test]
    fn trailing_space_before_whitespace() {
        // space after hex escape before whitespace chars
        upstream!(for_css_string("\" "), r"\22  "); // space
        upstream!(for_css_string("' "), r"\27  "); // space
        deviation!(CssTrailingSpace, for_css_string("\"\t"), r"\22 \9 "); // tab (also encoded)
        deviation!(CssTrailingSpace, for_css_string("\"\n"), r"\22 \a "); // LF (also encoded)
    }

    #[test]
    fn trailing_space_at_end_of_input() {
        deviation!(CssTrailingSpace, for_css_string("\""), r"\22 ");
        deviation!(CssTrailingSpace, for_css_string("'"), r"\27 ");
    }

    #[test]
    fn consecutive_encoded_chars() {
        deviation!(CssTrailingSpace, for_css_string("\"'"), r"\22\27 ");
        // \ → \5c, next input char is " which is not a hex digit (it will
        // be encoded separately), so no trailing space after \5c
        deviation!(CssTrailingSpace, for_css_string("\\\""), r"\5c\22 ");
    }

    #[test]
    fn css_string_xss_payload() {
        deviation!(
            CssStringParens,
            for_css_string("expression(alert(1))"),
            r"expression\28 alert\28 1\29\29 "
        );
    }

    #[test]
    fn noncharacters() {
        deviation!(CssNoncharacters, for_css_string("\u{FDD0}"), "_");
        deviation!(CssNoncharacters, for_css_string("\u{FFFE}"), "_");
        deviation!(CssNoncharacters, for_css_string("\u{FFFF}"), "_");
    }

    #[test]
    fn preserves_non_ascii() {
        for input in ["café", "日本語", "😀"] {
            upstream!(for_css_string(input), input);
        }
    }

    // -- C1 control characters (U+0080-U+009F) --

    #[test]
    fn c1_controls_encoded() {
        // boundary values
        deviation!(CssTrailingSpace, for_css_string("\u{0080}"), r"\80 ");
        deviation!(CssTrailingSpace, for_css_string("\u{009F}"), r"\9f ");
        // NEL (U+0085) — can affect CSS parsing
        deviation!(CssTrailingSpace, for_css_string("\u{0085}"), r"\85 ");
    }

    #[test]
    fn c1_controls_trailing_space_rules() {
        // next char is hex digit → trailing space
        upstream!(for_css_string("\u{0085}a"), r"\85 a");
        upstream!(for_css_string("\u{0085}F"), r"\85 F");
        // next char is not hex → no trailing space
        upstream!(for_css_string("\u{0085}z"), r"\85z");
        upstream!(for_css_string("\u{0085}!"), r"\85!");
    }

    #[test]
    fn c1_controls_in_url_context() {
        deviation!(CssTrailingSpace, for_css_url("\u{0080}"), r"\80 ");
        deviation!(CssTrailingSpace, for_css_url("\u{0085}"), r"\85 ");
        deviation!(CssTrailingSpace, for_css_url("\u{009F}"), r"\9f ");
    }

    #[test]
    fn non_ascii_above_c1_preserved() {
        // U+00A0 (NBSP) is right above C1 range — should NOT be encoded
        upstream!(for_css_string("\u{00A0}"), "\u{00A0}");
        upstream!(for_css_string("café"), "café");
    }

    // -- for_css_url vs for_css_string --

    #[test]
    fn url_encodes_parens_like_string() {
        // c is a hex digit so a separator space follows \29
        upstream!(for_css_url("a(b)c"), r"a\28 b\29 c");
        deviation!(CssStringParens, for_css_string("a(b)c"), r"a\28 b\29 c");
    }

    #[test]
    fn url_encodes_everything_else() {
        deviation!(CssTrailingSpace, for_css_url("\""), r"\22 ");
        deviation!(CssTrailingSpace, for_css_url("'"), r"\27 ");
        deviation!(CssTrailingSpace, for_css_url("\\"), r"\5c ");
        upstream!(for_css_url(r"a\b"), r"a\5c b");
        deviation!(CssTrailingSpace, for_css_url("<"), r"\3c ");
    }

    // -- url-token terminators (CSS Syntax Level 3 §4.3.6) --

    #[test]
    fn url_encodes_closing_paren() {
        // issue #49: `)` ends an unquoted url-token, and the declaration block
        deviation!(CssTrailingSpace, for_css_url(")"), r"\29 ");
        upstream!(for_css_url(");color:red}x{"), r"\29;color:red}x{");
        let encoded = for_css_url(");color:red}x{");
        std::assert_eq!(
            format!("#victim{{color:green;background:url({encoded});}}"),
            r"#victim{color:green;background:url(\29;color:red}x{);}"
        );
    }

    #[test]
    fn url_encodes_opening_paren() {
        deviation!(CssTrailingSpace, for_css_url("("), r"\28 ");
    }

    #[test]
    fn url_encodes_css_whitespace() {
        deviation!(CssTrailingSpace, for_css_url(" "), r"\20 ");
        deviation!(CssTrailingSpace, for_css_url("\t"), r"\9 ");
        deviation!(CssTrailingSpace, for_css_url("\n"), r"\a ");
        deviation!(CssTrailingSpace, for_css_url("\r"), r"\d ");
        deviation!(CssTrailingSpace, for_css_url("\x0C"), r"\c ");
        upstream!(for_css_url("a b"), r"a\20 b");
        upstream!(for_css_url("a  b"), r"a\20 \20 b");
    }

    #[test]
    fn url_preserves_unicode_spaces() {
        // css whitespace is space, tab and newline; the rest are ident chars
        upstream!(for_css_url("a\u{00A0}b"), "a\u{00A0}b");
        upstream!(for_css_url("a\u{2003}b"), "a\u{2003}b");
        upstream!(for_css_url("a\u{3000}b"), "a\u{3000}b");
    }

    #[test]
    fn url_string_encoding_agrees_without_spaces() {
        for input in ["image.png", "a(b)c", "expression(alert(1))", "café", ")("] {
            std::assert_eq!(for_css_url(input), for_css_string(input), "input {input:?}");
        }
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
        upstream!(for_uri_component(unreserved), unreserved);
    }

    const URI_ENCODERS: [(Parity, &str, ForFn); 3] = [
        (Upstream, "uri_component", for_uri_component),
        (NonOwasp, "uri_path", for_uri_path),
        (NonOwasp, "form_urlencoded", for_form_urlencoded),
    ];

    #[test]
    fn reserved_and_markup_chars_encoded() {
        let cases = [
            (":", "%3A"),
            ("?", "%3F"),
            ("#", "%23"),
            ("[", "%5B"),
            ("]", "%5D"),
            ("@", "%40"),
            ("!", "%21"),
            ("$", "%24"),
            ("&", "%26"),
            ("'", "%27"),
            ("(", "%28"),
            (")", "%29"),
            ("+", "%2B"),
            (",", "%2C"),
            (";", "%3B"),
            ("=", "%3D"),
            ("<", "%3C"),
            (">", "%3E"),
            ("\"", "%22"),
        ];
        for (parity, name, encode) in URI_ENCODERS {
            for (input, expected) in cases {
                check(parity, name, encode, input, expected);
            }
        }
        // `/` is kept by the path encoder, `*` by the form encoder
        upstream!(for_uri_component("/"), "%2F");
        non_owasp!(for_uri_path("/"), "/");
        non_owasp!(for_form_urlencoded("/"), "%2F");
        upstream!(for_uri_component("*"), "%2A");
        non_owasp!(for_uri_path("*"), "%2A");
        non_owasp!(for_form_urlencoded("*"), "*");
    }

    #[test]
    fn space_encoded() {
        upstream!(for_uri_component(" "), "%20");
    }

    #[test]
    fn utf8_and_controls_percent_encoded() {
        let cases = [
            // two-byte
            ("\u{00A0}", "%C2%A0"),
            ("é", "%C3%A9"),
            ("\u{07FF}", "%DF%BF"),
            // three-byte
            ("\u{0800}", "%E0%A0%80"),
            ("世", "%E4%B8%96"),
            ("\u{FFFD}", "%EF%BF%BD"),
            // four-byte
            ("\u{10000}", "%F0%90%80%80"),
            ("😀", "%F0%9F%98%80"),
            // controls
            ("\x00", "%00"),
            ("\x01", "%01"),
            ("\x1F", "%1F"),
            ("\x7F", "%7F"),
        ];
        for (parity, name, encode) in URI_ENCODERS {
            for (input, expected) in cases {
                check(parity, name, encode, input, expected);
            }
        }
    }

    // -- practical cases --

    #[test]
    fn query_parameter_encoding() {
        upstream!(
            for_uri_component("search term with spaces"),
            "search%20term%20with%20spaces"
        );
    }

    #[test]
    fn full_query_value() {
        upstream!(
            for_uri_component("key=value&other=more"),
            "key%3Dvalue%26other%3Dmore"
        );
    }

    #[test]
    fn unicode_path_segment() {
        upstream!(
            for_uri_component("ファイル"),
            "%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB"
        );
    }

    // -- Rust-specific: no surrogates --
    // the Java encoder handles surrogate pairs in char[] input and replaces
    // invalid surrogates with "-". Rust str is always valid UTF-8, so
    // surrogates cannot appear. supplementary plane characters (U+10000+)
    // are valid UTF-8 and encoded as 4-byte percent-encoded sequences.
}

// ===========================================================================
// URI path tests (RFC 3986 section 3.3)
// ===========================================================================

mod uri_path {
    use super::*;

    #[test]
    fn slashes_preserved() {
        for input in [
            "/",
            "//",
            "///",
            "/a/b/c",
            "/root",
            "/dir/",
            "//double",
            "///triple",
            "/a//b///c",
            "a/b/c",
        ] {
            non_owasp!(for_uri_path(input), input);
        }
    }

    // -- unreserved characters pass through --

    #[test]
    fn unreserved_chars_pass_through() {
        let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        non_owasp!(for_uri_path(unreserved), unreserved);
    }

    #[test]
    fn unreserved_in_segments() {
        non_owasp!(
            for_uri_path("/safe-text_v2.0/~user"),
            "/safe-text_v2.0/~user"
        );
    }

    #[test]
    fn space_encoded() {
        non_owasp!(for_uri_path(" "), "%20");
        non_owasp!(for_uri_path("/a b/c d"), "/a%20b/c%20d");
    }

    // -- slash vs uri_component comparison --

    #[test]
    fn slash_distinguishes_path_from_component() {
        // for_uri_component encodes slashes
        upstream!(for_uri_component("/a/b"), "%2Fa%2Fb");
        // for_uri_path preserves them
        non_owasp!(for_uri_path("/a/b"), "/a/b");
    }

    #[test]
    fn identical_for_no_slash_input() {
        // without slashes, the encoders produce identical output
        let inputs = ["hello", "a=b", "café", "", "safe-text_v2.0"];
        for input in inputs {
            std::assert_eq!(
                for_uri_path(input),
                for_uri_component(input),
                "mismatch for {:?}",
                input
            );
        }
    }

    // -- HTML-significant characters encoded (XSS safety) --

    #[test]
    fn html_significant_chars_encoded() {
        non_owasp!(
            for_uri_path("/<script>/alert('xss')"),
            "/%3Cscript%3E/alert%28%27xss%27%29"
        );
    }

    #[test]
    fn multibyte_in_path_segments() {
        non_owasp!(for_uri_path("/café/世界"), "/caf%C3%A9/%E4%B8%96%E7%95%8C");
        non_owasp!(
            for_uri_path("/ファイル/名前"),
            "/%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB/%E5%90%8D%E5%89%8D"
        );
    }

    // -- dot segments (not normalized — that's the caller's job) --

    #[test]
    fn dot_segments_preserved() {
        non_owasp!(for_uri_path("/a/./b"), "/a/./b");
        non_owasp!(for_uri_path("/a/../b"), "/a/../b");
        non_owasp!(for_uri_path("/../../../etc/passwd"), "/../../../etc/passwd");
    }

    // -- practical paths --

    #[test]
    fn api_style_path() {
        non_owasp!(
            for_uri_path("/api/v2/users/john doe/profile"),
            "/api/v2/users/john%20doe/profile"
        );
    }

    #[test]
    fn file_path_with_special_chars() {
        non_owasp!(
            for_uri_path("/files/report (final).pdf"),
            "/files/report%20%28final%29.pdf"
        );
    }

    #[test]
    fn path_with_query_like_content() {
        // query delimiters are encoded because this is a path encoder,
        // not a full URL encoder
        non_owasp!(
            for_uri_path("/search?q=foo&page=1"),
            "/search%3Fq%3Dfoo%26page%3D1"
        );
    }

    #[test]
    fn path_with_fragment_like_content() {
        non_owasp!(for_uri_path("/page#section"), "/page%23section");
    }

    // -- boundary conditions --

    #[test]
    fn slash_adjacent_to_encoded() {
        non_owasp!(for_uri_path("/ /"), "/%20/");
        non_owasp!(for_uri_path("/é/"), "/%C3%A9/");
    }
}

// ===========================================================================
// form-urlencoded tests (WHATWG URL Standard)
// ===========================================================================

mod form_urlencoded {
    use super::*;

    // -- safe characters pass through --

    #[test]
    fn safe_punctuation_passes_through() {
        non_owasp!(for_form_urlencoded("*"), "*");
        non_owasp!(for_form_urlencoded("-"), "-");
        non_owasp!(for_form_urlencoded("."), ".");
        non_owasp!(for_form_urlencoded("_"), "_");
        non_owasp!(for_form_urlencoded("-._*"), "-._*");
    }

    // -- space becomes + --

    #[test]
    fn space_encoded_as_plus() {
        non_owasp!(for_form_urlencoded(" "), "+");
        non_owasp!(for_form_urlencoded("hello world"), "hello+world");
        non_owasp!(for_form_urlencoded("  "), "++");
    }

    #[test]
    fn spaces_among_safe_chars() {
        non_owasp!(for_form_urlencoded("a b c"), "a+b+c");
        non_owasp!(for_form_urlencoded(" a "), "+a+");
    }

    // -- key differences from for_uri_component --

    #[test]
    fn tilde_is_encoded() {
        // RFC 3986 treats ~ as unreserved; WHATWG form encoding does not
        non_owasp!(for_form_urlencoded("~"), "%7E");
        non_owasp!(for_form_urlencoded("a~b"), "a%7Eb");
    }

    #[test]
    fn asterisk_is_safe() {
        // RFC 3986 treats * as a sub-delimiter (encoded); WHATWG form keeps it
        non_owasp!(for_form_urlencoded("*"), "*");
        non_owasp!(for_form_urlencoded("a*b"), "a*b");
    }

    // -- practical form encoding cases --

    #[test]
    fn form_value_with_spaces_and_specials() {
        non_owasp!(
            for_form_urlencoded("search term with spaces"),
            "search+term+with+spaces"
        );
    }

    #[test]
    fn form_key_value_encoding() {
        // encoding a single value — the caller constructs key=value&key=value
        non_owasp!(
            for_form_urlencoded("hello world & goodbye"),
            "hello+world+%26+goodbye"
        );
    }

    #[test]
    fn unicode_form_value() {
        non_owasp!(
            for_form_urlencoded("ファイル"),
            "%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB"
        );
    }

    #[test]
    fn mixed_safe_and_encoded() {
        non_owasp!(
            for_form_urlencoded("name=John Doe&age=30"),
            "name%3DJohn+Doe%26age%3D30"
        );
    }
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
        std::assert_eq!(for_xml(input), for_html(input));
        std::assert_eq!(for_xml_content(input), for_html_content(input));
        std::assert_eq!(for_xml_attribute(input), for_html_attribute(input));
    }

    // -- XML comment --

    #[test]
    fn comment_safe_passthrough() {
        upstream!(for_xml_comment("safe comment text"), "safe comment text");
        upstream!(for_xml_comment(""), "");
    }

    #[test]
    fn comment_neutralizes_hyphens() {
        for (input, expected) in [
            // `--` is forbidden inside a comment
            ("a--b", "a~~b"),
            ("a--b--c", "a~~b~~c"),
            ("a---b", "a~~~b"),
            ("---", "~~~"),
            ("----", "~~~~"),
            // a trailing `-` would form `--->` with the closing delimiter
            ("abc-", "abc~"),
            ("trailing-", "trailing~"),
            ("-", "~"),
            ("--", "~~"),
            // a leading `-` would form `--` after trusted text ending in `-`
            ("-><evil/>", "~><evil/>"),
            ("-a-b", "~a~b"),
        ] {
            upstream!(for_xml_comment(input), expected);
        }
    }

    #[test]
    fn comment_invalid_xml_chars_replaced() {
        // C0 controls (except tab/LF/CR)
        upstream!(for_xml_comment("a\x00b"), "a b");
        upstream!(for_xml_comment("a\x01b"), "a b");
        // DEL
        upstream!(for_xml_comment("a\x7Fb"), "a b");
        // C1 controls
        upstream!(for_xml_comment("a\u{0080}b"), "a b");
        // non-characters
        upstream!(for_xml_comment("a\u{FDD0}b"), "a b");
    }

    #[test]
    fn comment_preserves_allowed_chars() {
        upstream!(for_xml_comment("café 日本語"), "café 日本語");
        upstream!(for_xml_comment("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn comment_combined_edge_cases() {
        // hyphen + invalid char + hyphen
        upstream!(for_xml_comment("-\x00-"), "~ ~");
    }

    // -- CDATA --

    #[test]
    fn cdata_safe_passthrough() {
        upstream!(for_cdata("safe text"), "safe text");
        upstream!(for_cdata(""), "");
        // `<` and `&` are fine inside CDATA
        upstream!(for_cdata("a < b && c"), "a < b && c");
    }

    #[test]
    fn cdata_splits_closing_delimiter() {
        upstream!(
            for_cdata("a]]>b"),
            "a]]>]<![CDATA[]]>]<![CDATA[]]><![CDATA[>b"
        );
    }

    #[test]
    fn cdata_multiple_splits() {
        upstream!(
            for_cdata("x]]>y]]>z"),
            "x]]>]<![CDATA[]]>]<![CDATA[]]><![CDATA[>y]]>]<![CDATA[]]>]<![CDATA[]]><![CDATA[>z"
        );
        upstream!(
            for_cdata("<b>bold</b>"),
            "<b]]><![CDATA[>bold</b]]><![CDATA[>"
        );
    }

    #[test]
    fn cdata_brackets_without_gt() {
        // brackets away from the end
        upstream!(for_cdata("]]a"), "]]>]<![CDATA[]]>]<![CDATA[a");
        upstream!(for_cdata("a]b"), "a]]>]<![CDATA[b");
        // single bracket + >
        upstream!(for_cdata("]>"), "]]>]<![CDATA[]]><![CDATA[>");
    }

    #[test]
    fn cdata_splits_trailing_bracket() {
        upstream!(for_cdata("]"), "]]>]<![CDATA[");
        upstream!(for_cdata("]]"), "]]>]<![CDATA[]]>]<![CDATA[");
        upstream!(for_cdata("]]]"), "]]>]<![CDATA[]]>]<![CDATA[]]>]<![CDATA[");
        upstream!(for_cdata("a]"), "a]]>]<![CDATA[");
    }

    #[test]
    fn cdata_extra_brackets_before_gt() {
        // ]]]> = ] + ]]>
        upstream!(
            for_cdata("]]]>"),
            "]]>]<![CDATA[]]>]<![CDATA[]]>]<![CDATA[]]><![CDATA[>"
        );
        // ]]]]> = ]] + ]]>
        upstream!(
            for_cdata("]]]]>"),
            "]]>]<![CDATA[]]>]<![CDATA[]]>]<![CDATA[]]>]<![CDATA[]]><![CDATA[>"
        );
    }

    #[test]
    fn cdata_at_start() {
        upstream!(
            for_cdata("]]>rest"),
            "]]>]<![CDATA[]]>]<![CDATA[]]><![CDATA[>rest"
        );
    }

    #[test]
    fn cdata_at_end() {
        upstream!(
            for_cdata("start]]>"),
            "start]]>]<![CDATA[]]>]<![CDATA[]]><![CDATA[>"
        );
    }

    #[test]
    fn cdata_invalid_xml_replaced() {
        upstream!(for_cdata("a\x00b"), "a b");
        upstream!(for_cdata("a\x01b"), "a b");
        upstream!(for_cdata("a\u{FDD0}b"), "a b");
    }

    // -- XML 1.1 --

    #[test]
    fn xml11_entities() {
        upstream!(for_xml11("<&>\"'"), "&lt;&amp;&gt;&#34;&#39;");
    }

    #[test]
    fn xml11_controls_as_char_references() {
        // C0 controls (not tab/LF/CR) → &#xHH;
        deviation!(Xml11RefWidth, for_xml11("a\x01b"), "a&#x1;b");
        deviation!(Xml11RefWidth, for_xml11("a\x08b"), "a&#x8;b");
        deviation!(Xml11RefWidth, for_xml11("a\x0Bb"), "a&#xb;b");
        deviation!(Xml11RefWidth, for_xml11("a\x0Cb"), "a&#xc;b");
        upstream!(for_xml11("a\x1Fb"), "a&#x1f;b");
    }

    #[test]
    fn xml11_preserves_tab_lf_cr() {
        upstream!(for_xml11("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn xml11_nel_and_line_separator_as_references() {
        let encoders: [(&str, ForFn); 3] = [
            ("xml11", for_xml11),
            ("xml11_content", for_xml11_content),
            ("xml11_attribute", for_xml11_attribute),
        ];
        for (name, encode) in encoders {
            check(Upstream, name, encode, "a\u{0085}b", "a&#x85;b");
            check(
                Upstream,
                name,
                encode,
                "a\u{2028}b\u{2029}c",
                "a&#x2028;b\u{2029}c",
            );
        }
    }

    #[test]
    fn xml11_del_and_c1_as_references() {
        upstream!(for_xml11("a\x7Fb"), "a&#x7f;b");
        upstream!(for_xml11("a\u{0080}b"), "a&#x80;b");
        upstream!(for_xml11("a\u{0084}b"), "a&#x84;b");
        upstream!(for_xml11("a\u{0086}b"), "a&#x86;b");
        upstream!(for_xml11("a\u{009F}b"), "a&#x9f;b");
    }

    #[test]
    fn xml11_nul_replaced_with_space() {
        // NUL is invalid (not representable) in XML 1.1
        upstream!(for_xml11("a\x00b"), "a b");
    }

    #[test]
    fn xml11_nonchars_replaced_with_space() {
        upstream!(for_xml11("a\u{FDD0}b"), "a b");
        upstream!(for_xml11("a\u{FFFE}b"), "a b");
    }

    #[test]
    fn xml11_content_no_quotes() {
        upstream!(for_xml11_content(r#"a"b'c"#), r#"a"b'c"#);
        deviation!(Xml11RefWidth, for_xml11_content("a\x01b"), "a&#x1;b");
    }

    #[test]
    fn xml11_attribute_no_gt() {
        upstream!(for_xml11_attribute("a>b"), "a>b");
        upstream!(for_xml11_attribute(r#"a"b"#), "a&#34;b");
        deviation!(Xml11RefWidth, for_xml11_attribute("a\x01b"), "a&#x1;b");
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
        non_owasp!(for_rust_string("hello world"), "hello world");
        non_owasp!(for_rust_string(""), "");
        non_owasp!(for_rust_string("café 日本語 😀"), "café 日本語 😀");
    }

    #[test]
    fn string_escapes_double_quote_not_single() {
        non_owasp!(for_rust_string(r#"a"b"#), r#"a\"b"#);
        non_owasp!(for_rust_string("a'b"), "a'b");
    }

    #[test]
    fn string_named_escapes() {
        non_owasp!(for_rust_string("\0"), "\\0");
        non_owasp!(for_rust_string("\t"), "\\t");
        non_owasp!(for_rust_string("\n"), "\\n");
        non_owasp!(for_rust_string("\r"), "\\r");
    }

    #[test]
    fn string_hex_for_controls() {
        non_owasp!(for_rust_string("\x01"), "\\x01");
        non_owasp!(for_rust_string("\x08"), "\\x08");
        non_owasp!(for_rust_string("\x0B"), "\\x0b");
        non_owasp!(for_rust_string("\x0C"), "\\x0c");
        non_owasp!(for_rust_string("\x1F"), "\\x1f");
        non_owasp!(for_rust_string("\x7F"), "\\x7f");
    }

    #[test]
    fn string_backslash() {
        non_owasp!(for_rust_string(r"a\b"), r"a\\b");
    }

    #[test]
    fn string_nonchars_replaced() {
        non_owasp!(for_rust_string("\u{FDD0}"), " ");
        non_owasp!(for_rust_string("\u{FFFE}"), " ");
    }

    #[test]
    fn string_supplementary_plane_passes_through() {
        // unlike Java, Rust strings are UTF-8 — no surrogate pairs needed
        non_owasp!(for_rust_string("😀"), "😀");
        non_owasp!(for_rust_string("\u{10000}"), "\u{10000}");
    }

    // -- for_rust_char --

    #[test]
    fn char_passthrough() {
        non_owasp!(for_rust_char("hello world"), "hello world");
        non_owasp!(for_rust_char("café"), "café");
    }

    #[test]
    fn char_escapes_single_quote_not_double() {
        non_owasp!(for_rust_char("a'b"), r"a\'b");
        non_owasp!(for_rust_char(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn char_named_escapes() {
        non_owasp!(for_rust_char("\0"), "\\0");
        non_owasp!(for_rust_char("\t"), "\\t");
        non_owasp!(for_rust_char("\n"), "\\n");
        non_owasp!(for_rust_char("\r"), "\\r");
    }

    #[test]
    fn char_hex_for_controls() {
        non_owasp!(for_rust_char("\x01"), "\\x01");
        non_owasp!(for_rust_char("\x7F"), "\\x7f");
    }

    #[test]
    fn char_nonchars_replaced() {
        non_owasp!(for_rust_char("\u{FDD0}"), " ");
    }

    // -- for_rust_char_checked --

    #[test]
    fn char_checked_requires_exactly_one_character() {
        non_owasp!(for_rust_char_checked(""), None);
        non_owasp!(for_rust_char_checked("ab"), None);
        non_owasp!(for_rust_char_checked("it's"), None);
        non_owasp!(for_rust_char_checked("e\u{301}"), None);
        non_owasp!(for_rust_char_checked("a"), Some("a".to_string()));
    }

    #[test]
    fn char_checked_encodes_like_for_rust_char() {
        non_owasp!(for_rust_char_checked("'"), Some(r"\'".to_string()));
        non_owasp!(for_rust_char_checked("\\"), Some(r"\\".to_string()));
        non_owasp!(for_rust_char_checked("\t"), Some(r"\t".to_string()));
        non_owasp!(for_rust_char_checked("\x7F"), Some(r"\x7f".to_string()));
        non_owasp!(for_rust_char_checked("\u{FDD0}"), Some(" ".to_string()));
        non_owasp!(for_rust_char_checked("é"), Some("é".to_string()));
        non_owasp!(for_rust_char_checked("😀"), Some("😀".to_string()));
    }

    // -- trojan source (CVE-2021-42574) --

    /// the codepoints `rustc` rejects raw in a literal, with their escaped forms.
    const TEXT_DIRECTION: [(&str, &str); 9] = [
        ("\u{202A}", r"\u{202a}"),
        ("\u{202B}", r"\u{202b}"),
        ("\u{202C}", r"\u{202c}"),
        ("\u{202D}", r"\u{202d}"),
        ("\u{202E}", r"\u{202e}"),
        ("\u{2066}", r"\u{2066}"),
        ("\u{2067}", r"\u{2067}"),
        ("\u{2068}", r"\u{2068}"),
        ("\u{2069}", r"\u{2069}"),
    ];

    #[test]
    fn text_direction_controls_never_reach_a_char_literal_raw() {
        for (raw, escaped) in TEXT_DIRECTION {
            non_owasp!(for_rust_char(raw), escaped);
            non_owasp!(for_rust_char_checked(raw), Some(escaped.to_string()));
        }
    }

    #[test]
    fn text_direction_neighbours_still_pass_through() {
        for raw in [
            "\u{2029}", "\u{202F}", "\u{2065}", "\u{206A}", "\u{200E}", "\u{200F}",
        ] {
            non_owasp!(for_rust_string(raw), raw);
            non_owasp!(for_rust_char(raw), raw);
        }
    }

    // -- for_rust_byte_string --

    #[test]
    fn byte_string_ascii_passthrough() {
        non_owasp!(for_rust_byte_string("hello world"), "hello world");
        non_owasp!(for_rust_byte_string(""), "");
    }

    #[test]
    fn byte_string_escapes_double_quote_not_single() {
        non_owasp!(for_rust_byte_string(r#"a"b"#), r#"a\"b"#);
        non_owasp!(for_rust_byte_string("a'b"), "a'b");
    }

    #[test]
    fn byte_string_named_escapes() {
        non_owasp!(for_rust_byte_string("\0"), "\\0");
        non_owasp!(for_rust_byte_string("\t"), "\\t");
        non_owasp!(for_rust_byte_string("\n"), "\\n");
        non_owasp!(for_rust_byte_string("\r"), "\\r");
    }

    #[test]
    fn byte_string_hex_for_controls() {
        non_owasp!(for_rust_byte_string("\x01"), "\\x01");
        non_owasp!(for_rust_byte_string("\x7F"), "\\x7f");
    }

    #[test]
    fn byte_string_non_ascii_as_utf8_bytes() {
        // é = U+00E9 → UTF-8: C3 A9
        non_owasp!(for_rust_byte_string("café"), r"caf\xc3\xa9");
        // 日 = U+65E5 → UTF-8: E6 97 A5
        non_owasp!(for_rust_byte_string("日"), r"\xe6\x97\xa5");
        // 😀 = U+1F600 → UTF-8: F0 9F 98 80
        non_owasp!(for_rust_byte_string("😀"), r"\xf0\x9f\x98\x80");
    }

    #[test]
    fn byte_string_nonchars_as_bytes() {
        // non-characters get byte-encoded (not replaced with space)
        // U+FDD0 → UTF-8: EF B7 90
        non_owasp!(for_rust_byte_string("\u{FDD0}"), r"\xef\xb7\x90");
    }
}

// ===========================================================================
// JSON context tests
// ===========================================================================

mod json {
    use super::*;

    #[test]
    fn passthrough() {
        upstream!(for_json("hello world"), "hello world");
        upstream!(for_json(""), "");
        upstream!(for_json("café 日本語 😀"), "café 日本語 😀");
    }

    #[test]
    fn double_quotes_escaped() {
        upstream!(for_json(r#"say "hi""#), r#"say \"hi\""#);
    }

    #[test]
    fn single_quotes_not_escaped() {
        // JSON has no \' escape — single quotes are literal characters
        upstream!(for_json("it's"), "it's");
        upstream!(for_json("'quoted'"), "'quoted'");
    }

    #[test]
    fn backslash() {
        upstream!(for_json(r"back\slash"), r"back\\slash");
        upstream!(for_json(r"\\"), r"\\\\");
    }

    #[test]
    fn named_escapes() {
        upstream!(for_json("\x08"), "\\b");
        upstream!(for_json("\t"), "\\t");
        upstream!(for_json("\n"), "\\n");
        upstream!(for_json("\x0C"), "\\f");
        upstream!(for_json("\r"), "\\r");
    }

    #[test]
    fn c0_controls_use_unicode_not_hex() {
        // JSON mandates \uHHHH for control escapes — \xHH is invalid JSON
        upstream!(for_json("\x00"), "\\u0000");
        upstream!(for_json("\x01"), "\\u0001");
        upstream!(for_json("\x07"), "\\u0007");
        upstream!(for_json("\x0B"), "\\u000b");
        upstream!(for_json("\x0E"), "\\u000e");
        upstream!(for_json("\x1F"), "\\u001f");
    }

    #[test]
    fn line_separators_mandatory() {
        // U+2028/U+2029 are valid JSON per RFC 8259 but must be escaped
        // for safe embedding in HTML <script> blocks
        upstream!(for_json("\u{2028}"), "\\u2028");
        upstream!(for_json("\u{2029}"), "\\u2029");
        upstream!(for_json("a\u{2028}b\u{2029}c"), "a\\u2028b\\u2029c");
    }

    #[test]
    fn forward_slash_escaped() {
        // RFC 8259 §7 permits \/ — we use it to prevent </script> breakout
        deviation!(Json, for_json("/"), "\\/");
        deviation!(Json, for_json("a/b"), "a\\/b");
        deviation!(Json, for_json("</script>"), "\\u003c\\/script>");
        deviation!(
            Json,
            for_json("https://example.com"),
            "https:\\/\\/example.com"
        );
    }

    #[test]
    fn script_tag_breakout_prevented() {
        // JSON embedded in <script> blocks must not allow </script> injection
        deviation!(
            Json,
            for_json("</script><script>alert(1)//"),
            "\\u003c\\/script>\\u003cscript>alert(1)\\/\\/"
        );
    }

    #[test]
    fn script_data_double_escape_start_blocked() {
        deviation!(Json, for_json("<!--<script>"), "\\u003c!--\\u003cscript>");
        upstream!(for_json("<!--"), "\\u003c!--");
        upstream!(for_json("<script"), "\\u003cscript");
        upstream!(for_json("a<b"), "a\\u003cb");
    }

    #[test]
    fn ampersand_not_escaped() {
        deviation!(Json, for_json("a&b"), "a&b");
    }

    #[test]
    fn supplementary_plane_passes_through() {
        // JSON is UTF-8 — no surrogate pairs needed
        upstream!(for_json("😀"), "😀");
        upstream!(for_json("\u{10000}"), "\u{10000}");
    }

    // -- difference from for_javascript_source --

    #[test]
    fn json_vs_js_source_single_quotes() {
        // the key semantic difference: JS escapes ', JSON does not
        upstream!(for_json("it's"), "it's");
        upstream!(for_javascript_source("it's"), r"it\'s");
    }

    #[test]
    fn json_vs_js_source_control_format() {
        // JS uses \xHH; JSON uses \u00HH
        upstream!(for_json("\x01"), "\\u0001");
        upstream!(for_javascript_source("\x01"), "\\x01");
    }

    #[test]
    fn json_vs_js_source_common_escapes() {
        // both agree on named escapes and line separators
        std::assert_eq!(for_json("\n"), for_javascript_source("\n"));
        std::assert_eq!(for_json("\t"), for_javascript_source("\t"));
        std::assert_eq!(for_json("\\"), for_javascript_source("\\"));
        std::assert_eq!(for_json("\u{2028}"), for_javascript_source("\u{2028}"));
    }

    #[test]
    fn already_escaped_input() {
        // encoding should double-escape
        upstream!(for_json(r"\n"), r"\\n");
        upstream!(for_json(r#"\""#), r#"\\\""#);
    }
}

// ===========================================================================
// SQL context tests
// ===========================================================================

mod sql {
    use super::*;

    // -- for_sql: standard SQL string literals --

    #[test]
    fn sql_single_quote_doubled() {
        non_owasp!(for_sql("it's"), "it''s");
        non_owasp!(for_sql("'quoted'"), "''quoted''");
        non_owasp!(for_sql("a''b"), "a''''b");
        non_owasp!(for_sql("'''"), "''''''");
    }

    #[test]
    fn sql_injection_classic() {
        non_owasp!(
            for_sql("'; DROP TABLE users; --"),
            "''; DROP TABLE users; --"
        );
    }

    #[test]
    fn sql_injection_stacked() {
        non_owasp!(for_sql("' OR '1'='1"), "'' OR ''1''=''1");
    }

    #[test]
    fn sql_nul_removed() {
        non_owasp!(for_sql("before\x00after"), "beforeafter");
        non_owasp!(for_sql("\x00"), "");
        non_owasp!(for_sql("\x00\x00\x00"), "");
        non_owasp!(for_sql("a\x00b\x00c"), "abc");
    }

    #[test]
    fn sql_backslash_passes_through() {
        // standard SQL does NOT treat backslash specially
        non_owasp!(for_sql(r"\"), r"\");
        non_owasp!(for_sql(r"\\"), r"\\");
        non_owasp!(for_sql(r"\'"), r"\''");
    }

    #[test]
    fn sql_double_quote_passes_through() {
        non_owasp!(for_sql(r#"a"b"#), r#"a"b"#);
        non_owasp!(for_sql(r#""""#), r#""""#);
    }

    #[test]
    fn sql_control_chars_pass_through() {
        // standard SQL has no escape sequences for control characters
        non_owasp!(for_sql("\t"), "\t");
        non_owasp!(for_sql("\n"), "\n");
        non_owasp!(for_sql("\r"), "\r");
        non_owasp!(for_sql("\x08"), "\x08");
        non_owasp!(for_sql("\x1A"), "\x1A");
        non_owasp!(for_sql("\x01"), "\x01");
        non_owasp!(for_sql("\x7F"), "\x7F");
    }

    #[test]
    fn sql_nonchars_replaced() {
        non_owasp!(for_sql("\u{FDD0}"), " ");
        non_owasp!(for_sql("\u{FDEF}"), " ");
        non_owasp!(for_sql("\u{FFFE}"), " ");
        non_owasp!(for_sql("\u{FFFF}"), " ");
        non_owasp!(for_sql("\u{1FFFE}"), " ");
        non_owasp!(for_sql("\u{10FFFF}"), " ");
    }

    // -- unicode --

    #[test]
    fn sql_unicode_passthrough() {
        non_owasp!(for_sql("café"), "café");
        non_owasp!(for_sql("日本語"), "日本語");
        non_owasp!(for_sql("😀"), "😀");
        non_owasp!(for_sql("\u{10000}"), "\u{10000}");
    }

    #[test]
    fn sql_mixed_unicode_and_quotes() {
        non_owasp!(for_sql("café's best"), "café''s best");
        non_owasp!(for_sql("日本語'テスト"), "日本語''テスト");
    }

    // -- boundary conditions --

    #[test]
    fn sql_single_quote_only() {
        non_owasp!(for_sql("'"), "''");
    }

    // -- for_sql_backslash: MySQL/MariaDB --

    #[test]
    fn backslash_single_quote_escaped() {
        non_owasp!(for_sql_backslash("it's"), r"it\'s");
        non_owasp!(for_sql_backslash("'quoted'"), r"\'quoted\'");
        non_owasp!(for_sql_backslash("'''"), r"\'\'\'");
    }

    #[test]
    fn backslash_escapes_backslash() {
        non_owasp!(for_sql_backslash(r"\"), r"\\");
        non_owasp!(for_sql_backslash(r"\\"), r"\\\\");
        non_owasp!(for_sql_backslash(r"a\b"), r"a\\b");
    }

    #[test]
    fn backslash_all_named_escapes() {
        non_owasp!(for_sql_backslash("\x00"), r"\0");
        non_owasp!(for_sql_backslash("\x08"), r"\b");
        non_owasp!(for_sql_backslash("\t"), r"\t");
        non_owasp!(for_sql_backslash("\n"), r"\n");
        non_owasp!(for_sql_backslash("\r"), r"\r");
        non_owasp!(for_sql_backslash("\x1A"), r"\Z");
    }

    #[test]
    fn backslash_injection_classic() {
        non_owasp!(
            for_sql_backslash("'; DROP TABLE users; --"),
            r"\'; DROP TABLE users; --"
        );
    }

    #[test]
    fn backslash_injection_via_backslash() {
        // attacker tries \' to escape the closing quote — both get escaped
        non_owasp!(for_sql_backslash("\\'"), r"\\\'");
    }

    #[test]
    fn backslash_injection_stacked() {
        non_owasp!(for_sql_backslash("' OR '1'='1"), r"\' OR \'1\'=\'1");
    }

    #[test]
    fn backslash_nul_encoded_not_removed() {
        // unlike standard SQL, MySQL encodes NUL as \0 rather than removing
        non_owasp!(for_sql_backslash("a\x00b"), r"a\0b");
        non_owasp!(for_sql_backslash("\x00"), r"\0");
    }

    #[test]
    fn backslash_double_quote_passes_through() {
        non_owasp!(for_sql_backslash(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn backslash_other_controls_pass_through() {
        // controls not in MySQL's escape list pass through unchanged
        non_owasp!(for_sql_backslash("\x01"), "\x01");
        non_owasp!(for_sql_backslash("\x07"), "\x07");
        non_owasp!(for_sql_backslash("\x0B"), "\x0B");
        non_owasp!(for_sql_backslash("\x0C"), "\x0C");
        non_owasp!(for_sql_backslash("\x1F"), "\x1F");
        non_owasp!(for_sql_backslash("\x7F"), "\x7F");
    }

    #[test]
    fn backslash_nonchars_replaced() {
        non_owasp!(for_sql_backslash("\u{FDD0}"), " ");
        non_owasp!(for_sql_backslash("\u{FDEF}"), " ");
        non_owasp!(for_sql_backslash("\u{FFFE}"), " ");
        non_owasp!(for_sql_backslash("\u{FFFF}"), " ");
        non_owasp!(for_sql_backslash("\u{1FFFE}"), " ");
        non_owasp!(for_sql_backslash("\u{10FFFF}"), " ");
    }

    #[test]
    fn backslash_unicode_passthrough() {
        non_owasp!(for_sql_backslash("café"), "café");
        non_owasp!(for_sql_backslash("日本語"), "日本語");
        non_owasp!(for_sql_backslash("😀"), "😀");
    }
}

// ===========================================================================
// cross-context tests
// ===========================================================================

mod cross_context {
    use super::*;

    #[test]
    fn safe_string_unchanged_in_all_contexts() {
        let safe = "hello world 123";
        // safe in HTML (no angle brackets, quotes, or ampersands)
        upstream!(for_html(safe), safe);
        // safe in JS (no quotes, backslash, or control chars)
        deviation!(JsFragmentGuards, for_javascript(safe), safe);
        // safe in CSS (no special chars)
        upstream!(for_css_string(safe), safe);
        // safe in SQL (no quotes, NUL, or non-characters)
        non_owasp!(for_sql(safe), safe);
        non_owasp!(for_sql_backslash(safe), safe);
        // NOT safe in URI or form (space is encoded)
        upstream!(for_uri_component(safe), "hello%20world%20123");
        non_owasp!(for_form_urlencoded(safe), "hello+world+123");
    }
}
