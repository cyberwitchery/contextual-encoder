//! deterministic differential tests for html, xml 1.0, css, json and javascript.
//! independent parsers check containment and, where tested, round-trip values.
//!
//! input space is generated deterministically (seeded xorshift) from a palette
//! of context-significant fragments plus random unicode scalar values, and a
//! fixed corpus of adversarial literals is always exercised.

#![forbid(unsafe_code)]

use contextual_encoder::*;

// ---------------------------------------------------------------------------
// deterministic adversarial input generator
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// context-significant fragments for the tested sinks.
const FRAGS: &[&str] = &[
    "<",
    ">",
    "&",
    "\"",
    "'",
    "`",
    "\\",
    "/",
    "=",
    " ",
    "\t",
    "\n",
    "\r",
    "\x0c",
    "</script>",
    "<script>",
    "<!--",
    "-->",
    "</style>",
    "</textarea>",
    "</title>",
    "]]>",
    "<![CDATA[",
    "${",
    "}",
    "{",
    "(",
    ")",
    ";",
    ":",
    "--",
    "&#39;",
    "&lt;",
    "&amp;",
    "&#x27;",
    "javascript:",
    "expression(",
    "url(",
    "//",
    "\\x22",
    "\\u0027",
    "\u{2028}",
    "\u{2029}",
    "\0",
    "\x07",
    "\x1b",
    "\x7f",
    "\u{0080}",
    "\u{0085}",
    "\u{009f}",
    "\u{fffe}",
    "\u{fdd0}",
    "\u{10ffff}",
    "café",
    "😀",
    "a",
    "0",
    "f",
];

/// fixed adversarial corpus, included in every test's inputs.
const CORPUS: &[&str] = &[
    "",
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1);//",
    "</script><script>alert(1)</script>",
    "<!--<script>var x='</script>';</script>",
    "]]><script>alert(1)</script>",
    "${alert(1)}",
    "`+alert(1)+`",
    "x\u{2028}alert(1)",
    "\u{0085}onmouseover=alert(1)",
    "a\x00b",
    "------>",
    "]]]]>>",
    "\\'; DROP TABLE users; --",
    "url(javascript:alert(1))",
    "expression(alert(1))",
    "\t\n\r ",
    "&#x6a;avascript:",
    "𝕏</script>",
];

fn inputs(seed: u64, n: usize) -> Vec<String> {
    let mut rng = Rng(seed);
    let mut out: Vec<String> = CORPUS.iter().map(|s| s.to_string()).collect();
    for _ in 0..n {
        let parts = 1 + rng.below(8);
        let mut s = String::new();
        for _ in 0..parts {
            if rng.below(3) == 0 {
                // random scalar value (skip surrogates)
                loop {
                    let cp = rng.below(0x110000) as u32;
                    if let Some(c) = char::from_u32(cp) {
                        s.push(c);
                        break;
                    }
                }
            } else {
                s.push_str(FRAGS[rng.below(FRAGS.len())]);
            }
        }
        out.push(s);
    }
    out
}

fn show(s: &str) -> String {
    s.escape_debug().to_string()
}

// ---------------------------------------------------------------------------
// json strings round-trip through serde_json.
// ---------------------------------------------------------------------------

#[test]
fn json_roundtrips_through_serde() {
    for s in inputs(0x1111_2222_3333_4444, 30_000) {
        let doc = format!("\"{}\"", for_json(&s));
        match serde_json::from_str::<String>(&doc) {
            Ok(decoded) => assert_eq!(
                decoded,
                s,
                "for_json round-trip mismatch: input={} enc={}",
                show(&s),
                show(&for_json(&s))
            ),
            Err(e) => panic!(
                "for_json produced invalid JSON: input={} enc={} err={e}",
                show(&s),
                show(&for_json(&s))
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// html5ever checks element counts, comments and sink attributes.
// ---------------------------------------------------------------------------

mod html_oracle {
    use html5ever::tendril::TendrilSink;
    use html5ever::{parse_document, ParseOpts};
    use markup5ever_rcdom::{Handle, NodeData, RcDom};

    pub struct Parsed {
        pub element_locals: Vec<String>,
        pub comments: usize,
        dom: RcDom,
    }

    pub fn parse(html: &str) -> Parsed {
        let dom = parse_document(RcDom::default(), ParseOpts::default())
            .from_utf8()
            .read_from(&mut html.as_bytes())
            .expect("html5ever read");
        let mut element_locals = Vec::new();
        let mut comments = 0;
        collect(&dom.document, &mut element_locals, &mut comments);
        Parsed {
            element_locals,
            comments,
            dom,
        }
    }

    fn collect(h: &Handle, out: &mut Vec<String>, comments: &mut usize) {
        if let NodeData::Element { name, .. } = &h.data {
            out.push(name.local.to_string());
        }
        if let NodeData::Comment { .. } = &h.data {
            *comments += 1;
        }
        for c in h.children.borrow().iter() {
            collect(c, out, comments);
        }
    }

    impl Parsed {
        pub fn sink(&self) -> Handle {
            find(&self.dom.document, "sink").expect("sink element present")
        }
    }

    fn find(h: &Handle, id: &str) -> Option<Handle> {
        if let NodeData::Element { attrs, .. } = &h.data {
            for a in attrs.borrow().iter() {
                if &*a.name.local == "id" && &*a.value == id {
                    return Some(h.clone());
                }
            }
        }
        for c in h.children.borrow().iter() {
            if let Some(found) = find(c, id) {
                return Some(found);
            }
        }
        None
    }

    /// (sorted attribute local names, count of element children, count of comment children)
    pub fn sink_shape(h: &Handle) -> (Vec<String>, usize, usize) {
        let attrs = if let NodeData::Element { attrs, .. } = &h.data {
            let mut v: Vec<String> = attrs
                .borrow()
                .iter()
                .map(|a| a.name.local.to_string())
                .collect();
            v.sort();
            v
        } else {
            unreachable!()
        };
        let mut elems = 0;
        let mut comments = 0;
        for c in h.children.borrow().iter() {
            match &c.data {
                NodeData::Element { .. } => elems += 1,
                NodeData::Comment { .. } => comments += 1,
                _ => {}
            }
        }
        (attrs, elems, comments)
    }
}

/// exact element counts, including the implicit html/head/body elements.
fn skeleton_ok(parsed: &html_oracle::Parsed, expected_extra: &[&str]) -> bool {
    let mut expected = vec!["html", "head", "body"];
    expected.extend_from_slice(expected_extra);
    expected.sort_unstable();
    let mut actual: Vec<&str> = parsed.element_locals.iter().map(String::as_str).collect();
    actual.sort_unstable();
    actual == expected && parsed.comments == 0
}

#[test]
fn html_oracle_rejects_duplicate_elements() {
    let p = html_oracle::parse("<div id=sink></div><div></div>");
    assert!(!skeleton_ok(&p, &["div"]));
}

#[test]
fn html_oracle_rejects_swallowed_following_markup() {
    let p = html_oracle::parse("<script id=sink>var x='<!--<script>';</script><p>after</p>");
    assert!(!skeleton_ok(&p, &["script", "p"]));
}

#[test]
fn html_oracle_rejects_comments_outside_the_sink() {
    let p = html_oracle::parse("<div id=sink></div><!--injected-->");
    assert!(!skeleton_ok(&p, &["div"]));
}

#[test]
fn html_text_content_no_breakout() {
    for s in inputs(0xAAAA_0001, 20_000) {
        for (label, enc) in [
            ("for_html", for_html(&s)),
            ("for_html_content", for_html_content(&s)),
        ] {
            let html = format!("<!doctype html><body><div id=\"sink\">{enc}</div></body>");
            let p = html_oracle::parse(&html);
            assert!(
                skeleton_ok(&p, &["div"]),
                "{label}: injected element {:?} input={} enc={}",
                p.element_locals,
                show(&s),
                show(&enc)
            );
            let (attrs, elems, comments) = html_oracle::sink_shape(&p.sink());
            assert_eq!(
                attrs,
                vec!["id"],
                "{label}: injected attr input={}",
                show(&s)
            );
            assert_eq!(
                elems,
                0,
                "{label}: element child in text sink input={} enc={}",
                show(&s),
                show(&enc)
            );
            assert_eq!(
                comments,
                0,
                "{label}: comment child input={} enc={}",
                show(&s),
                show(&enc)
            );
        }
    }
}

#[test]
fn html_attribute_no_breakout() {
    for s in inputs(0xAAAA_0002, 20_000) {
        // for_html and for_html_attribute must both be safe in either quote style.
        for (label, enc) in [
            ("for_html", for_html(&s)),
            ("for_html_attribute", for_html_attribute(&s)),
        ] {
            for (q, doc) in [
                (
                    "double",
                    format!(
                        "<!doctype html><body><div id=\"sink\" data-x=\"{enc}\">m</div></body>"
                    ),
                ),
                (
                    "single",
                    format!("<!doctype html><body><div id=\"sink\" data-x='{enc}'>m</div></body>"),
                ),
            ] {
                let p = html_oracle::parse(&doc);
                assert!(
                    skeleton_ok(&p, &["div"]),
                    "{label}/{q}: injected element {:?} input={} enc={}",
                    p.element_locals,
                    show(&s),
                    show(&enc)
                );
                let (attrs, elems, _) = html_oracle::sink_shape(&p.sink());
                assert_eq!(
                    attrs,
                    vec!["data-x", "id"],
                    "{label}/{q}: attribute set changed input={} enc={}",
                    show(&s),
                    show(&enc)
                );
                assert_eq!(
                    elems,
                    0,
                    "{label}/{q}: element child input={} enc={}",
                    show(&s),
                    show(&enc)
                );
            }
        }
    }
}

#[test]
fn html_unquoted_attribute_no_breakout() {
    for s in inputs(0xAAAA_0003, 20_000) {
        let enc = for_html_unquoted_attribute(&s);
        let doc = format!("<!doctype html><body><div id=sink data-x={enc}>m</div></body>");
        let p = html_oracle::parse(&doc);
        assert!(
            skeleton_ok(&p, &["div"]),
            "unquoted: injected element {:?} input={} enc={}",
            p.element_locals,
            show(&s),
            show(&enc)
        );
        let (attrs, elems, _) = html_oracle::sink_shape(&p.sink());
        assert_eq!(
            attrs,
            vec!["data-x", "id"],
            "unquoted: attribute set changed input={} enc={}",
            show(&s),
            show(&enc)
        );
        assert_eq!(
            elems,
            0,
            "unquoted: element child input={} enc={}",
            show(&s),
            show(&enc)
        );
    }
}

#[test]
fn html_rcdata_and_rawtext_no_breakout() {
    for s in inputs(0xAAAA_0004, 15_000) {
        // rcdata: html encoding inside a textarea.
        let ta = format!(
            "<!doctype html><body><textarea id=sink>{}</textarea></body>",
            for_html(&s)
        );
        let p = html_oracle::parse(&ta);
        assert!(
            skeleton_ok(&p, &["textarea"]),
            "rcdata: injected {:?} input={}",
            p.element_locals,
            show(&s)
        );
        let (_, elems, _) = html_oracle::sink_shape(&p.sink());
        assert_eq!(elems, 0, "rcdata: element child input={}", show(&s));

        // rawtext: css string encoding inside a style element.
        let st = format!(
            "<!doctype html><body><style id=sink>a::before{{content:\"{}\"}}</style></body>",
            for_css_string(&s)
        );
        let p = html_oracle::parse(&st);
        assert!(
            skeleton_ok(&p, &["style"]),
            "rawtext: injected {:?} input={} enc={}",
            p.element_locals,
            show(&s),
            show(&for_css_string(&s))
        );
        let (_, elems, _) = html_oracle::sink_shape(&p.sink());
        assert_eq!(elems, 0, "rawtext: element child input={}", show(&s));
    }
}

// ---------------------------------------------------------------------------
// cssparser checks that quoted output stays one string token.
// ---------------------------------------------------------------------------

#[test]
fn css_string_stays_one_token() {
    use cssparser::{Parser, Token};
    for s in inputs(0xCCCC_0001, 25_000) {
        for (label, enc) in [
            ("for_css_string", for_css_string(&s)),
            ("for_css_url", for_css_url(&s)),
        ] {
            for quote in ['"', '\''] {
                let css = format!("{quote}{enc}{quote}");
                let mut p = Parser::new(&css);
                let is_string = matches!(p.next(), Ok(Token::QuotedString(_)));
                assert!(
                    is_string,
                    "{label}: not a single string token, input={} css={}",
                    show(&s),
                    show(&css)
                );
                assert!(
                    p.next().is_err(),
                    "{label}: trailing tokens => breakout, input={} css={}",
                    show(&s),
                    show(&css)
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// quick-xml checks start elements and reconstructed values.
// ---------------------------------------------------------------------------

fn is_invalid_xml(c: char) -> bool {
    let cp = c as u32;
    cp <= 0x08
        || cp == 0x0B
        || cp == 0x0C
        || (0x0E..=0x1F).contains(&cp)
        || cp == 0x7F
        || (0x80..=0x9F).contains(&cp)
        || (0xFDD0..=0xFDEF).contains(&cp)
        || (cp & 0xFFFE == 0xFFFE)
}

fn xml_expected(s: &str) -> String {
    s.chars()
        .map(|c| if is_invalid_xml(c) { ' ' } else { c })
        .collect()
}

/// xml attribute normalization: crlf/cr to lf, then tab/lf to space.
fn xml_attr_expected(s: &str) -> String {
    let base = xml_expected(s);
    let le = base.replace("\r\n", "\n").replace('\r', "\n");
    le.chars()
        .map(|c| if matches!(c, '\t' | '\n') { ' ' } else { c })
        .collect()
}

#[test]
fn xml_content_and_attribute_no_breakout() {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    for s in inputs(0xDDDD_0001, 20_000) {
        let doc = format!(
            "<r a=\"{}\">{}</r>",
            for_xml_attribute(&s),
            for_xml_content(&s)
        );
        let mut reader = Reader::from_str(&doc);
        let mut starts = Vec::new();
        let mut text = String::new();
        let mut attr_val = String::new();
        loop {
            match reader.read_event() {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => {
                    starts.push(e.name().as_ref().to_string());
                    for a in e.attributes() {
                        let a = a.expect("attr");
                        if a.key.as_ref() == "a" {
                            attr_val = a
                                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                .expect("normalize attr")
                                .to_string();
                        }
                    }
                }
                Ok(Event::Text(t)) => text.push_str(&t),
                Ok(Event::GeneralRef(r)) => {
                    if let Some(c) = r.resolve_char_ref().expect("char ref") {
                        text.push(c);
                    } else {
                        text.push(match r.as_ref() {
                            "lt" => '<',
                            "gt" => '>',
                            "amp" => '&',
                            "quot" => '"',
                            "apos" => '\'',
                            other => panic!("unexpected entity &{other}; input={}", show(&s)),
                        });
                    }
                }
                Ok(Event::End(e)) if e.name().as_ref() == "r" => {}
                Ok(event) => panic!(
                    "unexpected xml event {event:?}: input={} doc={}",
                    show(&s),
                    show(&doc)
                ),
                Err(e) => panic!(
                    "xml malformed: input={} doc={} err={e}",
                    show(&s),
                    show(&doc)
                ),
            }
        }
        assert_eq!(
            starts,
            vec!["r"],
            "injected element: input={} doc={}",
            show(&s),
            show(&doc)
        );
        let expected = xml_expected(&s);
        assert_eq!(text, expected, "content text mismatch: input={}", show(&s));
        assert_eq!(
            attr_val,
            xml_attr_expected(&s),
            "attr value mismatch: input={}",
            show(&s)
        );
    }
}

#[test]
fn xml_cdata_no_breakout() {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    for s in inputs(0xDDDD_0002, 20_000) {
        let doc = format!("<r><![CDATA[{}]]></r>", for_cdata(&s));
        let mut reader = Reader::from_str(&doc);
        let mut starts = Vec::new();
        let mut text = String::new();
        loop {
            match reader.read_event() {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => starts.push(e.name().as_ref().to_string()),
                Ok(Event::CData(c)) => text.push_str(&c),
                Ok(Event::Text(t)) => {
                    text.push_str(&quick_xml::escape::unescape(&t).expect("unescape"))
                }
                Ok(Event::End(e)) if e.name().as_ref() == "r" => {}
                Ok(event) => panic!(
                    "unexpected cdata event {event:?}: input={} doc={}",
                    show(&s),
                    show(&doc)
                ),
                Err(e) => panic!(
                    "cdata malformed: input={} doc={} err={e}",
                    show(&s),
                    show(&doc)
                ),
            }
        }
        assert_eq!(
            starts,
            vec!["r"],
            "cdata injected element: input={} doc={}",
            show(&s),
            show(&doc)
        );
        assert_eq!(
            text,
            xml_expected(&s),
            "cdata reconstruction mismatch: input={}",
            show(&s)
        );
    }
}

#[test]
fn xml_comment_no_breakout() {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    for s in inputs(0xDDDD_0003, 20_000) {
        let doc = format!("<r><!--{}--></r>", for_xml_comment(&s));
        let mut reader = Reader::from_str(&doc);
        reader.config_mut().check_comments = true;
        let mut starts = Vec::new();
        let mut comments = 0;
        let mut stray_text = String::new();
        loop {
            match reader.read_event() {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => starts.push(e.name().as_ref().to_string()),
                Ok(Event::Comment(_)) => comments += 1,
                Ok(Event::Text(t)) => stray_text.push_str(&t),
                Ok(Event::End(e)) if e.name().as_ref() == "r" => {}
                Ok(event) => panic!(
                    "unexpected comment event {event:?}: input={} doc={}",
                    show(&s),
                    show(&doc)
                ),
                Err(e) => panic!(
                    "comment malformed: input={} doc={} err={e}",
                    show(&s),
                    show(&doc)
                ),
            }
        }
        assert_eq!(
            starts,
            vec!["r"],
            "comment injected element: input={} doc={}",
            show(&s),
            show(&doc)
        );
        assert_eq!(
            comments,
            1,
            "comment count != 1 (early close?): input={} doc={}",
            show(&s),
            show(&doc)
        );
        assert!(
            stray_text.is_empty(),
            "stray text outside comment: input={} doc={}",
            show(&s),
            show(&doc)
        );
    }
}

// ---------------------------------------------------------------------------
// html5ever checks script containment and the following element.
// ---------------------------------------------------------------------------

#[test]
fn js_script_block_no_html_breakout() {
    for s in inputs(0xBBBB_0001, 15_000) {
        for (label, enc) in [
            ("for_javascript", for_javascript(&s)),
            ("for_javascript_block", for_javascript_block(&s)),
            ("for_js_template", for_js_template(&s)),
        ] {
            let body = if label == "for_js_template" {
                format!("var x = `{enc}`;")
            } else {
                format!("var x = \"{enc}\";")
            };
            let doc = format!(
                "<!doctype html><body><script id=sink>{body}</script><p id=after>after</p></body>"
            );
            let p = html_oracle::parse(&doc);
            assert!(
                skeleton_ok(&p, &["script", "p"]),
                "{label}: injected element {:?} input={} enc={}",
                p.element_locals,
                show(&s),
                show(&enc)
            );
            let (_, elems, _) = html_oracle::sink_shape(&p.sink());
            assert_eq!(
                elems,
                0,
                "{label}: element child in <script> input={} enc={}",
                show(&s),
                show(&enc)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// javascript string and template literals round-trip through boa.
// ---------------------------------------------------------------------------

#[test]
fn js_literals_roundtrip_through_boa() {
    use boa_engine::{Context, Source};
    let mut ctx = Context::default();

    for s in inputs(0xBBBB_0002, 12_000) {
        // four string-literal encoders, embedded in a double-quoted JS string
        for (label, enc) in [
            ("for_javascript", for_javascript(&s)),
            ("for_javascript_attribute", for_javascript_attribute(&s)),
            ("for_javascript_block", for_javascript_block(&s)),
            ("for_javascript_source", for_javascript_source(&s)),
        ] {
            let code = format!("\"{enc}\"");
            let v = ctx.eval(Source::from_bytes(&code)).unwrap_or_else(|e| {
                panic!(
                    "{label}: invalid JS: input={} code={} err={e}",
                    show(&s),
                    show(&code)
                )
            });
            let got = v
                .as_string()
                .unwrap_or_else(|| panic!("{label}: not a string: input={}", show(&s)))
                .to_std_string()
                .expect("utf8");
            assert_eq!(
                got,
                s,
                "{label}: round-trip mismatch input={} enc={}",
                show(&s),
                show(&enc)
            );
        }

        // template literal encoder, embedded between backticks
        let enc = for_js_template(&s);
        let code = format!("`{enc}`");
        let v = ctx.eval(Source::from_bytes(&code)).unwrap_or_else(|e| {
            panic!(
                "for_js_template: invalid JS: input={} code={} err={e}",
                show(&s),
                show(&code)
            )
        });
        let got = v
            .as_string()
            .unwrap_or_else(|| panic!("for_js_template: not a string: input={}", show(&s)))
            .to_std_string()
            .expect("utf8");
        assert_eq!(
            got,
            s,
            "for_js_template: round-trip mismatch input={} enc={}",
            show(&s),
            show(&enc)
        );
    }
}
