//! demonstrates contextual output encoding across all supported contexts.
//!
//! run with: `cargo run --example contexts`

// note: choose the encoder based on the final sink, not the input contents.
// when contexts are nested (e.g., a URI inside an HTML attribute), encode
// from the inside out.

use contextual_encoder::{
    for_cdata, for_css_string, for_css_url, for_go_byte_string, for_go_char, for_go_string,
    for_html, for_html_attribute, for_html_content, for_html_unquoted_attribute, for_java,
    for_javascript, for_javascript_attribute, for_javascript_block, for_javascript_source,
    for_rust_byte_string, for_rust_char, for_rust_string, for_uri_component, for_xml, for_xml11,
    for_xml11_attribute, for_xml11_content, for_xml_attribute, for_xml_comment, for_xml_content,
};

fn main() {
    let input = r#"<script>alert("xss")</script>"#;

    println!("input: {input}");
    println!();

    // -----------------------------------------------------------------------
    // comparison: same input across all encoders
    // -----------------------------------------------------------------------

    // html text content AND quoted attributes (safe default when unsure)
    println!("--- html ---");
    println!("  for_html:                     {}", for_html(input));

    // html text nodes only — does NOT encode quotes, so never use in attributes
    println!(
        "  for_html_content:             {}",
        for_html_content(input)
    );

    // quoted attribute values only — does NOT encode >, slightly more minimal
    println!(
        "  for_html_attribute:           {}",
        for_html_attribute(input)
    );

    // unquoted attribute values — most aggressive, encodes whitespace/grave/etc.
    println!(
        "  for_html_unquoted_attribute:  {}",
        for_html_unquoted_attribute(input)
    );
    println!();

    // universal js encoder — safe in event attrs, <script> blocks, and .js files
    println!("--- javascript ---");
    println!("  for_javascript:               {}", for_javascript(input));

    // html event attributes (onclick="...") — does not escape /
    println!(
        "  for_javascript_attribute:     {}",
        for_javascript_attribute(input)
    );

    // <script> blocks — uses \" and \' (not safe in html attributes)
    println!(
        "  for_javascript_block:         {}",
        for_javascript_block(input)
    );

    // standalone .js / json files — minimal, NOT safe in any html context
    println!(
        "  for_javascript_source:        {}",
        for_javascript_source(input)
    );
    println!();

    // quoted css string values, e.g., content: "..." or font-family: "..."
    println!("--- css ---");
    println!("  for_css_string:               {}", for_css_string(input));

    // css url() values — like for_css_string but parens pass through
    println!("  for_css_url:                  {}", for_css_url(input));
    println!();

    // uri component (query params, path segments) — NOT for full urls
    println!("--- uri ---");
    println!(
        "  for_uri_component:            {}",
        for_uri_component(input)
    );
    println!();

    // xml 1.0 aliases — identical to the html encoders
    println!("--- xml 1.0 ---");
    println!("  for_xml:                      {}", for_xml(input));
    println!("  for_xml_content:              {}", for_xml_content(input));
    println!(
        "  for_xml_attribute:            {}",
        for_xml_attribute(input)
    );

    // xml-only contexts
    println!("  for_xml_comment:              {}", for_xml_comment(input));
    println!("  for_cdata:                    {}", for_cdata(input));
    println!();

    // xml 1.1 — restricted chars get &#xHH; instead of space
    println!("--- xml 1.1 ---");
    let xml11_input = "a\x01b<c>";
    println!("  for_xml11:                    {}", for_xml11(xml11_input));
    println!(
        "  for_xml11_content:            {}",
        for_xml11_content(xml11_input)
    );
    println!(
        "  for_xml11_attribute:          {}",
        for_xml11_attribute(xml11_input)
    );
    println!();

    // java string literal — octal escapes, surrogate pairs
    println!("--- java ---");
    println!("  for_java:                     {}", for_java(input));
    println!();

    // go literals — \xHH escapes, \a and \v named escapes
    println!("--- go ---");
    println!("  for_go_string:                {}", for_go_string(input));
    println!("  for_go_char:                  {}", for_go_char(input));
    println!(
        "  for_go_byte_string:           {}",
        for_go_byte_string(input)
    );
    println!();

    // rust literals — \xHH escapes, UTF-8 byte encoding for byte strings
    println!("--- rust ---");
    println!("  for_rust_string:              {}", for_rust_string(input));
    println!("  for_rust_char:                {}", for_rust_char(input));
    println!(
        "  for_rust_byte_string:         {}",
        for_rust_byte_string(input)
    );

    // -----------------------------------------------------------------------
    // practical: one realistic input per sink, correct encoder for each
    // -----------------------------------------------------------------------

    let user_name = r#"Bob <img src=x onerror="alert(1)">"#;
    let user_query = "hello world & goodbye";
    let user_text = r#"hi from </script><script>alert(1)</script>"#;
    let user_css_text = r#"hello "css" \ test"#;

    println!("--- practical usage ---");

    // html text node — for_html_content is the right encoder
    println!(r#"  <p>{}</p>"#, for_html_content(user_name));

    // nested context: uri component inside an html attribute.
    // encode from inside out: first percent-encode the query value,
    // then html-attribute-encode the entire href.
    let href = format!("/search?q={}", for_uri_component(user_query));
    println!(r#"  <a href="{}">search</a>"#, for_html_attribute(&href),);

    // actual css string context: a quoted content value in a stylesheet
    println!(
        r#"  <style>.msg::after {{ content: "{}"; }}</style>"#,
        for_css_string(user_css_text),
    );

    // javascript string inside an event-handler attribute
    println!(
        r#"  <button onclick="greet('{}');">hi</button>"#,
        for_javascript_attribute(user_text),
    );
}
