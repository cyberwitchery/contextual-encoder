//! demonstrates contextual output encoding across all supported contexts.
//!
//! run with: `cargo run --example contexts`

// note: choose the encoder based on the final sink, not the input contents.
// when contexts are nested (e.g., a URI inside an HTML attribute), encode
// from the inside out.

use contextual_encoder::{
    for_css_string, for_css_url, for_html, for_html_attribute, for_html_content,
    for_html_unquoted_attribute, for_javascript, for_javascript_attribute, for_javascript_block,
    for_javascript_source, for_uri_component,
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
