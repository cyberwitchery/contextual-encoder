# changelog

## Unreleased

- **breaking:** `for_rust_string` and `for_rust_char` now escape the bidirectional formatting characters (U+202A-U+202E, U+2066-U+2069) as `\u{HHHH}`. emitted raw they made the literal a hard `rustc` error, and hid a Trojan Source direction override in the generated code
- **breaking:** the javascript encoders (`for_javascript`, `for_javascript_attribute`, `for_javascript_block`, `for_javascript_source`, `for_js_template`) now escape the bidirectional formatting characters (U+202A-U+202E, U+2066-U+2069) as `\uHHHH`. emitted raw they hid a Trojan Source direction override in the generated javascript
- `for_rust_char_checked`: encodes for a Rust char literal, or returns `None` when the input is not exactly one character (#63)
- `for_rust_char` now documents that its input must be exactly one character, and its examples no longer show multi-character input that cannot compile in a char literal (#63)
- the `display_*` wrappers now honour width, fill/alignment and precision, so `format!("{:>12}", display_html(s))` pads exactly as `format!("{:>12}", for_html(s))` does; any format spec used to be silently ignored

## [0.9.0] - 2026-08-17

- **breaking:** `for_js_template` now escapes `&` as `\x26`, as the other `<script>`-block encoders do
- **breaking:** `for_cdata` now splits a `]` that ends the input, as it already splits `]]>`
- **breaking:** `for_js_template` now escapes a trailing `$`
- **breaking:** the CSS encoders now append a separator space after a hex escape that ends the output

## [0.8.0] - 2026-08-10

- **breaking:** the `<script>`-block encoders and `for_json` now escape `<` as `\x3c`/`\u003c`

## [0.7.0] - 2026-08-08

- **breaking:** `for_css_url` now hex-escapes `(`, `)` and space (#49)

## [0.6.0] - 2026-07-05

- form-urlencoded encoder: `for_form_urlencoded`, `write_form_urlencoded`, `display_form_urlencoded`

## [0.5.0] - 2026-06-19

- **breaking:** removed the Java, Go, Ruby and Python literal encoders as out of scope
- URI path encoder: `for_uri_path`, `write_uri_path`, `display_uri_path`

## [0.4.0] - 2026-06-08

- `display_*` wrappers for all encoding contexts, delegating to `write_*` without an intermediate `String`

## [0.3.0] - 2026-04-26

- Ruby string literal encoder: `for_ruby_string` — escapes quotes, hash signs (interpolation prevention), and control characters for safe embedding in double-quoted Ruby strings
- writer-based variant for Ruby encoder
- CSS encoders (`for_css_string`, `for_css_url`) now encode C1 control characters (U+0080-U+009F), matching OWASP Java Encoder behaviour — U+0085 NEL in particular can affect CSS parsing
- ES6 template literal encoder: `for_js_template` — escapes backticks and `${` interpolation markers for safe embedding inside template literals
- writer-based variant for template literal encoder
- **breaking:** `for_json` now escapes forward slash (`/`) as `\/`
- JSON string encoder: `for_json` — distinct from JavaScript encoders (no `\'`, uses `\u00HH` instead of `\xHH`, mandatory U+2028/U+2029 encoding)
- writer-based variant for JSON encoder
- SQL string literal encoders: `for_sql` (standard double-quote escaping), `for_sql_backslash` (MySQL/MariaDB backslash escaping)
- writer-based variants for all SQL encoders
- Python literal encoders: `for_python_string`, `for_python_bytes`, `for_python_raw_string`
- writer-based variants for all Python encoders
- Go literal encoders: `for_go_string`, `for_go_char`, `for_go_byte_string`
- writer-based variants for all Go encoders

## [0.2.0]

- XML 1.0 aliases: `for_xml`, `for_xml_content`, `for_xml_attribute`
- XML comment encoder: `for_xml_comment`
- CDATA encoder: `for_cdata`
- XML 1.1 encoders: `for_xml11`, `for_xml11_content`, `for_xml11_attribute`
- Java string literal encoder: `for_java`
- Rust literal encoders: `for_rust_string`, `for_rust_char`, `for_rust_byte_string`
- writer-based variants for all new encoders

## [0.1.0]

- initial release
- HTML encoders: `for_html`, `for_html_content`, `for_html_attribute`, `for_html_unquoted_attribute`
- JavaScript encoders: `for_javascript`, `for_javascript_attribute`, `for_javascript_block`, `for_javascript_source`
- CSS encoders: `for_css_string`, `for_css_url`
- URI encoder: `for_uri_component`
- writer-based variants for all encoders
- zero dependencies
- `#![forbid(unsafe_code)]`
