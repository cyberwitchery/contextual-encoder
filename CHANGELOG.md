# changelog

## [unreleased]

- CSV field encoder: `for_csv_field` — RFC 4180 quoting (wraps fields containing commas, double quotes, or newlines in double quotes; escapes embedded quotes as `""`)
- writer-based variant for CSV encoder
- **breaking:** `for_json` now escapes forward slash (`/`) as `\/` to prevent `</script>` breakout when JSON is embedded in HTML `<script>` blocks (RFC 8259 §7 permits `\/`)
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
