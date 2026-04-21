//! CSV field encoder.
//!
//! encodes untrusted strings for safe embedding in CSV fields following
//! [RFC 4180](https://www.rfc-editor.org/rfc/rfc4180).
//!
//! - [`for_csv_field`] — safe for CSV field contexts
//!
//! # encoding rules
//!
//! RFC 4180 requires fields to be enclosed in double quotes when they contain
//! commas, double quotes, or line breaks (CR, LF, CRLF). embedded double
//! quotes are escaped by doubling them (`"` → `""`).
//!
//! this encoder **always** wraps the output in double quotes when quoting is
//! needed, and passes through fields that need no quoting unchanged. this is
//! the standard behavior expected by CSV parsers.
//!
//! | input contains | result |
//! |----------------|--------|
//! | `,` (comma) | field wrapped in `"..."` |
//! | `"` (double quote) | field wrapped in `"..."`, `"` → `""` |
//! | `\n` (LF) | field wrapped in `"..."` |
//! | `\r` (CR) | field wrapped in `"..."` |
//! | none of the above | field passed through unchanged |
//!
//! # security notes
//!
//! - **CSV injection / formula injection:** this encoder does not defend
//!   against formula injection attacks where fields starting with `=`, `+`,
//!   `-`, or `@` may be interpreted as formulas by spreadsheet applications.
//!   that is an application-level concern, not a CSV encoding concern — RFC
//!   4180 does not address it, and defenses depend on the consuming
//!   application. if you need formula injection protection, prefix such
//!   fields with a tab or single quote before encoding.
//! - **field delimiters:** this encoder assumes comma as the field delimiter.
//!   if your CSV dialect uses a different delimiter (semicolon, tab), this
//!   encoder may not be appropriate.

use std::fmt;

/// encodes `input` for safe embedding as a CSV field value following
/// [RFC 4180](https://www.rfc-editor.org/rfc/rfc4180).
///
/// if the input contains commas, double quotes, carriage returns, or line
/// feeds, the output is wrapped in double quotes with embedded double quotes
/// doubled. otherwise the input is returned unchanged.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_csv_field;
///
/// assert_eq!(for_csv_field("hello"), "hello");
/// assert_eq!(for_csv_field("hello,world"), r#""hello,world""#);
/// assert_eq!(for_csv_field(r#"say "hi""#), r#""say ""hi""""#);
/// assert_eq!(for_csv_field("line\nbreak"), "\"line\nbreak\"");
/// ```
pub fn for_csv_field(input: &str) -> String {
    if !needs_csv_quoting(input) {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len() + 2);
    write_csv_field(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the CSV-encoded form of `input` to `out`.
///
/// see [`for_csv_field`] for encoding rules.
pub fn write_csv_field<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    if !needs_csv_quoting(input) {
        return out.write_str(input);
    }

    out.write_char('"')?;
    for c in input.chars() {
        if c == '"' {
            out.write_str("\"\"")?;
        } else {
            out.write_char(c)?;
        }
    }
    out.write_char('"')
}

/// returns true if the field needs to be wrapped in double quotes.
fn needs_csv_quoting(input: &str) -> bool {
    input.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r'))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- passthrough (no quoting needed) --

    #[test]
    fn passthrough_plain() {
        assert_eq!(for_csv_field("hello world"), "hello world");
    }

    #[test]
    fn passthrough_empty() {
        assert_eq!(for_csv_field(""), "");
    }

    #[test]
    fn passthrough_alphanumeric() {
        assert_eq!(for_csv_field("abc123"), "abc123");
    }

    #[test]
    fn passthrough_unicode() {
        assert_eq!(for_csv_field("café"), "café");
        assert_eq!(for_csv_field("日本語"), "日本語");
        assert_eq!(for_csv_field("😀"), "😀");
    }

    #[test]
    fn passthrough_spaces_and_tabs() {
        assert_eq!(for_csv_field("hello world"), "hello world");
        assert_eq!(for_csv_field("col\tcol"), "col\tcol");
    }

    #[test]
    fn passthrough_special_chars() {
        // characters that are special in other contexts but not CSV
        assert_eq!(for_csv_field("<html>"), "<html>");
        assert_eq!(for_csv_field("it's"), "it's");
        assert_eq!(for_csv_field("a&b"), "a&b");
        assert_eq!(for_csv_field("a;b"), "a;b");
    }

    // -- comma triggers quoting --

    #[test]
    fn comma_triggers_quoting() {
        assert_eq!(for_csv_field("hello,world"), "\"hello,world\"");
    }

    #[test]
    fn multiple_commas() {
        assert_eq!(for_csv_field("a,b,c"), "\"a,b,c\"");
    }

    #[test]
    fn only_comma() {
        assert_eq!(for_csv_field(","), "\",\"");
    }

    // -- double quote triggers quoting and escaping --

    #[test]
    fn double_quote_escaped() {
        assert_eq!(for_csv_field(r#"say "hi""#), r#""say ""hi""""#);
    }

    #[test]
    fn only_double_quote() {
        assert_eq!(for_csv_field("\""), "\"\"\"\"");
    }

    #[test]
    fn multiple_double_quotes() {
        assert_eq!(for_csv_field("\"\""), "\"\"\"\"\"\"");
    }

    #[test]
    fn double_quote_at_boundaries() {
        assert_eq!(for_csv_field("\"hello\""), "\"\"\"hello\"\"\"");
    }

    // -- newlines trigger quoting --

    #[test]
    fn lf_triggers_quoting() {
        assert_eq!(for_csv_field("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn cr_triggers_quoting() {
        assert_eq!(for_csv_field("line\rbreak"), "\"line\rbreak\"");
    }

    #[test]
    fn crlf_triggers_quoting() {
        assert_eq!(for_csv_field("line\r\nbreak"), "\"line\r\nbreak\"");
    }

    // -- mixed special characters --

    #[test]
    fn comma_and_quote() {
        assert_eq!(
            for_csv_field("value,with \"quotes\""),
            "\"value,with \"\"quotes\"\"\""
        );
    }

    #[test]
    fn comma_and_newline() {
        assert_eq!(for_csv_field("a,b\nc"), "\"a,b\nc\"");
    }

    #[test]
    fn all_special_chars() {
        assert_eq!(for_csv_field("\",\n\r"), "\"\"\",\n\r\"");
    }

    // -- writer matches string --

    #[test]
    fn writer_matches_no_quoting() {
        let input = "hello world";
        let mut w = String::new();
        write_csv_field(&mut w, input).unwrap();
        assert_eq!(for_csv_field(input), w);
    }

    #[test]
    fn writer_matches_with_quoting() {
        let input = "value,with \"quotes\" and\nnewlines";
        let mut w = String::new();
        write_csv_field(&mut w, input).unwrap();
        assert_eq!(for_csv_field(input), w);
    }

    #[test]
    fn writer_matches_empty() {
        let input = "";
        let mut w = String::new();
        write_csv_field(&mut w, input).unwrap();
        assert_eq!(for_csv_field(input), w);
    }

    // -- formula injection is not in scope (documenting behavior) --

    #[test]
    fn formula_prefix_passes_through() {
        // this encoder does not defend against formula injection —
        // that is an application-level concern
        assert_eq!(for_csv_field("=SUM(A1)"), "=SUM(A1)");
        assert_eq!(for_csv_field("+1234"), "+1234");
        assert_eq!(for_csv_field("-1234"), "-1234");
        assert_eq!(for_csv_field("@SUM(A1)"), "@SUM(A1)");
    }
}
