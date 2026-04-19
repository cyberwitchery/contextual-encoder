//! POSIX shell single-quoted string encoder.
//!
//! encodes untrusted strings for safe embedding in POSIX shell
//! single-quoted string literals (`'...'`).
//!
//! - [`for_shell_single_quoted`] — returns an encoded `String`
//! - [`write_shell_single_quoted`] — writes encoded output to a `fmt::Write`
//!
//! # encoding rules
//!
//! inside a POSIX shell single-quoted string, all characters are literal
//! except the single quote itself — there is no escape sequence. the
//! standard technique to embed a single quote is to end the quoted region,
//! insert a backslash-escaped quote, and reopen the quoted region:
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `'` | `'\''` (end-quote, backslash-quote, reopen-quote) |
//! | NUL (`\0`) | removed |
//! | unicode non-characters | space |
//!
//! all other characters — including backslash, double quotes, dollar signs,
//! backticks, newlines, and other control characters — pass through
//! unchanged. they have no special meaning inside single quotes.
//!
//! # security notes
//!
//! - **the output must be placed inside single quotes.** the encoded string
//!   does not include the surrounding quotes — the caller must provide them.
//!   for example: `format!("'{}'", for_shell_single_quoted(user_input))`.
//! - **do not use this for double-quoted contexts.** double-quoted shell
//!   strings interpret `$`, `` ` ``, `\`, `!`, and `"` — this encoder
//!   does not escape any of those.
//! - **NUL bytes are removed** because POSIX shells cannot represent them
//!   in strings (they are the C string terminator).

use std::fmt;

use crate::engine::is_unicode_noncharacter;

/// encodes `input` for safe embedding in a POSIX shell single-quoted
/// string literal (`'...'`).
///
/// escapes single quotes using the end-quote / backslash-quote / reopen-quote
/// idiom (`'` → `'\''`). NUL bytes are removed. unicode non-characters are
/// replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_shell_single_quoted;
///
/// assert_eq!(for_shell_single_quoted("hello"), "hello");
/// assert_eq!(for_shell_single_quoted("it's"), "it'\\''s");
/// assert_eq!(for_shell_single_quoted("$HOME"), "$HOME");
/// assert_eq!(for_shell_single_quoted("`cmd`"), "`cmd`");
/// ```
pub fn for_shell_single_quoted(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_shell_single_quoted(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the POSIX-shell-single-quoted-encoded form of `input` to `out`.
///
/// see [`for_shell_single_quoted`] for encoding rules.
pub fn write_shell_single_quoted<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    crate::engine::encode_loop(out, input, needs_shell_encoding, write_shell_encoded)
}

fn needs_shell_encoding(c: char) -> bool {
    c == '\'' || c == '\0' || is_unicode_noncharacter(c as u32)
}

fn write_shell_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
    match c {
        '\'' => out.write_str("'\\''"),
        '\0' => Ok(()), // remove NUL bytes
        _ if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        _ => out.write_char(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- passthrough --

    #[test]
    fn passthrough() {
        assert_eq!(for_shell_single_quoted("hello world"), "hello world");
        assert_eq!(for_shell_single_quoted(""), "");
        assert_eq!(for_shell_single_quoted("SELECT 1"), "SELECT 1");
        assert_eq!(for_shell_single_quoted("café"), "café");
        assert_eq!(for_shell_single_quoted("日本語"), "日本語");
        assert_eq!(for_shell_single_quoted("\u{1F600}"), "\u{1F600}");
    }

    // -- single quote escaping --

    #[test]
    fn single_quote_escaped() {
        assert_eq!(for_shell_single_quoted("it's"), "it'\\''s");
        assert_eq!(for_shell_single_quoted("'quoted'"), "'\\''quoted'\\''");
        assert_eq!(for_shell_single_quoted("a''b"), "a'\\'''\\''b");
    }

    #[test]
    fn single_quote_only() {
        assert_eq!(for_shell_single_quoted("'"), "'\\''");
    }

    // -- shell metacharacters pass through (single-quoted) --

    #[test]
    fn dollar_passes_through() {
        assert_eq!(for_shell_single_quoted("$HOME"), "$HOME");
        assert_eq!(for_shell_single_quoted("${var}"), "${var}");
        assert_eq!(for_shell_single_quoted("$(cmd)"), "$(cmd)");
    }

    #[test]
    fn backtick_passes_through() {
        assert_eq!(for_shell_single_quoted("`cmd`"), "`cmd`");
    }

    #[test]
    fn backslash_passes_through() {
        assert_eq!(for_shell_single_quoted(r"back\slash"), r"back\slash");
        assert_eq!(for_shell_single_quoted(r"a\\b"), r"a\\b");
    }

    #[test]
    fn double_quote_passes_through() {
        assert_eq!(for_shell_single_quoted(r#"a"b"#), r#"a"b"#);
    }

    #[test]
    fn exclamation_passes_through() {
        assert_eq!(for_shell_single_quoted("hello!"), "hello!");
    }

    #[test]
    fn semicolon_passes_through() {
        assert_eq!(for_shell_single_quoted("a;b"), "a;b");
    }

    #[test]
    fn pipe_and_redirect_pass_through() {
        assert_eq!(for_shell_single_quoted("a|b"), "a|b");
        assert_eq!(for_shell_single_quoted("a>b"), "a>b");
        assert_eq!(for_shell_single_quoted("a<b"), "a<b");
    }

    #[test]
    fn glob_chars_pass_through() {
        assert_eq!(for_shell_single_quoted("*.txt"), "*.txt");
        assert_eq!(for_shell_single_quoted("file?"), "file?");
        assert_eq!(for_shell_single_quoted("[abc]"), "[abc]");
    }

    // -- NUL handling --

    #[test]
    fn nul_removed() {
        assert_eq!(for_shell_single_quoted("before\x00after"), "beforeafter");
        assert_eq!(for_shell_single_quoted("\x00"), "");
        assert_eq!(for_shell_single_quoted("\x00\x00"), "");
    }

    // -- control characters pass through --

    #[test]
    fn control_chars_pass_through() {
        // all control characters except NUL pass through — they are literal
        // inside single quotes
        assert_eq!(for_shell_single_quoted("\t"), "\t");
        assert_eq!(for_shell_single_quoted("\n"), "\n");
        assert_eq!(for_shell_single_quoted("\r"), "\r");
        assert_eq!(for_shell_single_quoted("\x08"), "\x08");
        assert_eq!(for_shell_single_quoted("\x01"), "\x01");
        assert_eq!(for_shell_single_quoted("\x7F"), "\x7F");
    }

    // -- unicode non-characters --

    #[test]
    fn nonchars_replaced() {
        assert_eq!(for_shell_single_quoted("\u{FDD0}"), " ");
        assert_eq!(for_shell_single_quoted("\u{FFFE}"), " ");
        assert_eq!(for_shell_single_quoted("\u{1FFFE}"), " ");
    }

    // -- injection attempts --

    #[test]
    fn command_injection_attempt() {
        assert_eq!(
            for_shell_single_quoted("'; rm -rf /; echo '"),
            "'\\''; rm -rf /; echo '\\''",
        );
    }

    // -- writer matches string --

    #[test]
    fn writer_matches() {
        let input = "test\x00'escape' café\u{FDD0}$HOME`cmd`";
        let mut w = String::new();
        write_shell_single_quoted(&mut w, input).unwrap();
        assert_eq!(for_shell_single_quoted(input), w);
    }
}
