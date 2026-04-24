//! POSIX shell single-quoted string encoder.
//!
//! encodes untrusted strings for safe embedding inside POSIX shell
//! single-quoted strings (`'...'`).
//!
//! - [`for_shell_single_quoted`] — returns an encoded [`String`]
//! - [`write_shell_single_quoted`] — writes to any [`fmt::Write`]
//!
//! # encoding rules
//!
//! POSIX single-quoted strings treat every character literally — there are
//! no escape sequences. the only character that cannot appear is the single
//! quote itself. the standard workaround is the "quote-break-requote"
//! pattern: close the current single-quoted segment, add a backslash-escaped
//! single quote, and re-open a new single-quoted segment.
//!
//! | character | encoded as | notes |
//! |-----------|-----------|-------|
//! | `'` | `'\''` | close, escaped quote, re-open |
//! | NUL (`\0`) | removed | shell args cannot contain NUL |
//! | unicode non-characters | space | consistent with other encoders |
//!
//! all other characters pass through unchanged — they have no special
//! meaning inside POSIX single quotes.
//!
//! # usage
//!
//! the caller is responsible for providing the surrounding single quotes:
//!
//! ```
//! use contextual_encoder::for_shell_single_quoted;
//!
//! let safe = for_shell_single_quoted("it's dangerous; rm -rf /");
//! let command = format!("echo '{safe}'");
//! assert_eq!(command, r"echo 'it'\''s dangerous; rm -rf /'");
//! ```
//!
//! # security notes
//!
//! - **this encoder is for the single-quoted context only.** if the result
//!   is not placed inside single quotes, shell metacharacters (`$`, `` ` ``,
//!   `|`, `;`, etc.) will be interpreted.
//! - **NUL bytes are silently removed.** POSIX command arguments cannot
//!   contain NUL — passing NUL to `exec` truncates at the first NUL byte.
//! - **double-quoted and unquoted contexts are different.** do not use this
//!   encoder for double-quoted strings or unquoted positions — those
//!   contexts have their own expansion rules.

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

/// encodes `input` for safe embedding in a POSIX shell single-quoted string
/// (`'...'`).
///
/// single quotes cannot appear inside single-quoted strings, so each `'` in
/// the input is replaced with `'\''` (close the quote, add a backslash-escaped
/// quote, re-open the quote). NUL bytes are removed. unicode non-characters
/// are replaced with space.
///
/// the caller must provide the surrounding single quotes.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_shell_single_quoted;
///
/// assert_eq!(for_shell_single_quoted("hello"), "hello");
/// assert_eq!(for_shell_single_quoted("it's"), r"it'\''s");
/// assert_eq!(for_shell_single_quoted("$HOME"), "$HOME");
/// assert_eq!(for_shell_single_quoted(r"back\slash"), r"back\slash");
/// ```
pub fn for_shell_single_quoted(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_shell_single_quoted(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the POSIX-shell-single-quote-encoded form of `input` to `out`.
///
/// see [`for_shell_single_quoted`] for encoding rules.
pub fn write_shell_single_quoted<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_shell_sq_encoding, write_shell_sq_encoded)
}

fn needs_shell_sq_encoding(c: char) -> bool {
    c == '\'' || c == '\0' || is_unicode_noncharacter(c as u32)
}

fn write_shell_sq_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
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

    #[test]
    fn passthrough() {
        assert_eq!(for_shell_single_quoted("hello world"), "hello world");
        assert_eq!(for_shell_single_quoted(""), "");
        assert_eq!(for_shell_single_quoted("ls -la /tmp"), "ls -la /tmp");
        assert_eq!(for_shell_single_quoted("café"), "café");
        assert_eq!(for_shell_single_quoted("日本語"), "日本語");
        assert_eq!(for_shell_single_quoted("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn single_quote_break_requote() {
        assert_eq!(for_shell_single_quoted("it's"), r"it'\''s");
        assert_eq!(for_shell_single_quoted("'"), r"'\''");
        assert_eq!(for_shell_single_quoted("''"), r"'\'''\''");
        assert_eq!(for_shell_single_quoted("a'b'c"), r"a'\''b'\''c");
    }

    #[test]
    fn shell_metacharacters_pass_through() {
        // inside single quotes, these are all literal
        assert_eq!(for_shell_single_quoted("$HOME"), "$HOME");
        assert_eq!(for_shell_single_quoted("`whoami`"), "`whoami`");
        assert_eq!(for_shell_single_quoted("$(id)"), "$(id)");
        assert_eq!(for_shell_single_quoted("a | b"), "a | b");
        assert_eq!(for_shell_single_quoted("a; b"), "a; b");
        assert_eq!(for_shell_single_quoted("a && b"), "a && b");
        assert_eq!(for_shell_single_quoted("a > b"), "a > b");
        assert_eq!(for_shell_single_quoted("*?[]"), "*?[]");
    }

    #[test]
    fn backslash_passes_through() {
        // no escape sequences exist inside single quotes
        assert_eq!(for_shell_single_quoted(r"a\b"), r"a\b");
        assert_eq!(for_shell_single_quoted(r"a\\b"), r"a\\b");
        assert_eq!(for_shell_single_quoted(r"a\n"), r"a\n");
    }

    #[test]
    fn double_quote_passes_through() {
        assert_eq!(for_shell_single_quoted(r#"say "hello""#), r#"say "hello""#);
    }

    #[test]
    fn control_characters_pass_through() {
        // single quotes preserve everything literally, including controls
        assert_eq!(for_shell_single_quoted("\t"), "\t");
        assert_eq!(for_shell_single_quoted("\n"), "\n");
        assert_eq!(for_shell_single_quoted("\r"), "\r");
        assert_eq!(for_shell_single_quoted("\x08"), "\x08");
    }

    #[test]
    fn removes_nul() {
        assert_eq!(for_shell_single_quoted("before\x00after"), "beforeafter");
        assert_eq!(for_shell_single_quoted("\x00"), "");
        assert_eq!(for_shell_single_quoted("\x00\x00"), "");
    }

    #[test]
    fn nonchars_replaced() {
        assert_eq!(for_shell_single_quoted("\u{FDD0}"), " ");
        assert_eq!(for_shell_single_quoted("\u{FFFE}"), " ");
        assert_eq!(for_shell_single_quoted("\u{1FFFE}"), " ");
    }

    #[test]
    fn injection_attempt() {
        assert_eq!(
            for_shell_single_quoted("'; rm -rf /; echo '"),
            r"'\''; rm -rf /; echo '\''",
        );
    }

    #[test]
    fn combined_output_with_wrapping_quotes() {
        // demonstrates the full pattern: caller wraps in single quotes
        let input = "it's";
        let command = format!("echo '{}'", for_shell_single_quoted(input));
        assert_eq!(command, r"echo 'it'\''s'");
    }

    #[test]
    fn writer_matches() {
        let input = "test\x00'escape' café\u{FDD0}";
        let mut w = String::new();
        write_shell_single_quoted(&mut w, input).unwrap();
        assert_eq!(for_shell_single_quoted(input), w);
    }
}
