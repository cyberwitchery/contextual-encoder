//! POSIX shell string literal encoders.
//!
//! encodes untrusted strings for safe embedding in POSIX shell string literals.
//!
//! - [`for_shell_single_quote`] — safe for single-quoted shell strings (`'...'`)
//! - [`for_shell_double_quote`] — safe for double-quoted shell strings (`"..."`)
//!
//! # encoding rules
//!
//! ## single-quoted strings (`for_shell_single_quote`)
//!
//! in POSIX shell, single-quoted strings treat all characters literally — no
//! escape sequences are recognized. the only character that cannot appear
//! inside single quotes is the single quote itself.
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `'` | `'\''` (close string, escaped quote, reopen) |
//! | NUL (`\0`) | removed |
//! | unicode non-characters | space |
//!
//! all other characters — including backslashes, dollar signs, backticks,
//! and control characters — pass through unchanged.
//!
//! ## double-quoted strings (`for_shell_double_quote`)
//!
//! in double-quoted shell strings, several characters have special meaning
//! and must be escaped with a backslash:
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `\` | `\\` |
//! | `"` | `\"` |
//! | `$` | `\$` |
//! | `` ` `` | `` \` `` |
//! | `!` | `\!` |
//! | NUL (`\0`) | removed |
//! | unicode non-characters | space |
//!
//! all other characters pass through unchanged.
//!
//! # security notes
//!
//! - **these encoders produce content for inside the quotes, not the quotes
//!   themselves.** the caller must wrap the output in the appropriate quote
//!   characters.
//! - **single-quote context is simpler and safer** when you have a choice.
//!   only the single quote itself needs handling, making the encoding trivial
//!   to audit.
//! - **double-quote context escapes `!`** to prevent history expansion in
//!   interactive bash/zsh shells. while `!` is not special in POSIX `sh`,
//!   escaping it is harmless in POSIX contexts and prevents a real injection
//!   vector in bash.
//! - **NUL bytes are removed.** shells use C strings internally, so NUL
//!   (U+0000) silently truncates the value. Rust `str` can contain NUL
//!   (it is valid UTF-8), so the encoder strips it to prevent truncation
//!   attacks.
//! - **command substitution in double quotes** uses both `$(...)` and
//!   `` `...` `` syntax. `for_shell_double_quote` escapes both `$` and
//!   `` ` `` to prevent either form.

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

// ---------------------------------------------------------------------------
// for_shell_single_quote — safe for POSIX single-quoted strings ('...')
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a POSIX shell single-quoted string
/// (`'...'`).
///
/// single-quoted shell strings treat all characters literally — the only
/// character that cannot appear is the single quote itself. single quotes
/// are encoded as `'\''` (close the string, insert an escaped literal
/// quote, reopen the string). NUL bytes are removed (shells cannot
/// represent them). unicode non-characters are replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_shell_single_quote;
///
/// assert_eq!(for_shell_single_quote("hello"), "hello");
/// assert_eq!(for_shell_single_quote("it's"), "it'\\''s");
/// assert_eq!(for_shell_single_quote("$HOME"), "$HOME");
/// assert_eq!(for_shell_single_quote(r"back\slash"), r"back\slash");
/// ```
pub fn for_shell_single_quote(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_shell_single_quote(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the single-quote-encoded form of `input` to `out`.
///
/// see [`for_shell_single_quote`] for encoding rules.
pub fn write_shell_single_quote<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_shell_single_quote_encoding,
        write_shell_single_quote_encoded,
    )
}

fn needs_shell_single_quote_encoding(c: char) -> bool {
    c == '\'' || c == '\0' || is_unicode_noncharacter(c as u32)
}

fn write_shell_single_quote_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        // close the single-quoted string, add a backslash-escaped quote,
        // then reopen. the shell concatenates the adjacent strings:
        //   'foo'\''bar' → foo'bar
        '\'' => out.write_str("'\\''"),
        '\0' => Ok(()),
        _ if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        _ => out.write_char(c),
    }
}

// ---------------------------------------------------------------------------
// for_shell_double_quote — safe for POSIX double-quoted strings ("...")
// ---------------------------------------------------------------------------

/// encodes `input` for safe embedding in a POSIX shell double-quoted string
/// (`"..."`).
///
/// escapes the characters that have special meaning inside double quotes:
/// backslash (`\\`), double quote (`\"`), dollar sign (`\$`), backtick
/// (`` \` ``), and exclamation mark (`\!`). NUL bytes are removed (shells
/// cannot represent them). unicode non-characters are replaced with space.
/// all other characters pass through unchanged.
///
/// the exclamation mark is escaped to prevent history expansion in
/// interactive bash and zsh shells. this is harmless in POSIX `sh` where
/// `!` has no special meaning inside double quotes.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_shell_double_quote;
///
/// assert_eq!(for_shell_double_quote("hello"), "hello");
/// assert_eq!(for_shell_double_quote("$HOME"), "\\$HOME");
/// assert_eq!(for_shell_double_quote(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(for_shell_double_quote("`whoami`"), "\\`whoami\\`");
/// ```
pub fn for_shell_double_quote(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_shell_double_quote(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the double-quote-encoded form of `input` to `out`.
///
/// see [`for_shell_double_quote`] for encoding rules.
pub fn write_shell_double_quote<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_shell_double_quote_encoding,
        write_shell_double_quote_encoded,
    )
}

fn needs_shell_double_quote_encoding(c: char) -> bool {
    matches!(c, '\\' | '"' | '$' | '`' | '!' | '\0') || is_unicode_noncharacter(c as u32)
}

fn write_shell_double_quote_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '\\' => out.write_str("\\\\"),
        '"' => out.write_str("\\\""),
        '$' => out.write_str("\\$"),
        '`' => out.write_str("\\`"),
        '!' => out.write_str("\\!"),
        '\0' => Ok(()),
        _ if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        _ => out.write_char(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_shell_single_quote --

    #[test]
    fn single_quote_passthrough() {
        assert_eq!(for_shell_single_quote("hello world"), "hello world");
        assert_eq!(for_shell_single_quote(""), "");
        assert_eq!(for_shell_single_quote("café"), "café");
        assert_eq!(for_shell_single_quote("日本語"), "日本語");
        assert_eq!(for_shell_single_quote("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn single_quote_escapes_single_quote() {
        assert_eq!(for_shell_single_quote("it's"), "it'\\''s");
        assert_eq!(for_shell_single_quote("'quoted'"), "'\\''quoted'\\''",);
        assert_eq!(for_shell_single_quote("'"), "'\\''");
    }

    #[test]
    fn single_quote_passes_special_chars() {
        // all of these are literal inside single quotes
        assert_eq!(for_shell_single_quote("$HOME"), "$HOME");
        assert_eq!(for_shell_single_quote("`whoami`"), "`whoami`");
        assert_eq!(for_shell_single_quote(r"back\slash"), r"back\slash");
        assert_eq!(for_shell_single_quote(r#"double"quote"#), r#"double"quote"#,);
        assert_eq!(for_shell_single_quote("!event"), "!event");
        assert_eq!(for_shell_single_quote("$(cmd)"), "$(cmd)");
    }

    #[test]
    fn single_quote_passes_control_chars() {
        assert_eq!(for_shell_single_quote("\t"), "\t");
        assert_eq!(for_shell_single_quote("\n"), "\n");
        assert_eq!(for_shell_single_quote("\r"), "\r");
        assert_eq!(for_shell_single_quote("\x01"), "\x01");
        assert_eq!(for_shell_single_quote("\x7F"), "\x7F");
    }

    #[test]
    fn single_quote_removes_nul() {
        assert_eq!(for_shell_single_quote("before\x00after"), "beforeafter");
        assert_eq!(for_shell_single_quote("\x00"), "");
        assert_eq!(for_shell_single_quote("\x00\x00"), "");
    }

    #[test]
    fn single_quote_nonchars_replaced() {
        assert_eq!(for_shell_single_quote("\u{FDD0}"), " ");
        assert_eq!(for_shell_single_quote("\u{FFFE}"), " ");
        assert_eq!(for_shell_single_quote("\u{1FFFE}"), " ");
    }

    #[test]
    fn single_quote_writer_matches() {
        let input = "test'escape'' café\u{FDD0}$HOME`cmd`";
        let mut w = String::new();
        write_shell_single_quote(&mut w, input).unwrap();
        assert_eq!(for_shell_single_quote(input), w);
    }

    // -- for_shell_double_quote --

    #[test]
    fn double_quote_passthrough() {
        assert_eq!(for_shell_double_quote("hello world"), "hello world");
        assert_eq!(for_shell_double_quote(""), "");
        assert_eq!(for_shell_double_quote("café"), "café");
        assert_eq!(for_shell_double_quote("日本語"), "日本語");
        assert_eq!(for_shell_double_quote("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn double_quote_escapes_double_quote() {
        assert_eq!(for_shell_double_quote(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(for_shell_double_quote(r#"""#), r#"\""#);
    }

    #[test]
    fn double_quote_escapes_backslash() {
        assert_eq!(for_shell_double_quote(r"a\b"), r"a\\b");
        assert_eq!(for_shell_double_quote(r"\\"), r"\\\\");
    }

    #[test]
    fn double_quote_escapes_dollar() {
        assert_eq!(for_shell_double_quote("$HOME"), "\\$HOME");
        assert_eq!(for_shell_double_quote("${USER}"), "\\${USER}");
        assert_eq!(for_shell_double_quote("$(whoami)"), "\\$(whoami)");
    }

    #[test]
    fn double_quote_escapes_backtick() {
        assert_eq!(for_shell_double_quote("`whoami`"), "\\`whoami\\`");
        assert_eq!(for_shell_double_quote("`"), "\\`");
    }

    #[test]
    fn double_quote_escapes_exclamation() {
        assert_eq!(for_shell_double_quote("!event"), "\\!event");
        assert_eq!(for_shell_double_quote("hello!"), "hello\\!");
    }

    #[test]
    fn double_quote_passes_single_quote() {
        assert_eq!(for_shell_double_quote("it's"), "it's");
    }

    #[test]
    fn double_quote_passes_control_chars() {
        assert_eq!(for_shell_double_quote("\t"), "\t");
        assert_eq!(for_shell_double_quote("\n"), "\n");
        assert_eq!(for_shell_double_quote("\r"), "\r");
        assert_eq!(for_shell_double_quote("\x01"), "\x01");
        assert_eq!(for_shell_double_quote("\x7F"), "\x7F");
    }

    #[test]
    fn double_quote_removes_nul() {
        assert_eq!(for_shell_double_quote("before\x00after"), "beforeafter");
        assert_eq!(for_shell_double_quote("\x00"), "");
        assert_eq!(for_shell_double_quote("\x00\x00"), "");
    }

    #[test]
    fn double_quote_nonchars_replaced() {
        assert_eq!(for_shell_double_quote("\u{FDD0}"), " ");
        assert_eq!(for_shell_double_quote("\u{FFFE}"), " ");
        assert_eq!(for_shell_double_quote("\u{1FFFE}"), " ");
    }

    #[test]
    fn double_quote_writer_matches() {
        let input = "test\"escape\\$HOME`cmd`!event café\u{FDD0}";
        let mut w = String::new();
        write_shell_double_quote(&mut w, input).unwrap();
        assert_eq!(for_shell_double_quote(input), w);
    }
}
