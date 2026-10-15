//! SQL string literal encoders.
//!
//! encodes untrusted strings for safe embedding in SQL string literals.
//!
//! - [`for_sql`] — safe for standard SQL string literals (`'...'`)
//! - [`for_sql_backslash`] — safe for MySQL/MariaDB string literals with
//!   backslash escaping enabled (`'...'`)
//!
//! # encoding rules
//!
//! ## standard SQL (`for_sql`)
//!
//! standard SQL escapes single quotes by doubling them:
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `'` | `''` |
//! | NUL (`\0`) | removed |
//! | unicode non-characters | space |
//!
//! all other characters (including backslash) pass through unchanged — they
//! have no special meaning in standard SQL string literals.
//!
//! ## MySQL/MariaDB backslash escaping (`for_sql_backslash`)
//!
//! MySQL and MariaDB (when `NO_BACKSLASH_ESCAPES` is not set) use C-style
//! backslash escape sequences:
//!
//! | character | encoded as |
//! |-----------|-----------|
//! | `'` | `\'` |
//! | `\` | `\\` |
//! | NUL (`\0`) | `\0` |
//! | newline (`\n`) | `\n` |
//! | carriage return (`\r`) | `\r` |
//! | tab (`\t`) | `\t` |
//! | backspace (`\x08`) | `\b` |
//! | Control-Z (`\x1A`) | `\Z` |
//! | unicode non-characters | space |
//!
//! # security notes
//!
//! - **parameterized queries are always preferred.** these encoders exist for
//!   cases where parameterized queries are not possible (e.g. string literals
//!   in DDL, legacy code).
//! - **identifiers cannot be encoded.** these encoders are for string literal
//!   values. a table or column name is delimited by `"..."` (standard) or
//!   `` `...` `` (MySQL), and neither delimiter is escaped — both pass through
//!   unchanged. validate an untrusted identifier against a whitelist instead.
//! - **know your dialect.** use `for_sql` for databases that follow the SQL
//!   standard (PostgreSQL, SQLite, SQL Server, Oracle). use
//!   `for_sql_backslash` for MySQL/MariaDB when `NO_BACKSLASH_ESCAPES` is
//!   not enabled.
//! - **do not use `for_sql` with MySQL** unless `NO_BACKSLASH_ESCAPES` is
//!   set — a backslash can be used to escape the closing quote.

use std::fmt;

use crate::engine::{encode_loop, is_unicode_noncharacter};

/// encodes `input` for safe embedding in a standard SQL string literal
/// (`'...'`).
///
/// escapes single quotes by doubling them (`'` → `''`). NUL bytes are
/// removed (they can cause truncation in many SQL implementations).
/// unicode non-characters are replaced with space.
///
/// suitable for PostgreSQL, SQLite, SQL Server, Oracle, and MySQL/MariaDB
/// with `NO_BACKSLASH_ESCAPES` enabled.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_sql;
///
/// assert_eq!(for_sql("it's"), "it''s");
/// assert_eq!(for_sql("hello"), "hello");
/// assert_eq!(for_sql(r"back\slash"), r"back\slash");
/// ```
pub fn for_sql(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_sql(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the standard-SQL-encoded form of `input` to `out`.
///
/// see [`for_sql`] for encoding rules.
pub fn write_sql<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(out, input, needs_sql_encoding, write_sql_encoded)
}

fn needs_sql_encoding(c: char) -> bool {
    c == '\'' || c == '\0' || is_unicode_noncharacter(c as u32)
}

fn write_sql_encoded<W: fmt::Write>(out: &mut W, c: char, _next: Option<char>) -> fmt::Result {
    match c {
        '\'' => out.write_str("''"),
        '\0' => Ok(()), // remove NUL bytes
        _ if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        _ => out.write_char(c),
    }
}

/// encodes `input` for safe embedding in a MySQL/MariaDB string literal
/// (`'...'`) when backslash escaping is active (the default).
///
/// escapes single quotes, backslashes, NUL bytes, and control characters
/// using MySQL's backslash escape sequences. unicode non-characters are
/// replaced with space.
///
/// # examples
///
/// ```
/// use contextual_encoder::for_sql_backslash;
///
/// assert_eq!(for_sql_backslash("it's"), r"it\'s");
/// assert_eq!(for_sql_backslash(r"back\slash"), r"back\\slash");
/// assert_eq!(for_sql_backslash("line\nbreak"), r"line\nbreak");
/// assert_eq!(for_sql_backslash("null\x00byte"), r"null\0byte");
/// ```
pub fn for_sql_backslash(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    write_sql_backslash(&mut out, input).expect("writing to string cannot fail");
    out
}

/// writes the MySQL-backslash-encoded form of `input` to `out`.
///
/// see [`for_sql_backslash`] for encoding rules.
pub fn write_sql_backslash<W: fmt::Write>(out: &mut W, input: &str) -> fmt::Result {
    encode_loop(
        out,
        input,
        needs_sql_backslash_encoding,
        write_sql_backslash_encoded,
    )
}

fn needs_sql_backslash_encoding(c: char) -> bool {
    matches!(c, '\0' | '\x08' | '\t' | '\n' | '\r' | '\x1A' | '\'' | '\\')
        || is_unicode_noncharacter(c as u32)
}

fn write_sql_backslash_encoded<W: fmt::Write>(
    out: &mut W,
    c: char,
    _next: Option<char>,
) -> fmt::Result {
    match c {
        '\0' => out.write_str("\\0"),
        '\x08' => out.write_str("\\b"),
        '\t' => out.write_str("\\t"),
        '\n' => out.write_str("\\n"),
        '\r' => out.write_str("\\r"),
        '\x1A' => out.write_str("\\Z"),
        '\'' => out.write_str("\\'"),
        '\\' => out.write_str("\\\\"),
        _ if is_unicode_noncharacter(c as u32) => out.write_char(' '),
        _ => out.write_char(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- for_sql --

    #[test]
    fn sql_backtick_passes_through() {
        assert_eq!(for_sql("a`b"), "a`b");
    }

    // -- for_sql_backslash --

    #[test]
    fn backslash_backtick_passes_through() {
        assert_eq!(for_sql_backslash("a`b"), "a`b");
    }
}
