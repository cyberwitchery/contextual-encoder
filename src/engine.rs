//! shared encoding engine used by all context-specific encoders.

use std::fmt;

/// shared encoding loop. writes safe runs of input directly and encodes
/// characters flagged by `needs_encoding` via `write_encoded`.
///
/// `needs_encoding` returns `true` for characters that require encoding.
/// `write_encoded` writes the encoded form for such characters. it receives
/// the current character and the next character (for lookahead-dependent
/// encodings like css hex escapes).
pub(crate) fn encode_loop<W, C, E>(
    out: &mut W,
    input: &str,
    needs_encoding: C,
    mut write_encoded: E,
) -> fmt::Result
where
    W: fmt::Write,
    C: Fn(char) -> bool,
    E: FnMut(&mut W, char, Option<char>) -> fmt::Result,
{
    let mut last_written = 0;
    let mut chars = input.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        if needs_encoding(c) {
            out.write_str(&input[last_written..i])?;
            let next = chars.peek().map(|(_, nc)| *nc);
            write_encoded(out, c, next)?;
            last_written = i + c.len_utf8();
        }
    }

    out.write_str(&input[last_written..])?;
    Ok(())
}

/// writes each UTF-8 byte of a non-ASCII character as `\xHH`.
pub(crate) fn write_utf8_hex_bytes<W: fmt::Write>(out: &mut W, c: char) -> fmt::Result {
    let mut buf = [0u8; 4];
    let encoded = c.encode_utf8(&mut buf);
    for b in encoded.as_bytes() {
        write!(out, "\\x{b:02x}")?;
    }
    Ok(())
}

/// attempts to write a C0 named escape for the given character.
///
/// covers the escapes shared by go and python: BEL (`\a`), BS (`\b`),
/// TAB (`\t`), LF (`\n`), VT (`\v`), FF (`\f`), CR (`\r`), and
/// backslash (`\\`).
///
/// returns `Some(Ok(()))` if an escape was written, `Some(Err(..))` on
/// write error, or `None` if the character has no named escape.
pub(crate) fn write_c0_named_escape<W: fmt::Write>(out: &mut W, c: char) -> Option<fmt::Result> {
    let s = match c {
        '\x07' => "\\a",
        '\x08' => "\\b",
        '\t' => "\\t",
        '\n' => "\\n",
        '\x0B' => "\\v",
        '\x0C' => "\\f",
        '\r' => "\\r",
        '\\' => "\\\\",
        _ => return None,
    };
    Some(out.write_str(s))
}

/// returns true if the character is invalid in XML 1.0 output and should be
/// replaced (with space or dash depending on context).
///
/// covers:
/// - C0 controls except tab (U+0009), LF (U+000A), CR (U+000D)
/// - DEL (U+007F)
/// - C1 controls (U+0080-U+009F)
/// - unicode non-characters (U+FDD0-U+FDEF, U+nFFFE, U+nFFFF)
pub(crate) fn is_invalid_for_xml(c: char) -> bool {
    let cp = c as u32;
    cp <= 0x08
        || cp == 0x0B
        || cp == 0x0C
        || (0x0E..=0x1F).contains(&cp)
        || cp == 0x7F
        || (0x80..=0x9F).contains(&cp)
        || is_unicode_noncharacter(cp)
}

/// returns true if the code point is a unicode non-character.
///
/// non-characters are: U+FDD0-U+FDEF and every code point ending in
/// FFFE or FFFF (U+FFFE, U+FFFF, U+1FFFE, U+1FFFF, ..., U+10FFFE, U+10FFFF).
pub(crate) fn is_unicode_noncharacter(cp: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE == 0xFFFE)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;

    #[test]
    fn invalid_xml_detects_c0_controls() {
        assert!(is_invalid_for_xml('\x00'));
        assert!(is_invalid_for_xml('\x01'));
        assert!(is_invalid_for_xml('\x08'));
        assert!(is_invalid_for_xml('\x0B'));
        assert!(is_invalid_for_xml('\x0C'));
        assert!(is_invalid_for_xml('\x0E'));
        assert!(is_invalid_for_xml('\x1F'));
    }

    #[test]
    fn invalid_xml_allows_tab_lf_cr() {
        assert!(!is_invalid_for_xml('\t'));
        assert!(!is_invalid_for_xml('\n'));
        assert!(!is_invalid_for_xml('\r'));
    }

    #[test]
    fn invalid_xml_detects_del() {
        assert!(is_invalid_for_xml('\x7F'));
    }

    #[test]
    fn invalid_xml_detects_c1_controls() {
        assert!(is_invalid_for_xml('\u{0080}'));
        assert!(is_invalid_for_xml('\u{0085}')); // NEL
        assert!(is_invalid_for_xml('\u{009F}'));
    }

    #[test]
    fn invalid_xml_allows_normal_chars() {
        assert!(!is_invalid_for_xml(' '));
        assert!(!is_invalid_for_xml('a'));
        assert!(!is_invalid_for_xml('Z'));
        assert!(!is_invalid_for_xml('0'));
        assert!(!is_invalid_for_xml('\u{00A0}')); // NBSP
        assert!(!is_invalid_for_xml('\u{4E16}')); // CJK
    }

    #[test]
    fn noncharacter_detection() {
        assert!(is_unicode_noncharacter(0xFDD0));
        assert!(is_unicode_noncharacter(0xFDEF));
        assert!(is_unicode_noncharacter(0xFFFE));
        assert!(is_unicode_noncharacter(0xFFFF));
        assert!(is_unicode_noncharacter(0x1FFFE));
        assert!(is_unicode_noncharacter(0x1FFFF));
        assert!(is_unicode_noncharacter(0x10FFFE));
        assert!(is_unicode_noncharacter(0x10FFFF));

        assert!(!is_unicode_noncharacter(0xFDCF));
        assert!(!is_unicode_noncharacter(0xFDF0));
        assert!(!is_unicode_noncharacter(0xFFFD));
        assert!(!is_unicode_noncharacter(0x10000));
    }

    #[test]
    fn encode_loop_passthrough() {
        let mut out = String::new();
        encode_loop(&mut out, "hello", |_| false, |_, _, _| unreachable!()).unwrap();
        assert_eq!(out, "hello");
    }

    #[test]
    fn encode_loop_encodes_flagged_chars() {
        let mut out = String::new();
        encode_loop(
            &mut out,
            "a<b",
            |c| c == '<',
            |out, _, _| out.write_str("&lt;"),
        )
        .unwrap();
        assert_eq!(out, "a&lt;b");
    }

    #[test]
    fn encode_loop_empty_input() {
        let mut out = String::new();
        encode_loop(&mut out, "", |_| false, |_, _, _| unreachable!()).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn encode_loop_provides_lookahead() {
        let mut seen_next = Vec::new();
        let mut out = String::new();
        encode_loop(
            &mut out,
            "abc",
            |_| true,
            |out, c, next| {
                seen_next.push(next);
                out.write_char(c)
            },
        )
        .unwrap();
        assert_eq!(seen_next, vec![Some('b'), Some('c'), None]);
    }
}
