//! zero-allocation [`Display`](std::fmt::Display) wrappers for all encoding
//! contexts.
//!
//! every `for_*` function allocates a `String`. when embedding encoded output
//! in a larger format string (e.g., `format!("<p>{}</p>", for_html(s))`), the
//! intermediate string is immediately consumed and discarded — a wasted
//! allocation.
//!
//! the `display_*` functions return lightweight wrappers that implement
//! [`Display`](std::fmt::Display) by delegating to the corresponding `write_*`
//! function. this enables zero-allocation inline formatting:
//!
//! ```
//! use contextual_encoder::display_html;
//!
//! let user_input = "<script>alert('xss')</script>";
//! // one allocation (the final String), zero intermediate allocations
//! let output = format!("<p>{}</p>", display_html(user_input));
//! assert!(output.contains("&lt;script&gt;"));
//! ```
//!
//! each `display_*` wrapper encodes identically to its `for_*` / `write_*`
//! counterpart. see the corresponding `for_*` function for encoding rules.
//!
//! # formatting parameters
//!
//! width, fill/alignment and precision apply to the *encoded* output, exactly
//! as `format!` applies them to the `String` returned by the `for_*`
//! counterpart:
//!
//! ```
//! use contextual_encoder::{display_html, for_html};
//!
//! assert_eq!(
//!     format!("{:*^12}", display_html("a<b")),
//!     format!("{:*^12}", for_html("a<b")),
//! );
//! ```
//!
//! a wrapper formatted with a width or a precision buffers the encoded output
//! into one intermediate `String`; the bare `{}` case stays allocation-free.
//!
//! precision counts characters of the *encoded* output, so it can cut an
//! escape or entity in half: `{:.4}` turns `a&lt;b` into `a&lt`, which an HTML
//! parser can read back as `a<`. `for_*` truncates the same way. do not use
//! precision to bound untrusted output — truncate the input before encoding it.

use std::fmt;

macro_rules! display_fns {
    (
        $($context:ident: $module:ident::{$for_fn:ident, $write_fn:ident, $display_fn:ident},)*
    ) => {$(
        #[doc = concat!(
            "zero-allocation display wrapper for [`",
            stringify!($for_fn),
            "`](crate::",
            stringify!($for_fn),
            ")."
        )]
        pub fn $display_fn(input: &str) -> impl fmt::Display + '_ {
            struct W<'a>(&'a str);
            impl fmt::Display for W<'_> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    if f.width().is_none() && f.precision().is_none() {
                        return crate::$module::$write_fn(f, self.0);
                    }
                    let mut encoded = String::with_capacity(self.0.len());
                    crate::$module::$write_fn(&mut encoded, self.0)?;
                    f.pad(&encoded)
                }
            }
            W(input)
        }
    )*};
}

encoders!(display_fns);

#[cfg(test)]
mod tests {
    use super::*;

    // verify that every display_* wrapper formats identically to its for_* counterpart.

    macro_rules! assert_fmt_parity {
        ($fmt:literal, $display_fn:ident, $input:expr, $encoded:expr) => {
            assert_eq!(
                format!($fmt, $display_fn($input)),
                format!($fmt, $encoded),
                "mismatch for {:?} formatted as {:?} on {}",
                $input,
                $fmt,
                stringify!($display_fn),
            );
        };
    }

    macro_rules! display_matches_for {
        (
            $($context:ident: $module:ident::{$for_fn:ident, $write_fn:ident, $display_fn:ident},)*
        ) => {$(
            #[test]
            fn $context() {
                assert_eq!(
                    [stringify!($for_fn), stringify!($write_fn), stringify!($display_fn)],
                    [
                        concat!("for_", stringify!($context)),
                        concat!("write_", stringify!($context)),
                        concat!("display_", stringify!($context)),
                    ],
                    "a list entry must name the for_/write_/display_ fns of its own context",
                );
                for input in [
                    "",
                    "hello",
                    "<script>alert('xss')</script>",
                    "café",
                    "世界",
                    "😀",
                    "a&b<c>d\"e'f",
                    "\x00\x01\x1F\x7F",
                    "\t\n\r",
                    "\u{0080}\u{009F}",
                    "\u{2028}\u{2029}",
                    "a\\b/c",
                    "key=val&foo=bar",
                    "`${inject}`",
                ] {
                    let encoded = crate::$for_fn(input);
                    assert_fmt_parity!("{}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:>12}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:<12}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:*^12}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:.0}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:.4}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:.99}", $display_fn, input, encoded);
                    assert_fmt_parity!("{:*>20.7}", $display_fn, input, encoded);
                }
            }
        )*};
    }

    encoders!(display_matches_for);

    // -- usage pattern tests --

    #[derive(Default)]
    struct ChunkCounter {
        out: String,
        chunks: usize,
    }

    impl fmt::Write for ChunkCounter {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            if !s.is_empty() {
                self.chunks += 1;
            }
            self.out.push_str(s);
            Ok(())
        }
    }

    #[test]
    fn bare_spec_writes_through_without_buffering() {
        use std::fmt::Write;
        let mut sink = ChunkCounter::default();
        write!(sink, "{}", display_html("a&b<c")).unwrap();
        assert_eq!(sink.out, crate::for_html("a&b<c"));
        assert!(
            sink.chunks > 1,
            "expected the encoder to write runs straight to the formatter, got {} chunk(s)",
            sink.chunks
        );
    }

    #[test]
    fn format_spec_buffers_into_a_single_chunk() {
        use std::fmt::Write;
        let mut sink = ChunkCounter::default();
        write!(sink, "{:.99}", display_html("a&b<c")).unwrap();
        assert_eq!(sink.out, format!("{:.99}", crate::for_html("a&b<c")));
        assert_eq!(sink.chunks, 1);
    }
}
