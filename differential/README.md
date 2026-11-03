# differential fuzzing harness

parser-based tests for contextual-encoder. fixed adversarial inputs and seeded
random inputs exercise selected encoders through independent parsers. this is a
deterministic test suite, without coverage-guided fuzzing or corpus minimization.

## run

use the current stable rust toolchain. from the repository root:

```sh
cargo test --manifest-path differential/Cargo.toml --release --locked
```

the first build compiles the parser dependencies. subsequent runs reuse them.
the checked-in lockfile pins their versions. normal `cargo test` at the
repository root does not run this package; ci runs it separately.

to rerun a single test, pass its name:

```sh
cargo test --manifest-path differential/Cargo.toml --release --locked js_literals_roundtrip_through_boa -- --exact --nocapture
```

failures include escaped input and encoding details. each test has a fixed seed
and input count. add regression inputs to `CORPUS` in `tests/differential.rs`;
`FRAGS` supplies context-significant fragments for the random generator.

## coverage

| encoders and sink | parser | assertion |
|-------------------|--------|-----------|
| `for_json` in a quoted json string | serde_json | decoded string equals the input |
| `for_html`, `for_html_content` in text | html5ever | expected elements and sink attributes, no injected comments |
| `for_html`, `for_html_attribute` in single- and double-quoted attributes | html5ever | expected elements and sink attributes, no injected comments |
| `for_html_unquoted_attribute` in an unquoted attribute | html5ever | expected elements and sink attributes, no injected comments |
| `for_html` in `<textarea>`, `for_css_string` in `<style>` | html5ever | expected elements, no injected comments |
| `for_css_string`, `for_css_url` in single- and double-quoted strings | cssparser | exactly one quoted string token |
| `for_xml_content`, `for_xml_attribute` in xml 1.0 text and a double-quoted attribute | quick-xml | expected start element and reconstructed values |
| `for_cdata` in a cdata section | quick-xml | expected start element and reconstructed text |
| `for_xml_comment` in an xml comment | quick-xml | one comment, expected start element, no stray text |
| `for_javascript`, `for_javascript_block`, `for_js_template` in `<script>` | html5ever | expected elements, no injected comments, following markup survives |
| `for_javascript`, `for_javascript_attribute`, `for_javascript_block`, `for_javascript_source` in double-quoted literals; `for_js_template` between backticks | boa | evaluated string equals the input |

## limits

coverage is limited to the encoders, wrappers and generated inputs above. the
suite does not compare output with the owasp java encoder or prove safety for
all inputs. uri, rust and sql encoders, xml 1.1, unquoted css `url()` values, and
composition across multiple writes are outside this harness's current coverage.
the root conformance and invariant suites provide additional checks.

html assertions check structure, not decoded text. css assertions check token
containment, not decoded values or url schemes. quick-xml is a streaming parser,
not a complete xml validator; these tests check its event stream and the stated
reconstruction rules. javascript attribute encoding is evaluated as a literal,
without an html event attribute wrapper.

encoding remains context-specific. `for_xml_comment` is for xml comments only;
it is unsafe for html comments. url schemes require separate validation.

## package isolation

this package has its own workspace and lockfile and sets `publish = false`.
the root package excludes `differential/` from its published archive. parser
dependencies may contain unsafe code; they do not enter the library's dependency
graph or unsafe budget. the harness source itself forbids unsafe code.

## checks

```sh
cargo fmt --manifest-path differential/Cargo.toml --check
cargo clippy --manifest-path differential/Cargo.toml --release --locked --all-targets -- -D warnings
cargo test --manifest-path differential/Cargo.toml --release --locked
```
