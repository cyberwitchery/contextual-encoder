# contextual-encoder

contextual output encoding for XSS defense, inspired by the
[OWASP Java Encoder](https://owasp.org/owasp-java-encoder/).

## disclaimer

contextual-encoder is an independent Rust crate for contextual output encoding for XSS
defense. Its API and security model are inspired by the OWASP Java Encoder.
This project is not affiliated with, endorsed by, or maintained by the OWASP
Foundation.

## what this is

a zero-dependency Rust library that encodes untrusted strings for safe
embedding in HTML, JavaScript, CSS, and URI contexts. each function targets a
specific output context so that only the necessary characters are encoded.

## what this is not

- **not a sanitizer.** encoding `<script>` as `&lt;script&gt;` makes it
  display safely — it does not remove it. if you need to allow a subset of
  HTML, use a dedicated sanitizer.
- **not a validator.** tag names, attribute names, event handler names, and
  URL schemes must be validated separately. encoding cannot make arbitrary
  names safe.
- **not a full URL encoder.** `for_uri_component` encodes a component, not
  a full URL. a `javascript:` URL will be percent-encoded but still execute.
  always validate the scheme before embedding untrusted URLs.

## supported contexts

### HTML / XML

| function | safe for | notes |
|----------|----------|-------|
| `for_html` | text content + quoted attributes | most conservative — safe default |
| `for_html_content` | text content only | does not encode quotes |
| `for_html_attribute` | quoted attributes only | does not encode `>` |
| `for_html_unquoted_attribute` | unquoted attribute values | most aggressive |

### JavaScript

| function | safe for | notes |
|----------|----------|-------|
| `for_javascript` | all JS contexts (universal) | hex-encodes quotes for HTML safety |
| `for_javascript_attribute` | HTML event attributes | does not escape `/` |
| `for_javascript_block` | `<script>` blocks | uses backslash quote escapes |
| `for_javascript_source` | standalone .js / JSON files | minimal encoding |

### CSS

| function | safe for | notes |
|----------|----------|-------|
| `for_css_string` | quoted CSS string values | hex escapes with separator spaces |
| `for_css_url` | CSS `url()` values | like `for_css_string` but parens pass through |

### URI

| function | safe for | notes |
|----------|----------|-------|
| `for_uri_component` | query params, path segments | RFC 3986 percent-encoding |

## unsupported / dangerous contexts

the following contexts are **intentionally not supported** because encoding
cannot make them safe:

- **raw tag names** — validate against a whitelist
- **raw attribute names** — validate against a whitelist
- **event handler names** — validate against a whitelist
- **raw JavaScript expressions** — no encoder can make `eval()` safe
- **raw CSS selectors / properties** — validate structure separately
- **HTML comments** — vendor-specific extensions (e.g., IE conditional
  comments) make safe encoding impractical
- **full untrusted URLs** — encoding preserves `javascript:` schemes;
  validate the URL scheme and structure first

## examples

```rust
use contextual_encoder::{for_html, for_javascript, for_css_string, for_uri_component};

let user_input = "<script>alert('xss')</script>";

// HTML text content or quoted attribute
let safe = for_html(user_input);
assert_eq!(safe, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");

// JavaScript string literal
let safe = for_javascript(user_input);
// quotes are hex-encoded, / is escaped to prevent </script>
assert!(safe.contains(r"<\/script>"));

// CSS string value
let safe = for_css_string(user_input);
assert!(safe.contains(r"\3c"));

// URI component
let safe = for_uri_component(user_input);
assert!(safe.contains("%3C"));
```

### writer-based API

every `for_*` function has a `write_*` counterpart that writes to any
`std::fmt::Write` implementor:

```rust
use contextual_encoder::write_html;

let mut buf = String::new();
write_html(&mut buf, "safe & sound").unwrap();
assert_eq!(buf, "safe &amp; sound");
```

## security model

this is a **contextual output encoder**, not a sanitizer. it prevents
cross-site scripting by encoding output for specific contexts.

### caveats

**grave accent (`` ` ``):** unpatched internet explorer treats the grave
accent as an attribute delimiter. `for_html_unquoted_attribute` encodes it
as `&#96;`, but numeric character references decode back to the original
character, so this is not a complete fix. the safest mitigation is to avoid
unquoted attributes entirely.

**template literals:** the JavaScript encoders do **not** encode backticks.
never embed untrusted data directly in ES2015+ template literals. instead,
encode into a regular JavaScript string variable and reference it from the
template literal:

```js
// WRONG — vulnerable:
// `Hello ${unsafeInput}`

// RIGHT:
var x = '<contextual_encoder::for_javascript output>';
`Hello ${x}`
```

**full URLs:** `for_uri_component` encodes a URI component, not an entire URL.
a `javascript:alert(1)` URL will be properly percent-encoded but will still
execute. always validate the URL scheme before embedding.

**HTML comments:** no HTML comment encoder is provided. HTML comments have
vendor-specific extensions (e.g., `<!--[if IE]>`) that make safe encoding
impractical. never embed untrusted data in HTML comments.

## differences from OWASP Java Encoder

### exact matches
- encoding rules for `for_html`, `for_html_content`, `for_html_attribute`,
  `for_html_unquoted_attribute`
- JavaScript encoding rules across all four contexts
- CSS hex escape format with trailing space separator
- URI component percent-encoding of UTF-8 bytes
- security caveats (grave accent, template literals, HTML comments, full URLs)

### intentional deviations
- **surrogate handling:** Java's `char[]` can contain invalid surrogate pairs
  which the Java encoder replaces with space or dash. Rust `str` is guaranteed
  valid UTF-8, so surrogates cannot appear. supplementary plane characters
  (U+10000+) are valid and pass through or are encoded normally.
- **`for_html` uses `&#34;` and `&#39;`** for quote encoding rather than
  `&quot;` — both are valid HTML and the numeric form is shorter.
- **C1 control handling in CSS:** the Java encoder may encode C1 controls
  (U+0080-U+009F) in CSS contexts. this crate currently does not encode them
  in CSS, only in HTML/XML contexts. this is a conservative choice that may
  be revisited.
- **`-` (hyphen) in JavaScript:** the Java encoder may escape `-` as `\-` in
  some JavaScript contexts to prevent `-->` sequences. this crate does not
  encode `-` in JavaScript. the `-->` sequence inside a JS string literal is
  harmless because the HTML parser does not scan string literal contents.

### phase 2 (not yet implemented)
- XML-specific aliases (`for_xml`, `for_xml_content`, `for_xml_attribute`)
- `for_xml_comment`
- XML 1.1 variants (`for_xml11`, `for_xml11_content`, `for_xml11_attribute`)
- `for_cdata`
- `for_java` (Java string literal encoding)

## license

MIT
