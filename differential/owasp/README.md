# OWASP parity check

`tests/conformance.rs` tags every vector `upstream`, `deviation` or
`non_owasp`. `Check.java` runs the first two through the OWASP Java Encoder:
an upstream vector must equal its output, a deviation must differ, and a
`JsFragmentGuards` deviation must differ only where java `\xHH`-escapes a
character that variant lists. a `non_owasp` vector must be for an encoder with
no OWASP method.

## run

needs a JDK 11 or later; ci does not run it. from the repository root:

```sh
curl -sSfO https://repo1.maven.org/maven2/org/owasp/encoder/encoder/1.5.0/encoder-1.5.0.jar
rm -f vectors.tsv
CONFORMANCE_EXPORT="$PWD/vectors.tsv" cargo test --test conformance
java -cp encoder-1.5.0.jar differential/owasp/Check.java vectors.tsv
```

a second argument writes each vector's java output, sorted, to that file, for
comparing two encoder versions.
