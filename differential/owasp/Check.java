import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.owasp.encoder.Encode;

public class Check {
    static final Map<String, String> METHODS = Map.ofEntries(
            Map.entry("html", "forHtml"),
            Map.entry("html_content", "forHtmlContent"),
            Map.entry("html_attribute", "forHtmlAttribute"),
            Map.entry("html_unquoted_attribute", "forHtmlUnquotedAttribute"),
            Map.entry("xml", "forXml"),
            Map.entry("xml_content", "forXmlContent"),
            Map.entry("xml_attribute", "forXmlAttribute"),
            Map.entry("xml_comment", "forXmlComment"),
            Map.entry("cdata", "forCDATA"),
            Map.entry("xml11", "forXml11"),
            Map.entry("xml11_content", "forXml11Content"),
            Map.entry("xml11_attribute", "forXml11Attribute"),
            Map.entry("javascript", "forJavaScript"),
            Map.entry("javascript_attribute", "forJavaScriptAttribute"),
            Map.entry("javascript_block", "forJavaScriptBlock"),
            Map.entry("javascript_source", "forJavaScriptSource"),
            Map.entry("css_string", "forCssString"),
            Map.entry("css_url", "forCssUrl"),
            Map.entry("uri_component", "forUriComponent"),
            Map.entry("json", "forJson"));

    static String unescape(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            if (s.startsWith("\\u{", i)) {
                int end = s.indexOf('}', i);
                out.appendCodePoint(Integer.parseInt(s.substring(i + 3, end), 16));
                i = end + 1;
            } else {
                out.append(s.charAt(i++));
            }
        }
        return out.toString();
    }

    static String escape(String s) {
        StringBuilder out = new StringBuilder();
        s.codePoints().forEach(cp -> {
            if (cp >= ' ' && cp <= '~' && cp != '\\') {
                out.append((char) cp);
            } else {
                out.append(String.format("\\u{%x}", cp));
            }
        });
        return out.toString();
    }

    // usage: java -cp encoder-<v>.jar Check.java vectors.tsv [java-outputs.tsv]
    public static void main(String[] args) throws Exception {
        int upstream = 0, deviation = 0, nonOwasp = 0, failed = 0;
        List<String> outputs = new ArrayList<>();
        for (String row : Files.readAllLines(Path.of(args[0]))) {
            String[] f = row.split("\t", -1);
            String tag = f[0], line = f[1], encoder = f[2].replaceFirst("^for_", "");
            if (tag.equals("non_owasp")) {
                nonOwasp++;
                continue;
            }
            String method = METHODS.get(encoder);
            if (method == null) {
                failed++;
                System.out.println("no OWASP method for " + encoder + " (line " + line + ")");
                continue;
            }
            String java = (String) Encode.class.getMethod(method, String.class)
                    .invoke(null, unescape(f[3]));
            boolean same = java.equals(unescape(f[4]));
            outputs.add(line + "\t" + encoder + "\t" + f[3] + "\t" + escape(java));
            if (tag.equals("upstream")) {
                upstream++;
            } else {
                deviation++;
            }
            if (same != tag.equals("upstream")) {
                failed++;
                System.out.println(tag + " line " + line + " " + encoder + "(" + f[3] + "): rust "
                        + f[4] + ", java " + escape(java));
            }
        }
        if (args.length > 1) {
            outputs.sort(null);
            Files.write(Path.of(args[1]), outputs);
        }
        System.out.println(upstream + " upstream, " + deviation + " deviation, " + nonOwasp
                + " non-OWASP, " + failed + " contradicted");
        System.exit(failed == 0 ? 0 : 1);
    }
}
