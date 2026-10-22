package io.github.jarreleaseaudit;

import java.io.IOException;
import java.util.regex.Pattern;

/** Bounded scalar inspection, not a general YAML loader; never resolves tags/aliases. */
final class YamlCredentials {
    private static final Pattern FIELD = Pattern.compile("^[ ]*(?:-[ ]+)?[\"']?([\\w.-]+)[\"']?[ ]*:[ ]*(.*)$");
    private YamlCredentials() { }
    static boolean inspect(String text) throws IOException {
        if (text.length() > 1_048_576) throw new IOException("YAML text limit");
        String[] lines = text.split("\\R", -1);
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].startsWith("\t")) throw new IOException("Unsupported YAML indentation");
            var match = FIELD.matcher(lines[i]);
            if (!match.matches() || !CredentialValues.key(match.group(1))) continue;
            String value = withoutComment(match.group(2)).strip();
            if (value.startsWith("|") || value.startsWith(">")) {
                if (!value.matches("[|>](?:[+-]?[1-9]?|[1-9][+-]?)")) throw new IOException("Unsupported YAML block header");
                int indent = indent(lines[i]);
                StringBuilder block = new StringBuilder();
                while (i + 1 < lines.length && (lines[i + 1].isBlank() || indent(lines[i + 1]) > indent))
                    block.append(lines[++i].strip()).append('\n');
                value = "\"" + block.toString().strip() + "\"";
            }
            if (JarScanner.literalValue(value)) return true;
        }
        return false;
    }
    private static int indent(String line) { int i = 0; while (i < line.length() && line.charAt(i) == ' ') i++; return i; }
    private static String withoutComment(String value) {
        char quote = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (quote == '"' && c == '\\') { i++; continue; }
            if (c == quote) quote = 0;
            else if (quote == 0 && (c == '"' || c == '\'')) quote = c;
            else if (quote == 0 && c == '#' && (i == 0 || Character.isWhitespace(value.charAt(i - 1)))) return value.substring(0, i);
        }
        return value;
    }
}
