package io.github.jarreleaseaudit;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Properties;
import java.io.StringReader;

final class CredentialValues {
    private CredentialValues() { }
    static boolean key(String name) {
        String last = name.substring(name.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT).replace("_", "").replace("-", "");
        return last.matches("(?:.*(?:password|passwd|secret|token)|apikey|accesskey)");
    }
    static boolean json(String text) throws IOException { return walk(Json.parse(text)); }
    static boolean properties(String text) throws IOException {
        if (text.length() > 1_048_576) throw new IOException("Properties text limit");
        boolean[] found = {false};
        Properties parser = new Properties() {
            @Override public synchronized Object put(Object key, Object value) {
                String literal = (String) value;
                if (CredentialValues.key((String) key) && !literal.isEmpty()
                        && !literal.matches("\\$\\{[A-Za-z_][A-Za-z0-9_.-]*:?}")) found[0] = true;
                return super.put(key, value);
            }
        };
        try { parser.load(new StringReader(text)); }
        catch (IllegalArgumentException e) { throw new IOException("Malformed Properties escape"); }
        return found[0]; // Inspect every assignment, including subsequently overwritten values.
    }
    private static boolean walk(Object value) {
        if (value instanceof Map<?, ?> map) {
            for (var e : map.entrySet()) {
                if (key((String) e.getKey()) && sensitive(e.getValue())) return true;
                if (walk(e.getValue())) return true;
            }
        } else if (value instanceof List<?> list) return list.stream().anyMatch(CredentialValues::walk);
        return false;
    }
    private static boolean sensitive(Object value) {
        if (value == null) return false;
        if (value instanceof String s) return JarScanner.literalValue("\"" + s + "\"");
        if (value instanceof List<?> list) return list.stream().anyMatch(CredentialValues::sensitive);
        return !(value instanceof Map<?, ?>);
    }
}
