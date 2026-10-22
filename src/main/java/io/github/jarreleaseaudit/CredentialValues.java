package io.github.jarreleaseaudit;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Locale;

final class CredentialValues {
    private CredentialValues() { }
    static boolean key(String name) {
        String last = name.substring(name.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT).replace("_", "").replace("-", "");
        return last.matches("(?:.*(?:password|passwd|secret|token)|apikey|accesskey)");
    }
    static boolean json(String text) throws IOException { return walk(Json.parse(text)); }
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
