package io.github.jarreleaseaudit;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Small bounded RFC 8259 codec; rejects ambiguous duplicate keys and invalid Unicode. */
final class Json {
    private static final Pattern NUMBER = Pattern.compile("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?");
    private final String text;
    private int position, values;
    private Json(String text) { this.text = text; }
    static Object parse(String text) throws IOException {
        if (text.length() > 1_048_576) throw bad();
        Json parser = new Json(text);
        Object value = parser.value(0);
        parser.space();
        if (parser.position != text.length()) throw bad();
        return value;
    }
    private Object value(int depth) throws IOException {
        if (depth > 32 || ++values > 10000) throw bad();
        space();
        if (position >= text.length()) throw bad();
        char c = text.charAt(position);
        if (c == '"') return string();
        if (c == '{') {
            position++;
            Map<String, Object> result = new LinkedHashMap<>();
            space();
            if (take('}')) return result;
            do {
                space();
                String key = string();
                space();
                if (!take(':') || result.containsKey(key)) throw bad();
                result.put(key, value(depth + 1));
                space();
                if (take('}')) return result;
            } while (take(','));
            throw bad();
        }
        if (c == '[') {
            position++;
            List<Object> result = new ArrayList<>();
            space();
            if (take(']')) return result;
            do {
                result.add(value(depth + 1));
                space();
                if (take(']')) return result;
            } while (take(','));
            throw bad();
        }
        for (String word : List.of("true", "false", "null")) {
            if (text.startsWith(word, position)) {
                position += word.length();
                return word.equals("null") ? null : Boolean.valueOf(word);
            }
        }
        var matcher = NUMBER.matcher(text).region(position, text.length());
        if (!matcher.lookingAt() || matcher.end() - position > 128) throw bad();
        String number = text.substring(position, matcher.end());
        position = matcher.end();
        try { return new BigDecimal(number); } catch (NumberFormatException e) { throw bad(); }
    }
    private String string() throws IOException {
        if (!take('"')) throw bad();
        StringBuilder out = new StringBuilder();
        while (position < text.length()) {
            char c = text.charAt(position++);
            if (c == '"') {
                String value = out.toString();
                for (int i = 0; i < value.length(); i++) {
                    char u = value.charAt(i);
                    if (Character.isHighSurrogate(u)) {
                        if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) throw bad();
                    } else if (Character.isLowSurrogate(u)) throw bad();
                }
                return value;
            }
            if (c < 32) throw bad();
            if (c == '\\') {
                if (position >= text.length()) throw bad();
                c = text.charAt(position++);
                switch (c) {
                    case '"', '\\', '/' -> out.append(c);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (position + 4 > text.length()) throw bad();
                        try { out.append((char) Integer.parseInt(text.substring(position, position + 4), 16)); }
                        catch (NumberFormatException e) { throw bad(); }
                        position += 4;
                    }
                    default -> throw bad();
                }
            } else out.append(c);
        }
        throw bad();
    }
    private boolean take(char c) {
        if (position < text.length() && text.charAt(position) == c) { position++; return true; }
        return false;
    }
    private void space() { while (position < text.length() && " \r\n\t".indexOf(text.charAt(position)) >= 0) position++; }
    private static IOException bad() { return new IOException("Malformed, ambiguous or over-budget JSON"); }
    static String write(Object value) { return write(value, 0); }
    private static String write(Object value, int depth) {
        if (depth > 32) throw new IllegalArgumentException("JSON nesting limit");
        if (value == null) return "null";
        if (value instanceof String s) return Main.quote(s);
        if (value instanceof Boolean || value instanceof BigDecimal || value instanceof Integer || value instanceof Long) return value.toString();
        List<String> parts = new ArrayList<>();
        if (value instanceof Map<?, ?> map) {
            for (var e : map.entrySet()) parts.add(Main.quote((String) e.getKey()) + ":" + write(e.getValue(), depth + 1));
            return "{" + String.join(",", parts) + "}";
        }
        if (value instanceof List<?> list) {
            for (Object item : list) parts.add(write(item, depth + 1));
            return "[" + String.join(",", parts) + "]";
        }
        throw new IllegalArgumentException("Unsupported JSON value");
    }
}
