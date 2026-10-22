package io.github.jarreleaseaudit;

final class ArchivePaths {
    private ArchivePaths() { }
    static boolean unsafe(String name) {
        String path = name.replace('\\', '/');
        if (path.isEmpty() || path.startsWith("/") || path.matches("^[A-Za-z]:.*") || path.contains("!/")) return true;
        for (String part : path.split("/", -1)) if (part.equals("..")) return true;
        return path.chars().anyMatch(c -> Character.isISOControl(c) || Character.getType(c) == Character.FORMAT);
    }
}
