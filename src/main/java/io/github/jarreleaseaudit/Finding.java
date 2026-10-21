package io.github.jarreleaseaudit;

/** Evidence uses fixed descriptions and archive entry names, never matched values. */
public record Finding(Severity severity, String rule, String entry, String message) {
    public enum Severity { LOW, MEDIUM, HIGH }
}
