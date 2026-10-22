package io.github.jarreleaseaudit;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

final class ReportDiff {
    private record Key(String rule, Finding.Severity severity, String entry) { }
    record Delta(List<Finding> added, List<Finding> resolved, int unchanged) { }
    private static Key key(Finding f) { return new Key(f.rule(), f.severity(), f.entry()); }
    static Delta compare(Report current, Report accepted) {
        if (!accepted.complete()) throw new IllegalArgumentException("Baseline must be complete");
        Set<Key> old = accepted.findings().stream().map(ReportDiff::key).collect(Collectors.toSet());
        Set<Key> now = current.findings().stream().map(ReportDiff::key).collect(Collectors.toSet());
        var added = current.findings().stream().filter(f -> !old.contains(key(f))).toList();
        var resolved = accepted.findings().stream().filter(f -> !now.contains(key(f))).toList();
        return new Delta(added, resolved, current.findings().size() - added.size());
    }
}
