package io.github.jarreleaseaudit;

import java.util.LinkedHashMap;
import java.util.Map;

final class SharedReport {
    private SharedReport() { }
    static Report redact(Report report) {
        Map<String, String> aliases = new LinkedHashMap<>();
        var findings = report.findings().stream().map(f -> new Finding(f.severity(), f.rule(),
                alias(aliases, f.entry()), Rules.get(f.rule()).action())).toList();
        var issues = report.issues().stream().map(i -> new Report.Issue(i.code(), alias(aliases, i.entry()), Rules.issueAdvice(i.code()))).toList();
        return new Report(findings, issues, report.entriesScanned());
    }
    private static String alias(Map<String, String> aliases, String entry) {
        return aliases.computeIfAbsent(entry, ignored -> "entry-" + (aliases.size() + 1));
    }
}
