package io.github.jarreleaseaudit;

import java.util.List;

public record Report(List<Finding> findings, List<Issue> issues, int entriesScanned) {
    public Report {
        findings = List.copyOf(findings);
        issues = List.copyOf(issues);
    }

    public boolean complete() { return issues.isEmpty(); }

    public long count(Finding.Severity severity) { return findings.stream().filter(f -> f.severity() == severity).count(); }

    public enum IssueCode {
        ENTRY_COUNT_LIMIT, ENTRY_SIZE_LIMIT, EXPANDED_SIZE_LIMIT, NESTING_DEPTH_LIMIT,
        AMBIGUOUS_ENTRY, INVALID_CLASS, INVALID_TEXT, ARCHIVE_INTEGRITY, ENTRY_READ_ERROR, PATH_INVALID
    }

    public record Issue(IssueCode code, String entry, String message) { }
}
