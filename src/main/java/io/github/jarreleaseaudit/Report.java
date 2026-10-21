package io.github.jarreleaseaudit;

import java.util.List;

public record Report(List<Finding> findings, List<Issue> issues, int entriesScanned) {
    public Report {
        findings = List.copyOf(findings);
        issues = List.copyOf(issues);
    }

    public boolean complete() { return issues.isEmpty(); }

    public record Issue(String entry, String message) { }
}
