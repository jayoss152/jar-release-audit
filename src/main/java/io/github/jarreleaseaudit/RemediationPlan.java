package io.github.jarreleaseaudit;

import java.util.Comparator;

final class RemediationPlan {
    private RemediationPlan() { }
    static String markdown(Report report) {
        StringBuilder out = new StringBuilder("# Deterministic remediation plan\n\nThis is reviewed rule guidance, not model output.\n\nScan: ")
                .append(report.complete() ? "COMPLETE" : "INCOMPLETE").append(". Findings: ").append(report.findings().size()).append(".\n");
        var evidence = Evidence.from(report);
        for (var rule : Rules.all().stream().sorted(Comparator.comparing(Rules.Rule::severity).reversed().thenComparing(Rules.Rule::id)).toList()) {
            var matches = evidence.stream().filter(e -> e.finding().rule().equals(rule.id())).toList();
            if (matches.isEmpty()) continue;
            out.append("\n## ").append(rule.id()).append(" [").append(rule.severity()).append("]\n\n")
                    .append(rule.action()).append("\n\nVerify: ").append(rule.verify()).append("\n\nEvidence:\n");
            for (var match : matches) out.append("- ").append(match.id()).append(": ").append(code(match.finding().entry())).append('\n');
            out.append("\nReference: ").append(rule.reference()).append('\n');
        }
        if (!report.complete()) {
            out.append("\n## Incomplete inspection\n");
            for (var issue : report.issues()) out.append("\n- ").append(issue.code()).append(": ").append(code(issue.entry()))
                    .append(" — ").append(Rules.issueAdvice(issue.code())).append('\n');
        }
        return out.append("\nReview each change and test the final release. This audit cannot prevent decompilation or prove absence of secrets.\n").toString();
    }
    static String code(String text) {
        return "`" + Main.quote(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "&#96;") + "`";
    }
}
