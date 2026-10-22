package io.github.jarreleaseaudit;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ReportIO {
    private ReportIO() { }
    static Report read(Path path) throws IOException { return parse(Documents.read(path, 1048576)); }
    static Report parse(String text) throws IOException {
        try {
            Map<?, ?> root = object(Json.parse(text), "schemaVersion", "complete", "entriesScanned", "summary", "findings", "issues");
            if (integer(root.get("schemaVersion")) != 2) throw invalid();
            int entries = integer(root.get("entriesScanned"));
            if (!(root.get("complete") instanceof Boolean complete)) throw invalid();
            List<Finding> findings = new ArrayList<>();
            Set<String> keys = new java.util.HashSet<>();
            for (Object item : list(root.get("findings"))) {
                Map<?, ?> f = object(item, "severity", "rule", "entry", "message");
                var rule = Rules.get(string(f.get("rule"), 80));
                var severity = Finding.Severity.valueOf(string(f.get("severity"), 10));
                if (severity != rule.severity()) throw invalid();
                String entry = string(f.get("entry"), 65535);
                string(f.get("message"), 4096); // Validate, but never trust imported prose.
                if (!keys.add(rule.id() + "\0" + entry)) throw invalid();
                findings.add(new Finding(severity, rule.id(), entry, rule.action()));
            }
            List<Report.Issue> issues = new ArrayList<>();
            for (Object item : list(root.get("issues"))) {
                Map<?, ?> issue = object(item, "code", "entry", "message");
                var code = Report.IssueCode.valueOf(string(issue.get("code"), 80));
                String entry = string(issue.get("entry"), 65535);
                string(issue.get("message"), 4096);
                issues.add(new Report.Issue(code, entry, Rules.issueAdvice(code)));
            }
            Report report = new Report(findings, issues, entries);
            if (complete != report.complete()) throw invalid();
            Map<?, ?> summary = object(root.get("summary"), "low", "medium", "high", "issues");
            if (integer(summary.get("low")) != report.count(Finding.Severity.LOW)
                    || integer(summary.get("medium")) != report.count(Finding.Severity.MEDIUM)
                    || integer(summary.get("high")) != report.count(Finding.Severity.HIGH)
                    || integer(summary.get("issues")) != issues.size()) throw invalid();
            return report;
        } catch (IllegalArgumentException | ArithmeticException e) { throw invalid(); }
    }
    static Map<?, ?> object(Object value, String... fields) throws IOException {
        if (!(value instanceof Map<?, ?> map) || !map.keySet().equals(Set.of(fields))) throw invalid();
        return map;
    }
    static List<?> list(Object value) throws IOException { if (value instanceof List<?> list) return list; throw invalid(); }
    static String string(Object value, int max) throws IOException { if (value instanceof String s && s.length() <= max) return s; throw invalid(); }
    static int integer(Object value) throws IOException {
        if (!(value instanceof BigDecimal n)) throw invalid();
        int result;
        try { result = n.intValueExact(); } catch (ArithmeticException e) { throw invalid(); }
        if (result < 0) throw invalid();
        return result;
    }
    private static IOException invalid() { return new IOException("Invalid or unsupported report structure"); }
}
