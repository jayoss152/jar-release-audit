package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.io.*;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ReportWorkflowTest {
    @TempDir Path temp;
    static Report sample() { return new Report(List.of(new Finding(Finding.Severity.HIGH, "PRIVATE_KEY", "keys/private.pem", "untrusted prose")), List.of(), 1); }
    @Test void reportImportValidatesConsistencyAndDropsUntrustedProse() throws Exception {
        String original = Main.json(sample());
        var imported = ReportIO.parse(original);
        assertEquals("PRIVATE_KEY", imported.findings().get(0).rule());
        assertFalse(Main.json(imported).contains("untrusted prose"));
        for (String malformed : List.of(original.replace("\"schemaVersion\":2", "\"schemaVersion\":99"),
                original.replace("\"high\":1", "\"high\":0"), original.replace("\"complete\":true", "\"complete\":false"),
                original.replace("\"HIGH\"", "\"LOW\""))) assertThrows(IOException.class, () -> ReportIO.parse(malformed));
        Path report = temp.resolve("report.json"); Files.writeString(report, original);
        assertEquals(1, Main.run(new String[] {"--from-report", report.toString(), "--format", "plan"}, new PrintStream(new ByteArrayOutputStream()), System.err));
        Files.writeString(report, " ".repeat(1048577));
        assertThrows(IOException.class, () -> ReportIO.read(report));
    }
    @Test void baselinesGateOnlyNewFindingsAndNeverHideIncompleteInspection() throws Exception {
        Report old = sample();
        var newFinding = new Finding(Finding.Severity.MEDIUM, "SOURCE_FILE", "New.java", "fixed");
        var current = new Report(List.of(old.findings().get(0), newFinding), List.of(), 2);
        var delta = ReportDiff.compare(current, old);
        assertEquals(List.of(newFinding), delta.added()); assertEquals(1, delta.unchanged());
        assertEquals(old.findings(), ReportDiff.compare(new Report(List.of(), List.of(), 1), old).resolved());
        Path baseline = temp.resolve("accepted.json"), input = temp.resolve("current.json");
        Files.writeString(baseline, Main.json(old)); Files.writeString(input, Main.json(old));
        var out = new ByteArrayOutputStream();
        assertEquals(0, Main.run(new String[] {"--from-report", input.toString(), "--baseline", baseline.toString()}, new PrintStream(out), System.err));
        assertTrue(out.toString().contains("PRIVATE_KEY"));
        Files.writeString(input, Main.json(current));
        assertEquals(1, Main.run(new String[] {"--from-report", input.toString(), "--baseline", baseline.toString()}, new PrintStream(new ByteArrayOutputStream()), System.err));
        var incomplete = new Report(old.findings(), List.of(new Report.Issue(Report.IssueCode.INVALID_TEXT, "x", "fixed")), 2);
        Files.writeString(input, Main.json(incomplete));
        assertEquals(2, Main.run(new String[] {"--from-report", input.toString(), "--baseline", baseline.toString(), "--fail-on", "none"}, new PrintStream(new ByteArrayOutputStream()), System.err));
    }
    @Test void sharedReportsRemovePathsAndRawMessagesAcrossFormats() throws Exception {
        var report = new Report(List.of(new Finding(Finding.Severity.HIGH, "PRIVATE_KEY", "SYNTHETIC-PATH-CANARY.pem", "SYNTHETIC-PROSE-CANARY")),
                List.of(new Report.Issue(Report.IssueCode.INVALID_TEXT, "SYNTHETIC-PATH-CANARY.pem", "SYNTHETIC-PROSE-CANARY")), 1);
        var shared = SharedReport.redact(report);
        assertEquals(shared.findings().get(0).entry(), shared.issues().get(0).entry());
        for (String output : List.of(Main.json(shared), RemediationPlan.markdown(shared), Sarif.render(shared))) {
            assertFalse(output.contains("CANARY")); assertTrue(output.contains("entry-1"));
        }
        assertFalse(shared.complete()); assertEquals(report.count(Finding.Severity.HIGH), shared.count(Finding.Severity.HIGH));
    }
    @Test void explicitGatePoliciesChangeOnlyFailureSelectionAndCannotAcceptIncompleteScans() throws Exception {
        Path policy = temp.resolve("policy.json"), input = temp.resolve("scan.json");
        Files.writeString(policy, "{\"schemaVersion\":1,\"failRules\":[\"SOURCE_FILE\"]}");
        Files.writeString(input, Main.json(sample()));
        var sink = new PrintStream(new ByteArrayOutputStream());
        assertEquals(0, Main.run(new String[] {"--from-report", input.toString(), "--policy", policy.toString()}, sink, sink));
        assertEquals(2, Main.run(new String[] {"--from-report", input.toString(), "--policy", policy.toString(), "--fail-on", "none"}, sink, sink));
        Files.writeString(policy, "{\"schemaVersion\":1,\"failRules\":[\"PRIVATE_KEY\"]}");
        assertEquals(1, Main.run(new String[] {"--from-report", input.toString(), "--policy", policy.toString()}, sink, sink));
        Files.writeString(input, Main.json(new Report(sample().findings(), List.of(new Report.Issue(Report.IssueCode.INVALID_TEXT, "x", "fixed")), 1)));
        Files.writeString(policy, "{\"schemaVersion\":1,\"failRules\":[]}");
        assertEquals(2, Main.run(new String[] {"--from-report", input.toString(), "--policy", policy.toString()}, sink, sink));
        Files.writeString(policy, "{\"schemaVersion\":1,\"failRules\":[\"invented\"]}");
        assertThrows(IOException.class, () -> GatePolicy.read(policy));
    }
}
