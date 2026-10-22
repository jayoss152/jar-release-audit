package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import java.io.*;
import java.util.HashSet;
import static org.junit.jupiter.api.Assertions.*;

class RulesTest {
    @Test void catalogHasUniqueActionsAndProvidesUserVisibleGuidance() {
        var ids = new HashSet<String>();
        var actions = new HashSet<String>();
        for (var rule : Rules.all()) {
            assertTrue(ids.add(rule.id())); assertTrue(actions.add(rule.actionId()));
            assertEquals(rule, Rules.get(rule.id()));
            assertFalse(rule.action().isBlank()); assertFalse(rule.verify().isBlank());
            assertTrue(rule.reference().startsWith("https://github.com/jayoss152/jar-release-audit/"));
        }
        var out = new ByteArrayOutputStream();
        assertEquals(0, Main.run(new String[] {"--list-rules"}, new PrintStream(out), System.err));
        for (String id : ids) assertTrue(out.toString().contains(id));
        assertThrows(IllegalArgumentException.class, () -> Rules.get("invented-rule"));
    }
    @Test void planReferencesEvidenceAndEscapesUntrustedArchiveNames() {
        var finding = new Finding(Finding.Severity.HIGH, "PRIVATE_KEY", "`</code><script>untrusted</script>", "ignored raw message");
        var report = new Report(java.util.List.of(finding), java.util.List.of(), 1);
        String plan = RemediationPlan.markdown(report);
        assertTrue(plan.contains("F00001")); assertTrue(plan.contains("remove") || plan.contains("Remove"));
        assertTrue(plan.contains("https://github.com/jayoss152/jar-release-audit/"));
        assertFalse(plan.contains("<script>")); assertFalse(plan.contains("ignored raw message"));
        assertTrue(plan.contains("not model output"));
        var incomplete = new Report(java.util.List.of(), java.util.List.of(new Report.Issue(Report.IssueCode.INVALID_TEXT, "x", "raw")), 1);
        assertTrue(RemediationPlan.markdown(incomplete).contains("INCOMPLETE"));
    }
    @Test void sarifPreservesLevelsEncodesLocationsAndShowsIncompleteInspection() throws Exception {
        var report = new Report(java.util.List.of(new Finding(Finding.Severity.HIGH, "PRIVATE_KEY", "lib.jar!/key space.pem", "untrusted message")),
                java.util.List.of(new Report.Issue(Report.IssueCode.INVALID_TEXT, "x", "untrusted error")), 2);
        String json = Sarif.render(report);
        assertTrue(Json.parse(json) instanceof java.util.Map);
        assertTrue(json.contains("\"version\":\"2.1.0\""));
        assertTrue(json.contains("\"level\":\"error\""));
        assertTrue(json.contains("key%20space.pem"));
        assertTrue(json.contains("\"executionSuccessful\":false"));
        assertTrue(json.contains("F00001")); assertFalse(json.contains("untrusted"));
    }
}
