package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.List;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.*;

class AiWorkflowTest {
    @TempDir Path temp;
    static Report sensitive() {
        return new Report(List.of(new Finding(Finding.Severity.HIGH, "PRIVATE_KEY", "SYNTHETIC-PATH-CANARY.pem", "SYNTHETIC-SECRET-CANARY")),
                List.of(new Report.Issue(Report.IssueCode.INVALID_TEXT, "SYNTHETIC-OTHER-PATH", "SYNTHETIC-ERROR-CANARY")), 2);
    }
    @Test void exportedModelEvidenceContainsOnlyAllowListedFields() throws Exception {
        String payload = AiEvidence.json(AiEvidence.from(sensitive()));
        assertFalse(payload.contains("CANARY")); assertFalse(payload.contains("SYNTHETIC"));
        assertTrue(payload.contains("F00001")); assertTrue(payload.contains("PRIVATE_KEY"));
        assertTrue(payload.contains("\"scanComplete\":false")); assertTrue(payload.contains("INVALID_TEXT"));
        assertTrue(Json.parse(payload) instanceof java.util.Map);
        var tooMany = new Report(java.util.Collections.nCopies(201, sensitive().findings().get(0)), List.of(), 201);
        assertThrows(IOException.class, () -> AiEvidence.from(tooMany));
    }
    static String validAdvice(String requestId) { return "{\"kind\":\"jar-release-audit-model-advice\",\"requestId\":\"" + requestId + "\",\"advice\":[{\"evidenceIds\":[\"F00001\"],\"actionId\":\"remove-rotate-key\",\"rationale\":\"Prioritize key review.\"}]}"; }
    @Test void modelAdviceRequiresKnownCitationsAndActionsWithoutAuthorityOverTheScan() throws Exception {
        var bundle = AiEvidence.from(sensitive());
        String valid = validAdvice(bundle.requestId());
        var advice = AiAdvice.parse(valid, bundle);
        String reviewed = AiAdvice.json(advice, bundle);
        assertTrue(reviewed.contains("\"advisoryOnly\":true"));
        assertTrue(reviewed.contains("\"deterministicScanComplete\":false"));
        for (String bad : List.of(valid.replace("F00001", "F99999"), valid.replace("remove-rotate-key", "execute-command"),
                valid.replace("\"advice\":", "\"findings\":[],\"advice\":"), valid.replace("Prioritize key review.", "bad\\u001bmessage")))
            assertThrows(IOException.class, () -> AiAdvice.parse(bad, bundle));
        String html = AiAdvice.json(AiAdvice.parse(valid.replace("Prioritize key review.", "<script>not executable</script>"), bundle), bundle);
        assertFalse(html.contains("<script>"));
    }
    @Test void adviceIsBoundToTheOriginalRequestAndMatchingInventory() throws Exception {
        var bundle = AiEvidence.from(sensitive());
        Path request = temp.resolve("request.json"); java.nio.file.Files.writeString(request, AiEvidence.json(bundle));
        assertEquals(bundle, AiEvidence.read(request, sensitive()));
        assertThrows(IOException.class, () -> AiAdvice.parse(validAdvice(bundle.requestId()), AiEvidence.from(sensitive())));
        assertThrows(IOException.class, () -> AiEvidence.read(request, new Report(List.of(), List.of(), 0)));
    }
}
