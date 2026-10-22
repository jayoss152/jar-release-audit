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
}
