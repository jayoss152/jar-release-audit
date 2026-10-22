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
    @Test void batchExportPartitionsLargeReportsWithoutPathsOrSilentTruncation() throws Exception {
        var findings = new java.util.ArrayList<Finding>();
        for (int i = 0; i < 205; i++) findings.add(new Finding(Finding.Severity.HIGH, "PRIVATE_KEY", "SYNTHETIC-PATH-" + i, "secret"));
        var report = new Report(findings, List.of(), 205);
        Path directory = temp.resolve("batches"); AiBatches.export(report, directory, 100);
        var ids = new java.util.HashSet<String>();
        for (int i = 1; i <= 3; i++) {
            Path file = directory.resolve(String.format(java.util.Locale.ROOT, "request-%03d.json", i));
            var bundle = AiEvidence.read(file, report);
            for (var item : bundle.evidence()) assertTrue(ids.add(item.id()));
            assertFalse(java.nio.file.Files.readString(file).contains("SYNTHETIC-PATH"));
        }
        assertEquals(205, ids.size());
        assertTrue(java.nio.file.Files.readString(directory.resolve("manifest.json")).contains("\"modelCallsPerformed\":0"));
        assertThrows(IOException.class, () -> AiBatches.export(report, directory, 100));
        assertThrows(IOException.class, () -> AiBatches.export(report, temp.resolve("too-many"), 1));
    }
    @Test void explicitCacheRevalidatesHitsWithoutAnotherNetworkRequest() throws Exception {
        var bundle = AiEvidence.from(sensitive());
        Path cache = temp.resolve("cache");
        try (var stub = new ModelStub()) {
            var first = AiCache.invoke(stub.options(), bundle, cache);
            assertEquals(first, AiCache.invoke(stub.options(), bundle, cache));
            assertEquals(1, stub.calls.get());
            Path entry;
            try (var files = java.nio.file.Files.list(cache)) { entry = files.findFirst().orElseThrow(); }
            assertFalse(java.nio.file.Files.readString(entry).contains("CANARY"));
            java.nio.file.Files.writeString(entry, "invalid cache");
            assertThrows(IOException.class, () -> AiCache.invoke(stub.options(), bundle, cache));
            assertEquals(1, stub.calls.get());
        }
    }
    @Test void explicitConfigCannotStoreCredentialsOrGrantConsent() throws Exception {
        try (var stub = new ModelStub()) {
            Path config = temp.resolve("local-model.json"), input = temp.resolve("scan.json");
            String json = Json.write(Json.object("schemaVersion", 1, "endpoint", stub.endpoint().toString(), "model", "synthetic-stub", "timeoutMillis", 5000));
            java.nio.file.Files.writeString(config, json); java.nio.file.Files.writeString(input, Main.json(ReportWorkflowTest.sample()));
            assertEquals(stub.endpoint(), AiConfig.read(config).endpoint());
            var sink = new java.io.PrintStream(new java.io.ByteArrayOutputStream());
            assertEquals(2, Main.run(new String[] {"--from-report", input.toString(), "--ai-config", config.toString(), "--ai-output", temp.resolve("not-created.json").toString()}, sink, sink));
            assertEquals(0, stub.calls.get());
            assertEquals(1, Main.run(new String[] {"--from-report", input.toString(), "--allow-ai", "--ai-config", config.toString(), "--ai-output", temp.resolve("advice.json").toString()}, sink, sink));
            assertEquals(1, stub.calls.get());
            java.nio.file.Files.writeString(config, json.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"apiKey\":\"not-allowed\""));
            assertThrows(IOException.class, () -> AiConfig.read(config));
        }
    }
}
