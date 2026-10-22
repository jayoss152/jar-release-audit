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
}
