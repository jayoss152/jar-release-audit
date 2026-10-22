package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.jarreleaseaudit.Fixtures.*;

class ArchiveBoundaryTest {
    @TempDir Path temp;
    @Test void unsafePathsAreIncompleteAtBothLevels() throws Exception {
        for (String path : new String[] {"../secret.txt", "/absolute.txt", "C:drive.txt", "a/../b", "a!/b", "bad\u001b.txt"}) {
            var report = new JarScanner().scan(jar(temp, Map.of(path, bytes("x"))));
            assertFalse(report.complete(), path);
            assertEquals(Report.IssueCode.PATH_INVALID, report.issues().get(0).code());
            assertFalse(new JarScanner().scan(jar(temp, Map.of("lib.jar", zip(Map.of(path, bytes("x")))))).complete());
        }
        assertTrue(new JarScanner().scan(jar(temp, Map.of("normal/file.txt", bytes("x")))).complete());
    }
    @Test void archiveMagicFindsDisguisedNestedContent() throws Exception {
        var report = new JarScanner().scan(jar(temp, Map.of("payload.bin", zip(Map.of("Hidden.java", bytes("class Hidden {}"))))));
        assertTrue(report.complete());
        assertEquals("payload.bin!/Hidden.java", report.findings().get(0).entry());
        assertTrue(new JarScanner().scan(jar(temp, Map.of("image.bin", new byte[] {(byte) 0x89, 'P', 'N', 'G'}))).findings().isEmpty());
        var limited = new JarScanner(new JarScanner.Limits(10000, 10000, 10000, 100, 0));
        assertFalse(limited.scan(jar(temp, Map.of("payload.dat", zip(Map.of())))).complete());
    }
    @Test void dataDescriptorPayloadMustAgreeWithCentralDirectory() throws Exception {
        for (int field : new int[] {16, 20, 24}) {
            byte[] nested = zip(Map.of("config.txt", bytes("safe content")));
            for (int i = 0; i + 46 < nested.length; i++) {
                if (nested[i] == 'P' && nested[i + 1] == 'K' && nested[i + 2] == 1 && nested[i + 3] == 2) {
                    nested[i + field] ^= 1;
                    break;
                }
            }
            var report = new JarScanner().scan(jar(temp, Map.of("nested.jar", nested)));
            assertFalse(report.complete());
            assertEquals(Report.IssueCode.ARCHIVE_INTEGRITY, report.issues().get(0).code());
        }
    }
    @Test void deadlineAndCancellationAreExplicitAndPreserveInterrupts() throws Exception {
        Path input = jar(temp, Map.of("file.txt", bytes("safe")));
        var clock = new java.util.concurrent.atomic.AtomicLong();
        var scanner = new JarScanner(JarScanner.Limits.defaults(), 1, () -> clock.addAndGet(2000000));
        assertEquals(Report.IssueCode.SCAN_TIME_LIMIT, scanner.scan(input).issues().get(0).code());
        Thread.currentThread().interrupt();
        try {
            assertEquals(Report.IssueCode.SCAN_CANCELLED, new JarScanner().scan(input).issues().get(0).code());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
    }
}
