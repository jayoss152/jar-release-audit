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
}
