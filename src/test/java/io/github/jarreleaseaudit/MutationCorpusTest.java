package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.jarreleaseaudit.Fixtures.*;

class MutationCorpusTest {
    @TempDir Path temp;
    private void inspect(byte[] bytes) throws Exception {
        Path file = temp.resolve("mutated.jar"); Files.write(file, bytes);
        try {
            var report = new JarScanner(new JarScanner.Limits(131072, 32768, 65536, 50, 2), 1000).scan(file);
            assertTrue(report.entriesScanned() <= 50);
            assertEquals(report.issues().isEmpty(), report.complete());
            assertTrue(report.findings().size() <= report.entriesScanned() * Rules.all().size());
            assertTrue(Json.parse(Main.json(report)) instanceof Map);
        } catch (IOException expectedInvalidOuterArchive) { /* Explicit rejection is a valid result. */ }
    }
    @Test void seededZipMutationsNeverEscapeResourceOrReportInvariants() throws Exception {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            byte[] original = zip(Map.of("config.txt", bytes("safe content"), "Hello.java", bytes("class Hello {}")));
            Random random = new Random(0x4a4152);
            for (int i = 0; i < 150; i++) {
                byte[] mutated = original.clone();
                for (int j = 0; j < 1 + i % 4; j++) mutated[random.nextInt(mutated.length)] ^= (byte) (1 << random.nextInt(8));
                if (i % 3 == 0) mutated = Arrays.copyOf(mutated, random.nextInt(mutated.length));
                inspect(i % 2 == 0 ? mutated : zip(Map.of("nested.data", mutated)));
            }
        });
    }
    @Test void seededClassMutationsProduceFindingsOrExplicitIncompleteReports() throws Exception {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            byte[] original;
            try (var in = ClassMetadata.class.getResourceAsStream("ClassMetadata.class")) { original = Objects.requireNonNull(in).readAllBytes(); }
            Random random = new Random(0xc1a55);
            for (int i = 0; i < 100; i++) {
                byte[] mutated = original.clone();
                mutated[random.nextInt(mutated.length)] ^= (byte) (1 << random.nextInt(8));
                if (i % 5 == 0) mutated = Arrays.copyOf(mutated, random.nextInt(mutated.length));
                inspect(zip(Map.of("Sample.class", mutated)));
            }
        });
    }
}
