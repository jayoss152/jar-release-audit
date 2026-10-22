package io.github.jarreleaseaudit;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import static io.github.jarreleaseaudit.Json.object;

final class AiBatches {
    private AiBatches() { }
    static void export(Report report, Path directory, int size) throws IOException {
        if (size < 1 || size > 200) throw new IOException("Invalid model batch size");
        var evidence = Evidence.from(report);
        int count = Math.max(1, (evidence.size() + size - 1) / size);
        if (count > 100) throw new IOException("Model batch count budget");
        Files.createDirectory(directory); // Existing directories are never reused or overwritten.
        List<Object> manifest = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            var part = evidence.subList(Math.min(i * size, evidence.size()), Math.min((i + 1) * size, evidence.size()));
            var bundle = AiEvidence.from(report, part);
            String name = String.format(Locale.ROOT, "request-%03d.json", i + 1);
            Documents.writeNew(directory.resolve(name), AiEvidence.json(bundle) + "\n");
            manifest.add(object("file", name, "requestId", bundle.requestId(), "evidenceCount", part.size()));
        }
        Documents.writeNew(directory.resolve("manifest.json"), Json.write(object("completeExport", true, "modelCallsPerformed", 0,
                "totalEvidence", evidence.size(), "batches", manifest)) + "\n");
    }
}
