package io.github.jarreleaseaudit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

final class Documents {
    private Documents() { }
    static String read(Path path, int limit) throws IOException {
        if (!Files.isRegularFile(path)) throw new IOException("Expected a regular document");
        try (var in = Files.newInputStream(path)) {
            byte[] bytes = in.readNBytes(limit + 1);
            if (bytes.length > limit) throw new IOException("Document size limit");
            return ResourceText.decode(bytes);
        }
    }
    static void writeNew(Path path, String text) throws IOException {
        Files.writeString(path, text, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
