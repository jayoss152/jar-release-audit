package io.github.jarreleaseaudit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

final class Fixtures {
    static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    static byte[] zip(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (var e : entries.entrySet()) { zip.putNextEntry(new ZipEntry(e.getKey())); zip.write(e.getValue()); zip.closeEntry(); }
        }
        return out.toByteArray();
    }
    static Path jar(Path dir, Map<String, byte[]> entries) throws IOException {
        Path path = Files.createTempFile(dir, "synthetic-", ".jar");
        Files.write(path, zip(entries));
        return path;
    }
}
