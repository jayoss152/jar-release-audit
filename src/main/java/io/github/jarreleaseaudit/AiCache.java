package io.github.jarreleaseaudit;

import java.io.IOException;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class AiCache {
    private AiCache() { }
    static AiAdvice.Advice invoke(AiClient.Options options, AiEvidence.Bundle bundle, Path directory) throws IOException {
        String key;
        try {
            String identity = options.endpoint() + "\n" + options.model() + "\n" + AiEvidence.json(bundle);
            key = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(identity.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException("Required SHA-256 unavailable"); }
        Files.createDirectories(directory);
        Path file = directory.resolve(key + ".json");
        if (Files.exists(file)) return AiAdvice.parse(Documents.read(file, 65536), bundle);
        var advice = AiClient.invoke(options, bundle);
        try { Documents.writeNew(file, AiAdvice.responseJson(advice) + "\n"); }
        catch (FileAlreadyExistsException e) { return AiAdvice.parse(Documents.read(file, 65536), bundle); }
        return advice;
    }
}
