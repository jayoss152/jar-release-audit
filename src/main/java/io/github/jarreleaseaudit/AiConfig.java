package io.github.jarreleaseaudit;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;

final class AiConfig {
    private AiConfig() { }
    static AiClient.Options read(Path file) throws IOException {
        var value = ReportIO.object(Json.parse(Documents.read(file, 8192)), "schemaVersion", "endpoint", "model", "timeoutMillis");
        if (ReportIO.integer(value.get("schemaVersion")) != 1) throw new IOException("Unsupported local model config");
        try {
            return new AiClient.Options(URI.create(ReportIO.string(value.get("endpoint"), 256)),
                    ReportIO.string(value.get("model"), 80), ReportIO.integer(value.get("timeoutMillis")));
        } catch (IllegalArgumentException e) { throw new IOException("Unsupported local model configuration"); }
    }
}
