import io.github.jarreleaseaudit.Main;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.regex.Pattern;
import java.util.zip.*;

/** A canned protocol stub, not an AI model. No weights, credentials or external requests. */
class ModelProtocolDemo {
    public static void main(String[] args) throws Exception {
        System.out.println("SYNTHETIC protocol stub demonstration: no real model is running.");
        Path directory = Path.of("target", "model-protocol-demo-" + UUID.randomUUID());
        Files.createDirectory(directory);
        Path artifact = directory.resolve("synthetic.jar"), request = directory.resolve("request.json");
        try (var zip = new ZipOutputStream(Files.newOutputStream(artifact))) {
            var entry = new ZipEntry("application.properties");
            entry.setTimeLocal(java.time.LocalDateTime.of(1980, 1, 1, 0, 0));
            zip.putNextEntry(entry); zip.write("password=synthetic-not-a-real-secret\n".getBytes(StandardCharsets.UTF_8)); zip.closeEntry();
        }
        ByteArrayOutputStream capture = new ByteArrayOutputStream();
        PrintStream sink = new PrintStream(capture, true, StandardCharsets.UTF_8);
        if (Main.run(new String[] {"--ai-export", request.toString(), artifact.toString()}, sink, sink) != 1)
            throw new IllegalStateException("Synthetic finding was not preserved during offline export");
        var matcher = Pattern.compile("\"requestId\":\"([0-9a-f-]{36})\"").matcher(Files.readString(request));
        if (!matcher.find()) throw new IllegalStateException("Missing request identifier");
        String advice = "{\"kind\":\"jar-release-audit-model-advice\",\"requestId\":\"" + matcher.group(1)
                + "\",\"advice\":[{\"evidenceIds\":[\"F00001\"],\"actionId\":\"externalize-credentials\",\"rationale\":\"Canned protocol fixture; review the credential finding.\"}]}";
        AtomicInteger calls = new AtomicInteger(); AtomicReference<String> payload = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            calls.incrementAndGet(); payload.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            String quoted = "\"" + advice.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
            byte[] response = ("{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\",\"content\":" + quoted + "}}]}").getBytes(StandardCharsets.UTF_8);
            try { exchange.sendResponseHeaders(200, response.length); exchange.getResponseBody().write(response); } finally { exchange.close(); }
        });
        server.start();
        try {
            String endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/chat/completions";
            List<String> options = new ArrayList<>(List.of("--ai-endpoint", endpoint, "--ai-model", "synthetic-protocol-stub", "--ai-request", request.toString(),
                    "--ai-output", directory.resolve("reviewed-advice.json").toString(), "--redact-paths", "--format", "json", artifact.toString()));
            if (Main.run(options.toArray(String[]::new), sink, sink) != 2 || calls.get() != 0)
                throw new IllegalStateException("Consent boundary failed");
            options.add("--allow-ai");
            if (Main.run(options.toArray(String[]::new), sink, sink) != 1 || calls.get() != 1)
                throw new IllegalStateException("Model advice changed the deterministic finding status");
            if (payload.get().contains("synthetic-not-a-real-secret") || payload.get().contains("application.properties") || payload.get().contains(directory.toString()))
                throw new IllegalStateException("Private fixture data crossed the model boundary");
            Path rawAdvice = directory.resolve("canned-response.json"); Files.writeString(rawAdvice, advice);
            if (Main.run(new String[] {"--ai-import", rawAdvice.toString(), "--ai-request", request.toString(), "--ai-output", directory.resolve("offline-reviewed.json").toString(), artifact.toString()}, sink, sink) != 1)
                throw new IllegalStateException("Offline advice replay changed the deterministic status");
        } finally { server.stop(0); sink.close(); }
        System.out.println("Verified synthetic model protocol: explicit consent, no source/path/secret payload, cited advice, unchanged audit exit 1.");
    }
}
