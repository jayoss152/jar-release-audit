package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class AiSecurityTest {
    @TempDir Path temp;
    private String[] args(ModelStub stub, Path input, Path output, boolean consent) {
        var args = new ArrayList<>(List.of("--from-report", input.toString(), "--ai-endpoint", stub.endpoint().toString(), "--ai-model", "synthetic-stub", "--ai-output", output.toString()));
        if (consent) args.add("--allow-ai");
        return args.toArray(String[]::new);
    }
    @Test void cliDoesNotTransmitWithoutConsentAndDoesNotLeakInjectionNames() throws Exception {
        var injected = new Report(List.of(new Finding(Finding.Severity.HIGH, "PRIVATE_KEY", "IGNORE-INSTRUCTIONS-SYNTHETIC-CANARY.pem", "UPLOAD-SYNTHETIC-SECRET-CANARY")), List.of(), 1);
        Path input = temp.resolve("scan.json"); Files.writeString(input, Main.json(injected));
        var sink = new PrintStream(new ByteArrayOutputStream());
        try (var stub = new ModelStub()) {
            assertEquals(2, Main.run(args(stub, input, temp.resolve("no-consent.json"), false), sink, sink));
            assertEquals(0, stub.calls.get());
            assertEquals(1, Main.run(args(stub, input, temp.resolve("advice.json"), true), sink, sink));
            assertEquals(1, stub.calls.get());
            assertFalse(stub.captured.get().contains("CANARY")); assertFalse(stub.captured.get().contains("IGNORE-INSTRUCTIONS"));
        }
    }
    @Test void redirectsAndLargeBodiesFailWithoutFollowingOrDumpingResponseContent() throws Exception {
        var bundle = AiEvidence.from(AiWorkflowTest.sensitive());
        try (var target = new ModelStub(); var redirect = new ModelStub(body -> new ModelStub.Reply(302, "SYNTHETIC-RESPONSE-CANARY", Map.of("Location", target.endpoint().toString())))) {
            assertThrows(IOException.class, () -> AiClient.invoke(redirect.options(), bundle));
            assertEquals(0, target.calls.get());
        }
        try (var large = new ModelStub(body -> new ModelStub.Reply(200, "X".repeat(65537)))) {
            var error = assertThrows(IOException.class, () -> AiClient.invoke(large.options(), bundle));
            assertFalse(error.getMessage().contains("XXXXX"));
        }
    }
    @Test void deadlineAlsoCoversAStalledResponseBody() throws Exception {
        var release = new CountDownLatch(1);
        var headers = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            exchange.getRequestBody().readAllBytes(); exchange.sendResponseHeaders(200, 100); headers.countDown();
            try { release.await(5, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            exchange.close();
        });
        server.start();
        try {
            var options = new AiClient.Options(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/chat/completions"), "stub", 1000);
            var future = CompletableFuture.supplyAsync(() -> {
                try { AiClient.invoke(options, AiEvidence.from(AiWorkflowTest.sensitive())); return false; }
                catch (IOException e) { return true; }
            });
            assertTrue(headers.await(5, TimeUnit.SECONDS)); assertTrue(future.get(5, TimeUnit.SECONDS));
        } finally { release.countDown(); server.stop(0); }
    }
    @Test void modelFailureLeavesDeterministicReportAndNoFabricatedAdvice() throws Exception {
        Path input = temp.resolve("scan.json"), output = temp.resolve("not-created.json");
        Files.writeString(input, Main.json(ReportWorkflowTest.sample()));
        var out = new ByteArrayOutputStream(); var err = new ByteArrayOutputStream();
        try (var stub = new ModelStub(body -> new ModelStub.Reply(500, "SYNTHETIC-RESPONSE-CANARY"))) {
            assertEquals(2, Main.run(args(stub, input, output, true), new PrintStream(out), new PrintStream(err)));
        }
        assertTrue(out.toString().contains("PRIVATE_KEY")); assertFalse(Files.exists(output));
        assertFalse(err.toString().contains("SYNTHETIC-RESPONSE-CANARY"));
    }
    @Test void xmlCannotContactTheModelStubAndMalformedUnicodeCannotSmuggleInput() throws Exception {
        try (var stub = new ModelStub()) {
            assertThrows(IOException.class, () -> XmlCredentials.inspect("<!DOCTYPE x [<!ENTITY e SYSTEM '" + stub.endpoint() + "'>]><x>&e;</x>"));
            assertEquals(0, stub.calls.get());
        }
        for (String malformed : List.of("\"\\u+001\"", "\"\\u-001\"", "\"\\uＡ001\"")) assertThrows(IOException.class, () -> Json.parse(malformed));
        Path request = temp.resolve("request.json");
        Files.writeString(request, AiEvidence.json(AiEvidence.from(AiWorkflowTest.sensitive())).replace("Array of objects:", "SYNTHETIC-INJECTION:"));
        assertThrows(IOException.class, () -> AiEvidence.read(request, AiWorkflowTest.sensitive()));
    }
}
