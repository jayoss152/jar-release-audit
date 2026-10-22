package io.github.jarreleaseaudit;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.jarreleaseaudit.Json.object;

class AiClientTest {
    @Test void localTransportUsesSanitizedPayloadAndValidatesTheRealProtocol() throws Exception {
        var captured = new AtomicReference<String>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            captured.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            var root = (java.util.Map<?, ?>) Json.parse(captured.get());
            var user = (java.util.Map<?, ?>) ((java.util.List<?>) root.get("messages")).get(1);
            String requestId = (String) ((java.util.Map<?, ?>) Json.parse((String) user.get("content"))).get("requestId");
            byte[] response = Json.write(object("choices", java.util.List.of(object("finish_reason", "stop", "message", object("role", "assistant", "content", AiWorkflowTest.validAdvice(requestId)))))).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length); exchange.getResponseBody().write(response); exchange.close();
        });
        server.start();
        try {
            var options = new AiClient.Options(new URI("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/chat/completions"), "synthetic-protocol-stub", 5000);
            var advice = AiClient.invoke(options, AiEvidence.from(AiWorkflowTest.sensitive()));
            assertEquals(1, advice.items().size()); assertFalse(captured.get().contains("CANARY"));
            assertTrue(captured.get().contains("synthetic-protocol-stub"));
        } finally { server.stop(0); }
    }
    @Test void endpointsCannotUseExternalHostsCredentialsQueriesOrOtherPaths() {
        for (String endpoint : java.util.List.of("https://example.invalid/v1/chat/completions", "http://localhost:1234/v1/chat/completions",
                "http://user@127.0.0.1:1234/v1/chat/completions", "http://127.0.0.1:1234/v1/chat/completions?key=notallowed", "http://127.0.0.1:1234/other"))
            assertThrows(IllegalArgumentException.class, () -> new AiClient.Options(URI.create(endpoint), "stub", 1000));
    }
}
