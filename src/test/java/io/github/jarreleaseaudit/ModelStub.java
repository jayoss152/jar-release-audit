package io.github.jarreleaseaudit;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.*;
import static io.github.jarreleaseaudit.Json.object;

/** Synthetic protocol service only; never represents model-quality evaluation. */
final class ModelStub implements AutoCloseable {
    record Reply(int status, String body, Map<String, String> headers) { Reply(int status, String body) { this(status, body, Map.of()); } }
    interface Responder { Reply respond(String body) throws Exception; }
    final AtomicInteger calls = new AtomicInteger();
    final AtomicReference<String> captured = new AtomicReference<>();
    private final HttpServer server;
    ModelStub() throws Exception { this(ModelStub::normal); }
    ModelStub(Responder responder) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            calls.incrementAndGet();
            String input = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8); captured.set(input);
            Reply reply;
            try { reply = responder.respond(input); } catch (Exception e) { reply = new Reply(500, "synthetic stub failure"); }
            reply.headers().forEach((k,v) -> exchange.getResponseHeaders().set(k,v));
            byte[] bytes = reply.body().getBytes(StandardCharsets.UTF_8);
            try { exchange.sendResponseHeaders(reply.status(), bytes.length); exchange.getResponseBody().write(bytes); } finally { exchange.close(); }
        });
        server.start();
    }
    URI endpoint() { return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/chat/completions"); }
    AiClient.Options options() { return new AiClient.Options(endpoint(), "synthetic-stub", 5000); }
    static String requestId(String body) throws Exception {
        var root = (Map<?, ?>) Json.parse(body);
        var user = (Map<?, ?>) ((List<?>) root.get("messages")).get(1);
        return (String) ((Map<?, ?>) Json.parse((String) user.get("content"))).get("requestId");
    }
    static Reply normal(String body) throws Exception {
        return new Reply(200, Json.write(object("choices", List.of(object("finish_reason", "stop", "message", object("role", "assistant", "content", AiWorkflowTest.validAdvice(requestId(body))))))));
    }
    @Override public void close() { server.stop(0); }
}
