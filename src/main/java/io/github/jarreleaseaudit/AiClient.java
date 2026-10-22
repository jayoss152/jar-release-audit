package io.github.jarreleaseaudit;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.Flow;
import static io.github.jarreleaseaudit.Json.object;

/** Opt-in local model transport. No credentials, proxies, redirects, tools or remote hosts. */
final class AiClient {
    record Options(URI endpoint, String model, long timeoutMillis) {
        Options {
            String host = endpoint.getHost();
            if (!"http".equals(endpoint.getScheme()) || !("127.0.0.1".equals(host) || "[::1]".equals(host) || "::1".equals(host))
                    || endpoint.getPort() < 1 || endpoint.getPort() > 65535 || endpoint.getRawUserInfo() != null
                    || endpoint.getRawQuery() != null || endpoint.getRawFragment() != null
                    || !"/v1/chat/completions".equals(endpoint.getRawPath())
                    || model == null || !model.matches("[A-Za-z0-9._:/-]{1,80}") || timeoutMillis < 100 || timeoutMillis > 60000)
                throw new IllegalArgumentException("Unsupported local model configuration");
        }
    }
    private AiClient() { }
    static AiAdvice.Advice invoke(Options options, AiEvidence.Bundle bundle) throws IOException {
        var proxy = new ProxySelector() {
            @Override public List<Proxy> select(URI uri) { return List.of(Proxy.NO_PROXY); }
            @Override public void connectFailed(URI uri, SocketAddress address, IOException e) { }
        };
        HttpClient client = HttpClient.newBuilder().proxy(proxy).followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofMillis(Math.min(options.timeoutMillis(), 3000))).build();
        String payload = Json.write(object("model", options.model(), "stream", false, "temperature", 0,
                "messages", List.of(object("role", "system", "content", AiEvidence.INSTRUCTIONS), object("role", "user", "content", AiEvidence.json(bundle)))));
        HttpRequest request = HttpRequest.newBuilder(options.endpoint()).timeout(Duration.ofMillis(options.timeoutMillis()))
                .header("Content-Type", "application/json; charset=utf-8").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload)).build();
        var future = client.sendAsync(request, ignored -> new BoundedBody());
        try {
            var response = future.get(options.timeoutMillis(), TimeUnit.MILLISECONDS);
            if (response.statusCode() != 200) throw new IOException("Local model returned an unsuccessful status");
            Object parsed = Json.parse(ResourceText.decode(response.body()));
            if (!(parsed instanceof Map<?, ?> root)) throw new IOException("Invalid local model response");
            var choices = ReportIO.list(root.get("choices"));
            if (choices.size() != 1 || !(choices.get(0) instanceof Map<?, ?> choice)
                    || !(choice.get("message") instanceof Map<?, ?> message)
                    || !"assistant".equals(message.get("role")) || message.get("tool_calls") != null
                    || message.get("function_call") != null || message.get("refusal") != null
                    || (choice.get("finish_reason") != null && !"stop".equals(choice.get("finish_reason"))))
                throw new IOException("Unsupported local model response envelope");
            return AiAdvice.parse(ReportIO.string(message.get("content"), 32768), bundle);
        } catch (InterruptedException e) {
            future.cancel(true); Thread.currentThread().interrupt(); throw new IOException("Local model request interrupted");
        } catch (ExecutionException | TimeoutException | IllegalArgumentException e) {
            future.cancel(true); throw new IOException("Local model request failed or exceeded its budget");
        }
    }
    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
        private Flow.Subscription subscription;
        private int bytes;
        @Override public CompletionStage<byte[]> getBody() { return delegate.getBody(); }
        @Override public void onSubscribe(Flow.Subscription s) { subscription = s; delegate.onSubscribe(s); }
        @Override public void onNext(List<ByteBuffer> buffers) {
            for (var buffer : buffers) {
                if (buffer.remaining() > 65536 - bytes) { subscription.cancel(); delegate.onError(new IOException("Model response byte limit")); return; }
                bytes += buffer.remaining();
            }
            delegate.onNext(buffers);
        }
        @Override public void onError(Throwable error) { delegate.onError(error); }
        @Override public void onComplete() { delegate.onComplete(); }
    }
}
