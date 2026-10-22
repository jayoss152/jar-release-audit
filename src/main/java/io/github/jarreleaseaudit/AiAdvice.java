package io.github.jarreleaseaudit;

import java.io.IOException;
import java.util.*;
import static io.github.jarreleaseaudit.Json.object;

/** Model prose remains untrusted; only catalog actions and existing citations are accepted. */
final class AiAdvice {
    record Item(List<String> evidenceIds, String actionId, String rationale) { Item { evidenceIds = List.copyOf(evidenceIds); } }
    record Advice(List<Item> items) { Advice { items = List.copyOf(items); } }
    private AiAdvice() { }
    static Advice parse(String text, AiEvidence.Bundle bundle) throws IOException {
        Map<?, ?> root = ReportIO.object(Json.parse(text), "kind", "advice");
        if (!"jar-release-audit-model-advice".equals(root.get("kind"))) throw invalid();
        Map<String, AiEvidence.Item> known = new HashMap<>();
        for (var item : bundle.evidence()) known.put(item.id(), item);
        List<?> values = ReportIO.list(root.get("advice"));
        if (values.size() > 100) throw invalid();
        Set<String> cited = new HashSet<>();
        List<Item> items = new ArrayList<>();
        for (Object value : values) {
            Map<?, ?> item = ReportIO.object(value, "evidenceIds", "actionId", "rationale");
            String action = ReportIO.string(item.get("actionId"), 80);
            String rationale = ReportIO.string(item.get("rationale"), 1000);
            if (rationale.isBlank() || rationale.chars().anyMatch(c -> Character.isISOControl(c) || Character.getType(c) == Character.FORMAT)) throw invalid();
            List<String> ids = new ArrayList<>();
            for (Object idValue : ReportIO.list(item.get("evidenceIds"))) {
                String id = ReportIO.string(idValue, 20);
                AiEvidence.Item evidence = known.get(id);
                if (evidence == null || !action.equals(evidence.actionId()) || !cited.add(id)) throw invalid();
                ids.add(id);
            }
            if (ids.isEmpty()) throw invalid();
            items.add(new Item(ids, action, rationale));
        }
        return new Advice(items);
    }
    static String json(Advice advice, AiEvidence.Bundle bundle) {
        List<Object> suggestions = new ArrayList<>();
        int covered = 0;
        for (var item : advice.items()) {
            var rule = Rules.all().stream().filter(r -> r.actionId().equals(item.actionId())).findFirst().orElseThrow();
            suggestions.add(object("evidenceIds", item.evidenceIds(), "actionId", rule.actionId(), "action", rule.action(),
                    "verification", rule.verify(), "reference", rule.reference(), "modelProvidedRationale", item.rationale()));
            covered += item.evidenceIds().size();
        }
        return Json.write(object("kind", "jar-release-audit-reviewed-advice", "advisoryOnly", true,
                "deterministicScanComplete", bundle.complete(), "addressedEvidence", covered, "totalEvidence", bundle.evidence().size(), "suggestions", suggestions));
    }
    private static IOException invalid() { return new IOException("Invalid model advice structure or citation"); }
}
