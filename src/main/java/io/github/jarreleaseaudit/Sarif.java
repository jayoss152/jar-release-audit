package io.github.jarreleaseaudit;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import static io.github.jarreleaseaudit.Json.object;

final class Sarif {
    private Sarif() { }
    static String render(Report report) {
        List<Object> rules = new ArrayList<>(), results = new ArrayList<>(), notifications = new ArrayList<>();
        for (var rule : Rules.all()) rules.add(object("id", rule.id(), "shortDescription", object("text", rule.action()), "helpUri", rule.reference()));
        for (var evidence : Evidence.from(report)) {
            Finding f = evidence.finding();
            String uri;
            try { uri = new URI(null, null, f.entry(), null).toASCIIString(); }
            catch (URISyntaxException e) { uri = evidence.id(); }
            String level = switch (f.severity()) { case HIGH -> "error"; case MEDIUM -> "warning"; case LOW -> "note"; };
            results.add(object("ruleId", f.rule(), "level", level,
                    "message", object("text", evidence.id() + ": " + Rules.get(f.rule()).action()),
                    "locations", List.of(object("physicalLocation", object("artifactLocation", object("uri", uri))))));
        }
        for (var issue : report.issues()) notifications.add(object("level", "error", "message", object("text", issue.code() + ": " + Rules.issueAdvice(issue.code()))));
        return Json.write(object("version", "2.1.0", "$schema", "https://json.schemastore.org/sarif-2.1.0.json", "runs", List.of(object(
                "tool", object("driver", object("name", "JAR Release Audit", "informationUri", "https://github.com/jayoss152/jar-release-audit", "rules", rules)),
                "invocations", List.of(object("executionSuccessful", report.complete(), "toolExecutionNotifications", notifications)), "results", results))));
    }
}
