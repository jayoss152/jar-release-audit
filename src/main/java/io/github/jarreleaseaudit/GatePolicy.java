package io.github.jarreleaseaudit;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

record GatePolicy(Set<String> failRules) {
    GatePolicy { failRules = Set.copyOf(failRules); }
    static GatePolicy read(Path path) throws IOException {
        var root = ReportIO.object(Json.parse(Documents.read(path, 8192)), "schemaVersion", "failRules");
        if (ReportIO.integer(root.get("schemaVersion")) != 1) throw new IOException("Unsupported gate policy");
        Set<String> rules = new HashSet<>();
        for (Object value : ReportIO.list(root.get("failRules"))) {
            String id = ReportIO.string(value, 80);
            try { Rules.get(id); } catch (IllegalArgumentException e) { throw new IOException("Unknown policy rule"); }
            if (!rules.add(id)) throw new IOException("Duplicate policy rule");
        }
        return new GatePolicy(rules);
    }
    boolean fails(List<Finding> findings) { return findings.stream().anyMatch(f -> failRules.contains(f.rule())); }
}
