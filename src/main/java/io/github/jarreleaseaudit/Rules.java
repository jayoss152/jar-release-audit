package io.github.jarreleaseaudit;

import java.util.List;
import static io.github.jarreleaseaudit.Finding.Severity.*;

/** Reviewed deterministic guidance. No model call, source text or matched value is involved. */
public final class Rules {
    public record Rule(String id, Finding.Severity severity, String actionId, String action, String verify, String reference) { }
    private static final String DOC = "https://github.com/jayoss152/jar-release-audit/blob/main/docs/THREAT_MODEL.md#covered-evidence";
    private static final List<Rule> ALL = List.of(
        new Rule("SOURCE_FILE", MEDIUM, "exclude-source", "Exclude unintended source resources from the executable release.", "Rebuild and audit the final executable JAR; publish source archives separately when intended.", DOC),
        new Rule("DEBUG_METADATA", LOW, "review-metadata", "Review diagnostic and framework metadata before removing it.", "Run startup, binding, serialization and diagnostic tests on the final package.", "https://github.com/jayoss152/jar-release-audit/blob/main/docs/OBFUSCATION.md"),
        new Rule("SENSITIVE_FILE", HIGH, "review-private-material", "Review credential/keystore resources and remove unintended private material.", "Inspect the rebuilt release and rotate any real credential already disclosed.", DOC),
        new Rule("SECRET_ASSIGNMENT", HIGH, "externalize-credentials", "Externalize real credentials, including literal placeholder fallbacks.", "Exercise missing-environment behavior and audit the final configuration resources.", DOC),
        new Rule("PRIVATE_KEY", HIGH, "remove-rotate-key", "Remove private key material and rotate any real exposed key through its issuer.", "Verify the old credential is revoked and audit a newly built release.", DOC),
        new Rule("DEVELOPMENT_ARTIFACT", MEDIUM, "exclude-development", "Review and exclude unintended logs, backups, dumps and development metadata.", "Audit the final archive and confirm intentional resources still work.", DOC),
        new Rule("MANIFEST_CLASSPATH", MEDIUM, "review-classpath", "Review external and parent-directory manifest classpath dependencies.", "Run the release in its intended deployment layout and audit its manifest.", DOC)
    );
    private Rules() { }
    public static List<Rule> all() { return ALL; }
    public static Rule get(String id) {
        return ALL.stream().filter(rule -> rule.id().equals(id)).findFirst().orElseThrow(() -> new IllegalArgumentException("Unknown audit rule"));
    }
    static String issueAdvice(Report.IssueCode code) {
        return switch (code) {
            case ENTRY_COUNT_LIMIT, ENTRY_SIZE_LIMIT, EXPANDED_SIZE_LIMIT, SCAN_TIME_LIMIT -> "Review the resource budget and rerun a complete scan within appropriate OS limits.";
            case NESTING_DEPTH_LIMIT -> "Review nested archives and explicitly choose a sufficient supported depth.";
            case SCAN_CANCELLED -> "Rerun the audit after intentional cancellation has been resolved.";
            default -> "Review and rebuild the malformed, unsupported or ambiguous entry before relying on a complete audit.";
        };
    }
}
