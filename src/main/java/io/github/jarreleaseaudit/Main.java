package io.github.jarreleaseaudit;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Locale;

public final class Main {
    private static final String USAGE = """
            Usage: java -jar jar-release-audit-0.1.0.jar [options] <release.jar>
              --format text|json|plan|sarif      Default: text; plan is deterministic Markdown
              --fail-on low|medium|high|none      Default: medium
              --output PATH                      Write a new UTF-8 report file (never overwrite)
              --max-archive-bytes N              Default: 134217728
              --max-entry-bytes N                Default: 8388608
              --max-expanded-bytes N             Default: 67108864
              --max-entries N                    Default: 10000
              --max-depth N                      Default: 2 (allowed: 0..8)
              --max-scan-millis N                Default: 30000 (allowed: 1..3600000)
              --help, -h / --version
              --list-rules                       List deterministic guidance and stable rule IDs
              --from-report PATH                 Import a validated schema v2 report instead of a JAR
              --baseline PATH                    Fail on new findings; all evidence stays in the report
              --redact-paths                     Replace paths and uncontrolled prose for local sharing
              --ai-export PATH                   Export anonymized prompt/evidence JSON locally; no network
              --ai-import PATH --ai-output PATH  Validate offline model advice into a new advisory sidecar
              --allow-ai --ai-endpoint URL --ai-model NAME --ai-output PATH
                                                 Explicit loopback-only model request; defaults off
              --ai-timeout-millis N               Local model deadline, 100..60000 (default 5000)
              --ai-request PATH                   Original anonymized request; required for offline import
              --                                 End options (for input names starting with -)
            Byte limits are positive decimal integers; incomplete scans always exit 2.
            """;
    private Main() { }

    public static void main(String[] args) {
        System.exit(run(args, new PrintStream(System.out, true, StandardCharsets.UTF_8),
                new PrintStream(System.err, true, StandardCharsets.UTF_8)));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        String format = "text";
        String threshold = "medium";
        String input = null;
        String output = null;
        String fromReport = null;
        String baseline = null;
        boolean redactPaths = false;
        String aiExport = null;
        String aiImport = null, aiOutput = null;
        String aiRequest = null;
        String aiEndpoint = null, aiModel = null;
        boolean allowAi = false;
        long aiTimeout = 5000;
        AiClient.Options aiOptions = null;
        boolean positional = false;
        JarScanner.Limits defaults = JarScanner.Limits.defaults();
        long archiveBytes = defaults.maxArchiveBytes(), expandedBytes = defaults.maxExpandedBytes();
        int entryBytes = defaults.maxEntryBytes(), entries = defaults.maxEntries(), depth = defaults.maxNestedDepth();
        JarScanner.Limits limits;
        long scanMillis = 30000;
        try {
            for (int i = 0; i < args.length; i++) {
                if (positional) {
                    if (input != null) throw new IllegalArgumentException();
                    input = args[i];
                    continue;
                }
                switch (args[i]) {
                    case "--" -> positional = true;
                    case "--output" -> output = args[++i];
                    case "--from-report" -> fromReport = args[++i];
                    case "--baseline" -> baseline = args[++i];
                    case "--redact-paths" -> redactPaths = true;
                    case "--ai-export" -> aiExport = args[++i];
                    case "--ai-import" -> aiImport = args[++i];
                    case "--ai-output" -> aiOutput = args[++i];
                    case "--ai-request" -> aiRequest = args[++i];
                    case "--allow-ai" -> allowAi = true;
                    case "--ai-endpoint" -> aiEndpoint = args[++i];
                    case "--ai-model" -> aiModel = args[++i];
                    case "--ai-timeout-millis" -> aiTimeout = Long.parseLong(args[++i]);
                    case "--help", "-h" -> { out.println(USAGE); return 0; }
                    case "--version" -> { out.println("jar-release-audit 0.1.0"); return 0; }
                    case "--list-rules" -> {
                        for (var rule : Rules.all()) out.printf("%s [%s] %s - %s%n", rule.id(), rule.severity(), rule.actionId(), rule.action());
                        return 0;
                    }
                    case "--max-archive-bytes" -> archiveBytes = Long.parseLong(args[++i]);
                    case "--max-entry-bytes" -> entryBytes = Integer.parseInt(args[++i]);
                    case "--max-expanded-bytes" -> expandedBytes = Long.parseLong(args[++i]);
                    case "--max-entries" -> entries = Integer.parseInt(args[++i]);
                    case "--max-depth" -> depth = Integer.parseInt(args[++i]);
                    case "--max-scan-millis" -> scanMillis = Long.parseLong(args[++i]);
                    case "--format" -> {
                        format = args[++i];
                        if (!format.matches("text|json|plan|sarif")) throw new IllegalArgumentException();
                    }
                    case "--fail-on" -> {
                        threshold = args[++i];
                        if (!threshold.matches("low|medium|high|none")) throw new IllegalArgumentException();
                    }
                    default -> {
                        if (args[i].startsWith("-") || input != null) throw new IllegalArgumentException();
                        input = args[i];
                    }
                }
            }
            if ((input == null) == (fromReport == null)) throw new IllegalArgumentException();
            if (aiImport != null && aiEndpoint != null) throw new IllegalArgumentException();
            if (aiImport != null && aiRequest == null) throw new IllegalArgumentException();
            if (aiRequest != null && aiImport == null && aiEndpoint == null && aiExport == null) throw new IllegalArgumentException();
            if ((aiImport != null || aiEndpoint != null) != (aiOutput != null)) throw new IllegalArgumentException();
            if (aiEndpoint != null) {
                if (!allowAi) throw new IllegalArgumentException();
                aiOptions = new AiClient.Options(java.net.URI.create(aiEndpoint), aiModel, aiTimeout);
            } else if (allowAi || aiModel != null || aiTimeout != 5000) throw new IllegalArgumentException();
            limits = new JarScanner.Limits(archiveBytes, entryBytes, expandedBytes, entries, depth);
            if (scanMillis < 1 || scanMillis > 3600000) throw new IllegalArgumentException();
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            err.println(USAGE);
            return 2;
        }
        Report report;
        try {
            report = fromReport == null ? new JarScanner(limits, scanMillis).scan(Path.of(input)) : ReportIO.read(Path.of(fromReport));
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            err.println("Unable to inspect archive: input unavailable, invalid ZIP, or input size limit exceeded.");
            return 2;
        }
        java.util.List<Finding> gateFindings = report.findings();
        if (baseline != null) {
            try { gateFindings = ReportDiff.compare(report, ReportIO.read(Path.of(baseline))).added(); }
            catch (IOException | IllegalArgumentException | SecurityException e) { err.println("Unable to use baseline: select a valid complete schema v2 report."); return 2; }
        }
        AiEvidence.Bundle selectedBundle = null;
        if (aiExport != null || aiImport != null || aiOptions != null) {
            try { selectedBundle = aiRequest == null ? AiEvidence.from(report) : AiEvidence.read(Path.of(aiRequest), report); }
            catch (IOException | IllegalArgumentException | SecurityException e) { err.println("Unable to construct or validate anonymized model request."); return 2; }
        }
        if (aiExport != null) {
            try { Documents.writeNew(Path.of(aiExport), AiEvidence.json(selectedBundle) + "\n"); }
            catch (IOException | IllegalArgumentException | SecurityException e) { err.println("Unable to export bounded anonymized AI evidence; use a new destination file."); return 2; }
        }
        boolean aiFailed = false;
        if (aiImport != null || aiOptions != null) {
            try {
                var bundle = selectedBundle;
                var advice = aiOptions == null ? AiAdvice.parse(Documents.read(Path.of(aiImport), 65536), bundle) : AiClient.invoke(aiOptions, bundle);
                Documents.writeNew(Path.of(aiOutput), AiAdvice.json(advice, bundle) + "\n");
            } catch (IOException | IllegalArgumentException | SecurityException e) { err.println("Optional model assistance failed or produced invalid advice. Deterministic findings were not changed."); aiFailed = true; }
        }
        Report displayed = redactPaths ? SharedReport.redact(report) : report;
        if (output == null) render(displayed, format, out);
        else {
            try (var stream = Files.newOutputStream(Path.of(output), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                 PrintStream file = new PrintStream(stream, false, StandardCharsets.UTF_8)) {
                render(displayed, format, file);
                if (file.checkError()) throw new IOException("Report write failed");
            } catch (IOException | IllegalArgumentException | SecurityException e) {
                err.println("Unable to write report: use a new file in an existing writable directory. Existing files are never overwritten.");
                return 2;
            }
        }
        if (!report.complete() || aiFailed) return 2;
        if (threshold.equals("none")) return 0;
        Finding.Severity minimum = Finding.Severity.valueOf(threshold.toUpperCase(Locale.ROOT));
        return gateFindings.stream().anyMatch(f -> f.severity().ordinal() >= minimum.ordinal()) ? 1 : 0;
    }

    private static void render(Report report, String format, PrintStream out) {
        if (format.equals("plan")) out.print(RemediationPlan.markdown(report));
        else if (format.equals("sarif")) out.println(Sarif.render(report));
        else if (format.equals("json")) out.println(json(report));
        else {
            out.printf("JAR Release Audit: %s; %d entries; %d findings%n",
                    report.complete() ? "COMPLETE" : "INCOMPLETE", report.entriesScanned(), report.findings().size());
            for (Finding f : report.findings())
                out.printf("[%s] %s %s - %s%n", f.severity(), f.rule(), quote(f.entry()), f.message());
            for (Report.Issue issue : report.issues()) out.printf("[INCOMPLETE %s] %s - %s%n", issue.code(), quote(issue.entry()), issue.message());
            out.println("Heuristic release hygiene checks; a clean report does not prevent decompilation or prove absence of secrets.");
        }
    }

    static String json(Report report) {
        StringBuilder b = new StringBuilder("{\"schemaVersion\":2,\"complete\":").append(report.complete())
                .append(",\"entriesScanned\":").append(report.entriesScanned())
                .append(",\"summary\":{\"low\":").append(report.count(Finding.Severity.LOW))
                .append(",\"medium\":").append(report.count(Finding.Severity.MEDIUM))
                .append(",\"high\":").append(report.count(Finding.Severity.HIGH))
                .append(",\"issues\":").append(report.issues().size()).append("},\"findings\":[");
        for (int i = 0; i < report.findings().size(); i++) {
            Finding f = report.findings().get(i);
            if (i > 0) b.append(',');
            b.append("{\"severity\":").append(quote(f.severity().name())).append(",\"rule\":").append(quote(f.rule()))
                    .append(",\"entry\":").append(quote(f.entry())).append(",\"message\":").append(quote(f.message())).append('}');
        }
        b.append("],\"issues\":[");
        for (int i = 0; i < report.issues().size(); i++) {
            Report.Issue issue = report.issues().get(i);
            if (i > 0) b.append(',');
            b.append("{\"code\":").append(quote(issue.code().name())).append(",\"entry\":").append(quote(issue.entry()))
                    .append(",\"message\":").append(quote(issue.message())).append('}');
        }
        return b.append("]}").toString();
    }

    /** JSON escaping also prevents terminal control characters from archive names. */
    static String quote(String text) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '<' || c == '>' || c == '&' || Character.isISOControl(c) || Character.isSurrogate(c) || c == '\u2028' || c == '\u2029'
                    || Character.getType(c) == Character.FORMAT) b.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
}
