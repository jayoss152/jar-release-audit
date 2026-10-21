package io.github.jarreleaseaudit;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Locale;

public final class Main {
    private static final String USAGE = "Usage: java -jar jar-release-audit-0.1.0.jar [--format text|json] [--fail-on low|medium|high|none] <release.jar>";
    private Main() { }

    public static void main(String[] args) {
        System.exit(run(args, new PrintStream(System.out, true, StandardCharsets.UTF_8),
                new PrintStream(System.err, true, StandardCharsets.UTF_8)));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        boolean json = false;
        String threshold = "medium";
        String input = null;
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--help", "-h" -> { out.println(USAGE); return 0; }
                    case "--version" -> { out.println("jar-release-audit 0.1.0"); return 0; }
                    case "--format" -> {
                        String format = args[++i];
                        if (!format.equals("text") && !format.equals("json")) throw new IllegalArgumentException();
                        json = format.equals("json");
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
            if (input == null) throw new IllegalArgumentException();
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            err.println(USAGE);
            return 2;
        }
        Report report;
        try {
            report = new JarScanner().scan(Path.of(input));
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            err.println("Unable to inspect archive: input unavailable, invalid ZIP, or input size limit exceeded.");
            return 2;
        }
        if (json) out.println(json(report));
        else {
            out.printf("JAR Release Audit: %s; %d entries; %d findings%n",
                    report.complete() ? "COMPLETE" : "INCOMPLETE", report.entriesScanned(), report.findings().size());
            for (Finding f : report.findings())
                out.printf("[%s] %s %s - %s%n", f.severity(), f.rule(), quote(f.entry()), f.message());
            for (Report.Issue issue : report.issues()) out.printf("[INCOMPLETE] %s - %s%n", quote(issue.entry()), issue.message());
            out.println("Heuristic release hygiene checks; a clean report does not prevent decompilation or prove absence of secrets.");
        }
        if (!report.complete()) return 2;
        if (threshold.equals("none")) return 0;
        Finding.Severity minimum = Finding.Severity.valueOf(threshold.toUpperCase(Locale.ROOT));
        return report.findings().stream().anyMatch(f -> f.severity().ordinal() >= minimum.ordinal()) ? 1 : 0;
    }

    static String json(Report report) {
        StringBuilder b = new StringBuilder("{\"schemaVersion\":1,\"complete\":").append(report.complete())
                .append(",\"entriesScanned\":").append(report.entriesScanned()).append(",\"findings\":[");
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
            b.append("{\"entry\":").append(quote(issue.entry())).append(",\"message\":").append(quote(issue.message())).append('}');
        }
        return b.append("]}").toString();
    }

    /** JSON escaping also prevents terminal control characters from archive names. */
    static String quote(String text) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (Character.isISOControl(c) || Character.isSurrogate(c) || c == '\u2028' || c == '\u2029'
                    || Character.getType(c) == Character.FORMAT) b.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
}
