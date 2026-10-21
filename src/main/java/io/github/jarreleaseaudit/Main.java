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
              --format text|json                 Default: text
              --fail-on low|medium|high|none      Default: medium
              --output PATH                      Write a new UTF-8 report file (never overwrite)
              --max-archive-bytes N              Default: 134217728
              --max-entry-bytes N                Default: 8388608
              --max-expanded-bytes N             Default: 67108864
              --max-entries N                    Default: 10000
              --max-depth N                      Default: 2 (allowed: 0..8)
              --help, -h / --version
              --                                 End options (for input names starting with -)
            Byte limits are positive decimal integers; incomplete scans always exit 2.
            """;
    private Main() { }

    public static void main(String[] args) {
        System.exit(run(args, new PrintStream(System.out, true, StandardCharsets.UTF_8),
                new PrintStream(System.err, true, StandardCharsets.UTF_8)));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        boolean json = false;
        String threshold = "medium";
        String input = null;
        String output = null;
        boolean positional = false;
        JarScanner.Limits defaults = JarScanner.Limits.defaults();
        long archiveBytes = defaults.maxArchiveBytes(), expandedBytes = defaults.maxExpandedBytes();
        int entryBytes = defaults.maxEntryBytes(), entries = defaults.maxEntries(), depth = defaults.maxNestedDepth();
        JarScanner.Limits limits;
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
                    case "--help", "-h" -> { out.println(USAGE); return 0; }
                    case "--version" -> { out.println("jar-release-audit 0.1.0"); return 0; }
                    case "--max-archive-bytes" -> archiveBytes = Long.parseLong(args[++i]);
                    case "--max-entry-bytes" -> entryBytes = Integer.parseInt(args[++i]);
                    case "--max-expanded-bytes" -> expandedBytes = Long.parseLong(args[++i]);
                    case "--max-entries" -> entries = Integer.parseInt(args[++i]);
                    case "--max-depth" -> depth = Integer.parseInt(args[++i]);
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
            limits = new JarScanner.Limits(archiveBytes, entryBytes, expandedBytes, entries, depth);
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            err.println(USAGE);
            return 2;
        }
        Report report;
        try {
            report = new JarScanner(limits).scan(Path.of(input));
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            err.println("Unable to inspect archive: input unavailable, invalid ZIP, or input size limit exceeded.");
            return 2;
        }
        if (output == null) render(report, json, out);
        else {
            try (var stream = Files.newOutputStream(Path.of(output), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                 PrintStream file = new PrintStream(stream, false, StandardCharsets.UTF_8)) {
                render(report, json, file);
                if (file.checkError()) throw new IOException("Report write failed");
            } catch (IOException | IllegalArgumentException | SecurityException e) {
                err.println("Unable to write report: use a new file in an existing writable directory. Existing files are never overwritten.");
                return 2;
            }
        }
        if (!report.complete()) return 2;
        if (threshold.equals("none")) return 0;
        Finding.Severity minimum = Finding.Severity.valueOf(threshold.toUpperCase(Locale.ROOT));
        return report.findings().stream().anyMatch(f -> f.severity().ordinal() >= minimum.ordinal()) ? 1 : 0;
    }

    private static void render(Report report, boolean json, PrintStream out) {
        if (json) out.println(json(report));
        else {
            out.printf("JAR Release Audit: %s; %d entries; %d findings%n",
                    report.complete() ? "COMPLETE" : "INCOMPLETE", report.entriesScanned(), report.findings().size());
            for (Finding f : report.findings())
                out.printf("[%s] %s %s - %s%n", f.severity(), f.rule(), quote(f.entry()), f.message());
            for (Report.Issue issue : report.issues()) out.printf("[INCOMPLETE] %s - %s%n", quote(issue.entry()), issue.message());
            out.println("Heuristic release hygiene checks; a clean report does not prevent decompilation or prove absence of secrets.");
        }
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
