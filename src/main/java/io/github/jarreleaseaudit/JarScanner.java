package io.github.jarreleaseaudit;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.CRC32;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import static io.github.jarreleaseaudit.Finding.Severity.*;
import static io.github.jarreleaseaudit.Report.IssueCode.*;

/** Offline, read-only ZIP/JAR inspection. Does not load classes or extract files. */
public final class JarScanner {
    public record Limits(long maxArchiveBytes, int maxEntryBytes, long maxExpandedBytes,
                         int maxEntries, int maxNestedDepth) {
        public Limits {
            if (maxArchiveBytes < 1 || maxEntryBytes < 1 || maxEntryBytes > Integer.MAX_VALUE - 8
                    || maxExpandedBytes < 1 || maxEntries < 1 || maxNestedDepth < 0 || maxNestedDepth > 8)
                throw new IllegalArgumentException("Invalid limits");
        }
        public static Limits defaults() { return new Limits(128L << 20, 8 << 20, 64L << 20, 10_000, 2); }
    }

    private static final Pattern SOURCE = Pattern.compile("(?s).*\\.(java|kt|kts|scala|groovy)$");
    private static final Pattern TEXT = Pattern.compile("(?s).*\\.(properties|ya?ml|json|xml|conf|cfg|ini|txt|pem|key|env)$");
    private static final Pattern SENSITIVE = Pattern.compile(
            "(^|/)(\\.env(?:\\..*)?|id_rsa|id_ed25519|[^/]*\\.(?:p12|pfx|jks|keystore|key))$");
    // Deliberately narrow, line-based heuristic. Values are never included in output.
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?im)^[ \\t]*[\\\"']?(?:[\\w.-]*[._-])?(?:password|passwd|secret|token|api[._-]?key|access[._-]?key)[\\\"']?[ \\t]*[:=][ \\t]*(.+?)[ \\t]*[,;]?[ \\t]*$");
    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----");
    private final Limits limits;

    public JarScanner() { this(Limits.defaults()); }
    public JarScanner(Limits limits) { this.limits = java.util.Objects.requireNonNull(limits); }

    public Report scan(Path archive) throws IOException {
        if (!Files.isRegularFile(archive)) throw new IOException("Input must be a regular file");
        if (Files.size(archive) > limits.maxArchiveBytes()) throw new IOException("Archive exceeds input size limit");
        State state = new State();
        try (ZipFile zip = new ZipFile(archive.toFile(), StandardCharsets.UTF_8)) {
            Set<String> names = new HashSet<>();
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!state.count(entry.getName())) break;
                if (ArchivePaths.unsafe(entry.getName())) {
                    state.issue(PATH_INVALID, entry.getName(), "Archive path is unsafe or ambiguous; entry was not inspected.");
                    continue;
                }
                if (!names.add(canonicalName(entry.getName()))) {
                    state.issue(AMBIGUOUS_ENTRY, entry.getName(), "Duplicate or ambiguous archive entry name; contents are not trustworthy.");
                    continue;
                }
                try (InputStream in = zip.getInputStream(entry)) {
                    byte[] content = state.read(in);
                    CRC32 crc = new CRC32();
                    crc.update(content);
                    if (entry.getSize() != content.length || entry.getCrc() != crc.getValue())
                        throw new ScanProblem(ARCHIVE_INTEGRITY, "Outer entry size or CRC does not match its directory.");
                    if (!entry.isDirectory()) inspect(entry.getName(), content, 0, state);
                    if (state.exhausted) break;
                } catch (IOException | IllegalArgumentException e) {
                    state.issue(entry.getName(), e);
                    if (state.exhausted) break;
                }
            }
        }
        state.findings.sort(Comparator.comparing(Finding::entry).thenComparing(Finding::rule));
        state.issues.sort(Comparator.comparing(Report.Issue::entry).thenComparing(Report.Issue::message));
        return new Report(state.findings, state.issues, state.entries);
    }

    private void inspect(String name, byte[] bytes, int depth, State state) throws IOException {
        String lower = name.replace('\\', '/').toLowerCase(Locale.ROOT);
        if (SOURCE.matcher(lower).matches())
            state.add(MEDIUM, "SOURCE_FILE", name, "Source code is packaged in the release; exclude it unless intentional.");
        if (SENSITIVE.matcher(lower).find())
            state.add(HIGH, "SENSITIVE_FILE", name, "Potential credential or keystore file; review and exclude private material.");
        if (lower.endsWith(".class")) {
            Set<String> debug;
            try { debug = ClassMetadata.debugAttributes(bytes); }
            catch (IOException e) { throw new ScanProblem(INVALID_CLASS, "Class metadata could not be parsed."); }
            if (!debug.isEmpty()) state.add(LOW, "DEBUG_METADATA", name,
                    "Class metadata present: " + String.join(", ", debug) + ". Review the diagnostics/exposure tradeoff.");
        }
        if (TEXT.matcher(lower).matches() || lower.substring(lower.lastIndexOf('/') + 1).startsWith(".env")) {
            String text;
            try { text = ResourceText.decode(bytes); }
            catch (IOException e) { throw new ScanProblem(INVALID_TEXT, "Text encoding is malformed or unsupported."); }
            if (PRIVATE_KEY.matcher(text).find())
                state.add(HIGH, "PRIVATE_KEY", name, "Private key marker found; remove it and rotate any real exposed key.");
            boolean structuredSecret = false;
            if (lower.endsWith(".json")) {
                try { structuredSecret = CredentialValues.json(text); }
                catch (IOException e) { throw new ScanProblem(INVALID_TEXT, "JSON resource is malformed or exceeds parser limits."); }
            } else if (lower.endsWith(".xml")) {
                try { structuredSecret = XmlCredentials.inspect(text); }
                catch (IOException e) { throw new ScanProblem(INVALID_TEXT, "XML resource is malformed, unsupported or exceeds parser limits."); }
            } else if (lower.endsWith(".properties")) {
                try { structuredSecret = CredentialValues.properties(text); }
                catch (IOException e) { throw new ScanProblem(INVALID_TEXT, "Properties resource is malformed or exceeds parser limits."); }
            }
            var matcher = ASSIGNMENT.matcher(lower.endsWith(".json") || lower.endsWith(".xml") || lower.endsWith(".properties") ? "" : text);
            while (structuredSecret || matcher.find()) {
                if (structuredSecret || literalValue(matcher.group(1))) {
                    state.add(HIGH, "SECRET_ASSIGNMENT", name,
                            "Potential literal credential assignment; externalize real credentials. Value redacted.");
                    break;
                }
            }
        }
        if (lower.endsWith(".jar") || lower.endsWith(".zip") || zipMagic(bytes)) {
            if (depth >= limits.maxNestedDepth()) {
                state.issue(NESTING_DEPTH_LIMIT, name, "Nested archive depth limit reached; contents were not inspected.");
                return;
            }
            // ZipInputStream alone accepts arbitrary non-ZIP input as an empty archive.
            ZipDirectory directory;
            try { directory = validateNestedZip(bytes); }
            catch (IOException e) { throw new ScanProblem(ARCHIVE_INTEGRITY, "Nested ZIP directory or headers are invalid or unsupported."); }
            try (ZipInputStream nested = new ZipInputStream(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8)) {
                Set<String> names = new HashSet<>();
                ZipEntry entry;
                int seen = 0;
                while ((entry = nested.getNextEntry()) != null) {
                    seen++;
                    String child = name + "!/" + entry.getName();
                    if (!state.count(child)) return;
                    if (ArchivePaths.unsafe(entry.getName()))
                        throw new ScanProblem(PATH_INVALID, "Nested entry path is unsafe or ambiguous.");
                    if (!names.add(canonicalName(entry.getName())))
                        throw new ScanProblem(AMBIGUOUS_ENTRY, "Duplicate or ambiguous nested entry name.");
                    try {
                        byte[] content = state.read(nested);
                        CentralEntry expected = directory.entries().get(entry.getName());
                        if (expected == null || expected.size() != content.length || expected.crc() != entry.getCrc()
                                || expected.compressedSize() != entry.getCompressedSize())
                            throw new ScanProblem(ARCHIVE_INTEGRITY, "Nested payload size or CRC does not match its central directory.");
                        if (!entry.isDirectory()) inspect(child, content, depth + 1, state);
                    } catch (IOException e) {
                        state.issue(child, e);
                        if (state.exhausted) return;
                    }
                    nested.closeEntry();
                }
                if (seen != directory.count()) throw new ScanProblem(ARCHIVE_INTEGRITY, "Nested directory entry count mismatch.");
            }
        }
    }

    private record CentralEntry(long size, long compressedSize, long crc) { }
    private record ZipDirectory(int count, Map<String, CentralEntry> entries) { }

    private static ZipDirectory validateNestedZip(byte[] b) throws IOException {
        // Require an end record and a bounded, consistent central directory. ZIP64 and
        // split nested archives are deliberately unsupported and yield INCOMPLETE.
        for (int end = b.length - 22; end >= Math.max(0, b.length - 65_557); end--) {
            if (u32(b, end) != 0x06054b50L || end + 22L + u16(b, end + 20) != b.length) continue;
            if (u16(b, end + 4) != 0 || u16(b, end + 6) != 0
                    || u16(b, end + 8) != u16(b, end + 10)) break;
            int count = u16(b, end + 10);
            Map<String, CentralEntry> directory = new HashMap<>();
            long size = u32(b, end + 12), offset = u32(b, end + 16);
            if (count == 65535 || offset + size != end || offset > b.length) break;
            long cursor = offset;
            for (int i = 0; i < count; i++) {
                if (cursor + 46 > end || u32(b, (int) cursor) != 0x02014b50L) throw new IOException("Invalid central directory");
                int p = (int) cursor;
                int nameLength = u16(b, p + 28);
                long next = cursor + 46L + nameLength + u16(b, p + 30) + u16(b, p + 32);
                long local = u32(b, p + 42), compressed = u32(b, p + 20);
                if (next > end || u16(b, p + 34) != 0 || local + 30 > offset
                        || u32(b, (int) local) != 0x04034b50L)
                    throw new IOException("Invalid local header reference");
                int h = (int) local, flags = u16(b, p + 8);
                if ((flags & 1) != 0 || u16(b, h + 6) != flags || u16(b, h + 8) != u16(b, p + 10)
                        || u16(b, h + 26) != nameLength
                        || local + 30L + nameLength + u16(b, h + 28) + compressed > offset)
                    throw new IOException("Inconsistent nested entry header");
                if (java.util.Arrays.mismatch(b, p + 46, p + 46 + nameLength,
                        b, h + 30, h + 30 + nameLength) != -1)
                    throw new IOException("Inconsistent nested entry name");
                if ((flags & 8) == 0 && (u32(b, h + 14) != u32(b, p + 16)
                        || u32(b, h + 18) != compressed || u32(b, h + 22) != u32(b, p + 24)))
                    throw new IOException("Inconsistent nested entry sizes or checksum");
                String entryName = new String(b, p + 46, nameLength, StandardCharsets.UTF_8);
                if (directory.putIfAbsent(entryName, new CentralEntry(u32(b, p + 24), compressed, u32(b, p + 16))) != null)
                    throw new IOException("Duplicate central directory name");
                cursor = next;
            }
            if (cursor != end || (count > 0 && u32(b, 0) != 0x04034b50L)) break;
            return new ZipDirectory(count, Map.copyOf(directory));
        }
        throw new IOException("Invalid or unsupported nested ZIP");
    }

    private static boolean zipMagic(byte[] b) {
        return b.length >= 4 && b[0] == 'P' && b[1] == 'K'
                && ((b[2] == 3 && b[3] == 4) || (b[2] == 5 && b[3] == 6) || (b[2] == 7 && b[3] == 8));
    }

    private static int u16(byte[] b, int p) { return (b[p] & 255) | ((b[p + 1] & 255) << 8); }
    private static long u32(byte[] b, int p) { return (long) u16(b, p) | ((long) u16(b, p + 2) << 16); }

    private static String canonicalName(String name) {
        String normalized = name.replace('\\', '/');
        while (normalized.startsWith("./")) normalized = normalized.substring(2);
        return normalized; // Deliberately case-sensitive, like Java resource lookup.
    }

    static boolean literalValue(String raw) {
        String value = raw.strip().replaceFirst("[,;]$", "").strip();
        boolean quoted = value.length() >= 2 && ((value.startsWith("\"") && value.endsWith("\""))
                || (value.startsWith("'") && value.endsWith("'")));
        if (quoted) value = value.substring(1, value.length() - 1).strip();
        if (value.isEmpty() || (value.startsWith("#") && !value.startsWith("#{"))) return false;
        if (!quoted && (value.equals("null") || value.equals("~"))) return false;
        // Only a whole reference with no nonempty fallback is known to be external.
        // Defaults, concatenation and arbitrary SpEL can still disclose literals.
        return !value.matches("\\$\\{[A-Za-z_][A-Za-z0-9_.-]*:?}");
    }

    private final class State {
        final List<Finding> findings = new ArrayList<>();
        final List<Report.Issue> issues = new ArrayList<>();
        int entries;
        long expanded;
        boolean exhausted;

        boolean count(String name) {
            if (entries >= limits.maxEntries()) {
                issue(ENTRY_COUNT_LIMIT, name, "Entry count limit reached; remaining entries were not inspected.");
                exhausted = true;
                return false;
            }
            entries++;
            return true;
        }

        byte[] read(InputStream in) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) {
                expanded += n;
                if (expanded > limits.maxExpandedBytes()) {
                    exhausted = true;
                    throw new ScanProblem(EXPANDED_SIZE_LIMIT, "Total expanded byte limit reached; scan stopped.");
                }
                if ((long) out.size() + n > limits.maxEntryBytes()) {
                    exhausted = true;
                    throw new ScanProblem(ENTRY_SIZE_LIMIT, "Expanded entry size limit reached; scan stopped.");
                }
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }

        void add(Finding.Severity severity, String rule, String entry, String message) {
            findings.add(new Finding(severity, rule, entry, message));
        }
        void issue(Report.IssueCode code, String entry, String message) { issues.add(new Report.Issue(code, entry, message)); }
        void issue(String entry, Exception error) {
            if (error instanceof ScanProblem problem) issue(problem.code, entry, problem.getMessage());
            else issue(ENTRY_READ_ERROR, entry, "Archive entry could not be read completely or uses an unsupported format.");
        }
    }

    private static final class ScanProblem extends IOException {
        final Report.IssueCode code;
        ScanProblem(Report.IssueCode code, String message) { super(message); this.code = code; }
    }
}
