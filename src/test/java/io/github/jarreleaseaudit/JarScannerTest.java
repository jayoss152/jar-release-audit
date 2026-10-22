package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class JarScannerTest {
    @TempDir Path temp;

    @Test void reportsSourcesSecretsAndKeysWithoutValues() throws Exception {
        Path jar = archive(Map.of("app/Hello.java", bytes("class Hello {}"),
                "BOOT-INF/classes/application.yml", bytes("spring.datasource.password: fake-only-123\napi_key: fake-only-456"),
                "keys/service.pem", bytes("-----BEGIN PRIVATE KEY-----\nFAKE-NOT-A-KEY"),
                ".env.production", bytes("token=fake-only-789")));
        Report r = new JarScanner().scan(jar);
        assertTrue(r.complete());
        assertEquals(Set.of("SOURCE_FILE", "SECRET_ASSIGNMENT", "PRIVATE_KEY", "SENSITIVE_FILE"), rules(r));
        String output = Main.json(r);
        assertFalse(output.contains("fake-only"));
        assertFalse(output.contains("FAKE-NOT-A-KEY"));
        assertEquals(2, r.findings().stream().filter(f -> f.rule().equals("SECRET_ASSIGNMENT")).count());
    }

    @Test void acceptsExternalizedAndEmptyValues() throws Exception {
        Report r = new JarScanner().scan(archive(Map.of("application.properties", bytes(
                "password=${DB_PASSWORD}\ntoken=${TOKEN}\nsecret=\napi_key=\n# passwd=external"))));
        assertTrue(r.complete());
        assertTrue(r.findings().isEmpty());
    }

    @Test void placeholderDefaultsExpressionsAndConcatenationRequireReview() throws Exception {
        for (String value : new String[] {"${PASSWORD:fake-only}", "\"${PASSWORD:fake-only}\"",
                "#{'fake-only'}", "${PASSWORD}suffix", "${PASSWORD", "\"null\""}) {
            Report r = new JarScanner().scan(archive(Map.of("application.properties", bytes("password=" + value))));
            assertEquals(Set.of("SECRET_ASSIGNMENT"), rules(r), value);
            assertFalse(Main.json(r).contains("fake-only"));
        }
        for (String value : new String[] {"${PASSWORD}", "${PASSWORD:}", "\"${PASSWORD}\""})
            assertTrue(new JarScanner().scan(archive(Map.of("application.yml", bytes("password: " + value)))).findings().isEmpty());
    }

    @Test void unicodeBomResourcesAreInspectedWithoutLeakingValues() throws Exception {
        for (var charset : new java.nio.charset.Charset[] {StandardCharsets.UTF_8, StandardCharsets.UTF_16LE, StandardCharsets.UTF_16BE}) {
            byte[] data = ("\ufeffpassword=fake-only-unicode").getBytes(charset);
            Report r = new JarScanner().scan(archive(Map.of("application.yml", data)));
            assertTrue(r.complete());
            assertEquals(Set.of("SECRET_ASSIGNMENT"), rules(r));
            assertFalse(Main.json(r).contains("fake-only"));
        }
    }

    @Test void malformedOrUnsupportedTextEncodingsAreIncomplete() throws Exception {
        for (byte[] data : new byte[][] {new byte[] {(byte) 0xc3, 0x28},
                new byte[] {(byte) 0xff, (byte) 0xfe, 0, 0},
                "password=fake".getBytes(StandardCharsets.UTF_16LE)})
            assertFalse(new JarScanner().scan(archive(Map.of("application.properties", data))).complete());
    }

    @Test void findsMetadataStructurallyAndDistinguishesStrippedClasses() throws Exception {
        byte[] debug = compile("-g", "class Sample { int calc(int arg) { int value = arg + 1; return value; } }");
        var metadata = ClassMetadata.debugAttributes(debug);
        assertTrue(metadata.containsAll(Set.of("SourceFile", "LineNumberTable", "LocalVariableTable")));
        byte[] stripped = compile("-g:none", "class Sample { String label() { return \"LineNumberTable\"; } }");
        assertTrue(ClassMetadata.debugAttributes(stripped).isEmpty());
        Report r = new JarScanner().scan(archive(Map.of("Sample.class", debug)));
        assertEquals(Set.of("DEBUG_METADATA"), rules(r));
    }

    @Test void detectsParameterNames() throws Exception {
        Path source = temp.resolve("Sample.java");
        Files.writeString(source, "class Sample { void call(String visibleName) {} }");
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-g:none", "-parameters", "-d", temp.toString(), source.toString()));
        assertTrue(ClassMetadata.debugAttributes(Files.readAllBytes(temp.resolve("Sample.class"))).contains("MethodParameters"));
    }

    @Test void parsesModernBytecodeIncludingRecordsLambdasAndWideConstants() throws Exception {
        byte[] compiled = compile("-g:none", "record Sample(long id, double value) { static final long L = 12345678901L; static final double D = 1.25; Runnable task() { return () -> System.out.println(id); } }");
        // Record canonical parameter names survive -g:none and are real metadata.
        assertEquals(Set.of("MethodParameters"), ClassMetadata.debugAttributes(compiled));
        assertTrue(new JarScanner().scan(archive(Map.of("Sample.class", compiled))).complete());
    }

    @Test void inspectsSpringBootNestedLibraries() throws Exception {
        byte[] nested = zip(Map.of("lib/Hidden.kt", bytes("fun main() {}")));
        Report r = new JarScanner().scan(archive(Map.of("BOOT-INF/lib/demo.jar", nested)));
        assertTrue(r.complete());
        assertEquals("BOOT-INF/lib/demo.jar!/lib/Hidden.kt", r.findings().get(0).entry());
    }

    @Test void invalidNestedArchiveIsIncompleteIncludingTruncation() throws Exception {
        for (byte[] bad : new byte[][] {bytes("not zip"), new byte[] {'P', 'K', 3, 4},
                java.util.Arrays.copyOf(zip(Map.of("x", bytes("x"))), 35)}) {
            Report r = new JarScanner().scan(archive(Map.of("bad.jar", bad)));
            assertFalse(r.complete());
            assertFalse(r.issues().isEmpty());
        }
    }

    @Test void emptyNestedArchiveIsValid() throws Exception {
        assertTrue(new JarScanner().scan(archive(Map.of("empty.jar", zip(Map.of())))).complete());
    }

    @Test void corruptedStoredOuterEntryCannotPassAsClean() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] payload = bytes("password=fake-only-value");
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            ZipEntry entry = new ZipEntry("application.properties");
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(payload.length);
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            crc.update(payload);
            entry.setCrc(crc.getValue());
            zip.putNextEntry(entry);
            zip.write(payload);
            zip.closeEntry();
        }
        byte[] corrupted = out.toByteArray();
        corrupted[30 + "application.properties".length()] ^= 1;
        Path jar = temp.resolve("corrupted.jar");
        Files.write(jar, corrupted);
        assertFalse(new JarScanner().scan(jar).complete());
        assertEquals(2, cli("--fail-on", "none", jar.toString()));
    }

    @Test void inconsistentNestedCentralAndLocalNamesAreIncomplete() throws Exception {
        byte[] nested = zip(Map.of("secret.txt", bytes("password=fake-value")));
        for (int p = 0; p + 46 < nested.length; p++) {
            if (nested[p] == 'P' && nested[p + 1] == 'K' && nested[p + 2] == 1 && nested[p + 3] == 2) {
                nested[p + 46] = 'x';
                break;
            }
        }
        Report report = new JarScanner().scan(archive(Map.of("lib.jar", nested)));
        assertFalse(report.complete());
    }

    @Test void duplicateNamesAreIncompleteAtEveryArchiveLevel() throws Exception {
        byte[] duplicate = zip(Map.of("a.txt", bytes("same"), "b.txt", bytes("same")));
        for (int p = 0; p + 5 <= duplicate.length; p++) {
            if (duplicate[p] == 'b' && duplicate[p + 1] == '.' && duplicate[p + 2] == 't'
                    && duplicate[p + 3] == 'x' && duplicate[p + 4] == 't') duplicate[p] = 'a';
        }
        Path outer = temp.resolve("duplicate.jar");
        Files.write(outer, duplicate);
        assertFalse(new JarScanner().scan(outer).complete());
        assertFalse(new JarScanner().scan(archive(Map.of("nested.jar", duplicate))).complete());
    }

    @Test void slashAliasesAreAmbiguousButCaseDistinctResourcesAreAllowed() throws Exception {
        assertFalse(new JarScanner().scan(archive(Map.of("app/x.txt", bytes("same"),
                "app\\x.txt", bytes("same")))).complete());
        assertTrue(new JarScanner().scan(archive(Map.of("A.txt", bytes("same"),
                "a.txt", bytes("same")))).complete());
    }

    @Test void depthLimitIsIncomplete() throws Exception {
        var scanner = new JarScanner(new JarScanner.Limits(10000, 10000, 10000, 100, 0));
        Report r = scanner.scan(archive(Map.of("nested.jar", zip(Map.of()))));
        assertFalse(r.complete());
        assertTrue(r.issues().get(0).message().contains("depth"));
    }

    @Test void entrySizeBudgetStopsHighlyCompressedData() throws Exception {
        var scanner = new JarScanner(new JarScanner.Limits(10000, 100, 10000, 100, 2));
        Report r = scanner.scan(archive(Map.of("large.txt", new byte[100_000])));
        assertFalse(r.complete());
    }

    @Test void totalExpansionBudgetIsShared() throws Exception {
        var scanner = new JarScanner(new JarScanner.Limits(10000, 100, 150, 100, 2));
        Report r = scanner.scan(archive(Map.of("a", new byte[80], "b", new byte[80])));
        assertFalse(r.complete());
    }

    @Test void nestedDirectoryPayloadsCannotBypassBudget() throws Exception {
        var scanner = new JarScanner(new JarScanner.Limits(10000, 500, 1000, 100, 2));
        Report r = scanner.scan(archive(Map.of("dir.jar", zip(Map.of("payload/", new byte[100_000])))));
        assertFalse(r.complete());
    }

    @Test void entryCountBudgetIsShared() throws Exception {
        var scanner = new JarScanner(new JarScanner.Limits(10000, 10000, 10000, 1, 2));
        Report r = scanner.scan(archive(Map.of("a", bytes("x"), "b", bytes("y"))));
        assertFalse(r.complete());
        assertEquals(1, r.entriesScanned());
    }

    @Test void inputSizeLimitRejectsBeforeScan() throws Exception {
        var scanner = new JarScanner(new JarScanner.Limits(1, 100, 100, 100, 2));
        Path jar = archive(Map.of());
        assertThrows(IOException.class, () -> scanner.scan(jar));
    }

    @Test void malformedClassNeverPassesAsClean() throws Exception {
        Report r = new JarScanner().scan(archive(Map.of("bad.class", bytes("not a class"))));
        assertFalse(r.complete());
        byte[] valid = compile("-g", "class Sample {}");
        assertThrows(IOException.class, () -> ClassMetadata.debugAttributes(java.util.Arrays.copyOf(valid, valid.length - 1)));
    }

    @Test void outputEscapesMaliciousNamesAndIsDeterministic() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("z\u001b\n.java", bytes("x"));
        entries.put("a\"\\.java", bytes("y"));
        Report first = new JarScanner().scan(archive(entries));
        var reversed = new LinkedHashMap<String, byte[]>();
        reversed.put("a\"\\.java", bytes("y"));
        reversed.put("z\u001b\n.java", bytes("x"));
        assertEquals(Main.json(first), Main.json(new JarScanner().scan(archive(reversed))));
        assertFalse(Main.json(first).contains("\u001b"));
        assertTrue(Main.json(first).contains("\\u001b\\u000a"));
        assertEquals("\"a\\\"\\\\\\u0009\"", Main.quote("a\"\\\t"));
    }

    @Test void cliThresholdsAndOperationalExitCodes() throws Exception {
        Path source = archive(Map.of("Hello.java", bytes("class Hello {}")));
        assertEquals(1, cli(source.toString()));
        assertEquals(0, cli("--fail-on", "high", source.toString()));
        assertEquals(0, cli("--fail-on", "none", source.toString()));
        assertEquals(2, cli("--fail-on", "invalid", source.toString()));
        assertEquals(2, cli("--format"));
        assertEquals(2, cli());
        assertEquals(2, cli("missing.jar"));
        assertEquals(0, cli("--help"));
        assertEquals(0, cli("--version"));
        Path incomplete = archive(Map.of("Broken.class", bytes("broken")));
        assertEquals(2, cli("--format", "json", "--fail-on", "none", incomplete.toString()));
        Path invalid = temp.resolve("invalid.jar");
        Files.writeString(invalid, "invalid");
        assertEquals(2, cli(invalid.toString()));
    }

    @Test void cliResourceLimitsAreConfigurableAndRejectInvalidValues() throws Exception {
        Path jar = archive(Map.of("a.txt", bytes("1234567890"), "b.txt", bytes("1234567890")));
        for (String flag : new String[] {"--max-archive-bytes", "--max-entry-bytes", "--max-expanded-bytes", "--max-entries"}) {
            assertEquals(2, cli(flag, "1", jar.toString()), flag);
            assertEquals(2, cli(flag, "0", jar.toString()), flag);
            assertEquals(2, cli(flag, "invalid", jar.toString()), flag);
            assertEquals(2, cli(flag, "999999999999999999999", jar.toString()), flag);
        }
        assertEquals(0, cli("--max-entry-bytes", "64", "--max-expanded-bytes", "128", jar.toString()));
        Path nested = archive(Map.of("nested.jar", zip(Map.of())));
        assertEquals(2, cli("--max-depth", "0", nested.toString()));
        assertEquals(2, cli("--max-depth", "9", jar.toString()));
        assertEquals(2, cli("--max-depth", "-1", jar.toString()));
    }

    @Test void cliWritesNewUtf8ReportsAndPreservesExistingFiles() throws Exception {
        Path jar = archive(Map.of("\u4e2d\u6587.java", bytes("class Sample {}")));
        Path output = temp.resolve("report.json");
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        assertEquals(1, Main.run(new String[] {"--format", "json", "--output", output.toString(), jar.toString()},
                new PrintStream(stdout), System.err));
        assertEquals("", stdout.toString(StandardCharsets.UTF_8));
        String report = Files.readString(output);
        assertTrue(report.contains("\u4e2d\u6587.java"));
        assertEquals(2, cli("--output", output.toString(), jar.toString()));
        assertEquals(report, Files.readString(output));
        byte[] original = Files.readAllBytes(jar);
        assertEquals(2, cli("--output", jar.toString(), jar.toString()));
        assertArrayEquals(original, Files.readAllBytes(jar));
        Path absent = temp.resolve("absent.json");
        assertEquals(2, cli("--output", absent.toString(), "missing.jar"));
        assertFalse(Files.exists(absent));
    }

    @Test void cliPersistsIncompleteReportsAndHonorsEndOfOptions() throws Exception {
        Path jar = archive(Map.of("broken.class", bytes("broken")));
        Path output = temp.resolve("incomplete.json");
        assertEquals(2, cli("--format", "json", "--output", output.toString(), jar.toString()));
        assertTrue(Files.readString(output).contains("\"complete\":false"));
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        assertEquals(2, Main.run(new String[] {"--", "--help"}, System.out, new PrintStream(err)));
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("Unable to inspect archive"));
    }

    @Test void cleanJarPassesAndJsonHasSchema() throws Exception {
        Path jar = archive(Map.of("application.properties", bytes("spring.datasource.password=${DB_PASSWORD}")));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals(0, Main.run(new String[] {"--format", "json", jar.toString()}, new PrintStream(out), System.err));
        assertTrue(out.toString(StandardCharsets.UTF_8).startsWith("{\"schemaVersion\":2,\"complete\":true"));
    }

    @Test void structuredIssuesAndSummaryHaveStableMachineReadableFields() throws Exception {
        Report broken = new JarScanner().scan(archive(Map.of("broken.class", bytes("bad"))));
        assertEquals(Report.IssueCode.INVALID_CLASS, broken.issues().get(0).code());
        Report invalidText = new JarScanner().scan(archive(Map.of("bad.txt", new byte[] {(byte) 0xff})));
        assertEquals(Report.IssueCode.INVALID_TEXT, invalidText.issues().get(0).code());
        Report limited = new JarScanner(new JarScanner.Limits(10000, 1, 1000, 100, 2))
                .scan(archive(Map.of("x", bytes("long"))));
        assertEquals(Report.IssueCode.ENTRY_SIZE_LIMIT, limited.issues().get(0).code());
        Report report = new Report(java.util.List.of(new Finding(Finding.Severity.HIGH, "PRIVATE_KEY", "x.pem", "redacted")),
                java.util.List.of(new Report.Issue(Report.IssueCode.INVALID_TEXT, "x.txt", "unsupported")), 2);
        assertEquals("{\"schemaVersion\":2,\"complete\":false,\"entriesScanned\":2,\"summary\":{\"low\":0,\"medium\":0,\"high\":1,\"issues\":1},\"findings\":[{\"severity\":\"HIGH\",\"rule\":\"PRIVATE_KEY\",\"entry\":\"x.pem\",\"message\":\"redacted\"}],\"issues\":[{\"code\":\"INVALID_TEXT\",\"entry\":\"x.txt\",\"message\":\"unsupported\"}]}", Main.json(report));
    }

    private int cli(String... args) {
        return Main.run(args, new PrintStream(new ByteArrayOutputStream()), new PrintStream(new ByteArrayOutputStream()));
    }
    private byte[] compile(String debug, String content) throws IOException {
        Path source = temp.resolve("Sample.java");
        Files.writeString(source, content);
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, debug, "-d", temp.toString(), source.toString()));
        return Files.readAllBytes(temp.resolve("Sample.class"));
    }
    private Path archive(Map<String, byte[]> entries) throws IOException {
        Path path = Files.createTempFile(temp, "fixture-", ".jar");
        Files.write(path, zip(entries));
        return path;
    }
    private static byte[] zip(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (var entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static Set<String> rules(Report report) { return report.findings().stream().map(Finding::rule).collect(Collectors.toSet()); }
}
