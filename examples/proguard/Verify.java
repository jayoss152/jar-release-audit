import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipFile;

/** Run from repository root after the scanner build and optional Maven dependency step. */
class Verify {
    public static void main(String[] args) throws Exception {
        Path root = Path.of("").toAbsolutePath();
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        if (System.getProperty("os.name").startsWith("Windows")) java = java.resolveSibling("java.exe");
        run(java, "examples/demo/Demo.java");
        String classpath = Files.readString(root.resolve("examples/proguard/target/classpath.txt")).strip();
        run(java, "-cp", classpath, "proguard.ProGuard", "@examples/proguard-demo.pro");
        String original = run(java, "-cp", "examples/demo/target/hardened.jar", "Hello").strip();
        String obfuscated = run(java, "-cp", "examples/demo/target/obfuscated.jar", "Hello").strip();
        if (!original.equals("hello release") || !original.equals(obfuscated))
            throw new IllegalStateException("Application behavior changed after obfuscation");
        try (ZipFile zip = new ZipFile(root.resolve("examples/demo/target/obfuscated.jar").toFile())) {
            if (zip.getEntry("Greeting.class") != null || zip.getEntry("Hello.class") == null
                    || zip.stream().filter(e -> e.getName().endsWith(".class")).count() != 2)
                throw new IllegalStateException("Expected a renamed helper and preserved entry point");
        }
        run(java, "-jar", "target/jar-release-audit-0.1.0.jar", "--fail-on", "low", "examples/demo/target/obfuscated.jar");
        System.out.println("Verified ProGuard 7.10.0: helper renamed, entry point runs, hardened audit passes.");
    }

    private static String run(Path java, String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(java.toString());
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (process.waitFor() != 0) {
            System.err.print(output);
            throw new IllegalStateException("Demo command failed");
        }
        return output;
    }
}
