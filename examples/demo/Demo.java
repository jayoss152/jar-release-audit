import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Run from repository root: java examples/demo/Demo.java */
class Demo {
    public static void main(String[] args) throws Exception {
        Path dir = Path.of("examples/demo/target");
        Files.createDirectories(dir);
        String source = "public class Hello { public static void main(String[] args) { System.out.println(\"hello release\"); } }\n";
        Path java = dir.resolve("Hello.java");
        Files.writeString(java, source);
        compile(dir, java, "-g");
        Map<String, byte[]> leaky = new LinkedHashMap<>();
        leaky.put("Hello.class", Files.readAllBytes(dir.resolve("Hello.class")));
        leaky.put("Hello.java", source.getBytes(StandardCharsets.UTF_8));
        leaky.put("application.properties", "password=demo-not-a-real-password\n".getBytes(StandardCharsets.UTF_8));
        jar(dir.resolve("leaky.jar"), leaky);
        compile(dir, java, "-g:none");
        Map<String, byte[]> hardened = new LinkedHashMap<>();
        hardened.put("Hello.class", Files.readAllBytes(dir.resolve("Hello.class")));
        hardened.put("application.properties", "password=${DB_PASSWORD}\n".getBytes(StandardCharsets.UTF_8));
        jar(dir.resolve("hardened.jar"), hardened);
        System.out.println("Created examples/demo/target/{leaky,hardened}.jar (synthetic fixtures only).");
    }

    private static void compile(Path dir, Path source, String debug) {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("A JDK is required");
        if (compiler.run(null, null, null, "--release", "17", debug, "-d", dir.toString(), source.toString()) != 0)
            throw new IllegalStateException("Compilation failed");
    }

    private static void jar(Path target, Map<String, byte[]> files) throws Exception {
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target))) {
            for (var file : files.entrySet()) {
                ZipEntry entry = new ZipEntry(file.getKey());
                entry.setTimeLocal(java.time.LocalDateTime.of(1980, 1, 1, 0, 0));
                zip.putNextEntry(entry);
                zip.write(file.getValue());
                zip.closeEntry();
            }
        }
    }
}
