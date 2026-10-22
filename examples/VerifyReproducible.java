import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** From repository root after mvn verify: checks forced packaging without deleting user files. */
class VerifyReproducible {
    public static void main(String[] args) throws Exception {
        Path artifact = Path.of("target/jar-release-audit-0.1.0.jar");
        String before = sha256(artifact);
        List<String> command = new ArrayList<>();
        if (System.getProperty("os.name").startsWith("Windows")) command.addAll(List.of("cmd.exe", "/d", "/c"));
        command.addAll(List.of("mvn", "-o", "-B", "-ntp", "-DskipTests", "-Dmaven.jar.forceCreation=true", "package"));
        if (new ProcessBuilder(command).inheritIO().start().waitFor() != 0) throw new IllegalStateException("Forced offline packaging failed");
        String after = sha256(artifact);
        if (!before.equals(after)) throw new IllegalStateException("Packaged JAR bytes changed during same-toolchain repackaging");
        System.out.println("Verified byte-identical forced JAR repackaging: " + after);
    }
    private static String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var in = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192]; int n;
            while ((n = in.read(buffer)) != -1) digest.update(buffer, 0, n);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
