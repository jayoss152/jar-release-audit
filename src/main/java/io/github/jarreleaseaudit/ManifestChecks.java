package io.github.jarreleaseaudit;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.jar.Manifest;

final class ManifestChecks {
    private ManifestChecks() { }
    static boolean externalClasspath(byte[] bytes) throws IOException {
        if (bytes.length > 65536) throw new IOException("Manifest size limit");
        String value = new Manifest(new ByteArrayInputStream(bytes)).getMainAttributes().getValue("Class-Path");
        if (value == null || value.isBlank()) return false;
        for (String token : value.strip().split("\\s+")) {
            try {
                URI uri = new URI(token);
                String path = uri.getPath();
                if (uri.isAbsolute() || uri.getRawAuthority() != null || (path != null &&
                        (path.startsWith("/") || Arrays.asList(path.split("/", -1)).contains("..")))) return true;
            } catch (URISyntaxException e) { throw new IOException("Malformed manifest classpath"); }
        }
        return false;
    }
}
