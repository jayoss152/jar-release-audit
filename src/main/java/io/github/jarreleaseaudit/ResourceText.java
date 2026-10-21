package io.github.jarreleaseaudit;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Explicit supported encodings; never silently replace malformed credential text. */
final class ResourceText {
    private ResourceText() { }

    static String decode(byte[] bytes) throws IOException {
        int offset = 0;
        Charset charset = StandardCharsets.UTF_8;
        if (starts(bytes, 0xff, 0xfe, 0, 0) || starts(bytes, 0, 0, 0xfe, 0xff))
            throw new IOException("Unsupported UTF-32 text");
        if (starts(bytes, 0xef, 0xbb, 0xbf)) offset = 3;
        else if (starts(bytes, 0xff, 0xfe)) { offset = 2; charset = StandardCharsets.UTF_16LE; }
        else if (starts(bytes, 0xfe, 0xff)) { offset = 2; charset = StandardCharsets.UTF_16BE; }
        String text = charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes, offset, bytes.length - offset)).toString();
        if (text.indexOf('\0') >= 0) throw new IOException("NUL in text resource or unsupported encoding");
        return text;
    }

    private static boolean starts(byte[] bytes, int... prefix) {
        if (bytes.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if ((bytes[i] & 255) != prefix[i]) return false;
        return true;
    }
}
