package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import java.io.*;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class ClassStructureTest {
    private byte[] sourceAttribute(byte[] body, boolean twice) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(bytes)) {
            out.writeInt(0xcafebabe); out.writeShort(0); out.writeShort(61); out.writeShort(7);
            out.writeByte(1); out.writeUTF("Sample"); out.writeByte(7); out.writeShort(1);
            out.writeByte(1); out.writeUTF("java/lang/Object"); out.writeByte(7); out.writeShort(3);
            out.writeByte(1); out.writeUTF("SourceFile"); out.writeByte(1); out.writeUTF("Sample.java");
            out.writeShort(0x21); out.writeShort(2); out.writeShort(4);
            out.writeShort(0); out.writeShort(0); out.writeShort(0); out.writeShort(twice ? 2 : 1);
            for (int i = 0; i < (twice ? 2 : 1); i++) { out.writeShort(5); out.writeInt(body.length); out.write(body); }
        }
        return bytes.toByteArray();
    }
    @Test void debugAttributesRequireValidBodiesReferencesAndMultiplicity() throws Exception {
        assertEquals(Set.of("SourceFile"), ClassMetadata.debugAttributes(sourceAttribute(new byte[] {0,6}, false)));
        assertThrows(IOException.class, () -> ClassMetadata.debugAttributes(sourceAttribute(new byte[0], false)));
        assertThrows(IOException.class, () -> ClassMetadata.debugAttributes(sourceAttribute(new byte[] {0,2}, false)));
        assertThrows(IOException.class, () -> ClassMetadata.debugAttributes(sourceAttribute(new byte[] {0,6}, true)));
    }
}
