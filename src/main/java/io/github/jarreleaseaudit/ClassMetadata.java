package io.github.jarreleaseaudit;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Set;
import java.util.TreeSet;

/** Reads actual class attributes; a string literal called LineNumberTable is not evidence. */
final class ClassMetadata {
    private ClassMetadata() { }

    static Set<String> debugAttributes(byte[] bytes) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (in.readInt() != 0xCAFEBABE) throw new IOException("Invalid class magic");
            in.readUnsignedShort();
            in.readUnsignedShort();
            int count = in.readUnsignedShort();
            if (count == 0) throw new IOException("Invalid constant pool");
            String[] pool = new String[count];
            for (int i = 1; i < count; i++) {
                switch (in.readUnsignedByte()) {
                    case 1 -> pool[i] = in.readUTF();
                    case 3, 4, 9, 10, 11, 12, 17, 18 -> skip(in, 4);
                    case 5, 6 -> {
                        skip(in, 8);
                        if (++i >= count) throw new IOException("Invalid wide constant");
                    }
                    case 7, 8, 16, 19, 20 -> skip(in, 2);
                    case 15 -> skip(in, 3);
                    default -> throw new IOException("Unknown constant pool tag");
                }
            }
            skip(in, 6);
            skip(in, 2L * in.readUnsignedShort());
            Set<String> found = new TreeSet<>();
            members(in, pool, found);
            members(in, pool, found);
            attributes(in, pool, found, false);
            if (in.available() != 0) throw new IOException("Trailing class data");
            return found;
        }
    }

    private static void members(DataInputStream in, String[] pool, Set<String> found) throws IOException {
        int count = in.readUnsignedShort();
        for (int i = 0; i < count; i++) {
            skip(in, 6);
            attributes(in, pool, found, true);
        }
    }

    private static void attributes(DataInputStream in, String[] pool, Set<String> found, boolean allowCode)
            throws IOException {
        int count = in.readUnsignedShort();
        for (int i = 0; i < count; i++) {
            int index = in.readUnsignedShort();
            if (index == 0 || index >= pool.length || pool[index] == null) throw new IOException("Invalid attribute name");
            String name = pool[index];
            long length = Integer.toUnsignedLong(in.readInt());
            if (length > in.available()) throw new IOException("Truncated attribute");
            if (Set.of("SourceFile", "SourceDebugExtension", "LineNumberTable", "LocalVariableTable",
                    "LocalVariableTypeTable", "MethodParameters").contains(name)) found.add(name);
            if (allowCode && name.equals("Code")) {
                byte[] code = in.readNBytes((int) length);
                try (DataInputStream body = new DataInputStream(new ByteArrayInputStream(code))) {
                    skip(body, 4);
                    skip(body, Integer.toUnsignedLong(body.readInt()));
                    skip(body, 8L * body.readUnsignedShort());
                    attributes(body, pool, found, false);
                    if (body.available() != 0) throw new IOException("Invalid Code attribute");
                }
            } else {
                skip(in, length);
            }
        }
    }

    private static void skip(DataInputStream in, long length) throws IOException {
        if (length < 0 || length > in.available()) throw new IOException("Truncated class data");
        in.skipNBytes(length);
    }
}
