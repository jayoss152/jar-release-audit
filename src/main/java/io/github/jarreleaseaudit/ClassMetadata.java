package io.github.jarreleaseaudit;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Set;
import java.util.TreeSet;

/** Reads actual class attributes; a string literal called LineNumberTable is not evidence. */
final class ClassMetadata {
    private enum Location { CLASS, FIELD, METHOD, CODE }
    private static final Set<String> DEBUG = Set.of("SourceFile", "SourceDebugExtension", "LineNumberTable", "LocalVariableTable", "LocalVariableTypeTable", "MethodParameters");
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
            members(in, pool, found, Location.FIELD);
            members(in, pool, found, Location.METHOD);
            attributes(in, pool, found, Location.CLASS);
            if (in.available() != 0) throw new IOException("Trailing class data");
            return found;
        }
    }

    private static void members(DataInputStream in, String[] pool, Set<String> found, Location location) throws IOException {
        int count = in.readUnsignedShort();
        for (int i = 0; i < count; i++) {
            skip(in, 6);
            attributes(in, pool, found, location);
        }
    }

    private static void attributes(DataInputStream in, String[] pool, Set<String> found, Location location)
            throws IOException {
        int count = in.readUnsignedShort();
        Set<String> unique = new java.util.HashSet<>();
        for (int i = 0; i < count; i++) {
            int index = in.readUnsignedShort();
            if (index == 0 || index >= pool.length || pool[index] == null) throw new IOException("Invalid attribute name");
            String name = pool[index];
            long length = Integer.toUnsignedLong(in.readInt());
            if (length > in.available()) throw new IOException("Truncated attribute");
            if (DEBUG.contains(name)) {
                byte[] body = in.readNBytes((int) length);
                validateDebug(name, body, pool, location);
                if ((name.equals("SourceFile") || name.equals("MethodParameters")) && !unique.add(name))
                    throw new IOException("Duplicate debug attribute");
                found.add(name);
                continue;
            }
            if (location == Location.METHOD && name.equals("Code")) {
                byte[] code = in.readNBytes((int) length);
                try (DataInputStream body = new DataInputStream(new ByteArrayInputStream(code))) {
                    skip(body, 4);
                    skip(body, Integer.toUnsignedLong(body.readInt()));
                    skip(body, 8L * body.readUnsignedShort());
                    attributes(body, pool, found, Location.CODE);
                    if (body.available() != 0) throw new IOException("Invalid Code attribute");
                }
            } else {
                skip(in, length);
            }
        }
    }

    private static void validateDebug(String name, byte[] bytes, String[] pool, Location location) throws IOException {
        try (var in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (name.equals("SourceFile")) {
                if (location != Location.CLASS || bytes.length != 2) throw new IOException("Invalid SourceFile shape");
                utf(pool, in.readUnsignedShort(), false);
            } else if (name.equals("SourceDebugExtension")) {
                if (location != Location.CLASS) throw new IOException("Invalid source debug location");
                return;
            } else if (name.equals("MethodParameters")) {
                if (location != Location.METHOD) throw new IOException("Invalid parameter location");
                int count = in.readUnsignedByte();
                if (bytes.length != 1 + count * 4) throw new IOException("Invalid parameter table length");
                for (int i = 0; i < count; i++) { utf(pool, in.readUnsignedShort(), true); in.readUnsignedShort(); }
            } else {
                if (location != Location.CODE) throw new IOException("Invalid code debug location");
                int count = in.readUnsignedShort(), width = name.equals("LineNumberTable") ? 4 : 10;
                if (bytes.length != 2 + count * width) throw new IOException("Invalid debug table length");
                for (int i = 0; i < count; i++) {
                    skip(in, 4);
                    if (width == 10) { utf(pool, in.readUnsignedShort(), false); utf(pool, in.readUnsignedShort(), false); skip(in, 2); }
                }
            }
        }
    }
    private static void utf(String[] pool, int index, boolean allowZero) throws IOException {
        if (allowZero && index == 0) return;
        if (index <= 0 || index >= pool.length || pool[index] == null) throw new IOException("Invalid debug constant reference");
    }

    private static void skip(DataInputStream in, long length) throws IOException {
        if (length < 0 || length > in.available()) throw new IOException("Truncated class data");
        in.skipNBytes(length);
    }
}
