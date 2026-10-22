package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.jarreleaseaudit.Fixtures.*;

class StructuredConfigTest {
    @TempDir Path temp;
    @Test void jsonSecretsAreFoundInSingleLinesArraysAndEscapedKeys() throws Exception {
        for (String json : new String[] {"{\"server\":{\"password\":\"synthetic-canary\"}}", "[{\"api_key\":\"synthetic-canary\"}]",
                "{\"pa\\u0073sword\":\"synthetic-canary\"}", "{\"token\":42}"}) {
            var r = new JarScanner().scan(jar(temp, Map.of("config.json", bytes(json))));
            assertTrue(r.complete());
            assertEquals("SECRET_ASSIGNMENT", r.findings().get(0).rule());
            assertFalse(Main.json(r).contains("synthetic-canary"));
        }
        assertTrue(new JarScanner().scan(jar(temp, Map.of("config.json", bytes("{\"password\":\"${PASSWORD}\"}")))).findings().isEmpty());
    }
    @Test void strictJsonRejectsAmbiguityBadUnicodeAndResourceExhaustion() throws Exception {
        for (String bad : new String[] {"{\"x\":null,\"x\":1}", "[01]", "[1,]", "\"\\ud800\"", "[".repeat(34) + "0" + "]".repeat(34)})
            assertThrows(java.io.IOException.class, () -> Json.parse(bad));
        Object value = Json.parse("{\"x\":[true,false,null,1.25,\"\\ud83d\\ude00\"]}");
        assertEquals(value, Json.parse(Json.write(value)));
        assertFalse(new JarScanner().scan(jar(temp, Map.of("bad.json", bytes("{\"x\":1,\"x\":2}")))).complete());
    }
    @Test void xmlCredentialsRespectPropertiesSyntaxWithoutEntities() throws Exception {
        for (String xml : new String[] {"<config><password>synthetic-value</password></config>",
                "<properties><entry key='api_key'>synthetic-value</entry></properties>",
                "<beans><property name='spring.datasource.password' value='synthetic-value'/></beans>"}) {
            var r = new JarScanner().scan(jar(temp, Map.of("config.xml", bytes(xml))));
            assertTrue(r.complete());
            assertEquals("SECRET_ASSIGNMENT", r.findings().get(0).rule());
            assertFalse(Main.json(r).contains("synthetic-value"));
        }
        assertFalse(XmlCredentials.inspect("<config><password>${PASSWORD}</password></config>"));
        assertThrows(java.io.IOException.class, () -> XmlCredentials.inspect("<!DOCTYPE x [<!ENTITY ext SYSTEM 'http://127.0.0.1:9/forbidden'>]><x>&ext;</x>"));
        assertFalse(new JarScanner().scan(jar(temp, Map.of("bad.xml", bytes("<unclosed>")))).complete());
    }
}
