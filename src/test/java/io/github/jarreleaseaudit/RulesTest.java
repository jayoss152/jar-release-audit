package io.github.jarreleaseaudit;

import org.junit.jupiter.api.Test;
import java.io.*;
import java.util.HashSet;
import static org.junit.jupiter.api.Assertions.*;

class RulesTest {
    @Test void catalogHasUniqueActionsAndProvidesUserVisibleGuidance() {
        var ids = new HashSet<String>();
        var actions = new HashSet<String>();
        for (var rule : Rules.all()) {
            assertTrue(ids.add(rule.id())); assertTrue(actions.add(rule.actionId()));
            assertEquals(rule, Rules.get(rule.id()));
            assertFalse(rule.action().isBlank()); assertFalse(rule.verify().isBlank());
            assertTrue(rule.reference().startsWith("https://github.com/jayoss152/jar-release-audit/"));
        }
        var out = new ByteArrayOutputStream();
        assertEquals(0, Main.run(new String[] {"--list-rules"}, new PrintStream(out), System.err));
        for (String id : ids) assertTrue(out.toString().contains(id));
        assertThrows(IllegalArgumentException.class, () -> Rules.get("invented-rule"));
    }
}
