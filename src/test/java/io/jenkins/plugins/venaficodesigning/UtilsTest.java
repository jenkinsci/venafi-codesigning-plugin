package io.jenkins.plugins.venaficodesigning;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;

public class UtilsTest {
    @Test
    public void testParseStringAsNewlineDelimitedList() {
        assertEquals(0,
            Utils.parseStringAsNewlineDelimitedList("").size());
        assertEquals(0,
            Utils.parseStringAsNewlineDelimitedList("\n\n").size());

        assertEquals(Arrays.asList("hello"),
            Utils.parseStringAsNewlineDelimitedList("hello"));
        assertEquals(Arrays.asList("hello"),
            Utils.parseStringAsNewlineDelimitedList("hello\n\n"));

        assertEquals(Arrays.asList("hello", "world", "hm"),
            Utils.parseStringAsNewlineDelimitedList("hello\nworld\n\nhm"));

        assertEquals(Arrays.asList("hello", "world", "hm"),
            Utils.parseStringAsNewlineDelimitedList("  hello\nworld \t\n\n\thm\n\n"));
    }
}
