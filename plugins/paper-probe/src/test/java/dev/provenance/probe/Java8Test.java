package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class Java8Test {
  @Test
  void immutableCopiesRetainValueSemantics() {
    List<String> source = new ArrayList<>(List.of("one"));
    List<String> copy = Java8.listCopy(source);
    source.add("two");
    assertEquals(List.of("one"), copy);
    assertThrows(UnsupportedOperationException.class, () -> copy.add("three"));
    assertThrows(NullPointerException.class, () -> Java8.listCopy(Arrays.asList("one", null)));
    assertThrows(IllegalArgumentException.class, () -> Java8.map("a", 1, "a", 2));
    assertThrows(IllegalArgumentException.class, () -> Java8.set("a", "a"));
    assertEquals(new PluginSnapshot("test", true, false), new PluginSnapshot("test", true, false));
    assertEquals(
        new PluginSnapshot("test", true, false).hashCode(),
        new PluginSnapshot("test", true, false).hashCode());
    assertNotEquals(
        new PluginSnapshot("test", true, false), new PluginSnapshot("test", true, true));
  }

  @Test
  void linesMatchModernJavaIncludingEmptyAndTrailingLines() {
    for (String value : List.of("", "\n", "a\n", "a\r\nb\rc\n", "\n\n", "a"))
      assertEquals(value.lines().toList(), Java8.lines(value));
    assertTrue(Java8.isBlank("\u2003\t\n"));
    assertFalse(Java8.isBlank(" x "));
  }

  @Test
  void boundedReadsAndHexMatchModernJava() throws Exception {
    byte[] bytes = new byte[] {0, 1, 127, -128, -1};
    assertArrayEquals(new byte[] {0, 1}, Java8.readNBytes(new ByteArrayInputStream(bytes), 2));
    assertArrayEquals(bytes, Java8.readNBytes(new ByteArrayInputStream(bytes), 20));
    assertEquals("00017f80ff", Java8.hex(bytes));
  }
}
