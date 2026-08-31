package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class CommandOutputCaptureTest {
  @Test
  void normalizesPlainOutputAndFormattingCodes() {
    CommandOutputCapture output = new CommandOutputCapture(100);

    output.append("\u00a7aCafe\u0301\r\nline\u0001");

    assertEquals("Café\nline\ufffd", output.text());
    assertEquals(List.of("Café", "line\ufffd"), output.lines());
  }

  @Test
  void truncatesOnlyAtUtf8CodePointBoundaries() {
    CommandOutputCapture output = new CommandOutputCapture(5);

    output.append("ééé");

    assertEquals("éé", output.text());
    assertEquals(4, output.capturedBytes());
    assertEquals(6, output.observedBytes());
    assertTrue(output.truncated());
  }
}
