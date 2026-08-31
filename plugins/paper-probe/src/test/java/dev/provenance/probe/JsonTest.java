package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.LinkedHashMap;
import org.junit.jupiter.api.Test;

class JsonTest {
  @Test
  void serializesEventEnvelopeAndEscapesValuesDeterministically() {
    LinkedHashMap<String, Object> data = new LinkedHashMap<>();
    data.put("plugin", "Example\nPlugin");
    data.put("enabled", true);
    data.put("message", null);

    String json =
        Json.event(
            new ProbeEvent(Instant.parse("2026-01-02T03:04:05Z"), EventType.PLUGIN_STATE, data));

    assertEquals(
        "{\"timestamp\":\"2026-01-02T03:04:05Z\",\"type\":\"PLUGIN_STATE\","
            + "\"data\":{\"plugin\":\"Example\\nPlugin\",\"enabled\":true,\"message\":null}}",
        json);
  }
}
