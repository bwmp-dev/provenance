package dev.provenance.probe;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public record ProbeEvent(Instant timestamp, EventType type, Map<String, Object> data) {
  public ProbeEvent {
    data = Collections.unmodifiableMap(new LinkedHashMap<>(data));
  }

  public static ProbeEvent now(EventType type, Map<String, Object> data) {
    return new ProbeEvent(Instant.now(), type, data);
  }
}
