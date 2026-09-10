package dev.provenance.probe;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ProbeEvent {
  private final Instant timestamp;
  private final EventType type;
  private final Map<String, Object> data;

  public ProbeEvent(Instant timestamp, EventType type, Map<String, Object> data) {

    data = Collections.unmodifiableMap(new LinkedHashMap<>(data));

    this.timestamp = timestamp;
    this.type = type;
    this.data = data;
  }

  public Instant timestamp() {
    return timestamp;
  }

  public EventType type() {
    return type;
  }

  public Map<String, Object> data() {
    return data;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof ProbeEvent)) return false;
    ProbeEvent that = (ProbeEvent) other;
    return java.util.Objects.equals(timestamp, that.timestamp)
        && java.util.Objects.equals(type, that.type)
        && java.util.Objects.equals(data, that.data);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(timestamp, type, data);
  }

  public static ProbeEvent now(EventType type, Map<String, Object> data) {
    return new ProbeEvent(Instant.now(), type, data);
  }
}
