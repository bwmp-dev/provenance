package dev.provenance.probe;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

final class Json {
  private Json() {}

  static String event(ProbeEvent event) {
    LinkedHashMap<String, Object> envelope = new LinkedHashMap<>();
    envelope.put("timestamp", event.timestamp().toString());
    envelope.put("type", event.type().name());
    envelope.put("data", event.data());
    return value(envelope);
  }

  static String value(Object value) {
    if (value == null) {
      return "null";
    }
    if (value instanceof String string) {
      return quote(string);
    }
    if (value instanceof Boolean || value instanceof Number) {
      return value.toString();
    }
    if (value instanceof Map<?, ?> map) {
      StringBuilder json = new StringBuilder("{");
      Iterator<? extends Map.Entry<?, ?>> entries = map.entrySet().iterator();
      while (entries.hasNext()) {
        Map.Entry<?, ?> entry = entries.next();
        json.append(quote(entry.getKey().toString())).append(':').append(value(entry.getValue()));
        if (entries.hasNext()) {
          json.append(',');
        }
      }
      return json.append('}').toString();
    }
    if (value instanceof Iterable<?> iterable) {
      StringBuilder json = new StringBuilder("[");
      Iterator<?> values = iterable.iterator();
      while (values.hasNext()) {
        json.append(value(values.next()));
        if (values.hasNext()) {
          json.append(',');
        }
      }
      return json.append(']').toString();
    }
    throw new IllegalArgumentException("unsupported JSON value: " + value.getClass().getName());
  }

  private static String quote(String value) {
    StringBuilder escaped = new StringBuilder(value.length() + 2).append('"');
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      switch (character) {
        case '"' -> escaped.append("\\\"");
        case '\\' -> escaped.append("\\\\");
        case '\b' -> escaped.append("\\b");
        case '\f' -> escaped.append("\\f");
        case '\n' -> escaped.append("\\n");
        case '\r' -> escaped.append("\\r");
        case '\t' -> escaped.append("\\t");
        default -> {
          if (character < 0x20) {
            escaped.append(String.format("\\u%04x", (int) character));
          } else {
            escaped.append(character);
          }
        }
      }
    }
    return escaped.append('"').toString();
  }
}
