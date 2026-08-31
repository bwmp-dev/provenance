package dev.provenance.probe;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

public record ProbeConfiguration(
    String target,
    List<String> requiredDependencies,
    Path eventFile,
    long stabilizationMillis,
    boolean requestShutdown) {
  public ProbeConfiguration {
    requiredDependencies = List.copyOf(requiredDependencies);
    if (stabilizationMillis < 0) {
      throw new IllegalArgumentException("stabilizationMillis must not be negative");
    }
  }

  public static ProbeConfiguration fromSystemProperties() {
    String target = trimToNull(System.getProperty("provenance.probe.target"));
    String dependencyProperty = System.getProperty("provenance.probe.requiredDependencies", "");
    LinkedHashSet<String> dependencies = new LinkedHashSet<>();
    Arrays.stream(dependencyProperty.split(","))
        .map(String::trim)
        .filter(value -> !value.isEmpty())
        .forEach(dependencies::add);
    long stabilizationMillis =
        Long.parseLong(System.getProperty("provenance.probe.stabilizationMillis", "3000"));
    return new ProbeConfiguration(
        target,
        List.copyOf(dependencies),
        Path.of(System.getProperty("provenance.probe.events", "provenance-probe-events.ndjson")),
        stabilizationMillis,
        Boolean.parseBoolean(System.getProperty("provenance.probe.requestShutdown", "true")));
  }

  private static String trimToNull(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return value.trim();
  }
}
