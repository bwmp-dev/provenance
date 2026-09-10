package dev.provenance.probe;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

public final class ProbeConfiguration {
  private final String target;
  private final List<String> requiredDependencies;
  private final Path eventFile;
  private final Path testPlanFile;
  private final long stabilizationMillis;
  private final int maximumCommandOutputBytes;
  private final boolean requestShutdown;

  public ProbeConfiguration(
      String target,
      List<String> requiredDependencies,
      Path eventFile,
      Path testPlanFile,
      long stabilizationMillis,
      int maximumCommandOutputBytes,
      boolean requestShutdown) {

    requiredDependencies = Java8.listCopy(requiredDependencies);
    if (stabilizationMillis < 0) {
      throw new IllegalArgumentException("stabilizationMillis must not be negative");
    }
    if (maximumCommandOutputBytes < 1_024 || maximumCommandOutputBytes > 16_384) {
      throw new IllegalArgumentException(
          "maximumCommandOutputBytes must be between 1024 and 16384");
    }

    this.target = target;
    this.requiredDependencies = requiredDependencies;
    this.eventFile = eventFile;
    this.testPlanFile = testPlanFile;
    this.stabilizationMillis = stabilizationMillis;
    this.maximumCommandOutputBytes = maximumCommandOutputBytes;
    this.requestShutdown = requestShutdown;
  }

  public String target() {
    return target;
  }

  public List<String> requiredDependencies() {
    return requiredDependencies;
  }

  public Path eventFile() {
    return eventFile;
  }

  public Path testPlanFile() {
    return testPlanFile;
  }

  public long stabilizationMillis() {
    return stabilizationMillis;
  }

  public int maximumCommandOutputBytes() {
    return maximumCommandOutputBytes;
  }

  public boolean requestShutdown() {
    return requestShutdown;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof ProbeConfiguration)) return false;
    ProbeConfiguration that = (ProbeConfiguration) other;
    return java.util.Objects.equals(target, that.target)
        && java.util.Objects.equals(requiredDependencies, that.requiredDependencies)
        && java.util.Objects.equals(eventFile, that.eventFile)
        && java.util.Objects.equals(testPlanFile, that.testPlanFile)
        && java.util.Objects.equals(stabilizationMillis, that.stabilizationMillis)
        && java.util.Objects.equals(maximumCommandOutputBytes, that.maximumCommandOutputBytes)
        && java.util.Objects.equals(requestShutdown, that.requestShutdown);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(
        target,
        requiredDependencies,
        eventFile,
        testPlanFile,
        stabilizationMillis,
        maximumCommandOutputBytes,
        requestShutdown);
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
        Java8.listCopy(dependencies),
        java.nio.file.Paths.get(
            System.getProperty("provenance.probe.events", "provenance-probe-events.ndjson")),
        java.nio.file.Paths.get(
            System.getProperty("provenance.probe.testPlan", "provenance-test-plan.json")),
        stabilizationMillis,
        Integer.parseInt(System.getProperty("provenance.probe.maximumCommandOutputBytes", "4096")),
        Boolean.parseBoolean(System.getProperty("provenance.probe.requestShutdown", "true")));
  }

  private static String trimToNull(String value) {
    if (value == null || Java8.isBlank(value)) {
      return null;
    }
    return value.trim();
  }
}
