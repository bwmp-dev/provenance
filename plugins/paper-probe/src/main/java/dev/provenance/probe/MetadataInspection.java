package dev.provenance.probe;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

public final class MetadataInspection {
  private final Path source;
  private final MetadataStatus status;
  private final PluginDescriptor descriptor;
  private final List<String> issues;

  public MetadataInspection(
      Path source, MetadataStatus status, PluginDescriptor descriptor, List<String> issues) {

    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(status, "status");
    issues =
        issues.stream()
            .map(issue -> Objects.requireNonNull(issue, "issue"))
            .distinct()
            .sorted()
            .collect(Java8.toList());
    if ((status == MetadataStatus.VALID) != (descriptor != null)) {
      throw new IllegalArgumentException("only valid metadata has a descriptor");
    }
    if ((status == MetadataStatus.VALID) != issues.isEmpty()) {
      throw new IllegalArgumentException("valid metadata must not have issues");
    }

    this.source = source;
    this.status = status;
    this.descriptor = descriptor;
    this.issues = issues;
  }

  public Path source() {
    return source;
  }

  public MetadataStatus status() {
    return status;
  }

  public PluginDescriptor descriptor() {
    return descriptor;
  }

  public List<String> issues() {
    return issues;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof MetadataInspection)) return false;
    MetadataInspection that = (MetadataInspection) other;
    return java.util.Objects.equals(source, that.source)
        && java.util.Objects.equals(status, that.status)
        && java.util.Objects.equals(descriptor, that.descriptor)
        && java.util.Objects.equals(issues, that.issues);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(source, status, descriptor, issues);
  }
}
