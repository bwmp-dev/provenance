package dev.provenance.probe;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

public record MetadataInspection(
    Path source, MetadataStatus status, PluginDescriptor descriptor, List<String> issues) {
  public MetadataInspection {
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(status, "status");
    issues =
        issues.stream()
            .map(issue -> Objects.requireNonNull(issue, "issue"))
            .distinct()
            .sorted()
            .toList();
    if ((status == MetadataStatus.VALID) != (descriptor != null)) {
      throw new IllegalArgumentException("only valid metadata has a descriptor");
    }
    if ((status == MetadataStatus.VALID) != issues.isEmpty()) {
      throw new IllegalArgumentException("valid metadata must not have issues");
    }
  }
}
