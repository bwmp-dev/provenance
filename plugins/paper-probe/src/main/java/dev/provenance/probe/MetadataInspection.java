package dev.provenance.probe;

import java.nio.file.Path;
import java.util.List;

public record MetadataInspection(
    Path source, MetadataStatus status, PluginDescriptor descriptor, List<String> issues) {
  public MetadataInspection {
    issues = List.copyOf(issues);
    if ((status == MetadataStatus.VALID) != (descriptor != null)) {
      throw new IllegalArgumentException("only valid metadata has a descriptor");
    }
  }
}
