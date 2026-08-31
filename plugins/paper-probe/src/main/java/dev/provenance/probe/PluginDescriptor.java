package dev.provenance.probe;

import java.nio.file.Path;
import java.util.List;

public record PluginDescriptor(
    String name,
    String version,
    String mainClass,
    String apiVersion,
    List<String> requiredDependencies,
    List<String> permissions,
    List<String> commands,
    Path source) {
  public PluginDescriptor {
    requiredDependencies = List.copyOf(requiredDependencies);
    permissions = List.copyOf(permissions);
    commands = List.copyOf(commands);
  }
}
