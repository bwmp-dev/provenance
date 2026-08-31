package dev.provenance.probe;

import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public record PluginDescriptor(
    String name,
    String version,
    String mainClass,
    String apiVersion,
    List<String> requiredDependencies,
    List<String> softDependencies,
    List<String> loadBeforeDependencies,
    List<String> permissions,
    List<String> commands,
    Path source) {
  private static final Comparator<String> CANONICAL_ORDER =
      Comparator.comparing((String value) -> value.toLowerCase(Locale.ROOT))
          .thenComparing(Comparator.naturalOrder());

  public PluginDescriptor {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(version, "version");
    Objects.requireNonNull(mainClass, "mainClass");
    Objects.requireNonNull(source, "source");
    requiredDependencies = canonicalCopy(requiredDependencies);
    softDependencies = canonicalCopy(softDependencies);
    loadBeforeDependencies = canonicalCopy(loadBeforeDependencies);
    permissions = canonicalCopy(permissions);
    commands = canonicalCopy(commands);
  }

  private static List<String> canonicalCopy(List<String> values) {
    return values.stream()
        .map(value -> Objects.requireNonNull(value, "list value"))
        .sorted(CANONICAL_ORDER)
        .toList();
  }
}
