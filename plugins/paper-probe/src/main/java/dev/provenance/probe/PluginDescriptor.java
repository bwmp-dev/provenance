package dev.provenance.probe;

import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class PluginDescriptor {
  private final String name;
  private final String version;
  private final String mainClass;
  private final String apiVersion;
  private final List<String> requiredDependencies;
  private final List<String> softDependencies;
  private final List<String> loadBeforeDependencies;
  private final List<String> permissions;
  private final List<String> commands;
  private final Path source;

  public PluginDescriptor(
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

    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(version, "version");
    Objects.requireNonNull(mainClass, "mainClass");
    Objects.requireNonNull(source, "source");
    requiredDependencies = canonicalCopy(requiredDependencies);
    softDependencies = canonicalCopy(softDependencies);
    loadBeforeDependencies = canonicalCopy(loadBeforeDependencies);
    permissions = canonicalCopy(permissions);
    commands = canonicalCopy(commands);

    this.name = name;
    this.version = version;
    this.mainClass = mainClass;
    this.apiVersion = apiVersion;
    this.requiredDependencies = requiredDependencies;
    this.softDependencies = softDependencies;
    this.loadBeforeDependencies = loadBeforeDependencies;
    this.permissions = permissions;
    this.commands = commands;
    this.source = source;
  }

  public String name() {
    return name;
  }

  public String version() {
    return version;
  }

  public String mainClass() {
    return mainClass;
  }

  public String apiVersion() {
    return apiVersion;
  }

  public List<String> requiredDependencies() {
    return requiredDependencies;
  }

  public List<String> softDependencies() {
    return softDependencies;
  }

  public List<String> loadBeforeDependencies() {
    return loadBeforeDependencies;
  }

  public List<String> permissions() {
    return permissions;
  }

  public List<String> commands() {
    return commands;
  }

  public Path source() {
    return source;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof PluginDescriptor)) return false;
    PluginDescriptor that = (PluginDescriptor) other;
    return java.util.Objects.equals(name, that.name)
        && java.util.Objects.equals(version, that.version)
        && java.util.Objects.equals(mainClass, that.mainClass)
        && java.util.Objects.equals(apiVersion, that.apiVersion)
        && java.util.Objects.equals(requiredDependencies, that.requiredDependencies)
        && java.util.Objects.equals(softDependencies, that.softDependencies)
        && java.util.Objects.equals(loadBeforeDependencies, that.loadBeforeDependencies)
        && java.util.Objects.equals(permissions, that.permissions)
        && java.util.Objects.equals(commands, that.commands)
        && java.util.Objects.equals(source, that.source);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(
        name,
        version,
        mainClass,
        apiVersion,
        requiredDependencies,
        softDependencies,
        loadBeforeDependencies,
        permissions,
        commands,
        source);
  }

  private static final Comparator<String> CANONICAL_ORDER =
      Comparator.comparing((String value) -> value.toLowerCase(Locale.ROOT))
          .thenComparing(Comparator.naturalOrder());

  private static List<String> canonicalCopy(List<String> values) {
    return values.stream()
        .map(value -> Objects.requireNonNull(value, "list value"))
        .sorted(CANONICAL_ORDER)
        .collect(Java8.toList());
  }
}
