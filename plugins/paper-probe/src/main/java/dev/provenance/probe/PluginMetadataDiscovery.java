package dev.provenance.probe;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

public final class PluginMetadataDiscovery {
  public List<MetadataInspection> inspectDirectory(Path pluginsDirectory) throws IOException {
    if (!Files.isDirectory(pluginsDirectory)) {
      return List.of();
    }
    List<Path> jars;
    try (var paths = Files.list(pluginsDirectory)) {
      jars =
          paths
              .filter(Files::isRegularFile)
              .filter(path -> path.getFileName().toString().toLowerCase().endsWith(".jar"))
              .sorted(Comparator.comparing(path -> path.getFileName().toString()))
              .toList();
    }
    return jars.stream().map(this::inspect).toList();
  }

  public List<PluginDescriptor> discover(Path pluginsDirectory) throws IOException {
    return inspectDirectory(pluginsDirectory).stream()
        .filter(inspection -> inspection.status() == MetadataStatus.VALID)
        .map(MetadataInspection::descriptor)
        .toList();
  }

  public MetadataInspection inspect(Path jarPath) {
    try (JarFile jar = new JarFile(jarPath.toFile())) {
      JarEntry metadata = jar.getJarEntry("plugin.yml");
      boolean paperMetadata = false;
      if (metadata == null) {
        metadata = jar.getJarEntry("paper-plugin.yml");
        paperMetadata = true;
      }
      if (metadata == null) {
        return new MetadataInspection(
            jarPath, MetadataStatus.MISSING, null, List.of("plugin metadata is missing"));
      }
      try (InputStream input = jar.getInputStream(metadata)) {
        return parse(input, jarPath, paperMetadata);
      }
    } catch (IOException | RuntimeException exception) {
      return new MetadataInspection(
          jarPath,
          MetadataStatus.INVALID,
          null,
          List.of("could not read plugin metadata: " + exception.getMessage()));
    }
  }

  public List<String> undeclaredConfiguredDependencies(
      PluginDescriptor descriptor, Iterable<String> configuredDependencies) {
    Set<String> declared =
        descriptor.requiredDependencies().stream()
            .map(String::toLowerCase)
            .collect(Collectors.toUnmodifiableSet());
    List<String> suggestions = new ArrayList<>();
    for (String configured : configuredDependencies) {
      if (!declared.contains(configured.toLowerCase())) {
        suggestions.add(configured);
      }
    }
    return List.copyOf(suggestions);
  }

  private MetadataInspection parse(InputStream input, Path source, boolean paperMetadata) {
    LoadSettings settings =
        LoadSettings.builder()
            .setLabel(source.getFileName().toString())
            .setAllowDuplicateKeys(false)
            .setMaxAliasesForCollections(0)
            .build();
    Object loaded = new Load(settings).loadFromInputStream(input);
    if (!(loaded instanceof Map<?, ?> root)) {
      return invalid(source, "plugin metadata root must be a mapping");
    }

    List<String> issues = new ArrayList<>();
    String name = requiredString(root, "name", issues);
    String version = requiredString(root, "version", issues);
    String mainClass = requiredString(root, "main", issues);
    String apiVersion = optionalString(root, "api-version", issues);

    if (name != null && !name.matches("[A-Za-z0-9_. -]{1,64}")) {
      issues.add("name contains unsupported characters");
    }
    if (version != null && version.length() > 128) {
      issues.add("version exceeds 128 characters");
    }
    if (mainClass != null
        && !mainClass.matches("[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)+")) {
      issues.add("main is not a fully-qualified Java class name");
    }

    LinkedHashSet<String> requiredDependencies = new LinkedHashSet<>();
    requiredDependencies.addAll(stringList(root.get("depend"), "depend", issues));
    if (paperMetadata) {
      readPaperDependencies(root.get("dependencies"), requiredDependencies, issues);
    }

    List<String> permissions = mappingKeys(root.get("permissions"), "permissions", issues);
    List<String> commands = mappingKeys(root.get("commands"), "commands", issues);
    if (!issues.isEmpty()) {
      return new MetadataInspection(source, MetadataStatus.INVALID, null, issues);
    }

    return new MetadataInspection(
        source,
        MetadataStatus.VALID,
        new PluginDescriptor(
            name,
            version,
            mainClass,
            apiVersion,
            List.copyOf(requiredDependencies),
            permissions,
            commands,
            source),
        List.of());
  }

  private static String requiredString(Map<?, ?> root, String field, List<String> issues) {
    String value = optionalString(root, field, issues);
    if (value == null) {
      issues.add(field + " is required");
    }
    return value;
  }

  private static String optionalString(Map<?, ?> root, String field, List<String> issues) {
    Object value = root.get(field);
    if (value == null) {
      return null;
    }
    if (!(value instanceof String string) || string.isBlank()) {
      issues.add(field + " must be a non-empty string");
      return null;
    }
    return string.trim();
  }

  private static List<String> stringList(Object value, String field, List<String> issues) {
    if (value == null) {
      return List.of();
    }
    if (!(value instanceof Iterable<?> values)) {
      issues.add(field + " must be a list of plugin names");
      return List.of();
    }
    List<String> result = new ArrayList<>();
    for (Object item : values) {
      if (!(item instanceof String string) || string.isBlank()) {
        issues.add(field + " entries must be non-empty strings");
      } else {
        result.add(string.trim());
      }
    }
    return List.copyOf(result);
  }

  private static List<String> mappingKeys(Object value, String field, List<String> issues) {
    if (value == null) {
      return List.of();
    }
    if (!(value instanceof Map<?, ?> mapping)) {
      issues.add(field + " must be a mapping");
      return List.of();
    }
    List<String> result = new ArrayList<>();
    for (Object key : mapping.keySet()) {
      if (!(key instanceof String string) || string.isBlank()) {
        issues.add(field + " keys must be non-empty strings");
      } else {
        result.add(string.trim());
      }
    }
    return List.copyOf(result);
  }

  private static void readPaperDependencies(
      Object value, LinkedHashSet<String> requiredDependencies, List<String> issues) {
    if (value == null) {
      return;
    }
    if (!(value instanceof Map<?, ?> dependencies)) {
      issues.add("dependencies must be a mapping");
      return;
    }
    Object serverValue = dependencies.get("server");
    if (serverValue == null) {
      return;
    }
    if (!(serverValue instanceof Map<?, ?> serverDependencies)) {
      issues.add("dependencies.server must be a mapping");
      return;
    }
    for (Map.Entry<?, ?> entry : serverDependencies.entrySet()) {
      if (!(entry.getKey() instanceof String name) || name.isBlank()) {
        issues.add("dependencies.server keys must be non-empty strings");
        continue;
      }
      if (!(entry.getValue() instanceof Map<?, ?> settings)) {
        issues.add("dependency " + name + " must be a mapping");
        continue;
      }
      if (Boolean.TRUE.equals(settings.get("required"))) {
        requiredDependencies.add(name.trim());
      }
    }
  }

  private static MetadataInspection invalid(Path source, String issue) {
    return new MetadataInspection(source, MetadataStatus.INVALID, null, List.of(issue));
  }
}
