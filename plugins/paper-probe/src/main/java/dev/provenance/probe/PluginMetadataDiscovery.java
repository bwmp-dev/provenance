package dev.provenance.probe;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

public final class PluginMetadataDiscovery {
  static final int MAX_METADATA_BYTES = 65_536;
  static final int MAX_PLUGIN_ARTIFACTS = 128;
  static final int MAX_DEPENDENCIES = 64;
  static final int MAX_CONFIGURED_DEPENDENCIES = 64;
  static final int MAX_PERMISSIONS = 256;
  static final int MAX_COMMANDS = 256;

  private static final int MAX_ROOT_FIELDS = 128;
  private static final int MAX_YAML_DEPTH = 16;
  private static final int MAX_YAML_NODES = 2_048;
  private static final int MAX_MAIN_CLASS_CHARACTERS = 512;
  private static final int MAX_API_VERSION_CHARACTERS = 32;
  private static final int MAX_PERMISSION_CHARACTERS = 128;
  private static final int MAX_COMMAND_CHARACTERS = 128;
  private static final Set<String> PAPER_DEPENDENCY_SCOPES = Set.of("bootstrap", "server");
  private static final Set<String> PAPER_DEPENDENCY_FIELDS =
      Set.of("load", "required", "join-classpath");
  private static final Pattern PLUGIN_NAME = Pattern.compile("[A-Za-z0-9_. -]{1,64}");
  private static final Pattern MAIN_CLASS =
      Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)+");
  private static final Comparator<String> CANONICAL_ORDER =
      Comparator.comparing((String value) -> value.toLowerCase(Locale.ROOT))
          .thenComparing(Comparator.naturalOrder());
  private static final Comparator<Path> CANONICAL_PATH_ORDER =
      Comparator.comparing(
              (Path path) -> path.getFileName().toString().toLowerCase(Locale.ROOT))
          .thenComparing(path -> path.getFileName().toString());

  public List<MetadataInspection> inspectDirectory(Path pluginsDirectory) throws IOException {
    if (!Files.isDirectory(pluginsDirectory, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    List<Path> jars;
    try (Stream<Path> paths = Files.list(pluginsDirectory)) {
      jars =
          paths
              .filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
              .filter(
                  path ->
                      path.getFileName()
                          .toString()
                          .toLowerCase(Locale.ROOT)
                          .endsWith(".jar"))
              .limit(MAX_PLUGIN_ARTIFACTS + 1L)
              .toList();
    }
    if (jars.size() > MAX_PLUGIN_ARTIFACTS) {
      throw new IOException("plugins directory contains more than 128 JAR files");
    }
    return jars.stream().sorted(CANONICAL_PATH_ORDER).map(this::inspect).toList();
  }

  public List<PluginDescriptor> discover(Path pluginsDirectory) throws IOException {
    return inspectDirectory(pluginsDirectory).stream()
        .filter(inspection -> inspection.status() == MetadataStatus.VALID)
        .map(MetadataInspection::descriptor)
        .toList();
  }

  public MetadataInspection inspect(Path jarPath) {
    Objects.requireNonNull(jarPath, "jarPath");
    if (!Files.isRegularFile(jarPath, LinkOption.NOFOLLOW_LINKS)) {
      return invalid(jarPath, "plugin artifact must be a regular file");
    }
    byte[] source;
    boolean paperMetadata;
    try (JarFile jar = new JarFile(jarPath.toFile(), true)) {
      JarEntry metadata = jar.getJarEntry("plugin.yml");
      paperMetadata = false;
      if (metadata == null) {
        metadata = jar.getJarEntry("paper-plugin.yml");
        paperMetadata = true;
      }
      if (metadata == null) {
        return new MetadataInspection(
            jarPath, MetadataStatus.MISSING, null, List.of("plugin metadata is missing"));
      }
      if (metadata.isDirectory()) {
        return invalid(jarPath, "plugin metadata must be a regular JAR entry");
      }
      if (metadata.getSize() > MAX_METADATA_BYTES) {
        return invalid(jarPath, "plugin metadata exceeds 65536 bytes");
      }
      try (InputStream input = jar.getInputStream(metadata)) {
        source = input.readNBytes(MAX_METADATA_BYTES + 1);
        if (source.length > MAX_METADATA_BYTES) {
          return invalid(jarPath, "plugin metadata exceeds 65536 bytes");
        }
      }
    } catch (SecurityException exception) {
      return invalid(jarPath, "plugin artifact failed JAR security verification");
    } catch (IOException exception) {
      return invalid(jarPath, "plugin artifact is not a readable JAR");
    }
    return parse(source, jarPath, paperMetadata);
  }

  public List<String> undeclaredConfiguredDependencies(
      PluginDescriptor descriptor, Iterable<String> configuredDependencies) {
    Objects.requireNonNull(descriptor, "descriptor");
    Objects.requireNonNull(configuredDependencies, "configuredDependencies");
    Map<String, String> configured = new HashMap<>();
    int count = 0;
    for (String dependency : configuredDependencies) {
      count++;
      if (count > MAX_CONFIGURED_DEPENDENCIES) {
        throw new IllegalArgumentException("configured dependencies must contain at most 64 entries");
      }
      String normalized = normalizedPluginName(dependency);
      if (normalized == null) {
        throw new IllegalArgumentException("configured dependencies must be plugin names");
      }
      String previous = configured.put(normalized.toLowerCase(Locale.ROOT), normalized);
      if (previous != null) {
        throw new IllegalArgumentException(
            "configured dependencies must be unique ignoring case");
      }
    }

    Set<String> declared = new HashSet<>();
    addCaseFolded(declared, descriptor.requiredDependencies());
    addCaseFolded(declared, descriptor.softDependencies());
    addCaseFolded(declared, descriptor.loadBeforeDependencies());
    return configured.entrySet().stream()
        .filter(entry -> !declared.contains(entry.getKey()))
        .map(Map.Entry::getValue)
        .sorted(CANONICAL_ORDER)
        .toList();
  }

  private MetadataInspection parse(byte[] input, Path source, boolean paperMetadata) {
    final String yaml;
    try {
      yaml =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(input))
              .toString();
    } catch (CharacterCodingException exception) {
      return invalid(source, "plugin metadata must be UTF-8");
    }

    LoadSettings settings =
        LoadSettings.builder()
            .setLabel(source.getFileName().toString())
            .setAllowDuplicateKeys(false)
            .setAllowRecursiveKeys(false)
            .setMaxAliasesForCollections(0)
            .setCodePointLimit(MAX_METADATA_BYTES)
            .build();
    final Object loaded;
    try {
      loaded = new Load(settings).loadFromString(yaml);
    } catch (RuntimeException | StackOverflowError exception) {
      // SnakeYAML Engine 2.10 has no configurable nesting limit, so deeply nested untrusted
      // flow collections must fail as invalid even if construction exhausts the parser stack.
      return invalid(source, "plugin metadata is not valid YAML");
    }
    String structureIssue = structureIssue(loaded);
    if (structureIssue != null) {
      return invalid(source, structureIssue);
    }
    if (!(loaded instanceof Map<?, ?> root)) {
      return invalid(source, "plugin metadata root must be a mapping");
    }

    List<String> issues = new ArrayList<>();
    if (root.size() > MAX_ROOT_FIELDS) {
      issues.add("plugin metadata root exceeds 128 fields");
    }
    if (root.keySet().stream().anyMatch(key -> !(key instanceof String))) {
      issues.add("plugin metadata root keys must be strings");
    }
    String name = requiredString(root, "name", issues);
    String version = requiredString(root, "version", issues);
    String mainClass = requiredString(root, "main", issues);
    String apiVersion = optionalString(root, "api-version", issues);

    if (name != null && normalizedPluginName(name) == null) {
      issues.add("name contains unsupported characters");
    }
    if (version != null
        && (version.length() > 128 || version.codePoints().anyMatch(Character::isISOControl))) {
      issues.add("version is invalid or exceeds 128 characters");
    }
    if (mainClass != null
        && (mainClass.length() > MAX_MAIN_CLASS_CHARACTERS
            || !MAIN_CLASS.matcher(mainClass).matches())) {
      issues.add("main is not a fully-qualified Java class name");
    }
    if (apiVersion != null
        && (apiVersion.length() > MAX_API_VERSION_CHARACTERS
            || apiVersion.codePoints().anyMatch(Character::isISOControl))) {
      issues.add("api-version is invalid or exceeds 32 characters");
    }

    DependencyLists dependencies = new DependencyLists();
    addNames(
        dependencies.required,
        stringList(root.get("depend"), "depend", MAX_DEPENDENCIES, issues));
    addNames(
        dependencies.soft,
        stringList(root.get("softdepend"), "softdepend", MAX_DEPENDENCIES, issues));
    addNames(
        dependencies.loadBefore,
        stringList(root.get("loadbefore"), "loadbefore", MAX_DEPENDENCIES, issues));
    if (paperMetadata) {
      readPaperDependencies(root.get("dependencies"), dependencies, issues);
    }

    List<String> permissions =
        mappingKeys(
            root.get("permissions"),
            "permissions",
            MAX_PERMISSIONS,
            MAX_PERMISSION_CHARACTERS,
            issues);
    List<String> commands =
        mappingKeys(
            root.get("commands"),
            "commands",
            MAX_COMMANDS,
            MAX_COMMAND_CHARACTERS,
            issues);
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
            List.copyOf(dependencies.required.values()),
            List.copyOf(dependencies.soft.values()),
            List.copyOf(dependencies.loadBefore.values()),
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

  private static List<String> stringList(
      Object value, String field, int maximum, List<String> issues) {
    if (value == null) {
      return List.of();
    }
    if (!(value instanceof List<?> values)) {
      issues.add(field + " must be a list of plugin names");
      return List.of();
    }
    if (values.size() > maximum) {
      issues.add(field + " must contain at most " + maximum + " entries");
      return List.of();
    }
    Map<String, String> result = new HashMap<>();
    for (Object item : values) {
      String pluginName = item instanceof String string ? normalizedPluginName(string) : null;
      if (pluginName == null) {
        issues.add(field + " entries must be plugin names");
        continue;
      }
      if (result.put(pluginName.toLowerCase(Locale.ROOT), pluginName) != null) {
        issues.add(field + " entries must be unique ignoring case");
      }
    }
    return result.values().stream().sorted(CANONICAL_ORDER).toList();
  }

  private static List<String> mappingKeys(
      Object value, String field, int maximum, int maximumCharacters, List<String> issues) {
    if (value == null) {
      return List.of();
    }
    if (!(value instanceof Map<?, ?> mapping)) {
      issues.add(field + " must be a mapping");
      return List.of();
    }
    if (mapping.size() > maximum) {
      issues.add(field + " must contain at most " + maximum + " entries");
      return List.of();
    }
    Map<String, String> result = new HashMap<>();
    for (Object key : mapping.keySet()) {
      String normalized =
          key instanceof String string ? normalizedOutputName(string, maximumCharacters) : null;
      if (normalized == null) {
        issues.add(field + " keys must be bounded non-empty strings");
        continue;
      }
      if (result.put(normalized.toLowerCase(Locale.ROOT), normalized) != null) {
        issues.add(field + " keys must be unique ignoring case");
      }
    }
    return result.values().stream().sorted(CANONICAL_ORDER).toList();
  }

  private static void readPaperDependencies(
      Object value, DependencyLists dependencies, List<String> issues) {
    if (value == null) {
      return;
    }
    if (!(value instanceof Map<?, ?> scopes)) {
      issues.add("dependencies must be a mapping");
      return;
    }
    for (Object scope : scopes.keySet()) {
      if (!(scope instanceof String string) || !PAPER_DEPENDENCY_SCOPES.contains(string)) {
        issues.add("dependencies contains an unsupported scope");
      }
    }
    readPaperDependencyScope("bootstrap", scopes.get("bootstrap"), dependencies, issues);
    readPaperDependencyScope("server", scopes.get("server"), dependencies, issues);
  }

  private static void readPaperDependencyScope(
      String scope, Object value, DependencyLists dependencies, List<String> issues) {
    if (value == null) {
      return;
    }
    String field = "dependencies." + scope;
    if (!(value instanceof Map<?, ?> declarations)) {
      issues.add(field + " must be a mapping");
      return;
    }
    if (declarations.size() > MAX_DEPENDENCIES) {
      issues.add(field + " must contain at most 64 entries");
      return;
    }
    Set<String> observedNames = new HashSet<>();
    for (Map.Entry<?, ?> entry : declarations.entrySet()) {
      String name =
          entry.getKey() instanceof String string ? normalizedPluginName(string) : null;
      if (name == null) {
        issues.add(field + " keys must be plugin names");
        continue;
      }
      if (!observedNames.add(name.toLowerCase(Locale.ROOT))) {
        issues.add(field + " keys must be unique ignoring case");
        continue;
      }
      if (!(entry.getValue() instanceof Map<?, ?> settings)) {
        issues.add(field + " dependency settings must be mappings");
        continue;
      }
      validatePaperDependencyFields(field, settings, issues);
      Boolean required = paperRequired(field, settings, issues);
      String load = paperLoad(field, settings, issues);
      validateJoinClasspath(field, settings, issues);
      if (required == null || load == null) {
        continue;
      }
      addName(required ? dependencies.required : dependencies.soft, name);
      if (load.equals("AFTER")) {
        addName(dependencies.loadBefore, name);
      }
    }
  }

  private static void validatePaperDependencyFields(
      String field, Map<?, ?> settings, List<String> issues) {
    for (Object key : settings.keySet()) {
      if (!(key instanceof String string) || !PAPER_DEPENDENCY_FIELDS.contains(string)) {
        issues.add(field + " dependency contains an unsupported field");
      }
    }
  }

  private static Boolean paperRequired(
      String field, Map<?, ?> settings, List<String> issues) {
    if (!settings.containsKey("required")) {
      return true;
    }
    Object value = settings.get("required");
    if (!(value instanceof Boolean required)) {
      issues.add(field + ".required must be a boolean");
      return null;
    }
    return required;
  }

  private static String paperLoad(String field, Map<?, ?> settings, List<String> issues) {
    if (!settings.containsKey("load")) {
      return "OMIT";
    }
    Object value = settings.get("load");
    if (!(value instanceof String load)) {
      issues.add(field + ".load must be BEFORE, AFTER, or OMIT");
      return null;
    }
    String normalized = load.toUpperCase(Locale.ROOT);
    if (!Set.of("BEFORE", "AFTER", "OMIT").contains(normalized)) {
      issues.add(field + ".load must be BEFORE, AFTER, or OMIT");
      return null;
    }
    return normalized;
  }

  private static void validateJoinClasspath(
      String field, Map<?, ?> settings, List<String> issues) {
    if (settings.containsKey("join-classpath")
        && !(settings.get("join-classpath") instanceof Boolean)) {
      issues.add(field + ".join-classpath must be a boolean");
    }
  }

  private static String structureIssue(Object root) {
    ArrayDeque<StructuredValue> pending = new ArrayDeque<>();
    pending.push(new StructuredValue(root, 0));
    int nodes = 0;
    while (!pending.isEmpty()) {
      StructuredValue current = pending.pop();
      nodes++;
      if (nodes > MAX_YAML_NODES) {
        return "plugin metadata exceeds 2048 YAML nodes";
      }
      if (current.depth() > MAX_YAML_DEPTH) {
        return "plugin metadata exceeds 16 levels of nesting";
      }
      if (current.value() instanceof Map<?, ?> mapping) {
        for (Map.Entry<?, ?> entry : mapping.entrySet()) {
          if (entry.getKey() != null) {
            pending.push(new StructuredValue(entry.getKey(), current.depth() + 1));
          }
          if (entry.getValue() != null) {
            pending.push(new StructuredValue(entry.getValue(), current.depth() + 1));
          }
        }
      } else if (current.value() instanceof List<?> list) {
        for (Object value : list) {
          if (value != null) {
            pending.push(new StructuredValue(value, current.depth() + 1));
          }
        }
      }
    }
    return null;
  }

  private static String normalizedPluginName(String value) {
    if (value == null) {
      return null;
    }
    String normalized = value.trim();
    return PLUGIN_NAME.matcher(normalized).matches() ? normalized : null;
  }

  private static String normalizedOutputName(String value, int maximumCharacters) {
    String normalized = value.trim();
    if (normalized.isEmpty()
        || normalized.length() > maximumCharacters
        || normalized.codePoints().anyMatch(Character::isISOControl)) {
      return null;
    }
    return normalized;
  }

  private static void addNames(Map<String, String> target, Iterable<String> names) {
    for (String name : names) {
      addName(target, name);
    }
  }

  private static void addName(Map<String, String> target, String name) {
    target.merge(
        name.toLowerCase(Locale.ROOT),
        name,
        (left, right) -> CANONICAL_ORDER.compare(left, right) <= 0 ? left : right);
  }

  private static void addCaseFolded(Set<String> target, Iterable<String> names) {
    for (String name : names) {
      target.add(name.toLowerCase(Locale.ROOT));
    }
  }

  private static MetadataInspection invalid(Path source, String issue) {
    return new MetadataInspection(source, MetadataStatus.INVALID, null, List.of(issue));
  }

  private static final class DependencyLists {
    private final Map<String, String> required = new HashMap<>();
    private final Map<String, String> soft = new HashMap<>();
    private final Map<String, String> loadBefore = new HashMap<>();
  }

  private record StructuredValue(Object value, int depth) {}
}
