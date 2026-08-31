package dev.provenance.probe;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

public final class MetadataInspectorMain {
  static final long MAX_ARTIFACT_BYTES = 512L * 1024L * 1024L;

  private static final String SCHEMA_VERSION = "provenance.paper-metadata/v1";
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
  private static final int EXIT_USAGE = 64;
  private static final int EXIT_INPUT = 65;
  private static final int EXIT_OPERATIONAL = 70;
  private MetadataInspectorMain() {}

  public static void main(String[] arguments) {
    System.exit(run(arguments, System.out, System.err));
  }

  static int run(String[] arguments, PrintStream output, PrintStream error) {
    if (arguments.length != 3 || !"--expected-sha256".equals(arguments[0])) {
      return fail(error, EXIT_USAGE, "usage");
    }
    String expectedSha256 = arguments[1];
    if (!SHA256.matcher(expectedSha256).matches()) {
      return fail(error, EXIT_USAGE, "expected_sha256_invalid");
    }

    final Path source;
    try {
      source = Path.of(arguments[2]);
    } catch (InvalidPathException exception) {
      return fail(error, EXIT_INPUT, "artifact_path_invalid");
    }

    Path staged = null;
    try {
      BasicFileAttributes attributes =
          Files.readAttributes(source, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!attributes.isRegularFile() || Files.isSymbolicLink(source)) {
        return fail(error, EXIT_INPUT, "artifact_not_regular");
      }
      if (attributes.size() > MAX_ARTIFACT_BYTES) {
        return fail(error, EXIT_INPUT, "artifact_too_large");
      }

      staged = Files.createTempFile("provenance-metadata-", ".jar");
      staged.toFile().deleteOnExit();
      String actualSha256 = copyAndHash(source, staged);
      if (!actualSha256.equals(expectedSha256)) {
        return fail(error, EXIT_INPUT, "artifact_hash_mismatch");
      }

      MetadataInspection inspection = new PluginMetadataDiscovery().inspect(staged);
      output.print(Json.value(result(expectedSha256, inspection)) + "\n");
      return 0;
    } catch (ArtifactTooLargeException exception) {
      return fail(error, EXIT_INPUT, "artifact_too_large");
    } catch (IOException | SecurityException exception) {
      return fail(error, EXIT_OPERATIONAL, "artifact_read_failed");
    } catch (RuntimeException | LinkageError exception) {
      return fail(error, EXIT_OPERATIONAL, "inspection_failed");
    } finally {
      if (staged != null) {
        try {
          Files.deleteIfExists(staged);
        } catch (IOException ignored) {
          // The inspection result is already independent of the private staging file.
        }
      }
    }
  }

  private static String copyAndHash(Path source, Path destination) throws IOException {
    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
    long count = 0;
    byte[] buffer = new byte[64 * 1024];
    try (InputStream input =
            Files.newInputStream(source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        OutputStream output =
            Files.newOutputStream(
                destination,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING,
                LinkOption.NOFOLLOW_LINKS)) {
      int read;
      while ((read = input.read(buffer)) != -1) {
        count += read;
        if (count > MAX_ARTIFACT_BYTES) {
          throw new ArtifactTooLargeException();
        }
        digest.update(buffer, 0, read);
        output.write(buffer, 0, read);
      }
    }
    return java.util.HexFormat.of().formatHex(digest.digest());
  }

  private static Map<String, Object> result(
      String artifactSha256, MetadataInspection inspection) {
    LinkedHashMap<String, Object> result = new LinkedHashMap<>();
    result.put("schemaVersion", SCHEMA_VERSION);
    result.put("artifactSha256", artifactSha256);
    result.put("status", inspection.status().name().toLowerCase(Locale.ROOT));
    result.put("issues", issueCodes(inspection.issues()));
    if (inspection.descriptor() != null) {
      PluginDescriptor descriptor = inspection.descriptor();
      LinkedHashMap<String, Object> plugin = new LinkedHashMap<>();
      plugin.put("name", descriptor.name());
      plugin.put("version", descriptor.version());
      plugin.put("mainClass", descriptor.mainClass());
      plugin.put("apiVersion", descriptor.apiVersion());
      plugin.put("requiredDependencies", descriptor.requiredDependencies());
      plugin.put("softDependencies", descriptor.softDependencies());
      plugin.put("loadBeforeDependencies", descriptor.loadBeforeDependencies());
      plugin.put("permissions", descriptor.permissions());
      plugin.put("commands", descriptor.commands());
      result.put("plugin", plugin);
    }
    return result;
  }

  static List<String> issueCodes(List<String> issues) {
    TreeSet<String> codes = new TreeSet<>();
    for (String issue : issues) {
      codes.add(issueCode(issue));
    }
    return List.copyOf(codes);
  }

  private static String issueCode(String issue) {
    if (issue.equals("plugin metadata is missing")) {
      return "plugin_metadata_missing";
    }
    if (issue.equals("plugin artifact failed JAR security verification")) {
      return "artifact_signature_invalid";
    }
    if (issue.equals("plugin artifact is not a readable JAR")
        || issue.equals("plugin artifact must be a regular file")) {
      return "artifact_invalid";
    }
    if (issue.equals("plugin metadata must be a regular JAR entry")) {
      return "plugin_metadata_entry_invalid";
    }
    if (issue.equals("plugin metadata exceeds 65536 bytes")) {
      return "plugin_metadata_too_large";
    }
    if (issue.equals("plugin metadata must be UTF-8")) {
      return "plugin_metadata_utf8_invalid";
    }
    if (issue.equals("plugin metadata is not valid YAML")) {
      return "plugin_metadata_yaml_invalid";
    }
    if (issue.equals("plugin metadata exceeds 2048 YAML nodes")
        || issue.equals("plugin metadata exceeds 16 levels of nesting")) {
      return "plugin_metadata_structure_limit";
    }
    if (issue.equals("plugin metadata root must be a mapping")) {
      return "plugin_metadata_root_invalid";
    }
    if (issue.equals("plugin metadata root exceeds 128 fields")) {
      return "plugin_metadata_root_field_limit";
    }
    if (issue.equals("plugin metadata root keys must be strings")) {
      return "plugin_metadata_root_key_invalid";
    }
    if (issue.startsWith("name ")) {
      return "plugin_name_invalid";
    }
    if (issue.startsWith("version ")) {
      return "plugin_version_invalid";
    }
    if (issue.startsWith("main ")) {
      return "plugin_main_class_invalid";
    }
    if (issue.startsWith("api-version ")) {
      return "plugin_api_version_invalid";
    }
    if (issue.startsWith("depend ")
        || issue.startsWith("softdepend ")
        || issue.startsWith("loadbefore ")
        || issue.startsWith("dependencies")) {
      return "plugin_dependencies_invalid";
    }
    if (issue.startsWith("permissions ")) {
      return "plugin_permissions_invalid";
    }
    if (issue.startsWith("commands ")) {
      return "plugin_commands_invalid";
    }
    return "plugin_metadata_invalid";
  }

  private static int fail(PrintStream error, int exitCode, String code) {
    error.print("paper_metadata_inspector:" + code + "\n");
    return exitCode;
  }

  private static final class ArtifactTooLargeException extends IOException {}
}
