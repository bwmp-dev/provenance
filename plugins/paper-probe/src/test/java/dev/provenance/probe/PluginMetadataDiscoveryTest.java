package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PluginMetadataDiscoveryTest {
  @TempDir Path plugins;

  @Test
  void inspectsAndCanonicalizesLegacyPluginMetadata() throws IOException {
    writeJar(
        "target.jar",
        "plugin.yml",
        """
        name: TargetPlugin
        version: 1.2.3
        main: example.TargetPlugin
        api-version: '1.21'
        depend: [ZuluRequired, alphaRequired]
        softdepend: [ZuluSoft, alphaSoft]
        loadbefore: [ZuluLater, alphaLater]
        permissions:
          zulu.permission:
            default: op
          alpha.permission:
            default: true
        commands:
          zulu:
            description: Zulu command
          alpha:
            description: Alpha command
        """);

    MetadataInspection inspection =
        new PluginMetadataDiscovery().inspect(plugins.resolve("target.jar"));
    PluginDescriptor descriptor = inspection.descriptor();

    assertEquals(MetadataStatus.VALID, inspection.status());
    assertEquals("TargetPlugin", descriptor.name());
    assertEquals("1.2.3", descriptor.version());
    assertEquals("example.TargetPlugin", descriptor.mainClass());
    assertEquals("1.21", descriptor.apiVersion());
    assertEquals(
        List.of("alphaRequired", "ZuluRequired"), descriptor.requiredDependencies());
    assertEquals(List.of("alphaSoft", "ZuluSoft"), descriptor.softDependencies());
    assertEquals(List.of("alphaLater", "ZuluLater"), descriptor.loadBeforeDependencies());
    assertEquals(
        List.of("alpha.permission", "zulu.permission"), descriptor.permissions());
    assertEquals(List.of("alpha", "zulu"), descriptor.commands());
  }

  @Test
  void inspectsPaperDependencyScopesDefaultsAndLoadOrder() throws IOException {
    writeJar(
        "paper.jar",
        "paper-plugin.yml",
        """
        name: PaperTarget
        version: 1.0.0
        main: example.PaperTarget
        dependencies:
          bootstrap:
            BootstrapDefaultRequired:
              load: BEFORE
            BootstrapOptionalAfter:
              required: false
              load: AFTER
          server:
            ServerRequiredAfter:
              required: true
              load: AFTER
              join-classpath: false
            ServerOptionalBefore:
              required: false
              load: before
        """);

    PluginDescriptor descriptor =
        new PluginMetadataDiscovery().discover(plugins).getFirst();

    assertEquals(
        List.of("BootstrapDefaultRequired", "ServerRequiredAfter"),
        descriptor.requiredDependencies());
    assertEquals(
        List.of("BootstrapOptionalAfter", "ServerOptionalBefore"),
        descriptor.softDependencies());
    assertEquals(
        List.of("BootstrapOptionalAfter", "ServerRequiredAfter"),
        descriptor.loadBeforeDependencies());
  }

  @Test
  void classifiesMissingAndInvalidMetadataBeforeRunnerExecution() throws IOException {
    writeJar("missing.jar", "README.txt", "not plugin metadata");
    writeJar(
        "invalid.jar",
        "plugin.yml",
        """
        name: InvalidPlugin
        version: 1.0.0
        main: not a class
        commands: []
        """);

    MetadataInspection missing =
        new PluginMetadataDiscovery().inspect(plugins.resolve("missing.jar"));
    MetadataInspection invalid =
        new PluginMetadataDiscovery().inspect(plugins.resolve("invalid.jar"));

    assertEquals(MetadataStatus.MISSING, missing.status());
    assertNull(missing.descriptor());
    assertEquals(List.of("plugin metadata is missing"), missing.issues());
    assertEquals(MetadataStatus.INVALID, invalid.status());
    assertNull(invalid.descriptor());
    assertEquals(
        List.of("commands must be a mapping", "main is not a fully-qualified Java class name"),
        invalid.issues());
  }

  @Test
  void rejectsMalformedPaperDependencySettingsDeterministically() throws IOException {
    writeJar(
        "invalid-paper.jar",
        "paper-plugin.yml",
        """
        name: PaperTarget
        version: 1.0.0
        main: example.PaperTarget
        dependencies:
          client:
            UnknownScope: {}
          server:
            Malformed:
              unknown: true
              required: required
              load: SIDEWAYS
              join-classpath: perhaps
        """);

    MetadataInspection inspection =
        new PluginMetadataDiscovery().inspect(plugins.resolve("invalid-paper.jar"));

    assertEquals(MetadataStatus.INVALID, inspection.status());
    assertEquals(
        List.of(
            "dependencies contains an unsupported scope",
            "dependencies.server dependency contains an unsupported field",
            "dependencies.server.join-classpath must be a boolean",
            "dependencies.server.load must be BEFORE, AFTER, or OMIT",
            "dependencies.server.required must be a boolean"),
        inspection.issues());
  }

  @Test
  void suggestionsAreOfflineCanonicalBoundedAndCoverAllDeclarationKinds() throws IOException {
    writeJar(
        "target.jar",
        "plugin.yml",
        """
        name: TargetPlugin
        version: 1.2.3
        main: example.TargetPlugin
        depend: [Required]
        softdepend: [Soft]
        loadbefore: [LoadedLater]
        """);
    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();
    PluginDescriptor descriptor = discovery.inspect(plugins.resolve("target.jar")).descriptor();

    assertEquals(
        List.of("AlphaUndeclared", "ZuluUndeclared"),
        discovery.undeclaredConfiguredDependencies(
            descriptor,
            List.of(
                "ZuluUndeclared",
                "soft",
                "REQUIRED",
                "loadedlater",
                "AlphaUndeclared")));

    List<String> maximum =
        IntStream.range(0, PluginMetadataDiscovery.MAX_CONFIGURED_DEPENDENCIES)
            .mapToObj(index -> "Dependency" + index)
            .toList();
    assertEquals(
        PluginMetadataDiscovery.MAX_CONFIGURED_DEPENDENCIES,
        discovery.undeclaredConfiguredDependencies(descriptor, maximum).size());

    List<String> overMaximum = new ArrayList<>(maximum);
    overMaximum.add("DependencyOverLimit");
    assertThrows(
        IllegalArgumentException.class,
        () -> discovery.undeclaredConfiguredDependencies(descriptor, overMaximum));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            discovery.undeclaredConfiguredDependencies(
                descriptor, List.of("Duplicate", "duplicate")));
  }

  @Test
  void enforcesMetadataByteBoundaryAndStrictUtf8() throws IOException {
    byte[] validPrefix =
        """
        name: BoundaryPlugin
        version: 1.0.0
        main: example.BoundaryPlugin
        """
            .getBytes(StandardCharsets.UTF_8);
    byte[] atLimit = Arrays.copyOf(validPrefix, PluginMetadataDiscovery.MAX_METADATA_BYTES);
    Arrays.fill(atLimit, validPrefix.length, atLimit.length, (byte) ' ');
    writeJar("at-limit.jar", "plugin.yml", atLimit);
    writeJar(
        "over-limit.jar",
        "plugin.yml",
        Arrays.copyOf(atLimit, PluginMetadataDiscovery.MAX_METADATA_BYTES + 1));
    writeJar("invalid-utf8.jar", "plugin.yml", new byte[] {(byte) 0xc3, (byte) 0x28});

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();

    assertEquals(
        MetadataStatus.VALID, discovery.inspect(plugins.resolve("at-limit.jar")).status());
    assertEquals(
        List.of("plugin metadata exceeds 65536 bytes"),
        discovery.inspect(plugins.resolve("over-limit.jar")).issues());
    assertEquals(
        List.of("plugin metadata must be UTF-8"),
        discovery.inspect(plugins.resolve("invalid-utf8.jar")).issues());
  }

  @Test
  void enforcesDependencyCollectionBoundary() throws IOException {
    writeJar(
        "at-limit.jar",
        "plugin.yml",
        legacyMetadataWithDependencies(PluginMetadataDiscovery.MAX_DEPENDENCIES));
    writeJar(
        "over-limit.jar",
        "plugin.yml",
        legacyMetadataWithDependencies(PluginMetadataDiscovery.MAX_DEPENDENCIES + 1));

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();

    assertEquals(
        PluginMetadataDiscovery.MAX_DEPENDENCIES,
        discovery
            .inspect(plugins.resolve("at-limit.jar"))
            .descriptor()
            .requiredDependencies()
            .size());
    assertEquals(
        List.of("depend must contain at most 64 entries"),
        discovery.inspect(plugins.resolve("over-limit.jar")).issues());
  }

  @Test
  void rejectsDuplicateDeclarationsAliasesAndExcessiveNesting() throws IOException {
    writeJar(
        "duplicates.jar",
        "plugin.yml",
        """
        name: DuplicatePlugin
        version: 1.0.0
        main: example.DuplicatePlugin
        depend: [Dependency, dependency]
        """);
    writeJar(
        "alias.jar",
        "plugin.yml",
        """
        name: AliasPlugin
        version: 1.0.0
        main: example.AliasPlugin
        depend: &dependencies [Dependency]
        softdepend: *dependencies
        """);
    StringBuilder nested =
        new StringBuilder(
            """
            name: NestedPlugin
            version: 1.0.0
            main: example.NestedPlugin
            extra:
            """);
    for (int depth = 0; depth < 18; depth++) {
      nested.append("  ".repeat(depth + 1)).append("level").append(depth).append(":\n");
    }
    nested.append("  ".repeat(19)).append("value\n");
    writeJar("nested.jar", "plugin.yml", nested.toString());

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();

    assertEquals(
        List.of("depend entries must be unique ignoring case"),
        discovery.inspect(plugins.resolve("duplicates.jar")).issues());
    assertEquals(
        List.of("plugin metadata is not valid YAML"),
        discovery.inspect(plugins.resolve("alias.jar")).issues());
    assertEquals(
        List.of("plugin metadata exceeds 16 levels of nesting"),
        discovery.inspect(plugins.resolve("nested.jar")).issues());
  }

  @Test
  void directoryInspectionIsCanonicalAndBounded() throws IOException {
    writeJar("zulu.jar", "README.txt", "zulu");
    writeJar("Alpha.jar", "README.txt", "alpha");

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();

    assertEquals(
        List.of("Alpha.jar", "zulu.jar"),
        discovery.inspectDirectory(plugins).stream()
            .map(inspection -> inspection.source().getFileName().toString())
            .toList());

    for (int index = 2; index < PluginMetadataDiscovery.MAX_PLUGIN_ARTIFACTS; index++) {
      writeJar(String.format("plugin-%03d.jar", index), "README.txt", "plugin");
    }
    assertEquals(
        PluginMetadataDiscovery.MAX_PLUGIN_ARTIFACTS,
        discovery.inspectDirectory(plugins).size());
    writeJar("overflow.jar", "README.txt", "overflow");
    assertThrows(IOException.class, () -> discovery.inspectDirectory(plugins));
  }

  @Test
  void reportsUnreadableArtifactsWithoutLeakingPlatformErrors() throws IOException {
    Path invalidJar = plugins.resolve("invalid.jar");
    Files.writeString(invalidJar, "not a JAR", StandardCharsets.UTF_8);

    MetadataInspection inspection = new PluginMetadataDiscovery().inspect(invalidJar);

    assertEquals(MetadataStatus.INVALID, inspection.status());
    assertEquals(List.of("plugin artifact is not a readable JAR"), inspection.issues());
  }

  @Test
  void classifiesTamperedSignedJarAsInvalid() throws Exception {
    Path signedJar = plugins.resolve("signed.jar");
    Path keyStore = plugins.resolve("test-signing.p12");
    writeJar(
        signedJar.getFileName().toString(),
        "plugin.yml",
        """
        name: SignedPlugin
        version: 1.0.0
        main: example.SignedPlugin
        """);
    runJdkTool(
        "keytool",
        "-genkeypair",
        "-alias",
        "test-signing",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        "36500",
        "-dname",
        "CN=Provenance Metadata Test",
        "-storetype",
        "PKCS12",
        "-keystore",
        keyStore.toString(),
        "-storepass",
        "changeit",
        "-keypass",
        "changeit",
        "-noprompt");
    runJdkTool(
        "jarsigner",
        "-keystore",
        keyStore.toString(),
        "-storepass",
        "changeit",
        "-keypass",
        "changeit",
        signedJar.toString(),
        "test-signing");
    try (FileSystem jar = FileSystems.newFileSystem(signedJar)) {
      Files.writeString(
          jar.getPath("/plugin.yml"),
          """
          name: TamperedPlugin
          version: 2.0.0
          main: example.TamperedPlugin
          """,
          StandardCharsets.UTF_8);
    }

    MetadataInspection inspection = new PluginMetadataDiscovery().inspect(signedJar);

    assertEquals(MetadataStatus.INVALID, inspection.status());
    assertNull(inspection.descriptor());
    assertEquals(
        List.of("plugin artifact failed JAR security verification"), inspection.issues());
    assertEquals(
        List.of("artifact_signature_invalid"),
        MetadataInspectorMain.issueCodes(inspection.issues()));

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ByteArrayOutputStream error = new ByteArrayOutputStream();
    int exitCode;
    try (PrintStream outputStream = new PrintStream(output, true, StandardCharsets.UTF_8);
        PrintStream errorStream = new PrintStream(error, true, StandardCharsets.UTF_8)) {
      exitCode =
          MetadataInspectorMain.run(
              new String[] {
                "--expected-sha256", sha256(signedJar), signedJar.toString()
              },
              outputStream,
              errorStream);
    }
    assertEquals(0, exitCode);
    assertEquals("", error.toString(StandardCharsets.UTF_8));
    assertEquals(
        "{\"schemaVersion\":\"provenance.paper-metadata/v1\","
            + "\"artifactSha256\":\""
            + sha256(signedJar)
            + "\",\"status\":\"invalid\","
            + "\"issues\":[\"artifact_signature_invalid\"]}\n",
        output.toString(StandardCharsets.UTF_8));
  }

  private static String legacyMetadataWithDependencies(int count) {
    String dependencies =
        IntStream.range(0, count)
            .mapToObj(index -> "Dependency" + index)
            .collect(java.util.stream.Collectors.joining(", "));
    return """
        name: BoundaryPlugin
        version: 1.0.0
        main: example.BoundaryPlugin
        depend: [%s]
        """
        .formatted(dependencies);
  }

  private void writeJar(String name, String entryName, String contents) throws IOException {
    writeJar(name, entryName, contents.getBytes(StandardCharsets.UTF_8));
  }

  private void writeJar(String name, String entryName, byte[] contents) throws IOException {
    try (JarOutputStream output =
        new JarOutputStream(Files.newOutputStream(plugins.resolve(name)))) {
      output.putNextEntry(new JarEntry(entryName));
      output.write(contents);
      output.closeEntry();
    }
  }

  private void runJdkTool(String tool, String... arguments) throws Exception {
    String executableName =
        System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows")
            ? tool + ".exe"
            : tool;
    List<String> command = new ArrayList<>();
    command.add(Path.of(System.getProperty("java.home"), "bin", executableName).toString());
    command.addAll(List.of(arguments));
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    if (!process.waitFor(30, TimeUnit.SECONDS)) {
      process.destroyForcibly();
      throw new IOException(tool + " did not finish within 30 seconds");
    }
    String output =
        new String(process.getInputStream().readNBytes(16_384), StandardCharsets.UTF_8);
    assertEquals(0, process.exitValue(), output);
  }

  private static String sha256(Path path) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (var input = Files.newInputStream(path)) {
      byte[] buffer = new byte[8192];
      int read;
      while ((read = input.read(buffer)) != -1) {
        digest.update(buffer, 0, read);
      }
    }
    return HexFormat.of().formatHex(digest.digest());
  }
}
