package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
        api-version: '1.21'
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
  void paperDescriptorTakesPrecedenceWhenBothDescriptorsExist() throws IOException {
    LinkedHashMap<String, byte[]> entries = new LinkedHashMap<>();
    entries.put(
        "plugin.yml",
        """
        name: LegacyIdentity
        version: 1.0.0
        main: example.LegacyIdentity
        depend: [LegacyDependency]
        """
            .getBytes(StandardCharsets.UTF_8));
    entries.put(
        "paper-plugin.yml",
        """
        name: PaperIdentity
        version: 2.0.0
        main: example.PaperIdentity
        api-version: '1.21'
        dependencies:
          server:
            PaperDependency:
              required: true
        """
            .getBytes(StandardCharsets.UTF_8));

    PluginDescriptor descriptor =
        new PluginMetadataDiscovery().inspect(writeJar("both.jar", entries)).descriptor();

    assertEquals("PaperIdentity", descriptor.name());
    assertEquals("2.0.0", descriptor.version());
    assertEquals("example.PaperIdentity", descriptor.mainClass());
    assertEquals(List.of("PaperDependency"), descriptor.requiredDependencies());
  }

  @Test
  void rejectsNamesPaperWillNotLoad() throws IOException {
    writeJar(
        "space.jar",
        "plugin.yml",
        """
        name: Space Plugin
        version: 1.0.0
        main: example.SpacePlugin
        """);
    writeJar(
        "reserved.jar",
        "plugin.yml",
        """
        name: PaPeR
        version: 1.0.0
        main: example.ReservedPlugin
        """);

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();

    assertEquals(
        List.of("name contains unsupported characters"),
        discovery.inspect(plugins.resolve("space.jar")).issues());
    assertEquals(
        List.of("name contains unsupported characters"),
        discovery.inspect(plugins.resolve("reserved.jar")).issues());
  }

  @Test
  void rejectsDescriptorScalarEdgeSpacesInsteadOfNormalizingThem() throws IOException {
    Map<String, String> expectedIssues =
        Map.of(
            "name", "name contains unsupported characters",
            "version", "version is invalid or exceeds 128 characters",
            "main", "main is not a fully-qualified Java class name",
            "api-version", "api-version is invalid or exceeds 32 characters");

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();
    for (String descriptor : List.of("plugin.yml", "paper-plugin.yml")) {
      for (Map.Entry<String, String> field : expectedIssues.entrySet()) {
        for (String edge : List.of("leading", "trailing")) {
          Map<String, String> values = new LinkedHashMap<>();
          values.put("name", "EdgeSpacePlugin");
          values.put("version", "1.0.0");
          values.put("main", "example.EdgeSpacePlugin");
          values.put("api-version", "1.21");
          String original = values.get(field.getKey());
          values.put(field.getKey(), edge.equals("leading") ? " " + original : original + " ");
          String artifactName =
              descriptor.replace(".yml", "") + "-" + field.getKey() + "-" + edge + ".jar";

          writeJar(artifactName, descriptor, descriptorMetadata(values));

          assertEquals(
              List.of(field.getValue()),
              discovery.inspect(plugins.resolve(artifactName)).issues(),
              descriptor + " " + field.getKey() + " " + edge);
        }
      }
    }
  }

  @Test
  void enforcesPaperMainNamespacesCaseSensitivelyWithoutChangingLegacyRules()
      throws IOException {
    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();
    List<String> forbiddenMains =
        List.of(
            "net.minecraft.PluginMain",
            "org.bukkit.PluginMain",
            "io.papermc.paper.PluginMain",
            "com.destroystokoyo.paper.PluginMain");
    for (int index = 0; index < forbiddenMains.size(); index++) {
      String artifactName = "paper-forbidden-main-" + index + ".jar";
      writeJar(
          artifactName,
          "paper-plugin.yml",
          descriptorMetadata(
              Map.of(
                  "name", "PaperNamespacePlugin",
                  "version", "1.0.0",
                  "main", forbiddenMains.get(index),
                  "api-version", "1.21")));

      assertEquals(
          List.of("main is not a fully-qualified Java class name"),
          discovery.inspect(plugins.resolve(artifactName)).issues());
    }

    writeJar(
        "paper-case-variant-main.jar",
        "paper-plugin.yml",
        descriptorMetadata(
            Map.of(
                "name", "PaperCaseVariant",
                "version", "1.0.0",
                "main", "Org.bukkit.PluginMain",
                "api-version", "1.21")));
    writeJar(
        "legacy-forbidden-main.jar",
        "plugin.yml",
        descriptorMetadata(
            Map.of(
                "name", "LegacyNamespacePlugin",
                "version", "1.0.0",
                "main", "org.bukkit.PluginMain",
                "api-version", "1.21")));

    assertEquals(
        MetadataStatus.VALID,
        discovery.inspect(plugins.resolve("paper-case-variant-main.jar")).status());
    assertEquals(
        MetadataStatus.VALID,
        discovery.inspect(plugins.resolve("legacy-forbidden-main.jar")).status());
  }

  @Test
  void validatesPaperApiVersionFloorAndPreservesValidRawPatch() throws IOException {
    writeJar("paper-api-missing.jar", "paper-plugin.yml", paperApiMetadata(null));
    writeJar("paper-api-malformed.jar", "paper-plugin.yml", paperApiMetadata("1.x"));
    writeJar("paper-api-below-floor.jar", "paper-plugin.yml", paperApiMetadata("1.18.2"));
    writeJar("paper-api-floor.jar", "paper-plugin.yml", paperApiMetadata("1.19.0"));
    writeJar("paper-api-future.jar", "paper-plugin.yml", paperApiMetadata("999.0"));

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();

    assertEquals(
        List.of("api-version is required"),
        discovery.inspect(plugins.resolve("paper-api-missing.jar")).issues());
    assertEquals(
        List.of("api-version is invalid or exceeds 32 characters"),
        discovery.inspect(plugins.resolve("paper-api-malformed.jar")).issues());
    assertEquals(
        List.of("api-version is invalid or exceeds 32 characters"),
        discovery.inspect(plugins.resolve("paper-api-below-floor.jar")).issues());
    assertEquals(
        "1.19.0",
        discovery.inspect(plugins.resolve("paper-api-floor.jar")).descriptor().apiVersion());
    assertEquals(
        "999.0",
        discovery.inspect(plugins.resolve("paper-api-future.jar")).descriptor().apiVersion());
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
        api-version: '1.21'
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
  void enforcesFinalMergedDependencyBoundaries() throws IOException {
    writeJar(
        "required-at-limit.jar",
        "paper-plugin.yml",
        paperMetadataWithDependencies("depend", 1, 31, true, false, 32, true, false));
    writeJar(
        "required-over-limit.jar",
        "paper-plugin.yml",
        paperMetadataWithDependencies("depend", 1, 31, true, false, 33, true, false));
    writeJar(
        "soft-at-limit.jar",
        "paper-plugin.yml",
        paperMetadataWithDependencies("softdepend", 1, 31, false, false, 32, false, false));
    writeJar(
        "soft-over-limit.jar",
        "paper-plugin.yml",
        paperMetadataWithDependencies("softdepend", 1, 31, false, false, 33, false, false));
    writeJar(
        "load-at-limit.jar",
        "paper-plugin.yml",
        paperMetadataWithDependencies("loadbefore", 1, 32, true, true, 31, false, true));
    writeJar(
        "load-over-limit.jar",
        "paper-plugin.yml",
        paperMetadataWithDependencies("loadbefore", 1, 32, true, true, 32, false, true));

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();

    assertEquals(
        64,
        discovery
            .inspect(plugins.resolve("required-at-limit.jar"))
            .descriptor()
            .requiredDependencies()
            .size());
    assertEquals(
        List.of("dependencies produce more than 64 required entries"),
        discovery.inspect(plugins.resolve("required-over-limit.jar")).issues());
    assertEquals(
        64,
        discovery
            .inspect(plugins.resolve("soft-at-limit.jar"))
            .descriptor()
            .softDependencies()
            .size());
    assertEquals(
        List.of("dependencies produce more than 64 soft entries"),
        discovery.inspect(plugins.resolve("soft-over-limit.jar")).issues());
    assertEquals(
        64,
        discovery
            .inspect(plugins.resolve("load-at-limit.jar"))
            .descriptor()
            .loadBeforeDependencies()
            .size());
    assertEquals(
        List.of("dependencies produce more than 64 load-before entries"),
        discovery.inspect(plugins.resolve("load-over-limit.jar")).issues());
  }

  @Test
  void rejectsUnpairedSurrogatesAndCountsAstralCharacters() throws IOException {
    String emoji = "\uD83D\uDE00";
    writeJar(
        "astral-at-limit.jar",
        "plugin.yml",
        freeTextMetadata("version", "\"" + emoji.repeat(128) + "\""));
    writeJar(
        "astral-over-limit.jar",
        "plugin.yml",
        freeTextMetadata("version", "\"" + emoji.repeat(129) + "\""));

    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();
    assertEquals(
        emoji.repeat(128),
        discovery.inspect(plugins.resolve("astral-at-limit.jar")).descriptor().version());
    assertEquals(
        List.of("version is invalid or exceeds 128 characters"),
        discovery.inspect(plugins.resolve("astral-over-limit.jar")).issues());

    for (String surrogate : List.of("\\uD800", "\\uDC00")) {
      String suffix = surrogate.endsWith("800") ? "high" : "low";
      assertFreeTextIssue(
          discovery,
          suffix + "-version.jar",
          freeTextMetadata("version", "\"" + surrogate + "\""),
          "version is invalid or exceeds 128 characters");
      assertFreeTextIssue(
          discovery,
          suffix + "-api.jar",
          freeTextMetadata("api-version", "\"" + surrogate + "\""),
          "api-version is invalid or exceeds 32 characters");
      assertFreeTextIssue(
          discovery,
          suffix + "-permission.jar",
          freeTextMetadata("permissions", "\n  \"" + surrogate + "\": {}"),
          "permissions keys must be bounded non-empty strings");
      assertFreeTextIssue(
          discovery,
          suffix + "-command.jar",
          freeTextMetadata("commands", "\n  \"" + surrogate + "\": {}"),
          "commands keys must be bounded non-empty strings");
    }
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
  void boundsJarEntryCountAndActualExpandedBytes() throws Exception {
    byte[] metadata =
        """
        name: BoundedPlugin
        version: 1.0.0
        main: example.BoundedPlugin
        """
            .getBytes(StandardCharsets.UTF_8);
    byte[] compressedExpansion = new byte[1024];
    Path expanded =
        writeJar(
            "expanded.jar",
            Map.of("plugin.yml", metadata, "compressed-resource.bin", compressedExpansion));
    assertTrue(Files.size(expanded) < metadata.length + compressedExpansion.length);

    MetadataInspection atByteBoundaries =
        new PluginMetadataDiscovery(2, compressedExpansion.length, metadata.length + 1024L)
            .inspect(expanded);
    assertEquals(MetadataStatus.VALID, atByteBoundaries.status());

    assertVerificationLimit(
        new PluginMetadataDiscovery(2, compressedExpansion.length - 1L, Long.MAX_VALUE)
            .inspect(expanded));
    assertVerificationLimit(
        new PluginMetadataDiscovery(2, Long.MAX_VALUE, metadata.length + 1023L)
            .inspect(expanded));

    LinkedHashMap<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("plugin.yml", metadata);
    entries.put("first/", new byte[0]);
    entries.put("second/", new byte[0]);
    Path crowded = writeJar("crowded.jar", entries);
    assertEquals(
        MetadataStatus.VALID,
        new PluginMetadataDiscovery(3, 1024, 4096).inspect(crowded).status());
    assertVerificationLimit(new PluginMetadataDiscovery(2, 1024, 4096).inspect(crowded));

    Path directoryPayload =
        writeJar(
            "directory-payload.jar",
            Map.of("plugin.yml", metadata, "payload/", compressedExpansion));
    assertEquals(
        MetadataStatus.VALID,
        new PluginMetadataDiscovery(2, compressedExpansion.length, metadata.length + 1024L)
            .inspect(directoryPayload)
            .status());
    assertVerificationLimit(
        new PluginMetadataDiscovery(2, compressedExpansion.length - 1L, Long.MAX_VALUE)
            .inspect(directoryPayload));
  }

  @Test
  void rejectsDuplicateJarEntryNamesBeforeSelectingMetadata() throws IOException {
    byte[] validMetadata =
        """
        name: UniquePlugin
        version: 1.0.0
        main: example.UniquePlugin
        """
            .getBytes(StandardCharsets.UTF_8);
    byte[] invalidMetadata = "not: valid: metadata".getBytes(StandardCharsets.UTF_8);

    LinkedHashMap<String, byte[]> validFirst = new LinkedHashMap<>();
    validFirst.put("plugin.yml", validMetadata);
    validFirst.put("Plugin.yml", invalidMetadata);
    Path laterDuplicate = writeJar("later-duplicate.jar", validFirst);
    renameJarEntry(laterDuplicate, "Plugin.yml", "plugin.yml");
    assertDuplicateEntry(laterDuplicate);

    LinkedHashMap<String, byte[]> validLast = new LinkedHashMap<>();
    validLast.put("plugin.yml", invalidMetadata);
    validLast.put("Plugin.yml", validMetadata);
    Path earlierDuplicate = writeJar("earlier-duplicate.jar", validLast);
    renameJarEntry(earlierDuplicate, "Plugin.yml", "plugin.yml");
    assertDuplicateEntry(earlierDuplicate);

    LinkedHashMap<String, byte[]> duplicateResource = new LinkedHashMap<>();
    duplicateResource.put("plugin.yml", validMetadata);
    duplicateResource.put("resource.bin", new byte[] {1});
    duplicateResource.put("Resource.bin", new byte[] {2});
    Path resources = writeJar("duplicate-resource.jar", duplicateResource);
    renameJarEntry(resources, "Resource.bin", "resource.bin");
    assertDuplicateEntry(resources);
  }

  @Test
  void classifiesTamperedSignedNonMetadataEntryAsInvalid() throws Exception {
    Path signedJar = plugins.resolve("signed.jar");
    Path keyStore = plugins.resolve("test-signing.p12");
    byte[] signedResource = new byte[] {1, 2, 3, 4};
    writeJar(
        signedJar.getFileName().toString(),
        Map.of("example/SignedPlugin.class", signedResource));
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
      signedResource[signedResource.length - 1] ^= 0x7f;
      Files.write(jar.getPath("/example/SignedPlugin.class"), signedResource);
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

  private static String paperMetadataWithDependencies(
      String legacyField,
      int legacyCount,
      int bootstrapCount,
      boolean bootstrapRequired,
      boolean bootstrapAfter,
      int serverCount,
      boolean serverRequired,
      boolean serverAfter) {
    StringBuilder metadata =
        new StringBuilder(
            """
            name: BoundaryPlugin
            version: 1.0.0
            main: example.BoundaryPlugin
            api-version: '1.21'
            """);
    metadata
        .append(legacyField)
        .append(": [")
        .append(
            IntStream.range(0, legacyCount)
                .mapToObj(index -> "Legacy" + index)
                .collect(java.util.stream.Collectors.joining(", ")))
        .append("]\n")
        .append("dependencies:\n");
    appendPaperDependencyScope(
        metadata, "bootstrap", "Bootstrap", bootstrapCount, bootstrapRequired, bootstrapAfter);
    appendPaperDependencyScope(
        metadata, "server", "Server", serverCount, serverRequired, serverAfter);
    return metadata.toString();
  }

  private static void appendPaperDependencyScope(
      StringBuilder metadata,
      String scope,
      String prefix,
      int count,
      boolean required,
      boolean loadAfter) {
    metadata.append("  ").append(scope).append(":\n");
    for (int index = 0; index < count; index++) {
      metadata
          .append("    ")
          .append(prefix)
          .append(index)
          .append(":\n")
          .append("      required: ")
          .append(required)
          .append("\n")
          .append("      load: ")
          .append(loadAfter ? "AFTER" : "OMIT")
          .append("\n");
    }
  }

  private static String freeTextMetadata(String field, String yamlValue) {
    StringBuilder metadata =
        new StringBuilder(
            """
            name: TextPlugin
            main: example.TextPlugin
            """);
    if (!field.equals("version")) {
      metadata.append("version: 1.0.0\n");
    }
    return metadata.append(field).append(": ").append(yamlValue).append("\n").toString();
  }

  private static String paperApiMetadata(String apiVersion) {
    return """
        name: PaperApiPlugin
        version: 1.0.0
        main: example.PaperApiPlugin
        """
        + (apiVersion == null ? "" : "api-version: '" + apiVersion + "'\n");
  }

  private static String descriptorMetadata(Map<String, String> values) {
    return "name: '"
        + values.get("name")
        + "'\nversion: '"
        + values.get("version")
        + "'\nmain: '"
        + values.get("main")
        + "'\napi-version: '"
        + values.get("api-version")
        + "'\n";
  }

  private void assertFreeTextIssue(
      PluginMetadataDiscovery discovery, String name, String metadata, String expectedIssue)
      throws IOException {
    writeJar(name, "plugin.yml", metadata);
    assertEquals(List.of(expectedIssue), discovery.inspect(plugins.resolve(name)).issues());
  }

  private void writeJar(String name, String entryName, String contents) throws IOException {
    writeJar(name, entryName, contents.getBytes(StandardCharsets.UTF_8));
  }

  private void writeJar(String name, String entryName, byte[] contents) throws IOException {
    writeJar(name, Map.of(entryName, contents));
  }

  private Path writeJar(String name, Map<String, byte[]> entries) throws IOException {
    Path artifact = plugins.resolve(name);
    try (JarOutputStream output =
        new JarOutputStream(Files.newOutputStream(artifact))) {
      for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey()));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return artifact;
  }

  private static void renameJarEntry(Path artifact, String existing, String replacement)
      throws IOException {
    byte[] source = existing.getBytes(StandardCharsets.UTF_8);
    byte[] target = replacement.getBytes(StandardCharsets.UTF_8);
    assertEquals(source.length, target.length);
    byte[] jar = Files.readAllBytes(artifact);
    int replacements = 0;
    for (int index = 0; index <= jar.length - source.length; index++) {
      if (Arrays.equals(jar, index, index + source.length, source, 0, source.length)) {
        System.arraycopy(target, 0, jar, index, target.length);
        replacements++;
        index += source.length - 1;
      }
    }
    assertEquals(2, replacements);
    Files.write(artifact, jar);
  }

  private static void assertDuplicateEntry(Path artifact) {
    MetadataInspection inspection = new PluginMetadataDiscovery().inspect(artifact);
    assertEquals(MetadataStatus.INVALID, inspection.status());
    assertNull(inspection.descriptor());
    assertEquals(List.of("plugin artifact contains duplicate entries"), inspection.issues());
    assertEquals(List.of("artifact_invalid"), MetadataInspectorMain.issueCodes(inspection.issues()));
  }

  private static void assertVerificationLimit(MetadataInspection inspection) {
    assertEquals(MetadataStatus.INVALID, inspection.status());
    assertNull(inspection.descriptor());
    assertEquals(List.of("plugin artifact exceeds verification limits"), inspection.issues());
    assertEquals(List.of("artifact_invalid"), MetadataInspectorMain.issueCodes(inspection.issues()));
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
