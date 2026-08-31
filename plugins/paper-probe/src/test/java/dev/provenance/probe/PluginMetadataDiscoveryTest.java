package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PluginMetadataDiscoveryTest {
  @TempDir Path plugins;

  @Test
  void inspectsLegacyPluginMetadata() throws IOException {
    writeJar(
        "target.jar",
        "plugin.yml",
        """
        name: TargetPlugin
        version: 1.2.3
        main: example.TargetPlugin
        api-version: '1.21'
        depend: [DependencyOne, 'DependencyTwo']
        permissions:
          target.admin:
            default: op
        commands:
          target:
            description: Target command
        """);

    MetadataInspection inspection =
        new PluginMetadataDiscovery().inspect(plugins.resolve("target.jar"));
    PluginDescriptor descriptor = inspection.descriptor();

    assertEquals(MetadataStatus.VALID, inspection.status());
    assertEquals("TargetPlugin", descriptor.name());
    assertEquals("1.2.3", descriptor.version());
    assertEquals("example.TargetPlugin", descriptor.mainClass());
    assertEquals("1.21", descriptor.apiVersion());
    assertEquals(List.of("DependencyOne", "DependencyTwo"), descriptor.requiredDependencies());
    assertEquals(List.of("target.admin"), descriptor.permissions());
    assertEquals(List.of("target"), descriptor.commands());
  }

  @Test
  void discoversOnlyRequiredPaperServerDependencies() throws IOException {
    writeJar(
        "paper.jar",
        "paper-plugin.yml",
        """
        name: PaperTarget
        version: 1.0.0
        main: example.PaperTarget
        dependencies:
          server:
            RequiredPlugin:
              required: true
            OptionalPlugin:
              required: false
        """);

    List<PluginDescriptor> descriptors = new PluginMetadataDiscovery().discover(plugins);

    assertEquals(List.of("RequiredPlugin"), descriptors.getFirst().requiredDependencies());
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
    assertEquals(MetadataStatus.INVALID, invalid.status());
    assertNull(invalid.descriptor());
    assertEquals(
        List.of("main is not a fully-qualified Java class name", "commands must be a mapping"),
        invalid.issues());
  }

  @Test
  void suggestsConfiguredDependenciesThatMetadataDoesNotDeclare() throws IOException {
    writeJar(
        "target.jar",
        "plugin.yml",
        """
        name: TargetPlugin
        version: 1.2.3
        main: example.TargetPlugin
        depend: [Declared]
        """);
    PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();
    PluginDescriptor descriptor = discovery.inspect(plugins.resolve("target.jar")).descriptor();

    assertEquals(
        List.of("Undeclared"),
        discovery.undeclaredConfiguredDependencies(descriptor, List.of("declared", "Undeclared")));
  }

  private void writeJar(String name, String entryName, String contents) throws IOException {
    try (JarOutputStream output =
        new JarOutputStream(Files.newOutputStream(plugins.resolve(name)))) {
      output.putNextEntry(new JarEntry(entryName));
      output.write(contents.getBytes(StandardCharsets.UTF_8));
      output.closeEntry();
    }
  }
}
