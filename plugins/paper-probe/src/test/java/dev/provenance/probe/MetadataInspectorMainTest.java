package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetadataInspectorMainTest {
  @TempDir Path directory;

  @Test
  void emitsCanonicalLegacyDescriptorBoundToExpectedHash() throws Exception {
    Path artifact =
        writeJar(
            "legacy.jar",
            "plugin.yml",
            """
            name: LegacyPlugin
            version: 1.2.3
            main: example.LegacyPlugin
            api-version: '1.21'
            depend: [ZuluRequired, alphaRequired]
            softdepend: [ZuluSoft, alphaSoft]
            loadbefore: [ZuluLater, alphaLater]
            permissions:
              zulu.permission: {}
              alpha.permission: {}
            commands:
              zulu: {}
              alpha: {}
            """
                .getBytes(StandardCharsets.UTF_8));
    String hash = sha256(artifact);

    Invocation invocation = invoke(hash, artifact);

    assertEquals(0, invocation.exitCode());
    assertEquals("", invocation.error());
    assertEquals(
        "{\"schemaVersion\":\"provenance.paper-metadata/v1\","
            + "\"artifactSha256\":\""
            + hash
            + "\",\"status\":\"valid\",\"issues\":[],\"plugin\":{"
            + "\"name\":\"LegacyPlugin\",\"version\":\"1.2.3\","
            + "\"mainClass\":\"example.LegacyPlugin\",\"apiVersion\":\"1.21\","
            + "\"requiredDependencies\":[\"alphaRequired\",\"ZuluRequired\"],"
            + "\"softDependencies\":[\"alphaSoft\",\"ZuluSoft\"],"
            + "\"loadBeforeDependencies\":[\"alphaLater\",\"ZuluLater\"],"
            + "\"permissions\":[\"alpha.permission\",\"zulu.permission\"],"
            + "\"commands\":[\"alpha\",\"zulu\"]}}\n",
        invocation.output());
  }

  @Test
  void emitsCanonicalPaperDependenciesDeterministically() throws Exception {
    Path artifact =
        writeJar(
            "paper.jar",
            "paper-plugin.yml",
            """
            name: PaperPlugin
            version: 2.0.0
            main: example.PaperPlugin
            api-version: '1.21'
            dependencies:
              bootstrap:
                Bootstrap:
                  load: BEFORE
              server:
                OptionalAfter:
                  required: false
                  load: AFTER
            """
                .getBytes(StandardCharsets.UTF_8));
    String hash = sha256(artifact);

    Invocation first = invoke(hash, artifact);
    Invocation second = invoke(hash, artifact);

    assertEquals(0, first.exitCode());
    assertEquals(first, second);
    assertEquals(
        "{\"schemaVersion\":\"provenance.paper-metadata/v1\","
            + "\"artifactSha256\":\""
            + hash
            + "\",\"status\":\"valid\",\"issues\":[],\"plugin\":{"
            + "\"name\":\"PaperPlugin\",\"version\":\"2.0.0\","
            + "\"mainClass\":\"example.PaperPlugin\",\"apiVersion\":\"1.21\","
            + "\"requiredDependencies\":[\"Bootstrap\"],"
            + "\"softDependencies\":[\"OptionalAfter\"],"
            + "\"loadBeforeDependencies\":[\"OptionalAfter\"],"
            + "\"permissions\":[],\"commands\":[]}}\n",
        first.output());
  }

  @Test
  void returnsHandledMissingAndInvalidResultsWithoutParserDetails() throws Exception {
    Path missing =
        writeJar("missing.jar", "README.txt", "none".getBytes(StandardCharsets.UTF_8));
    Path malformedUtf8 =
        writeJar("utf8.jar", "plugin.yml", new byte[] {(byte) 0xc3, (byte) 0x28});
    byte[] oversized = new byte[PluginMetadataDiscovery.MAX_METADATA_BYTES + 1];
    java.util.Arrays.fill(oversized, (byte) ' ');
    Path oversizedMetadata = writeJar("oversized.jar", "plugin.yml", oversized);

    Invocation missingResult = invoke(sha256(missing), missing);
    Invocation utf8Result = invoke(sha256(malformedUtf8), malformedUtf8);
    Invocation oversizedResult = invoke(sha256(oversizedMetadata), oversizedMetadata);

    assertEquals(0, missingResult.exitCode());
    assertEquals("", missingResult.error());
    assertEquals(
        resultPrefix(sha256(missing))
            + "\"missing\",\"issues\":[\"plugin_metadata_missing\"]}\n",
        missingResult.output());
    assertEquals(0, utf8Result.exitCode());
    assertEquals(
        resultPrefix(sha256(malformedUtf8))
            + "\"invalid\",\"issues\":[\"plugin_metadata_utf8_invalid\"]}\n",
        utf8Result.output());
    assertEquals(0, oversizedResult.exitCode());
    assertEquals(
        resultPrefix(sha256(oversizedMetadata))
            + "\"invalid\",\"issues\":[\"plugin_metadata_too_large\"]}\n",
        oversizedResult.output());
  }

  @Test
  void failsClosedForHashMismatchAndNonRegularInputs() throws Exception {
    Path artifact =
        writeJar(
            "plugin.jar",
            "plugin.yml",
            """
            name: Target
            version: 1.0.0
            main: example.Target
            """
                .getBytes(StandardCharsets.UTF_8));

    Invocation mismatch = invoke("0".repeat(64), artifact);
    Invocation directoryResult = invoke("0".repeat(64), directory);

    assertNotEquals(0, mismatch.exitCode());
    assertEquals("", mismatch.output());
    assertEquals("paper_metadata_inspector:artifact_hash_mismatch\n", mismatch.error());
    assertNotEquals(0, directoryResult.exitCode());
    assertEquals("", directoryResult.output());
    assertEquals("paper_metadata_inspector:artifact_not_regular\n", directoryResult.error());
    assertFalse(mismatch.error().contains(artifact.toString()));
  }

  @Test
  void rejectsSymbolicLinkInputWithoutFollowingIt() throws Exception {
    Path artifact =
        writeJar(
            "target.jar",
            "plugin.yml",
            """
            name: Target
            version: 1.0.0
            main: example.Target
            """
                .getBytes(StandardCharsets.UTF_8));
    Path link = directory.resolve("link.jar");
    try {
      Files.createSymbolicLink(link, artifact.getFileName());
    } catch (FileSystemException | UnsupportedOperationException exception) {
      assumeTrue(false, "symbolic links are unavailable: " + exception.getClass().getSimpleName());
    }

    Invocation invocation = invoke(sha256(artifact), link);

    assertNotEquals(0, invocation.exitCode());
    assertEquals("", invocation.output());
    assertEquals("paper_metadata_inspector:artifact_not_regular\n", invocation.error());
  }

  @Test
  void reportsOnlyBoundedStableCodesForMalformedYaml() throws Exception {
    Path artifact =
        writeJar(
            "malformed.jar",
            "plugin.yml",
            "name: [unterminated".getBytes(StandardCharsets.UTF_8));

    Invocation invocation = invoke(sha256(artifact), artifact);

    assertEquals(0, invocation.exitCode());
    assertEquals(
        resultPrefix(sha256(artifact))
            + "\"invalid\",\"issues\":[\"plugin_metadata_yaml_invalid\"]}\n",
        invocation.output());
    assertEquals("", invocation.error());
  }

  @Test
  void failsWhenTheResultCannotBeWritten() throws Exception {
    Path artifact =
        writeJar(
            "write-failure.jar",
            "plugin.yml",
            """
            name: WriteFailure
            version: 1.0.0
            main: example.WriteFailure
            """
                .getBytes(StandardCharsets.UTF_8));
    ByteArrayOutputStream error = new ByteArrayOutputStream();
    int exitCode;
    try (PrintStream output =
            new PrintStream(
                new OutputStream() {
                  @Override
                  public void write(int value) throws IOException {
                    throw new IOException("simulated closed output");
                  }
                },
                true,
                StandardCharsets.UTF_8);
        PrintStream errorStream = new PrintStream(error, true, StandardCharsets.UTF_8)) {
      exitCode =
          MetadataInspectorMain.run(
              new String[] {"--expected-sha256", sha256(artifact), artifact.toString()},
              output,
              errorStream);
    }

    assertNotEquals(0, exitCode);
    assertEquals(
        "paper_metadata_inspector:result_write_failed\n",
        error.toString(StandardCharsets.UTF_8));
  }

  private static String resultPrefix(String hash) {
    return "{\"schemaVersion\":\"provenance.paper-metadata/v1\","
        + "\"artifactSha256\":\""
        + hash
        + "\",\"status\":";
  }

  private Invocation invoke(String expectedHash, Path artifact) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ByteArrayOutputStream error = new ByteArrayOutputStream();
    int exitCode;
    try (PrintStream outputStream = new PrintStream(output, true, StandardCharsets.UTF_8);
        PrintStream errorStream = new PrintStream(error, true, StandardCharsets.UTF_8)) {
      exitCode =
          MetadataInspectorMain.run(
              new String[] {"--expected-sha256", expectedHash, artifact.toString()},
              outputStream,
              errorStream);
    }
    return new Invocation(
        exitCode,
        output.toString(StandardCharsets.UTF_8),
        error.toString(StandardCharsets.UTF_8));
  }

  private Path writeJar(String name, String entryName, byte[] contents) throws IOException {
    Path artifact = directory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(artifact))) {
      output.putNextEntry(new JarEntry(entryName));
      output.write(contents);
      output.closeEntry();
    }
    return artifact;
  }

  private static String sha256(Path path) throws IOException, NoSuchAlgorithmException {
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

  private record Invocation(int exitCode, String output, String error) {}
}
