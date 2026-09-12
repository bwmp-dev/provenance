package dev.provenance.fixtures;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class TestSecretDeliveryPluginTest {
  @TempDir Path directory;
  private static final String SYNTHETIC = "provenance-synthetic-alpha-" + "a".repeat(32);

  Path value(String content) throws Exception {
    Path path = Files.createTempFile(directory, "synthetic-", ".txt");
    Files.writeString(path, content);
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"));
    return path;
  }

  @Test void readsOnlySyntheticReadonlyInput() throws Exception {
    List<String> output = new ArrayList<>();
    TestSecretDeliveryPlugin.inspect(value(SYNTHETIC), output::add);
    assertEquals(List.of(SYNTHETIC), output);
  }

  @Test void refusesMissingDirectoryAndSymlinkWithoutOutput() throws Exception {
    Path link = directory.resolve("link");
    Files.createSymbolicLink(link, value(SYNTHETIC));
    for (Path path : List.of(directory.resolve("absent"), directory, link)) refuse(path);
  }

  @Test void refusesWritableInput() throws Exception {
    Path path = value(SYNTHETIC);
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    refuse(path);
  }

  @Test void refusesNonSyntheticMalformedAndOversizeInput() throws Exception {
    for (String input : List.of("", "not-a-fixture-value", SYNTHETIC + "\n", SYNTHETIC + "☃", "x".repeat(257))) {
      refuse(value(input));
    }
  }

  private void refuse(Path path) {
    List<String> output = new ArrayList<>();
    IllegalStateException failure = assertThrows(IllegalStateException.class,
        () -> TestSecretDeliveryPlugin.inspect(path, output::add));
    assertEquals("Synthetic test-secret fixture refused", failure.getMessage());
    assertNull(failure.getCause());
    assertTrue(output.isEmpty());
  }
}
