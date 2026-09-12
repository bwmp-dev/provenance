package dev.provenance.fixtures;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Set;
import java.util.function.Consumer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;

/** Opt-in by selecting this fixture and provisioning its synthetic-only value. */
public final class TestSecretDeliveryPlugin extends JavaPlugin {
  private static final Path SECRET = Path.of("/run/provenance/test-secrets/fixture-token");
  private static final int MAX_BYTES = 256;

  @Override
  public void onEnable() {
    inspect(SECRET, ignored -> {});
  }

  @Override
  public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
    inspect(SECRET, value -> {
      sender.sendMessage("PROVENANCE_SECRET_FIXTURE_VALUE=" + value);
      sender.sendMessage("PROVENANCE_SECRET_FIXTURE_OK");
    });
    return true;
  }

  static void inspect(Path path, Consumer<String> output) {
    byte[] bytes = null;
    try {
      if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
        throw new IOException();
      }
      Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
      if (permissions.contains(PosixFilePermission.OWNER_WRITE)
          || permissions.contains(PosixFilePermission.GROUP_WRITE)
          || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
        throw new IOException();
      }
      try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
        bytes = input.readNBytes(MAX_BYTES + 1);
      }
      if (bytes.length > MAX_BYTES) throw new IOException();
      String value = new String(bytes, StandardCharsets.US_ASCII);
      if (!value.matches("provenance-synthetic-alpha-[a-f0-9]{32,128}")) {
        throw new IOException();
      }
      output.accept(value);
    } catch (IOException | UnsupportedOperationException failure) {
      // No path, input value, parser detail or exception cause reaches Paper logs.
      throw new IllegalStateException("Synthetic test-secret fixture refused");
    } finally {
      if (bytes != null) Arrays.fill(bytes, (byte) 0);
    }
  }
}
