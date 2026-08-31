package dev.provenance.fixtures.hostile;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.bukkit.plugin.java.JavaPlugin;

public final class DiskFillPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    requireOptIn();
    Path target = getDataFolder().toPath().resolve("disk-fill.bin");
    new Thread(() -> fill(target), "provenance-disk-fill").start();
  }

  private static void fill(Path target) {
    try {
      Files.createDirectories(target.getParent());
      byte[] block = new byte[1024 * 1024];
      try (BufferedOutputStream output = new BufferedOutputStream(Files.newOutputStream(target))) {
        while (true) output.write(block);
      }
    } catch (IOException exception) {
      throw new IllegalStateException("disk-fill fixture stopped", exception);
    }
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled"))
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
  }
}
