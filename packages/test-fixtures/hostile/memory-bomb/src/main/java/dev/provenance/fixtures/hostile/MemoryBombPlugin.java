package dev.provenance.fixtures.hostile;

import java.util.ArrayList;
import java.util.List;
import org.bukkit.plugin.java.JavaPlugin;

public final class MemoryBombPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    requireOptIn();
    Thread worker =
        new Thread(
            () -> {
              List<byte[]> retained = new ArrayList<>();
              while (true) retained.add(new byte[8 * 1024 * 1024]);
            },
            "provenance-memory-bomb");
    worker.start();
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled"))
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
  }
}
