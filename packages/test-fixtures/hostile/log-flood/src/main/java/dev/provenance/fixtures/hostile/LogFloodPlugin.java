package dev.provenance.fixtures.hostile;

import org.bukkit.plugin.java.JavaPlugin;

public final class LogFloodPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    requireOptIn();
    new Thread(
            () -> {
              long sequence = 0;
              while (true) getLogger().info("PROVENANCE_LOG_FLOOD " + sequence++);
            },
            "provenance-log-flood")
        .start();
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled"))
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
  }
}
