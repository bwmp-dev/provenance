package dev.provenance.fixtures.hostile;

import org.bukkit.plugin.java.JavaPlugin;

public final class ProcessExitPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    requireOptIn();
    Runtime.getRuntime().halt(17);
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled"))
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
  }
}
