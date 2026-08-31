package dev.provenance.fixtures.hostile;

import java.util.concurrent.CountDownLatch;
import org.bukkit.plugin.java.JavaPlugin;

public final class EnableHangPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    requireOptIn();
    try {
      new CountDownLatch(1).await();
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
    }
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled"))
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
  }
}
