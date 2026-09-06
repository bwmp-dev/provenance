package dev.provenance.fixtures;

import org.bukkit.plugin.java.JavaPlugin;

/** One immutable benign artifact with deterministic three-environment behavior. */
public final class MatrixCompatibilityPlugin extends JavaPlugin {
  static final long OBSERVATION_WINDOW_MILLIS = 10_000;

  @Override
  public void onEnable() {
    // The runner reports RUNNING before launching Paper. This bounded fixture-
    // only window lets restart acceptance observe a live attempt before the
    // deliberate result, without changing product or startup deadlines.
    observeBeforeClassification(Thread::sleep);
    requireSupportedVersion(getServer().getMinecraftVersion());
  }

  interface ObservationWait {
    void await(long milliseconds) throws InterruptedException;
  }

  static void observeBeforeClassification(ObservationWait wait) {
    try {
      wait.await(OBSERVATION_WINDOW_MILLIS);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("provenance fixture observation interrupted", interrupted);
    }
  }

  static void requireSupportedVersion(String version) {
    // This acceptance fixture deliberately supports only the frozen passing
    // environment. Unknown versions must not silently add passing coverage.
    if (!"1.21.8".equals(version)) {
      throw new IllegalStateException("provenance matrix fixture version is incompatible");
    }
  }
}
