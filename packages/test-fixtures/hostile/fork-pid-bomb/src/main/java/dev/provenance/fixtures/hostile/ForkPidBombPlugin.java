package dev.provenance.fixtures.hostile;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import org.bukkit.plugin.java.JavaPlugin;

public final class ForkPidBombPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    requireOptIn();
    ForkPidBombProcess.spawnChildren();
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled"))
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
  }
}

final class ForkPidBombProcess {
  private ForkPidBombProcess() {}

  public static void main(String[] args) {
    spawnChildren();
    try {
      Thread.currentThread().join();
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
    }
  }

  static void spawnChildren() {
    try {
      String java =
          System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
      String jar =
          Path.of(
                  ForkPidBombProcess.class
                      .getProtectionDomain()
                      .getCodeSource()
                      .getLocation()
                      .toURI())
              .toString();
      for (int child = 0; child < 2; child++)
        new ProcessBuilder(java, "-cp", jar, ForkPidBombProcess.class.getName()).start();
    } catch (IOException | URISyntaxException exception) {
      throw new IllegalStateException("fork/PID fixture could not spawn", exception);
    }
  }
}
