package dev.provenance.fixtures.hostile;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import org.bukkit.plugin.java.JavaPlugin;

public final class NetworkScanPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    requireOptIn();
    for (int host = 1; host < 255; host++) {
      int address = host;
      Thread.ofPlatform().name("provenance-network-scan-" + host).start(() -> probe(address));
    }
  }

  private static void probe(int host) {
    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress("10.0.0." + host, 80), 1_000);
    } catch (IOException ignored) {
    }
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled"))
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
  }
}
