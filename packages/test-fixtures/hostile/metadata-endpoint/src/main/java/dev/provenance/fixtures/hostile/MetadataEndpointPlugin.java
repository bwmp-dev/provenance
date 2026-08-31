package dev.provenance.fixtures.hostile;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import org.bukkit.plugin.java.JavaPlugin;

public final class MetadataEndpointPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    requireOptIn();
    try {
      HttpURLConnection connection =
          (HttpURLConnection)
              URI.create("http://169.254.169.254/latest/meta-data/").toURL().openConnection();
      connection.setRequestProperty("Metadata-Flavor", "Google");
      connection.setConnectTimeout(2_000);
      connection.setReadTimeout(2_000);
      connection.getResponseCode();
    } catch (IOException ignored) {
    }
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled"))
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
  }
}
