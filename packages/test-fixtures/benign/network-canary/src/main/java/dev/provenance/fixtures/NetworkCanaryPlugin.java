package dev.provenance.fixtures;

import java.io.IOException;
import java.net.URI;
import javax.net.ssl.HttpsURLConnection;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;

/** Explicit, bounded probe of one public endpoint; never reads test secrets. */
public final class NetworkCanaryPlugin extends JavaPlugin {
  static final String ENDPOINT = "https://api.github.com/";

  @FunctionalInterface
  interface ConnectionFactory {
    HttpsURLConnection open() throws IOException;
  }

  @Override public void onEnable() {
    getLogger().info("PROVENANCE_NETWORK_CANARY_READY");
  }

  @Override public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
    if (!label.equalsIgnoreCase("networkcanary") || args.length != 0) return false;
    String result = probe(() -> (HttpsURLConnection) URI.create(ENDPOINT).toURL().openConnection());
    sender.sendMessage(result);
    getLogger().info(result);
    return true;
  }

  static String probe(ConnectionFactory factory) {
    HttpsURLConnection connection = null;
    try {
      connection = factory.open();
      connection.setRequestMethod("HEAD");
      connection.setRequestProperty("User-Agent", "provenance-alpha-network-canary/1");
      connection.setInstanceFollowRedirects(false);
      connection.setUseCaches(false);
      connection.setConnectTimeout(5000);
      connection.setReadTimeout(5000);
      int status = connection.getResponseCode();
      return "PROVENANCE_NETWORK_CANARY_" + (status >= 200 && status < 300 ? "HTTP_SUCCESS" : "HTTP_UNEXPECTED");
    } catch (IOException failure) {
      // A failed request alone is not proof that a network policy denied it.
      return "PROVENANCE_NETWORK_CANARY_UNREACHABLE";
    } finally {
      if (connection != null) connection.disconnect();
    }
  }
}
