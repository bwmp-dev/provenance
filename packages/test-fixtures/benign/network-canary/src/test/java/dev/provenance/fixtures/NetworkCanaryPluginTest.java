package dev.provenance.fixtures;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.URI;
import java.security.cert.Certificate;
import javax.net.ssl.HttpsURLConnection;
import org.bukkit.command.Command;
import org.junit.jupiter.api.Test;

final class NetworkCanaryPluginTest {
  static final class Connection extends HttpsURLConnection {
    int status;
    boolean fail;
    int requests;
    boolean disconnected;
    Connection(int status, boolean fail) throws Exception {
      super(URI.create(NetworkCanaryPlugin.ENDPOINT).toURL());
      this.status = status;
      this.fail = fail;
    }
    @Override public int getResponseCode() throws IOException {
      requests++;
      assertEquals("https://one.one.one.one/", getURL().toString());
      assertEquals("HEAD", getRequestMethod());
      assertEquals("provenance-alpha-network-canary/1", getRequestProperty("User-Agent"));
      assertEquals(5000, getConnectTimeout());
      assertEquals(5000, getReadTimeout());
      assertFalse(getInstanceFollowRedirects());
      assertFalse(getUseCaches());
      if (fail) throw new IOException("must not echo private transport diagnostics");
      return status;
    }
    @Override public void disconnect() { disconnected = true; }
    @Override public boolean usingProxy() { return false; }
    @Override public void connect() { fail("test must never open a real connection"); }
    @Override public String getCipherSuite() { return "synthetic"; }
    @Override public Certificate[] getLocalCertificates() { return null; }
    @Override public Certificate[] getServerCertificates() { return new Certificate[0]; }
  }

  @Test void fixedBoundedHeadAndCleanupForSuccess() throws Exception {
    for (int status : new int[] {200, 204, 299}) {
      Connection connection = new Connection(status, false);
      assertEquals("PROVENANCE_NETWORK_CANARY_HTTP_SUCCESS", NetworkCanaryPlugin.probe(() -> connection));
      assertEquals(1, connection.requests);
      assertTrue(connection.disconnected);
    }
  }

  @Test void redirectsAndFailuresDoNotBecomeSuccess() throws Exception {
    for (int status : new int[] {199, 301, 307, 403, 429, 503}) {
      Connection connection = new Connection(status, false);
      assertEquals("PROVENANCE_NETWORK_CANARY_HTTP_UNEXPECTED", NetworkCanaryPlugin.probe(() -> connection));
      assertEquals(1, connection.requests);
      assertTrue(connection.disconnected);
    }
  }

  @Test void transportFailureHasClosedOutputAndReleasesConnection() throws Exception {
    Connection connection = new Connection(200, true);
    assertEquals("PROVENANCE_NETWORK_CANARY_UNREACHABLE", NetworkCanaryPlugin.probe(() -> connection));
    assertTrue(connection.disconnected);
    assertEquals("PROVENANCE_NETWORK_CANARY_UNREACHABLE", NetworkCanaryPlugin.probe(() -> { throw new IOException("private"); }));
  }

  @Test void unknownCommandAndUserDestinationArgumentsAreRefusedWithoutOutput() {
    NetworkCanaryPlugin plugin = new NetworkCanaryPlugin();
    Command command = new Command() {};
    assertFalse(plugin.onCommand(value -> fail("unexpected output"), command, "other", new String[0]));
    assertFalse(plugin.onCommand(value -> fail("unexpected output"), command, "networkcanary", new String[] {"untrusted.example"}));
  }
}
