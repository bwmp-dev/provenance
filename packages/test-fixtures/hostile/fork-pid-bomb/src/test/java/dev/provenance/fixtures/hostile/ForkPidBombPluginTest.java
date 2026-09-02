package dev.provenance.fixtures.hostile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

final class ForkPidBombPluginTest {
  @AfterEach
  void clearOptIn() {
    System.clearProperty(ForkPidBombPlugin.HOSTILE_OPT_IN);
  }

  @Test
  void failsClosedBeforeRegistrationOrChildCreationWithoutExplicitOptIn() {
    AtomicInteger registrations = new AtomicInteger();
    AtomicInteger starts = new AtomicInteger();
    ForkPidBombPlugin plugin =
        new ForkPidBombPlugin(
            registrations::incrementAndGet,
            () -> {
              starts.incrementAndGet();
              throw pidLimitDenial();
            });

    assertThrows(IllegalStateException.class, plugin::onEnable);
    assertEquals(0, registrations.get());
    assertEquals(0, starts.get());
  }

  @Test
  void onEnableOnlyRegistersAndServerLoadStartsExactlyOnce() {
    System.setProperty(ForkPidBombPlugin.HOSTILE_OPT_IN, "true");
    AtomicInteger registrations = new AtomicInteger();
    AtomicInteger starts = new AtomicInteger();
    ForkPidBombPlugin plugin =
        new ForkPidBombPlugin(
            registrations::incrementAndGet,
            () -> {
              int attempt = starts.incrementAndGet();
              if (attempt == 3) {
                throw pidLimitDenial();
              }
              return new RetainedProcess();
            });

    plugin.onEnable();
    assertEquals(1, registrations.get());
    assertEquals(0, starts.get(), "onEnable must not create a child");

    plugin.onServerLoad(null);
    plugin.onServerLoad(null);

    assertEquals(3, starts.get(), "the second event must not restart the attack");
  }

  @Test
  void serverLoadHandlerUsesMonitorPriority() throws ReflectiveOperationException {
    Method handler =
        ForkPidBombPlugin.class.getMethod(
            "onServerLoad", org.bukkit.event.server.ServerLoadEvent.class);
    EventHandler annotation = handler.getAnnotation(EventHandler.class);

    assertEquals(EventPriority.MONITOR, annotation.priority());
  }

  @Test
  void stopsAtFirstPidDenialAndRetainsEverySuccessfulSleeper() {
    AtomicInteger starts = new AtomicInteger();
    List<RetainedProcess> children = new ArrayList<>();
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              if (starts.incrementAndGet() == 4) {
                throw pidLimitDenial();
              }
              RetainedProcess child = new RetainedProcess();
              children.add(child);
              return child;
            });

    assertEquals(3, attack.startOnce());
    assertEquals(3, attack.retainedChildCount());
    assertEquals(4, starts.get());
    assertTrue(children.stream().allMatch(Process::isAlive));
    assertEquals(3, attack.startOnce());
    assertEquals(4, starts.get(), "a repeated trigger must not attempt another child");
    assertTrue(children.stream().allMatch(Process::isAlive));
  }

  @Test
  void nonPidCreationFailureIsNotMisreportedAsLimitDenial() {
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              throw new IOException("permission denied");
            });

    assertThrows(IllegalStateException.class, attack::startOnce);
    assertEquals(0, attack.retainedChildCount());
  }

  @Test
  void childCommandIsAnAllowlistedNonRecursiveSleeper() throws IOException {
    List<String> command = SleeperProcess.command();
    String executable = command.getFirst();

    assertEquals(2, command.size());
    assertTrue(executable.equals("/usr/bin/sleep") || executable.equals("/bin/sleep"));
    assertFalse(executable.contains("java"));
    assertEquals("2147483647", command.get(1));
  }

  private static IOException pidLimitDenial() {
    return new IOException("Cannot run program: error=11, Resource temporarily unavailable");
  }

  private static final class RetainedProcess extends Process {
    private boolean alive = true;

    @Override
    public OutputStream getOutputStream() {
      return new ByteArrayOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return new ByteArrayInputStream(new byte[0]);
    }

    @Override
    public InputStream getErrorStream() {
      return new ByteArrayInputStream(new byte[0]);
    }

    @Override
    public int waitFor() {
      alive = false;
      return 0;
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      alive = false;
    }

    @Override
    public boolean isAlive() {
      return alive;
    }
  }
}
