package dev.provenance.fixtures.hostile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
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
              throw eagainPidLimitDenial();
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
                throw eagainPidLimitDenial();
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
  void stopsAtFirstEagainPidDenialAndRetainsEverySuccessfulSleeper() {
    AtomicInteger starts = new AtomicInteger();
    AtomicInteger pressureHolds = new AtomicInteger();
    List<RetainedProcess> children = new ArrayList<>();
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              if (starts.incrementAndGet() == 4) {
                throw eagainPidLimitDenial();
              }
              RetainedProcess child = new RetainedProcess();
              children.add(child);
              return child;
            },
            () -> {
              pressureHolds.incrementAndGet();
              assertEquals(3, children.size());
              assertTrue(children.stream().allMatch(Process::isAlive));
            });

    assertEquals(1, attack.startOnce());
    assertEquals(1, attack.retainedChildCount());
    assertEquals(4, starts.get());
    assertEquals(1, pressureHolds.get());
    assertTrue(children.getFirst().isAlive());
    assertTrue(children.subList(1, children.size()).stream().noneMatch(Process::isAlive));
    assertTrue(children.subList(1, children.size()).stream().allMatch(RetainedProcess::reaped));
    assertEquals(1, attack.startOnce());
    assertEquals(4, starts.get(), "a repeated trigger must not attempt another child");
    assertEquals(1, pressureHolds.get(), "a repeated trigger must not hold pressure again");
    assertTrue(children.getFirst().isAlive());
  }

  @Test
  void recognizesGvisorEnomemAndRetainsSuccessfulSleepers() {
    AtomicInteger starts = new AtomicInteger();
    AtomicInteger pressureHolds = new AtomicInteger();
    RetainedProcess child = new RetainedProcess();
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              if (starts.incrementAndGet() == 1) {
                return child;
              }
              throw new IOException("Cannot run program: error=12, Cannot allocate memory");
            },
            () -> {
              pressureHolds.incrementAndGet();
              assertTrue(child.isAlive());
            });

    assertEquals(1, attack.startOnce());
    assertEquals(2, starts.get());
    assertEquals(1, pressureHolds.get());
    assertEquals(1, attack.retainedChildCount());
    assertTrue(child.isAlive());
  }

  @Test
  void nonPidCreationFailuresAreNotMisreportedAsLimitDenial() {
    assertNotPidDenial("permission denied");
    assertNotPidDenial("Cannot run program: error=11, Permission denied");
    assertNotPidDenial("Cannot run program: Resource temporarily unavailable");
    assertNotPidDenial("Cannot run program: error=12, Java heap space");
    assertNotPidDenial("Cannot run program: Cannot allocate memory");
    assertNotPidDenial("error=12, Cannot allocate memory");
    assertNotPidDenial("Cannot run program: error=13, Permission denied");
  }

  private static void assertNotPidDenial(String message) {
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              throw new IOException(message);
            },
            () -> {});

    assertThrows(IllegalStateException.class, attack::startOnce);
    assertEquals(0, attack.retainedChildCount());
  }

  @Test
  void interruptedPressureHoldReapsEveryControlledSleeper() {
    AtomicInteger starts = new AtomicInteger();
    List<RetainedProcess> children = new ArrayList<>();
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              if (starts.incrementAndGet() == 3) {
                throw eagainPidLimitDenial();
              }
              RetainedProcess child = new RetainedProcess();
              children.add(child);
              return child;
            },
            () -> {
              throw new InterruptedException("test interruption");
            });

    try {
      assertThrows(IllegalStateException.class, attack::startOnce);
      assertTrue(Thread.currentThread().isInterrupted());
      assertEquals(0, attack.retainedChildCount());
      assertTrue(children.stream().noneMatch(Process::isAlive));
      assertTrue(children.stream().allMatch(RetainedProcess::reaped));
    } finally {
      Thread.interrupted();
    }
  }

  @Test
  void unexpectedLaunchFailureReapsEveryControlledSleeper() {
    AtomicInteger starts = new AtomicInteger();
    List<RetainedProcess> children = new ArrayList<>();
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              if (starts.incrementAndGet() == 3) {
                throw new IOException("Cannot run program: error=13, Permission denied");
              }
              RetainedProcess child = new RetainedProcess();
              children.add(child);
              return child;
            },
            () -> {});

    assertThrows(IllegalStateException.class, attack::startOnce);
    assertEquals(0, attack.retainedChildCount());
    assertTrue(children.stream().noneMatch(Process::isAlive));
    assertTrue(children.stream().allMatch(RetainedProcess::reaped));
  }

  @Test
  void launcherErrorIsRethrownAfterControlledSleepersAreReaped() {
    AtomicInteger starts = new AtomicInteger();
    RetainedProcess child = new RetainedProcess();
    AssertionError launcherError = new AssertionError("test launcher error");
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              if (starts.incrementAndGet() == 1) {
                return child;
              }
              throw launcherError;
            },
            () -> {});

    assertSame(launcherError, assertThrows(AssertionError.class, attack::startOnce));
    assertEquals(0, attack.retainedChildCount());
    assertFalse(child.isAlive());
    assertTrue(child.reaped());
  }

  @Test
  void cleanupFailureRetainsOwnershipOfAnUnreapedSleeper() {
    AtomicInteger starts = new AtomicInteger();
    UnreapableProcess child = new UnreapableProcess();
    ForkPidBombAttack attack =
        new ForkPidBombAttack(
            () -> {
              if (starts.incrementAndGet() == 1) {
                return child;
              }
              throw new IOException("Cannot run program: error=13, Permission denied");
            },
            () -> {});

    IllegalStateException failure =
        assertThrows(IllegalStateException.class, attack::startOnce);

    assertEquals(1, failure.getSuppressed().length);
    assertEquals(1, attack.retainedChildCount());
    assertTrue(child.isAlive());
  }

  @Test
  void productionPressureHoldIsBoundedAboveSamplingWindow() throws InterruptedException {
    assertEquals(2_000, SleeperPressureHold.HOLD_MILLIS);

    long started = System.nanoTime();
    SleeperPressureHold.sustain();
    long elapsedMillis =
        java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

    assertTrue(elapsedMillis >= SleeperPressureHold.HOLD_MILLIS);
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

  private static IOException eagainPidLimitDenial() {
    return new IOException("Cannot run program: error=11, Resource temporarily unavailable");
  }

  private static class RetainedProcess extends Process {
    private boolean alive = true;
    private boolean reaped;

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
      reaped = true;
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, java.util.concurrent.TimeUnit unit) {
      if (!alive) {
        reaped = true;
      }
      return !alive;
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

    boolean reaped() {
      return reaped;
    }
  }

  private static final class UnreapableProcess extends RetainedProcess {
    @Override
    public void destroy() {
      throw new IllegalStateException("test destroy failure");
    }
  }
}
