package dev.provenance.probe;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.ErrorManager;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

public final class LifecycleExceptionHandler extends Handler {
  private final EventSink sink;
  private final Map<String, String> pluginByMainClass;
  private final Set<Throwable> emitted = Collections.newSetFromMap(new IdentityHashMap<>());

  public LifecycleExceptionHandler(EventSink sink, Map<String, String> pluginByMainClass) {
    this.sink = sink;
    this.pluginByMainClass = Map.copyOf(pluginByMainClass);
  }

  @Override
  public synchronized void publish(LogRecord record) {
    publish(record.getThrown());
  }

  public synchronized void publish(Throwable thrown) {
    if (thrown == null || emitted.contains(thrown)) {
      return;
    }
    PhaseAndPlugin match = identify(thrown);
    if (match.phase().equals("UNKNOWN")) {
      return;
    }
    emitted.add(thrown);

    LinkedHashMap<String, Object> data = new LinkedHashMap<>();
    data.put("phase", match.phase());
    data.put("plugin", match.plugin());
    data.put("exceptionType", thrown.getClass().getName());
    data.put("message", thrown.getMessage());
    data.put("stackTrace", stackTrace(thrown));
    try {
      sink.emit(ProbeEvent.now(EventType.LIFECYCLE_EXCEPTION, data));
      ProbeClassification classification =
          match.phase().equals("LOAD")
              ? ProbeClassification.ON_LOAD_FAILURE
              : ProbeClassification.ON_ENABLE_FAILURE;
      sink.emit(
          ProbeEvent.now(
              EventType.CLASSIFICATION, classification.data(Map.of("plugin", match.plugin()))));
    } catch (RuntimeException exception) {
      reportError("could not emit lifecycle exception", exception, ErrorManager.WRITE_FAILURE);
    }
  }

  @Override
  public void flush() {}

  @Override
  public void close() {}

  private PhaseAndPlugin identify(Throwable failure) {
    String phase = "UNKNOWN";
    String plugin = "";
    Throwable current = failure;
    while (current != null) {
      for (StackTraceElement frame : current.getStackTrace()) {
        if (frame.getMethodName().equals("onLoad")) {
          phase = "LOAD";
        } else if (frame.getMethodName().equals("onEnable")) {
          phase = "ENABLE";
        }
        String knownPlugin = pluginByMainClass.get(frame.getClassName());
        if (knownPlugin != null) {
          plugin = knownPlugin;
        }
      }
      current = current.getCause();
    }
    return new PhaseAndPlugin(phase, plugin);
  }

  private static List<String> stackTrace(Throwable failure) {
    List<String> frames = new ArrayList<>();
    Throwable current = failure;
    while (current != null && frames.size() < 32) {
      for (StackTraceElement frame : current.getStackTrace()) {
        if (frames.size() == 32) {
          break;
        }
        frames.add(frame.toString());
      }
      current = current.getCause();
    }
    return List.copyOf(frames);
  }

  private record PhaseAndPlugin(String phase, String plugin) {}
}
