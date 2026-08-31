package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;

class LifecycleExceptionHandlerTest {
  @Test
  void emitsStructuredEnableExceptionFromThrowableFramesWithoutParsingMessageProse() {
    CollectingSink sink = new CollectingSink();
    LifecycleExceptionHandler handler =
        new LifecycleExceptionHandler(sink, Map.of("example.TargetPlugin", "TargetPlugin"));
    IllegalStateException failure = new IllegalStateException("arbitrary prose");
    failure.setStackTrace(
        new StackTraceElement[] {
          new StackTraceElement("example.TargetPlugin", "onEnable", "TargetPlugin.java", 14)
        });
    LogRecord record = new LogRecord(Level.SEVERE, "message format unrelated to lifecycle");
    record.setThrown(failure);

    handler.publish(record);
    handler.publish(record);

    assertEquals(2, sink.events.size());
    ProbeEvent event = sink.events.getFirst();
    assertEquals(EventType.LIFECYCLE_EXCEPTION, event.type());
    assertEquals("ENABLE", event.data().get("phase"));
    assertEquals("TargetPlugin", event.data().get("plugin"));
    assertEquals(IllegalStateException.class.getName(), event.data().get("exceptionType"));
    assertEquals("arbitrary prose", event.data().get("message"));
    ProbeEvent classification = sink.events.get(1);
    assertEquals(EventType.CLASSIFICATION, classification.type());
    assertEquals("on_enable_failure", classification.data().get("code"));
    assertEquals("FAILURE_CATEGORY_PLUGIN", classification.data().get("category"));
    assertEquals("FAILURE_STAGE_STARTUP", classification.data().get("stage"));
  }

  @Test
  void classifiesLoadExceptionsSeparatelyFromEnableExceptions() {
    CollectingSink sink = new CollectingSink();
    LifecycleExceptionHandler handler =
        new LifecycleExceptionHandler(sink, Map.of("example.TargetPlugin", "TargetPlugin"));
    IllegalStateException failure = new IllegalStateException("load failed");
    failure.setStackTrace(
        new StackTraceElement[] {
          new StackTraceElement("example.TargetPlugin", "onLoad", "TargetPlugin.java", 9)
        });
    LogRecord record = new LogRecord(Level.SEVERE, "not parsed");
    record.setThrown(failure);

    handler.publish(record);

    assertEquals("LOAD", sink.events.getFirst().data().get("phase"));
    assertEquals("on_load_failure", sink.events.get(1).data().get("code"));
  }

  @Test
  void ignoresUnrelatedThrowables() {
    CollectingSink sink = new CollectingSink();
    LifecycleExceptionHandler handler = new LifecycleExceptionHandler(sink, Map.of());
    LogRecord record = new LogRecord(Level.WARNING, "unrelated");
    record.setThrown(new IOExceptionForTest());

    handler.publish(record);

    assertEquals(List.of(), sink.events);
  }

  private static final class CollectingSink implements EventSink {
    private final List<ProbeEvent> events = new ArrayList<>();

    @Override
    public void emit(ProbeEvent event) {
      events.add(event);
    }
  }

  private static final class IOExceptionForTest extends RuntimeException {}
}
