package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.junit.jupiter.api.Test;

class Log4jLifecycleExceptionAppenderTest {
  @Test
  void forwardsAttachedThrowablesWithoutInspectingFormattedLogMessages() {
    CollectingSink sink = new CollectingSink();
    LifecycleExceptionHandler handler =
        new LifecycleExceptionHandler(sink, Map.of("example.TargetPlugin", "TargetPlugin"));
    IllegalStateException failure = new IllegalStateException("unrelated prose");
    failure.setStackTrace(
        new StackTraceElement[] {
          new StackTraceElement("example.TargetPlugin", "onLoad", "TargetPlugin.java", 9)
        });
    Log4jLifecycleExceptionAppender appender =
        new Log4jLifecycleExceptionAppender(handler, null, Set.of());

    appender.append(
        Log4jLogEvent.newBuilder()
            .setMessage(new org.apache.logging.log4j.message.SimpleMessage("not parsed"))
            .setThrown(failure)
            .build());

    assertEquals(2, sink.events.size());
    assertEquals(EventType.LIFECYCLE_EXCEPTION, sink.events.getFirst().type());
    assertEquals("LOAD", sink.events.getFirst().data().get("phase"));
    assertEquals("on_load_failure", sink.events.get(1).data().get("code"));
  }

  private static final class CollectingSink implements EventSink {
    private final List<ProbeEvent> events = new ArrayList<>();

    @Override
    public void emit(ProbeEvent event) {
      events.add(event);
    }
  }
}
