package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.re2j.Pattern;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class CommandTestRunnerTest {
  @Test
  void emitsBoundedOutputAndPassingContainsAndRegexAssertions() {
    CollectingSink sink = new CollectingSink();
    try (CommandTestRunner runner = new CommandTestRunner(sink, 1_024)) {
      CommandTestRunner.CommandSuiteResult result =
          runner.run(
              List.of(successTest()),
              dispatcher(
                  true,
                  output -> {
                    output.append("PROVENANCE_FIXTURE_COMMAND_OK");
                    return true;
                  }));

      assertTrue(result.passed());
      assertFalse(result.timedOut());
      assertEquals(1, sink.events(EventType.COMMAND_OUTPUT).size());
      assertEquals(2, sink.events(EventType.COMMAND_ASSERTION).size());
      assertTrue(
          sink.events(EventType.COMMAND_ASSERTION).stream()
              .allMatch(event -> Boolean.TRUE.equals(event.data().get("passed"))));
    }
  }

  @Test
  void classifiesRegistrationExecutionAndAssertionFailuresDistinctly() {
    CollectingSink sink = new CollectingSink();
    try (CommandTestRunner runner = new CommandTestRunner(sink, 1_024)) {
      runner.run(List.of(successTest()), dispatcher(false, output -> true));
      runner.run(
          List.of(successTest()),
          dispatcher(
              true,
              output -> {
                throw new IllegalStateException("arbitrary command failure");
              }));
      runner.run(
          List.of(successTest()),
          dispatcher(
              true,
              output -> {
                output.append("different output");
                return true;
              }));
    }

    assertEquals(
        List.of(
            "command_not_registered", "command_execution_failure", "command_assertion_failure"),
        sink.events(EventType.CLASSIFICATION).stream()
            .map(event -> (String) event.data().get("code"))
            .toList());
  }

  @Test
  void failsClosedWhenOutputIsTruncated() {
    CollectingSink sink = new CollectingSink();
    try (CommandTestRunner runner = new CommandTestRunner(sink, 8)) {
      CommandTestRunner.CommandSuiteResult result =
          runner.run(
              List.of(successTest()),
              dispatcher(
                  true,
                  output -> {
                    output.append("PROVENANCE_FIXTURE_COMMAND_OK");
                    return true;
                  }));

      assertFalse(result.passed());
      assertEquals(
          "command_output_truncated",
          sink.events(EventType.CLASSIFICATION).getFirst().data().get("code"));
      assertTrue(
          sink.events(EventType.COMMAND_ASSERTION).stream()
              .allMatch(event -> Boolean.FALSE.equals(event.data().get("evaluated"))));
    }
  }

  @Test
  void watchdogReportsTimeoutAndStopsTheSuite() {
    CollectingSink sink = new CollectingSink();
    var watchdog = Executors.newSingleThreadScheduledExecutor();
    try (CommandTestRunner runner = new CommandTestRunner(sink, 1_024, watchdog)) {
      CommandTestRunner.CommandSuiteResult result =
          runner.run(
              List.of(timeoutTest(), successTest()),
              dispatcher(
                  true,
                  output -> {
                    try {
                      assertTrue(sink.timeout.await(2, TimeUnit.SECONDS));
                    } catch (InterruptedException exception) {
                      Thread.currentThread().interrupt();
                      throw new AssertionError(exception);
                    }
                    return true;
                  }));

      assertFalse(result.passed());
      assertTrue(result.timedOut());
      assertEquals(1, sink.events(EventType.COMMAND_EXECUTION_STARTED).size());
      assertEquals(
          "command_timeout", sink.events(EventType.CLASSIFICATION).getFirst().data().get("code"));
    }
  }

  private static ConsoleCommandTest successTest() {
    return new ConsoleCommandTest(
        "command-success",
        "provenance-success",
        60,
        List.of(
            new CommandAssertion(
                "command-success:1",
                CommandOutputStream.COMBINED,
                CommandAssertionOperator.CONTAINS,
                "FIXTURE_COMMAND_OK",
                CommandAssertionMatch.PRESENT,
                1,
                null),
            new CommandAssertion(
                "command-success:2",
                CommandOutputStream.COMBINED,
                CommandAssertionOperator.REGEX,
                "^PROVENANCE_.*_OK$",
                CommandAssertionMatch.PRESENT,
                1,
                Pattern.compile("^PROVENANCE_.*_OK$"))));
  }

  private static ConsoleCommandTest timeoutTest() {
    ConsoleCommandTest test = successTest();
    return new ConsoleCommandTest(test.id(), test.command(), 0, test.assertions());
  }

  private static CommandTestRunner.CommandDispatcher dispatcher(
      boolean registered, DispatchBehavior behavior) {
    return new CommandTestRunner.CommandDispatcher() {
      @Override
      public boolean isRegistered(String commandLabel) {
        return registered;
      }

      @Override
      public boolean dispatch(String command, CommandOutputCapture output) {
        return behavior.dispatch(output);
      }
    };
  }

  @FunctionalInterface
  private interface DispatchBehavior {
    boolean dispatch(CommandOutputCapture output);
  }

  private static final class CollectingSink implements EventSink {
    private final List<ProbeEvent> values = new ArrayList<>();
    private final CountDownLatch timeout = new CountDownLatch(1);

    @Override
    public synchronized void emit(ProbeEvent event) {
      values.add(event);
      if (event.type() == EventType.COMMAND_TIMEOUT) {
        timeout.countDown();
      }
    }

    synchronized List<ProbeEvent> events(EventType type) {
      return values.stream().filter(event -> event.type() == type).toList();
    }
  }
}
