package dev.provenance.probe;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class CommandTestRunner implements AutoCloseable {
  private final EventSink sink;
  private final ScheduledExecutorService watchdog;
  private final int maximumOutputBytes;

  CommandTestRunner(EventSink sink, int maximumOutputBytes) {
    this(
        sink,
        maximumOutputBytes,
        Executors.newSingleThreadScheduledExecutor(
            runnable -> {
              Thread thread = new Thread(runnable, "provenance-command-watchdog");
              thread.setDaemon(true);
              return thread;
            }));
  }

  CommandTestRunner(
      EventSink sink, int maximumOutputBytes, ScheduledExecutorService watchdog) {
    this.sink = sink;
    this.maximumOutputBytes = maximumOutputBytes;
    this.watchdog = watchdog;
  }

  CommandSuiteResult run(List<ConsoleCommandTest> tests, CommandDispatcher dispatcher) {
    boolean passed = true;
    for (ConsoleCommandTest test : tests) {
      CommandRunResult result = run(test, dispatcher);
      passed &= result.passed();
      if (result.timedOut()) {
        return new CommandSuiteResult(false, true);
      }
    }
    return new CommandSuiteResult(passed, false);
  }

  private CommandRunResult run(ConsoleCommandTest test, CommandDispatcher dispatcher) {
    final boolean registered;
    try {
      registered = dispatcher.isRegistered(test.commandLabel());
    } catch (RuntimeException exception) {
      emit(
          EventType.COMMAND_REGISTRATION,
          Map.of(
              "testId", test.id(),
              "commandLabel", test.commandLabel(),
              "registered", false,
              "status", "LOOKUP_FAILED",
              "exceptionType", exception.getClass().getName()));
      classify(
          ProbeClassification.COMMAND_REGISTRATION_FAILURE,
          Map.of("testId", test.id(), "commandLabel", test.commandLabel()));
      completeTest(test.id(), false);
      return new CommandRunResult(false, false);
    }
    emit(
        EventType.COMMAND_REGISTRATION,
        Map.of(
            "testId", test.id(),
            "commandLabel", test.commandLabel(),
            "registered", registered,
            "status", registered ? "REGISTERED" : "NOT_REGISTERED"));
    if (!registered) {
      classify(
          ProbeClassification.COMMAND_NOT_REGISTERED,
          Map.of("testId", test.id(), "commandLabel", test.commandLabel()));
      completeTest(test.id(), false);
      return new CommandRunResult(false, false);
    }

    CommandOutputCapture output = new CommandOutputCapture(maximumOutputBytes);
    AtomicReference<ExecutionState> state = new AtomicReference<>(ExecutionState.RUNNING);
    emit(
        EventType.COMMAND_EXECUTION_STARTED,
        Map.of(
            "testId", test.id(),
            "commandLabel", test.commandLabel(),
            "timeoutSeconds", test.timeoutSeconds()));
    ScheduledFuture<?> timeout =
        watchdog.schedule(
            () -> {
              if (state.compareAndSet(ExecutionState.RUNNING, ExecutionState.TIMED_OUT)) {
                emit(
                    EventType.COMMAND_TIMEOUT,
                    Map.of("testId", test.id(), "timeoutSeconds", test.timeoutSeconds()));
                classify(
                    ProbeClassification.COMMAND_TIMEOUT,
                    Map.of("testId", test.id(), "timeoutSeconds", test.timeoutSeconds()));
              }
            },
            test.timeoutSeconds(),
            TimeUnit.SECONDS);

    final boolean dispatched;
    try {
      dispatched = dispatcher.dispatch(test.command(), output);
    } catch (RuntimeException exception) {
      state.compareAndSet(ExecutionState.RUNNING, ExecutionState.FINISHED);
      timeout.cancel(false);
      boolean timedOut = state.get() == ExecutionState.TIMED_OUT;
      emitOutput(test, output);
      emit(
          EventType.COMMAND_EXECUTION_COMPLETED,
          Map.of(
              "testId", test.id(),
              "status", timedOut ? "TIMED_OUT" : "EXECUTION_FAILED",
              "exceptionType", exception.getClass().getName()));
      if (!timedOut) {
        classify(
            ProbeClassification.COMMAND_EXECUTION_FAILURE,
            Map.of("testId", test.id(), "exceptionType", exception.getClass().getName()));
      }
      completeTest(test.id(), false);
      return new CommandRunResult(false, timedOut);
    }

    state.compareAndSet(ExecutionState.RUNNING, ExecutionState.FINISHED);
    timeout.cancel(false);
    boolean timedOut = state.get() == ExecutionState.TIMED_OUT;
    emitOutput(test, output);
    emit(
        EventType.COMMAND_EXECUTION_COMPLETED,
        Map.of(
            "testId", test.id(),
            "status", timedOut ? "TIMED_OUT" : dispatched ? "COMPLETED" : "DISPATCH_REJECTED",
            "dispatched", dispatched));
    if (timedOut) {
      completeTest(test.id(), false);
      return new CommandRunResult(false, true);
    }
    if (!dispatched) {
      classify(
          ProbeClassification.COMMAND_EXECUTION_FAILURE,
          Map.of("testId", test.id(), "reason", "dispatch_rejected"));
      completeTest(test.id(), false);
      return new CommandRunResult(false, false);
    }
    if (output.truncated()) {
      for (CommandAssertion assertion : test.assertions()) {
        emitAssertion(test.id(), assertion, 0, false, false);
      }
      classify(
          ProbeClassification.COMMAND_OUTPUT_TRUNCATED,
          Map.of(
              "testId", test.id(),
              "capturedBytes", output.capturedBytes(),
              "observedBytes", output.observedBytes()));
      completeTest(test.id(), false);
      return new CommandRunResult(false, false);
    }

    List<String> failedAssertions = new ArrayList<>();
    for (CommandAssertion assertion : test.assertions()) {
      String selected =
          switch (assertion.stream()) {
            case STDOUT, COMBINED -> output.text();
            case STDERR -> "";
          };
      int occurrences = assertion.occurrences(selected);
      boolean assertionPassed = assertion.passes(occurrences);
      emitAssertion(test.id(), assertion, occurrences, true, assertionPassed);
      if (!assertionPassed) {
        failedAssertions.add(assertion.id());
      }
    }
    boolean passed = failedAssertions.isEmpty();
    if (!passed) {
      classify(
          ProbeClassification.COMMAND_ASSERTION_FAILURE,
          Map.of("testId", test.id(), "failedAssertions", failedAssertions));
    }
    completeTest(test.id(), passed);
    return new CommandRunResult(passed, false);
  }

  private void completeTest(String testId, boolean passed) {
    emit(
        EventType.COMMAND_TEST_COMPLETED,
        Map.of("testId", testId, "passed", passed));
  }

  private void emitOutput(ConsoleCommandTest test, CommandOutputCapture output) {
    LinkedHashMap<String, Object> data = new LinkedHashMap<>();
    data.put("testId", test.id());
    data.put("stream", "stdout");
    data.put("lines", output.lines());
    data.put("capturedBytes", output.capturedBytes());
    data.put("observedBytes", output.observedBytes());
    data.put("truncated", output.truncated());
    data.put("normalization", "utf8-nfc-lf-plain-v1");
    emit(EventType.COMMAND_OUTPUT, data);
  }

  private void emitAssertion(
      String testId,
      CommandAssertion assertion,
      int occurrences,
      boolean evaluated,
      boolean passed) {
    LinkedHashMap<String, Object> data = new LinkedHashMap<>();
    data.put("testId", testId);
    data.put("assertionId", assertion.id());
    data.put("stream", assertion.stream().name().toLowerCase(java.util.Locale.ROOT));
    data.put("operator", assertion.operator().name().toLowerCase(java.util.Locale.ROOT));
    data.put("match", assertion.match().name().toLowerCase(java.util.Locale.ROOT));
    data.put("minimumOccurrences", assertion.minimumOccurrences());
    data.put("actualOccurrences", occurrences);
    data.put("evaluated", evaluated);
    data.put("passed", passed);
    emit(EventType.COMMAND_ASSERTION, data);
  }

  private void classify(ProbeClassification classification, Map<String, ?> evidence) {
    emit(EventType.CLASSIFICATION, classification.data(evidence));
  }

  private void emit(EventType type, Map<String, Object> data) {
    sink.emit(ProbeEvent.now(type, data));
  }

  @Override
  public void close() {
    watchdog.shutdownNow();
  }

  interface CommandDispatcher {
    boolean isRegistered(String commandLabel);

    boolean dispatch(String command, CommandOutputCapture output);
  }

  record CommandSuiteResult(boolean passed, boolean timedOut) {}

  private record CommandRunResult(boolean passed, boolean timedOut) {}

  private enum ExecutionState {
    RUNNING,
    FINISHED,
    TIMED_OUT
  }
}
