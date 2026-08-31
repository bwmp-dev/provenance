package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class CommandTestPlanReaderTest {
  private final CommandTestPlanReader reader = new CommandTestPlanReader();

  @Test
  void readsRunnerPlanAndBothAssertionOperators() throws TestPlanException {
    CommandTestPlan plan =
        reader.parse(
            """
            {
              "targetPlugin": "ExamplePlugin",
              "requiredDependencies": ["DependencyPlugin"],
              "stabilizationMilliseconds": 3000,
              "console": [{
                "id": "version-command",
                "command": "/example version",
                "timeoutSeconds": 10,
                "assertions": [
                  {
                    "stream": "combined",
                    "operator": "contains",
                    "pattern": "ExamplePlugin",
                    "match": "present",
                    "minimumOccurrences": 1
                  },
                  {
                    "stream": "stderr",
                    "pattern": "Exception|ERROR",
                    "match": "absent"
                  }
                ]
              }]
            }
            """);

    ConsoleCommandTest command = plan.console().getFirst();
    assertEquals("example version", command.command());
    assertEquals(10, command.timeoutSeconds());
    assertEquals(CommandAssertionOperator.CONTAINS, command.assertions().get(0).operator());
    assertEquals(CommandAssertionOperator.REGEX, command.assertions().get(1).operator());
    assertEquals("version-command:2", command.assertions().get(1).id());
  }

  @Test
  void acceptsExistingRunnerPlanWithoutConsoleCommands() throws TestPlanException {
    CommandTestPlan plan =
        reader.parse(
            """
            {
              "targetPlugin": "ExamplePlugin",
              "requiredDependencies": [],
              "stabilizationMilliseconds": 25
            }
            """);

    assertEquals(0, plan.console().size());
  }

  @Test
  void rejectsUnknownFieldsAndUnsafeRegularExpressions() {
    assertThrows(
        TestPlanException.class,
        () ->
            reader.parse(
                """
                {"console": [], "unbounded": true}
                """));
    assertThrows(
        TestPlanException.class,
        () ->
            reader.parse(
                """
                {
                  "console": [{
                    "id": "unsafe-regex",
                    "command": "example",
                    "timeoutSeconds": 1,
                    "assertions": [{
                      "stream": "combined",
                      "operator": "regex",
                      "pattern": "(a+)\\1",
                      "match": "present"
                    }]
                  }]
                }
                """));
  }

  @Test
  void rejectsDuplicateIdsAndAbsentOccurrenceThresholds() {
    assertThrows(
        TestPlanException.class,
        () ->
            reader.parse(
                """
                {
                  "console": [{
                    "id": "duplicate",
                    "command": "one",
                    "timeoutSeconds": 1,
                    "assertions": [{"stream":"combined","pattern":"one","match":"present"}]
                  }, {
                    "id": "duplicate",
                    "command": "two",
                    "timeoutSeconds": 1,
                    "assertions": [{"stream":"combined","pattern":"two","match":"present"}]
                  }]
                }
                """));
    assertThrows(
        TestPlanException.class,
        () ->
            reader.parse(
                """
                {
                  "console": [{
                    "id": "invalid-absent",
                    "command": "example",
                    "timeoutSeconds": 1,
                    "assertions": [{
                      "stream": "combined",
                      "pattern": "ERROR",
                      "match": "absent",
                      "minimumOccurrences": 2
                    }]
                  }]
                }
                """));
  }

  @Test
  void rejectsPlansThatExceedTheStructuredEventBudget() {
    String commands =
        IntStream.range(0, 100)
            .mapToObj(
                index ->
                    """
                    {
                      "id":"command-%d",
                      "command":"example",
                      "timeoutSeconds":1,
                      "assertions":[{"stream":"combined","pattern":"ok","match":"present"}]
                    }
                    """
                        .formatted(index))
            .collect(java.util.stream.Collectors.joining(","));

    assertThrows(
        TestPlanException.class,
        () -> reader.parse("{\"console\":[" + commands + "]}"));
  }
}
