package dev.provenance.probe;

import java.util.List;

record ConsoleCommandTest(
    String id, String command, long timeoutSeconds, List<CommandAssertion> assertions) {
  ConsoleCommandTest {
    assertions = List.copyOf(assertions);
  }

  String commandLabel() {
    int separator = command.indexOf(' ');
    return separator < 0 ? command : command.substring(0, separator);
  }
}

record CommandTestPlan(List<ConsoleCommandTest> console) {
  CommandTestPlan {
    console = List.copyOf(console);
  }
}
