package dev.provenance.probe;

import java.util.List;

final class ConsoleCommandTest {
  private final String id;
  private final String command;
  private final long timeoutSeconds;
  private final List<CommandAssertion> assertions;

  ConsoleCommandTest(
      String id, String command, long timeoutSeconds, List<CommandAssertion> assertions) {

    assertions = Java8.listCopy(assertions);

    this.id = id;
    this.command = command;
    this.timeoutSeconds = timeoutSeconds;
    this.assertions = assertions;
  }

  public String id() {
    return id;
  }

  public String command() {
    return command;
  }

  public long timeoutSeconds() {
    return timeoutSeconds;
  }

  public List<CommandAssertion> assertions() {
    return assertions;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof ConsoleCommandTest)) return false;
    ConsoleCommandTest that = (ConsoleCommandTest) other;
    return java.util.Objects.equals(id, that.id)
        && java.util.Objects.equals(command, that.command)
        && java.util.Objects.equals(timeoutSeconds, that.timeoutSeconds)
        && java.util.Objects.equals(assertions, that.assertions);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(id, command, timeoutSeconds, assertions);
  }

  String commandLabel() {
    int separator = command.indexOf(' ');
    return separator < 0 ? command : command.substring(0, separator);
  }
}

final class CommandTestPlan {
  private final List<ConsoleCommandTest> console;

  CommandTestPlan(List<ConsoleCommandTest> console) {

    console = Java8.listCopy(console);

    this.console = console;
  }

  public List<ConsoleCommandTest> console() {
    return console;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof CommandTestPlan)) return false;
    CommandTestPlan that = (CommandTestPlan) other;
    return java.util.Objects.equals(console, that.console);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(console);
  }
}
